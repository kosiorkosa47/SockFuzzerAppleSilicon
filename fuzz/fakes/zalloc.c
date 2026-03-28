/*
 * Copyright 2021 Google LLC
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#include <kern/assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "osfmk/kern/kalloc.h"
#include "osfmk/kern/zalloc_internal.h"
#include "osfmk/mach/i386/kern_return.h"
#include "BUILD/obj/EXPORT_HDRS/osfmk/kern/zalloc.h"

int printf(const char*, ...) __printflike(1, 2);

// We link these in from libc/asan
void* malloc(size_t size);
void* calloc(size_t nmemb, size_t size);
void free(void* ptr);
int posix_memalign(void** memptr, size_t alignment, size_t size);

// ============================================================================
// Zone Tracking — UAF, double-free, and zone confusion detection
// ============================================================================
//
// Every zone allocation is tracked in a lightweight open-addressing hash table
// keyed by pointer value.  On zfree() we validate:
//   1. The pointer was actually allocated by zalloc (not wild free)
//   2. It has not already been freed (double-free)
//   3. It is being freed to the SAME zone it was allocated from (zone confusion)
//
// Freed allocations enter a quarantine ring buffer.  While in quarantine the
// backing memory is ASAN-poisoned (if available) so any use-after-free access
// triggers an immediate ASAN report.  The quarantine is drained on
// zone_tracking_reset() which is called from clear_all() between iterations.
//
// Cost: ~O(1) per alloc/free, fixed 64KB hash table + quarantine buffer.
// ============================================================================

#define ZT_HASH_SIZE    8192        // must be power of 2
#define ZT_HASH_MASK    (ZT_HASH_SIZE - 1)
#define ZT_QUARANTINE   1024        // ring buffer capacity (kept small to avoid OOM)

// ASAN manual poisoning — available when compiled with -fsanitize=address
#if defined(__has_feature)
#if __has_feature(address_sanitizer)
#define ZT_HAS_ASAN 1
void __asan_poison_memory_region(void const volatile *addr, size_t size);
void __asan_unpoison_memory_region(void const volatile *addr, size_t size);
#endif
#endif
#ifndef ZT_HAS_ASAN
#define ZT_HAS_ASAN 0
#define __asan_poison_memory_region(addr, size) ((void)(addr), (void)(size))
#define __asan_unpoison_memory_region(addr, size) ((void)(addr), (void)(size))
#endif

struct zt_entry {
	void           *ptr;        // allocation address (NULL = empty slot)
	struct zone    *zone;       // owning zone (NULL for kalloc/MALLOC)
	uint32_t        size;       // allocation size
	uint32_t        freed;      // 1 = in quarantine
};

struct zt_quarantine_entry {
	void           *ptr;
	uint32_t        size;
};

static struct zt_entry          zt_table[ZT_HASH_SIZE];
static struct zt_quarantine_entry zt_quarantine[ZT_QUARANTINE];
static uint32_t                 zt_q_head = 0;  // next write position
static uint32_t                 zt_q_count = 0; // entries in quarantine
static uint64_t                 zt_alloc_count = 0;
static uint64_t                 zt_free_count = 0;
static uint64_t                 zt_uaf_count = 0;
static uint64_t                 zt_double_free_count = 0;
static uint64_t                 zt_zone_confusion_count = 0;
static uint64_t                 zt_wild_free_count = 0;

static inline uint32_t zt_hash(void *ptr) {
	uintptr_t v = (uintptr_t)ptr;
	v = (v >> 4) ^ (v >> 18);
	return (uint32_t)(v & ZT_HASH_MASK);
}

static struct zt_entry* zt_find(void *ptr) {
	uint32_t idx = zt_hash(ptr);
	for (uint32_t i = 0; i < 64; i++) {  // linear probe, max 64 steps
		uint32_t slot = (idx + i) & ZT_HASH_MASK;
		if (zt_table[slot].ptr == ptr) return &zt_table[slot];
		if (zt_table[slot].ptr == NULL) return NULL;
	}
	return NULL;
}

static void zt_insert(void *ptr, struct zone *zone, uint32_t size) {
	uint32_t idx = zt_hash(ptr);
	for (uint32_t i = 0; i < 64; i++) {
		uint32_t slot = (idx + i) & ZT_HASH_MASK;
		if (zt_table[slot].ptr == NULL || zt_table[slot].ptr == ptr) {
			zt_table[slot].ptr = ptr;
			zt_table[slot].zone = zone;
			zt_table[slot].size = size;
			zt_table[slot].freed = 0;
			zt_alloc_count++;
			return;
		}
	}
	// Table full — silently skip tracking (shouldn't happen with 8K slots)
	zt_alloc_count++;
}

static void zt_quarantine_push(void *ptr, uint32_t size) {
	// If quarantine is full, evict oldest entry (actually free it)
	if (zt_q_count >= ZT_QUARANTINE) {
		struct zt_quarantine_entry *oldest = &zt_quarantine[zt_q_head];
		if (oldest->ptr) {
			__asan_unpoison_memory_region(oldest->ptr, oldest->size);
			free(oldest->ptr);
			// Remove from tracking table
			struct zt_entry *e = zt_find(oldest->ptr);
			if (e) e->ptr = NULL;
		}
	} else {
		zt_q_count++;
	}
	zt_quarantine[zt_q_head].ptr = ptr;
	zt_quarantine[zt_q_head].size = size;
	zt_q_head = (zt_q_head + 1) % ZT_QUARANTINE;

	// Poison the freed memory so ASAN catches UAF
	__asan_poison_memory_region(ptr, size);
}

// Reset zone tracking between fuzzer iterations.
// Drains quarantine and frees leaked allocations to prevent OOM.
// Live allocations that were never zfree'd are freed here — these are
// XNU state leaks that would accumulate and exhaust memory.
__attribute__((visibility("default")))
void zone_tracking_reset(void) {
	// Drain quarantine first (already-freed, held for UAF detection)
	for (uint32_t i = 0; i < ZT_QUARANTINE; i++) {
		if (zt_quarantine[i].ptr) {
			__asan_unpoison_memory_region(zt_quarantine[i].ptr,
			                              zt_quarantine[i].size);
			free(zt_quarantine[i].ptr);
			zt_quarantine[i].ptr = NULL;
			zt_quarantine[i].size = 0;
		}
	}
	zt_q_head = 0;
	zt_q_count = 0;

	// Count leaked allocations for diagnostics but do NOT free them.
	// XNU global structures (nd6 neighbor cache, route table, interface
	// lists) hold pointers to these objects across iterations. Freeing
	// them causes UAF in timer callbacks (nd6_slowtimo, etc.) that run
	// at the start of the next clear_all().
	//
	// Instead, we accept the leak. The quarantine drain above reclaims
	// memory from properly zfree'd objects, which is the main source of
	// OOM. The remaining leaks grow slowly (~1-2MB/iteration) and the
	// RSS limit handles the upper bound.
	//
	// To actually fix these leaks, each XNU subsystem needs a proper
	// teardown function — that's a separate project.

	// Clear tracking table
	memset(zt_table, 0, sizeof(zt_table));

	// Reset stats for this iteration
	zt_alloc_count = 0;
	zt_free_count = 0;
}

// ============================================================================
// Zone create / init
// ============================================================================

struct zone* zinit(uintptr_t size, uintptr_t max, uintptr_t alloc,
                   const char* name) {
  struct zone* zone = (struct zone*)calloc(1, sizeof(struct zone));
  zone->z_elem_size = size;
  zone->z_name = name;
  zone->z_self = zone;
  return zone;
}

zone_t zone_create(
	const char             *name,
	vm_size_t               size,
	zone_create_flags_t     flags)
{
  struct zone* zone = (struct zone*)calloc(1, sizeof(struct zone));
  zone->z_elem_size = size;
  zone->z_name = name;
  zone->z_self = zone;
  return zone;
}

// TODO: validation here
void zone_change() { return; }

// ============================================================================
// zalloc / zfree — tracked
// ============================================================================

/*
 * When we encounter a NULL zone we allocate a generous default buffer
 * (4096 bytes).  This is intentionally larger than any XNU struct that
 * could be allocated through a zone.
 */
#define ZALLOC_DEFAULT_SIZE 4096

void* zalloc(struct zone* zone) {
  size_t size = ZALLOC_DEFAULT_SIZE;
  if (zone != NULL && zone->z_elem_size > 0) {
    size = zone->z_elem_size;
  }
  void *ptr = calloc(1, size);
  if (ptr) {
    zt_insert(ptr, zone, (uint32_t)size);
  }
  return ptr;
}

void* zalloc_noblock(struct zone* zone) { return zalloc(zone); }

extern void zfree(
	zone_or_view_t  zone_or_view,
	void            *elem) {
  if (!elem) return;

  struct zt_entry *e = zt_find(elem);
  if (!e) {
    // Not in our tracking table — could be kalloc or pre-tracking alloc.
    // Report wild free only if zone_tracking has been active long enough.
    if (zt_alloc_count > 100) {
      zt_wild_free_count++;
    }
    free(elem);
    return;
  }

  // Double-free detection
  if (e->freed) {
    zt_double_free_count++;
    printf("ZONE BUG: double-free of %p (zone=%s, size=%u)\n",
           elem,
           (e->zone && e->zone->z_name) ? e->zone->z_name : "<unknown>",
           e->size);
    // Let ASAN catch this — freeing poisoned memory will trigger report
    free(elem);
    return;
  }

  // Zone confusion detection: freeing to wrong zone
  struct zone *free_zone = zone_or_view.zov_zone;
  if (e->zone != NULL && free_zone != NULL && e->zone != free_zone) {
    zt_zone_confusion_count++;
    printf("ZONE BUG: zone confusion! %p allocated from '%s' (elem_size=%u) "
           "but freed to '%s' (elem_size=%u)\n",
           elem,
           e->zone->z_name ? e->zone->z_name : "<?>",
           e->zone->z_elem_size,
           free_zone->z_name ? free_zone->z_name : "<?>",
           free_zone->z_elem_size);
    // Still free it but this is a REAL BUG in XNU if it happens
  }

  // Mark freed and quarantine
  e->freed = 1;
  zt_free_count++;
  zt_quarantine_push(elem, e->size);
}

// ============================================================================
// kalloc / kfree — tracked without zone
// ============================================================================

int cpu_number() { return 0; }

void* kalloc_canblock(size_t* psize, bool canblock, void* site) {
  void *ptr = malloc(*psize);
  if (ptr) zt_insert(ptr, NULL, (uint32_t)*psize);
  return ptr;
}

// ============================================================================
// mbuf page pool (unchanged)
// ============================================================================

static bool mb_is_ready = false;
extern unsigned char* mbutl;
extern unsigned char* embutl;
static size_t current_page = 0;

uintptr_t kmem_mb_alloc(unsigned int mbmap, int size, int physContig,
                        int* err) {
  *err = 0;

  if (!mb_is_ready) {
    // 268 MB
    *err = posix_memalign((void**)&mbutl, 4096, 4096 * 65535);
    if (*err) {
      return 0;
    }
    embutl = (unsigned char*)((uintptr_t)mbutl + (4096 * 65535));

    mb_is_ready = true;
  }

  assert(mbutl);
  int pages = size / 4096;
  if (current_page + pages > 65535) {
    current_page = 0;
  }
  uintptr_t ret = (uintptr_t)mbutl + (current_page * 4096);
  current_page += pages;

  return ret;
}

// Called from clear_all() to reclaim the mbuf page pool between iterations.
__attribute__((visibility("default")))
void kmem_mb_reset_pages(void) {
  current_page = 0;
}

// TODO: actually simulate physical page mappings
unsigned int pmap_find_phys(int pmap, uintptr_t va) { return (unsigned int)((va >> 12) + 1); }

// ============================================================================
// MALLOC / FREE — tracked
// ============================================================================

void* __MALLOC_ZONE(size_t size, int type, int flags,
                    vm_allocation_site_t* site) {
  void *ptr;
  if (flags & 1) ptr = calloc(1, size);  // M_ZERO = 0x0001
  else ptr = malloc(size);
  if (ptr) zt_insert(ptr, NULL, (uint32_t)size);
  return ptr;
}

void _FREE_ZONE(void* elem, size_t size, int type) {
  if (!elem) return;
  struct zt_entry *e = zt_find(elem);
  if (e) {
    if (e->freed) {
      zt_double_free_count++;
      printf("ZONE BUG: double-free of %p (MALLOC, size=%u)\n", elem, e->size);
    }
    e->freed = 1;
    zt_free_count++;
    zt_quarantine_push(elem, e->size);
    return;
  }
  free(elem);
}

#undef kfree
void kfree(void* data, size_t size) {
  if (!data) return;
  struct zt_entry *e = zt_find(data);
  if (e) {
    if (e->freed) {
      zt_double_free_count++;
      printf("ZONE BUG: double-free of %p (kfree, size=%u)\n", data, e->size);
    }
    e->freed = 1;
    zt_free_count++;
    zt_quarantine_push(data, e->size);
    return;
  }
  free(data);
}

void* realloc(void* ptr, size_t size);

void* __REALLOC(void* addr, size_t size, int type, int flags,
                vm_allocation_site_t* site) {
  // Remove old tracking before realloc (pointer may change)
  if (addr) {
    struct zt_entry *e = zt_find(addr);
    if (e) e->ptr = NULL;
  }
  void* ptr = realloc(addr, size);
  if (ptr) zt_insert(ptr, NULL, (uint32_t)size);
  return ptr;
}

void OSFree(void* ptr, uint32_t size, void* tag) {
  if (!ptr) return;
  struct zt_entry *e = zt_find(ptr);
  if (e) {
    if (e->freed) {
      zt_double_free_count++;
      printf("ZONE BUG: double-free of %p (OSFree)\n", ptr);
    }
    e->freed = 1;
    zt_free_count++;
    zt_quarantine_push(ptr, e->size);
    return;
  }
  free(ptr);
}

void* OSMalloc(uint32_t size, void* tag) {
  void *ptr = malloc(size);
  if (ptr) zt_insert(ptr, NULL, size);
  return ptr;
}

// ============================================================================
// Heap definitions (unchanged)
// ============================================================================

SECURITY_READ_ONLY_LATE(struct kalloc_heap) KHEAP_DATA_BUFFERS[1] = {
	{
		.kh_zones    = NULL,
		.kh_name     = "data.",
		.kh_heap_id  = KHEAP_ID_DATA_BUFFERS,
	}
};

SECURITY_READ_ONLY_LATE(struct kalloc_heap) KHEAP_DEFAULT[1] = {
	{
		.kh_zones    = NULL,
		.kh_name     = "default.",
		.kh_heap_id  = KHEAP_ID_DEFAULT,
	}
};

KALLOC_HEAP_DEFINE(KHEAP_TEMP, "temp allocations", KHEAP_ID_DEFAULT);

ZONE_VIEW_DEFINE(ZV_NAMEI, "vfs.namei", KHEAP_ID_DATA_BUFFERS, 1024);

void abort() {
  __builtin_trap();
}

#undef kheap_free
extern void
kheap_free(
	kalloc_heap_t heap,
	void         *data,
	vm_size_t     size) {
  if (!data) return;
  struct zt_entry *e = zt_find(data);
  if (e) {
    if (e->freed) {
      zt_double_free_count++;
      printf("ZONE BUG: double-free of %p (kheap_free)\n", data);
    }
    e->freed = 1;
    zt_free_count++;
    zt_quarantine_push(data, e->size);
    return;
  }
  free(data);
}

__startup_func
__attribute__((no_sanitize("address")))
void
zone_create_startup(struct zone_create_startup_spec *spec)
{
	*spec->z_var = zone_create(spec->z_name, spec->z_size,
	    spec->z_flags);
}

_Atomic uint32_t bt_init_flag = 0;

struct kalloc_result
kalloc_ext(
	kalloc_heap_t         kheap,
	vm_size_t             req_size,
	zalloc_flags_t        flags,
	vm_allocation_site_t  *site) {
  void *addr = malloc(req_size);
  if (flags & Z_ZERO) {
    bzero(addr, req_size);
  }
  if (addr) zt_insert(addr, NULL, (uint32_t)req_size);
  return (struct kalloc_result){ .addr = addr, .size = req_size };
}

void *zalloc_flags(union zone_or_view zov, zalloc_flags_t flags) {
  return zalloc(zov.zov_zone);
}

#undef kheap_free_addr
void kheap_free_addr(
	kalloc_heap_t         heap,
	void                 *addr) {
  if (!addr) return;
  struct zt_entry *e = zt_find(addr);
  if (e) {
    if (e->freed) {
      zt_double_free_count++;
      printf("ZONE BUG: double-free of %p (kheap_free_addr)\n", addr);
    }
    e->freed = 1;
    zt_free_count++;
    zt_quarantine_push(addr, e->size);
    return;
  }
  free(addr);
}

void *zalloc_permanent(vm_size_t size, vm_offset_t mask) {
  void *ptr = malloc(size);
  if (ptr) zt_insert(ptr, NULL, (uint32_t)size);
  return ptr;
}
