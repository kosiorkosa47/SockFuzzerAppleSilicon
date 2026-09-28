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

#include "bsd/machine/param.h"
#include "bsd/sys/mbuf.h"

// We link these in from libc/asan
void* malloc(size_t size);
void* calloc(size_t nmemb, size_t size);
void free(void* ptr);
int posix_memalign(void** memptr, size_t alignment, size_t size);

typedef struct {
  size_t bufsize;
  // Must we always return clusters?
  bool cluster_cache;
} mcache_t;

mcache_t* mcache_create(const char* name, size_t bufsize, size_t align,
                        u_int32_t flags, int wait) {
  mcache_t* cache = (mcache_t*)malloc(sizeof(mcache_t));
  if (cache == NULL) {
    return NULL;
  }
  cache->bufsize = bufsize;
  cache->cluster_cache = false;
  return cache;
}

// type doesn't match but we just need the address
void mbuf_cslab_alloc(void);

mcache_t* mcache_create_ext(const char* name, size_t bufsize, void* allocfn,
                            void* freefn, void* auditfn, void* logfn,
                            void* notifyfn, void* arg, u_int32_t flags,
                            int wait) {
  mcache_t* cache = (mcache_t*)malloc(sizeof(mcache_t));
  if (cache == NULL) {
    return NULL;
  }
  cache->bufsize = bufsize;
  cache->cluster_cache = allocfn == mbuf_cslab_alloc;
  return cache;
}

void assfail() { assert(false); }

struct mbuf* mbuf_create(const uint8_t* data, size_t size, bool is_header,
                         bool force_ext, int mtype, int pktflags) {
  struct mbuf* m = NULL;
  assert(sizeof(struct mbuf) == MSIZE);
  if (posix_memalign((void**)&m, MSIZE, sizeof(struct mbuf))) {
    return NULL;
  }
  memset((void*)m, 0, sizeof(struct mbuf));
  m->m_type = mtype;
  // TODO: use fuzzed data to create all kinds of mbuf chains
  size_t max_size = MBIGCLBYTES;
  if (njcl > 0) {
    max_size = njclbytes;
  }
  if (size >= max_size) {
    // Refuse instead of quietly shortening the packet. Truncating here made
    // the mbuf disagree with the length the caller believed it had asked for,
    // and in a chain that mismatch is invisible until something reads past
    // the end.
    free(m);
    return NULL;
  }

  if (force_ext || size > sizeof(m->M_dat.MH.MH_dat.MH_databuf)) {
    // calloc(0) may legitimately return NULL, so keep one byte as the floor.
    size_t ext_size = size > 0 ? size : 1;
    caddr_t buf = (caddr_t)calloc(1, ext_size);
    if (buf == NULL) {
      free(m);
      return NULL;
    }
    struct ext_ref* rfa = (struct ext_ref*)calloc(1, sizeof(struct ext_ref));
    if (rfa == NULL) {
      free(buf);
      free(m);
      return NULL;
    }
    m->m_flags = M_EXT;
    m->m_data = m->m_ext.ext_buf = buf;
    m->m_ext.ext_size = size;

    rfa->refcnt = 1;
    rfa->minref = 1;
    int EXTF_COMPOSITE = 0x1;
    rfa->flags = EXTF_COMPOSITE;
    m->m_ext.ext_refflags = (struct ext_ref*)rfa;
  } else {
    m->m_flags = M_PKTHDR;
    m->m_data = m->m_pktdat;
  }

  if (data) memcpy(m->m_data, data, size);
  m->m_len = size;
  if (is_header) {
    m->m_flags |= M_PKTHDR;
    m->m_pkthdr.len = m->m_len;
    m->m_pkthdr.redzone = ((u_int32_t)(uintptr_t)m);
    m->m_pkthdr.pkt_flags = pktflags;
  }

  assert(m->m_len <= ((njcl > 0) ? njclbytes : MBIGCLBYTES));

  return m;
}

void* mcache_alloc(mcache_t* cp, int flags) {
  if (cp->cluster_cache) {
    return mbuf_create(NULL, cp->bufsize, false, cp->cluster_cache, MT_FREE, 0);
  }

  void* m = NULL;
  if (posix_memalign((void**)&m, MSIZE, cp->bufsize)) {
    return NULL;
  }
  return m;
}

uint16_t m_decref(struct mbuf* m) {
  struct ext_ref* rfa = m->m_ext.ext_refflags;
  if (rfa) {
    rfa->refcnt--;
    return rfa->refcnt;
  }
  return 0;
}

struct mbuf* m_free(struct mbuf* m) {
  if ((m->m_flags & M_EXT)) {
    uint16_t refcnt = m_decref(m);
    if (!refcnt) {
      free(m->m_ext.ext_buf);
      free(m->m_ext.ext_refflags);
    }
  }
  struct mbuf* ret = m->m_next;
  free(m);
  return ret;
}

void mcache_free(mcache_t* cp, void* buf) {
  if (cp->cluster_cache) {
    m_free((struct mbuf*)buf);
  } else {
    free(buf);
  }
}

void mcache_init() {
  // Nothing to do for mocked case.
}

void mcache_reap_now() {}

int mcache_alloc_ext(mcache_t* cp, void** list, unsigned int num, int wait) {
  // Allocate num objects, chained via obj_next (first pointer in each buffer).
  // This matches XNU's mcache_alloc_ext which returns a singly-linked list.
  void* head = NULL;
  unsigned int allocated = 0;
  for (unsigned int i = 0; i < num; i++) {
    struct mbuf* m = (struct mbuf*)calloc(1, sizeof(struct mbuf));
    if (!m) break;
    m->m_hdr.mh_next = (struct mbuf*)head;  // chain via mh_next
    m->m_hdr.mh_nextpkt = NULL;
    m->m_type = MT_FREE;
    m->m_flags = M_EXT;
    void *aligned_buf;
    if (posix_memalign(&aligned_buf, 256, cp->bufsize) != 0) {  // MSIZE=256
      free(m);
      break;
    }
    memset(aligned_buf, 0, cp->bufsize);
    m->m_ext.ext_buf = (caddr_t)aligned_buf;
    m->m_ext.ext_size = cp->bufsize;
    m->m_hdr.mh_data = m->m_ext.ext_buf;
    m->m_hdr.mh_len = cp->bufsize;
    struct ext_ref* rfa = (struct ext_ref*)calloc(1, sizeof(struct ext_ref));
    if (rfa == NULL) {
      free(aligned_buf);
      free(m);
      break;
    }
    rfa->refcnt = 1;
    rfa->minref = 1;
    m->m_ext.ext_refflags = rfa;
    head = m;
    allocated++;
  }
  *list = head;
  return allocated;
}

void mcache_audit_cache() {}

void mcache_audit_free_verify() {}

void mcache_audit_free_verify_set() {}

int mcache_bkt_isempty() { return 1; }

void mcache_buffer_log() {}

unsigned int mcache_cache_line_size() {
  return 64;
}

void mcache_dump_mca() {}

// mcache_obj_t is the first field of any mcache-allocated buffer.
// In XNU: typedef struct mcache_obj { struct mcache_obj *obj_next; } mcache_obj_t;
typedef struct mcache_obj { struct mcache_obj *obj_next; } mcache_obj_t;

void mcache_free_ext(mcache_t *cp, mcache_obj_t *list) {
  while (list) {
    mcache_obj_t *next = list->obj_next;
    struct mbuf *m = (struct mbuf *)list;
    if (m->m_flags & M_EXT) {
      if (m->m_ext.ext_buf) free(m->m_ext.ext_buf);
      if (m->m_ext.ext_refflags) free(m->m_ext.ext_refflags);
    }
    free(list);
    list = next;
  }
}

unsigned int mcache_getflags() { return 0; }

void mcache_purge_cache() {}

void mcache_reap() {}

void mcache_set_pattern() {}

void mcache_waiter_dec() {}

void mcache_waiter_inc() {}