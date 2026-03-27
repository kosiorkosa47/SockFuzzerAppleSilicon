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
#include <kern/btlog.h>
#include <kern/counter.h>
#include <kern/locks.h>
#include <stdbool.h>
#include <vm/vm_kern.h>

int printf(const char*, ...);
#define STUB_ABORT(name) void name() { printf("STUB HIT: " #name "\n"); __builtin_trap(); }

void kheap_startup_init() {}

void zone_view_startup_init(struct zone_view_startup_spec *sp) {}

void lck_attr_startup_init(struct lck_attr_startup_spec *sp) {}

void lck_grp_startup_init(struct lck_grp_startup_spec *sp) {}

lck_attr_t *lck_attr_alloc_init() { return (void *)1; }

void lck_mtx_assert(lck_mtx_t *lck, unsigned int type) {}

void lck_mtx_init(lck_mtx_t *lck, lck_grp_t *grp, lck_attr_t *attr) {}

void lck_mtx_lock(lck_mtx_t *lck) {}

void lck_spin_init(lck_spin_t *lck, lck_grp_t *grp, lck_attr_t *attr) {}

void lck_rw_startup_init(struct lck_rw_startup_spec *spec) {}

// fake these so they aren't null but still invalid
lck_grp_attr_t  *lck_grp_attr_alloc_init(
void) {
  return (void*)1;
}

lck_grp_t *lck_grp_alloc_init(
    const char *grp_name,
    lck_grp_attr_t *attr) {
  return (void*)1;
}

lck_rw_t *lck_rw_alloc_init(
    lck_grp_t *grp,
    lck_attr_t *attr) {
  return (void*)1;
}

lck_mtx_t *lck_mtx_alloc_init(
    lck_grp_t *grp,
    lck_attr_t *attr) {
  return (void*)1;
}

lck_spin_t      *lck_spin_alloc_init(
	lck_grp_t               *grp,
	lck_attr_t              *attr) { return (void*)1; }

void lck_mtx_lock_spin(lck_mtx_t *lck) {}

void lck_mtx_convert_spin(lck_mtx_t *lck) {}

void lck_mtx_free(lck_mtx_t *lck, lck_grp_t *grp) {}

void lck_rw_init(lck_rw_t *lck, lck_grp_t *grp, lck_attr_t *attr) {}

void lck_mtx_unlock(lck_mtx_t *lck) {}

void lck_attr_free(lck_attr_t *attr) {}

void lck_attr_setdebug(lck_attr_t *attr) {}

OS_OVERLOADABLE
uint64_t counter_load(unsigned long long **counter) { printf("STUB HIT: counter_load\n"); assert(false); }

int32_t sysctl_get_bound_cpuid(void) { printf("STUB HIT: sysctl_get_bound_cpuid\n"); assert(false); }

kern_return_t sysctl_thread_bind_cpuid(int32_t cpuid) { printf("STUB HIT: sysctl_thread_bind_cpuid\n"); assert(false); }

kern_return_t kernel_memory_allocate(vm_map_t map, vm_offset_t *addrp,
                                     vm_size_t size, vm_offset_t mask,
                                     kma_flags_t flags, vm_tag_t tag) {
  printf("STUB HIT: kernel_memory_allocate\n");
  assert(false);
}

void lck_mtx_startup_init(struct lck_mtx_startup_spec *spec) {}

void
btlog_add_entry(btlog_t *btlog,
    void *element,
    uint8_t operation,
    void *bt[],
    size_t btcount)
{}

void
btlog_remove_entries_for_element(btlog_t *btlog,
    void *element) {}

btlog_t *
btlog_create(size_t numrecords,
    size_t record_btdepth,
    boolean_t caller_will_remove_entries_for_element) {
      printf("STUB HIT: btlog_create\n");
      assert(false);
    }

void machine_init() {}
void device_service_create() {}
void bsd_init() {}

void slave_machine_init(__unused void *param) {}

void phys_carveout_init() {}
void hv_support_init() {}
void vm_mem_bootstrap() {}
void kdp_init() {}
void workq_init() {}
void machine_lockdown() {}
void thread_max() {}
void kperf_init_early() {}
void thread_daemon_init() {}
void mac_policy_initmach() {}
void vm_kernel_reserved_entry_init() {}
void kdebug_free_early_buf() {}
void turnstiles_init() {}
void vm_commpage_text_init() {}
void machine_load_context() {}
void ipc_pthread_priority_init() {}
void PE_i_can_has_debugger() {}
void sfi_init() {}
void dtrace_early_init() {}
void sched_startup() {}
void ml_get_interrupts_enabled() {}
void kernel_list_tests() {}
void thread_machine_init_template() {}
void task_max() {}
void thread_get_perfcontrol_class() {}
void ml_set_interrupts_enabled() {}
void processor_up() {}
void exception_init() {}
void vm_set_restrictions() {}
void thread_init() {}
void console_init() {}
void idle_thread_create() {}
void PE_init_iokit() {}
void mac_policy_init() {}
void bsd_scale_setup() {}
void mapping_adjust() {}
void trust_cache_init() {}

vm_size_t mem_size = 4000000;

void version_minor() {}
void restartable_init() {}
void clock_init() {}
void kpc_init() {}
void vnguard_policy_init() {}
void coalitions_init() {}
void PE_lockdown_iokit() {}
void work_interval_subsystem_init() {}
void kernel_do_post() {}
void stack_alloc_try() {}
void vm_commpage_init() {}
void serial_keyboard_init() {}
void stackshot_init() {}
void task_threadmax() {}
void version() {}
void mach_init_activity_id() {}
void current_processor() {}
void telemetry_init() {}
void vm_pageout() {}
void sdt_early_init() {}
void task_init() {}
void vm_page_init_local_q() {}
void bootprofile_init() {}

struct machine_info machine_info;
uint64_t max_mem_actual = 4000000;

void thread_bind() {}
void spinlock_timeout_panic() {}
void sched_dualq_dispatch() {}
void processor_state_update_explicit() {}
void mapping_free_prime() {}
void PE_parse_boot_arg_str() {}
void timer_start() {}
void atm_init() {}
void version_major() {}
void waitq_bootstrap() {}
void sched_init() {}
void kperf_init() {}
void kernel_thread_create() {}
void machine_set_current_thread() {}
void idle_thread() {}
void kasan_late_init() {}
void thread_call_initialize() {}
void clock_service_create() {}
void ipc_thread_call_init() {}
void corpses_init() {}
void OSKextRemoveKextBootstrap() {}
void bank_init() {}
void kdebug_init() {}
void vm_free_delayed_pages() {}
void initialize_screen() {}
void serverperfmode() {}
void host_statistics_init() {}

boolean_t doprnt_hide_pointers = true;

/* Stubs for functions and variables from startup.c (excluded on macOS arm64
 * build because it includes deeply nested i386 headers with x86 asm).
 *
 * kernel_startup_initialize_upto iterates the __DATA,__init_entry_set
 * section, which is populated by __STARTUP macros in XNU source files.
 * This is how zones, locks, etc. get created at boot. We call an
 * external helper (startup_iterate_section) compiled without -nostdinc
 * that uses getsectdata() to locate and iterate the entries. */
#include <kern/startup.h>

/* Startup stubs — all no-ops for fuzzer build */
void kernel_startup_bootstrap(void) {}
void kernel_and_kext_startup(void *param, int wait_result) {}
vm_offset_t vm_kernel_addrperm = 0;
vm_offset_t buf_kernel_addrperm = 0;
vm_offset_t vm_kernel_addrperm_ext = 0;
uint64_t vm_kernel_addrhash_salt = 0;
uint64_t vm_kernel_addrhash_salt_ext = 0;
/* kevent_debug_flags: now provided by kern_event.c via TUNABLE() macro. */
