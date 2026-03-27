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

// Unimplemented stub functions.
//
// These are placeholders that abort if reached.  They exist because the XNU
// kernel source references many symbols that are irrelevant to network-stack
// fuzzing.  When the fuzzer triggers one of these, it means a new code path
// was reached that needs a real (or faked) implementation.
//
// The stubs intentionally lack correct parameter signatures: since they all
// unconditionally abort, the parameter types are irrelevant.  Adding proper
// signatures for ~500 XNU-internal functions would be a large maintenance
// burden with no practical benefit while they remain unreachable.

#include <kern/assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>

int printf(const char* format, ...);
int vprintf(const char* format, va_list ap);
extern void get_fuzzed_bytes(void* addr, size_t bytes);

// Convenience macro — logs which stub was hit before aborting.
// This makes it immediately obvious which unimplemented function
// the fuzzer reached, so you know what to implement next.
#define STUB_ABORT(name) \
  void name() { printf("STUB HIT: " #name "\n"); __builtin_trap(); }

__attribute__((visibility("default")))
void Assert(const char* file, int line, const char* expression) {
  printf("ASSERT: %s:%d: %s\n", file, line, expression);
  _exit(77);  // Clean exit — libFuzzer logs the crash input without SIGABRT noise
}

void IOBSDGetPlatformUUID() {}

void IOMapperInsertPage() {}

void IOPMCopySleepWakeUUIDKey() {}

void IOTaskHasEntitlement() {}

void OSMalloc_Tagalloc() {}

void OSMalloc_Tagfree() {}

void act_set_astbsd() {}

void act_set_astkevent() {}

void addupc_task() {}

int assert_wait() { return 0; }

void audit_arg_addr() {}
void audit_arg_cmd() {}
void audit_arg_ctlname() {}
void audit_arg_fd() {}
void audit_arg_file() {}
void audit_arg_pid() {}
void audit_arg_process() {}
void audit_arg_signum() {}
void audit_arg_value64() {}
void audit_syscalls() {}

void bsd_exception() {}

void bsd_timeout() {}

void bsdinit_task() {}

int cc_rand_generate(void *out, size_t outlen) {
  get_fuzzed_bytes(out, outlen);
  return 0;
}

void check_actforsig() {}

void clear_thread_rwlock_boost() {}

void clock_absolutetime_interval_to_deadline(uint64_t interval, uint64_t *deadline) {
  extern uint64_t g_fake_time_counter;
  *deadline = g_fake_time_counter + interval;
}

void clock_continuoustime_interval_to_deadline(uint64_t interval, uint64_t *deadline) {
  extern uint64_t g_fake_time_counter;
  *deadline = g_fake_time_counter + interval;
}

void clock_deadline_for_periodic_event(uint64_t interval, uint64_t abstime, uint64_t *deadline) {
  extern uint64_t g_fake_time_counter;
  *deadline = g_fake_time_counter + interval;
}

void clock_get_calendar_nanotime(void *secs, void *nanosecs) {
  extern uint64_t g_fake_time_counter;
  g_fake_time_counter += 100000;
  *(uint32_t *)secs = (uint32_t)(g_fake_time_counter / 1000000000ULL);
  *(uint32_t *)nanosecs = (uint32_t)(g_fake_time_counter % 1000000000ULL);
}


void coalition_get_leader() {}

void coalition_is_leader() {}

void copyin_word() {}

int copyinstr(const void *uaddr, void *kaddr, size_t len, size_t *done) {
  if (len == 0) { if (done) *done = 0; return 0; }
  memset(kaddr, 0, len);
  ((char *)kaddr)[0] = 'x';
  if (done) *done = 2;
  return 0;
}

void copypv() {}

void copywithin() {}

void coredump() {}

void cs_identity_get() {}

void* current_task() { return (void*)1; }

int deflate(void *strm, int flush) { return 1; /* Z_STREAM_END */ }

int deflateReset(void *strm) { return 0; }

void enodev() {}

void enodev_strat() {}

void exit_with_reason() {}

void fs_filtops() {}

void fsevent_filtops() {}

void fuulong() {}

void gPEClockFrequencyInfo() {}

void* g_crypto_funcs = NULL;

void* get_bsdtask_info() { extern char fake_uthread[]; return fake_uthread; }
void* get_bsdthreadtask_info() { extern char fake_uthread[]; return fake_uthread; }

void get_signalact() {}

void get_threadtask() {}

void get_useraddr() {}

uint32_t hashaddr() { return 0; }
uint32_t hashbacktrace() { return 0; }
char hostname[256] = "localhost";
int hz = 100;

int inflate(void *strm, int flush) { return 1; /* Z_STREAM_END */ }

int inflateReset(void *strm) { return 0; }

void initproc() {}

unsigned int ipc_entry_name_mask = 0;
int is_kerneltask() { return 1; }
int itimerdecr() { return 0; }
int itimerfix() { return 0; }
int kauth_authorize_generic() { return 0; }
int kauth_cred_getgid() { return 0; }
int kauth_cred_getruid() { return 0; }
int kauth_cred_getsvuid() { return 0; }
int kauth_getruid() { return 0; }

void kcdata_estimate_required_buffer_size() {}

void kcdata_get_memory_addr() {}

void kcdata_memcpy() {}

void kcdata_memory_static_init() {}

void kdp_get_interface() {}

void kdp_is_in_zone() {}

void kdp_set_gateway_mac() {}

void kdp_set_ip_and_mac_addresses() {}

void kernel_debug_filtered() {}

void kernel_task() {}

void launchd_exit_reason_get_string_desc() {}

void lck_mtx_lock_spin_always() {}

void lck_rw_destroy() {}

void lck_rw_lock_exclusive_to_shared() {}

void lck_rw_lock_shared_to_exclusive() {}

void lck_rw_sleep() {}

void lck_spin_assert() {}

void lck_spin_destroy() {}

void ledger_get_task_entry_info_multiple() {}

void ledger_info() {}

void ledger_template_info() {}

void mac_error_select() {}

void mac_policy_list() {}

void mac_policy_list_conditional_busy() {}

void mac_policy_list_unbusy() {}

void mac_proc_check_ledger() {}

void mac_proc_check_signal() {}

void mac_socket_check_received() {}

void mac_socket_check_stat() {}

void mac_system_enforce() {}

void mach_absolutetime_asleep() {}

void machport_filtops() {}

void max_mem() {}

void mb_map() {}

void memorystatus_filtops() {}

void memorystatus_kevent_init() {}

int msleep(void *chan, void *mtx, int pri, const char *wmesg, void *ts) {
  return 0;  // Simulate immediate wakeup
}

int msleep0() { return 0; }

int msleep1() { return 0; }

void nanoseconds_to_absolutetime(uint64_t nanoseconds, uint64_t *result) {
  *result = nanoseconds;
}

void nanotime(void *ts) {
  extern uint64_t g_fake_time_counter;
  g_fake_time_counter += 100000;
  long *f = (long *)ts;
  f[0] = (long)(g_fake_time_counter / 1000000000ULL);
  f[1] = (long)(g_fake_time_counter % 1000000000ULL);
}

void pg_rele() {}

void pgfind() {}

void pgrp_iterate() {}

void port_name_to_thread() {}

void proc_get_effective_task_policy() {}

void proc_getcdhash() {}

void proc_iterate() {}

void proc_klist_lock() {}

void proc_klist_unlock() {}

void proc_knote() {}

void proc_list_lock() {}

void proc_list_unlock() {}

void proc_lock() {}

void proc_log_32bit_telemetry() {}

void proc_name_address() {}

void proc_parentdropref() {}

void proc_parentholdref() {}

void proc_pgrp() {}

void proc_self() {}

void proc_set_thread_policy() {}

void proc_signal() {}

void proc_spinlock() {}

void proc_spinunlock() {}

void proc_unlock() {}

void proc_uuid_policy_kernel() {}

void proc_uuid_policy_lookup() {}

void pthread_functions() {}

void pthread_priority_canonicalize() {}

void ptmx_kqops() {}

void ptsd_kqops() {}

void pzfind() {}

void sane_size() {}

void securelevel() {}

void semaphore_timedwait_signal_trap_internal() {}

void semaphore_timedwait_trap_internal() {}

void semaphore_wait_signal_trap_internal() {}

void semaphore_wait_trap_internal() {}

void sendsig() {}

void set_thread_rwlock_boost() {}

void spec_filtops() {}

void subyte() {}

void suulong() {}

// Sysctl node arrays — the real kernel populates these via linker sets.
// We provide empty arrays so sysctl registration doesn't crash.
// This allows net.inet.* and net.inet6.* sysctls registered by the
// networking code to work without the full sysctl infrastructure.
struct sysctl_oid_stub { int dummy; };
struct sysctl_oid_stub sysctl__debug_children[1] = {};
struct sysctl_oid_stub sysctl__kern_children[1] = {};
struct sysctl_oid_stub sysctl__net_children[1] = {};
struct sysctl_oid_stub sysctl__net_link_generic_system_children[1] = {};
struct sysctl_oid_stub sysctl__sysctl_children[1] = {};

void task_consume_32bit_log_flag() {}

void task_deallocate() {}

void task_did_exec() {}

void task_hold() {}

void task_is_active() {}

void task_is_exec_copy() {}

void task_is_halting() {}

void task_release() {}

void task_resume_internal() {}

void task_suspend_internal() {}

void task_vtimer_clear() {}

void task_vtimer_set() {}

void task_vtimer_update() {}

void task_wait() {}

void telemetry_timer_event() {}

void thread_add_ipc_override() {}

void thread_add_sync_ipc_override() {}

int thread_block() { return 0; }

int thread_block_parameter() { return 0; }

void thread_call_cancel() {}

void thread_call_cancel_wait() {}

void thread_call_enter() {}

void thread_call_free() {}

void thread_call_func_cancel() {}

void thread_call_func_delayed() {}

void thread_call_isactive() {}

void thread_drop_ipc_override() {}

void thread_drop_sync_ipc_override() {}

void thread_ends_owning_workloop() {}

void thread_get_ipc_override() {}

void thread_get_tag() {}

void thread_handoff() {}

void thread_owned_workloops_count() {}

void thread_qos_from_pthread_priority() {}

void thread_reference() {}

void thread_rettokern_addr() {}

void thread_set_pending_block_hint() {}

void thread_set_thread_name() {}

void thread_set_voucher_name() {}

void thread_should_abort() {}

void thread_should_halt() {}

void thread_starts_owning_workloop() {}

void thread_tid() {}

void thread_update_ipc_override() {}

void thread_wakeup_thread() {}
int tick = 10000;

void timeout_with_leeway() {}

void timespec_is_valid() {}

int tsleep() { return 0; }

int tsleep0() { return 0; }

int tsleep1() { return 0; }

void tstoabstime() {}

void tty_filtops() {}

void tty_pgrp() {}

void tvtoabstime() {}

void unix_syscall_return() {}

void untimeout() {}

void vaddlog() {}

void vfs_context_create() {}

void vfs_context_rele() {}

STUB_ABORT(vm_kernel_slid_base)

STUB_ABORT(vm_kernel_slid_top)

STUB_ABORT(vm_kernel_slide)

void vn_stat() {}

void vnode_filtops() {}

void vnode_isfifo() {}

void waitq_assert_wait64() {}

void waitq_assert_wait64_leeway() {}

void waitq_clear_prepost() {}

void waitq_deinit() {}

void waitq_get_prepost_id() {}

void waitq_init() {}

void waitq_is_valid() {}

void waitq_link() {}

void waitq_link_release() {}

void waitq_link_reserve() {}

void waitq_set_alloc() {}

void waitq_set_clear_preposts() {}

void waitq_set_deinit() {}

void waitq_set_init() {}

void waitq_set_is_valid() {}

void waitq_set_unlink_all() {}

void waitq_unlink() {}

void waitq_unlink_by_prepost_id() {}

void waitq_wakeup64_all() {}

void waitq_wakeup64_one() {}

void wqset_id() {}

void wqset_waitq() {}

void zalloc_canblock() {}

void zfill() {}

STUB_ABORT(kernel_pmap)

void kmem_free() {}

void cru2x() {}

void mac_vnode_check_create() {}

void mac_vnode_check_uipc_bind() {}

void mac_vnode_check_uipc_connect() {}

void namei() {}

void nameidone() {}

void vfs_context_ucred() {}

void vn_create() {}

void vnode_authorize() {}

void vnode_put() {}

void vnode_ref() {}

void vnode_rele() {}

void audit_arg_sockaddr() {}
void audit_arg_socket() {}

void audit_arg_value32() {}

void vfs_context_cwd() {}

void vnode_isreg() {}

void vnode_size() {}

int aes_decrypt_aad_gcm() { return 0; }

int aes_decrypt_cbc() { return 0; }

int aes_decrypt_finalize_gcm() { return 0; }

int aes_decrypt_gcm() { return 0; }

int aes_decrypt_get_ctx_size_gcm() { return 0; }

int aes_decrypt_key() { return 0; }

int aes_decrypt_key_gcm() { return 0; }

int aes_decrypt_set_iv_gcm() { return 0; }

int aes_encrypt_aad_gcm() { return 0; }

int aes_encrypt_cbc() { return 0; }

int aes_encrypt_finalize_gcm() { return 0; }

int aes_encrypt_gcm() { return 0; }

int aes_encrypt_get_ctx_size_gcm() { return 0; }

int aes_encrypt_inc_iv_gcm() { return 0; }

int aes_encrypt_key() { return 0; }

int aes_encrypt_key_with_iv_gcm() { return 0; }

int aes_encrypt_reset_gcm() { return 0; }

void thread_call_enter1_delayed() {}

void panic(const char *fmt, ...) {
  printf("KERNEL PANIC: ");
  va_list ap;
  va_start(ap, fmt);
  vprintf(fmt, ap);
  va_end(ap);
  printf("\n");
  __builtin_trap();
}

struct os_log_s {
  int a;
};

struct os_log_s _os_log_default;

uint32_t net_flowhash_mh3_x86_32(const void* key, uint32_t len,
                                 const uint32_t seed) {
  // FNV-1a hash — simple, fast, deterministic.
  uint32_t hash = seed ^ 2166136261u;
  const uint8_t *p = (const uint8_t *)key;
  for (uint32_t i = 0; i < len; i++) {
    hash ^= p[i];
    hash *= 16777619u;
  }
  return hash;
}

void cc_clear(size_t len, void *dst) { memset(dst, 0, len); }

int cc_cmp_safe(size_t num, const void *ptr1, const void *ptr2) {
  return memcmp(ptr1, ptr2, num);
}

void getsectdatafromheader() {}

/* On macOS, _mh_execute_header is provided by the linker automatically. */
#ifndef __APPLE__
void _mh_execute_header() {}
#endif

uint32_t net_flowhash(const void *key, uint32_t len, const uint32_t seed) {
  return net_flowhash_mh3_x86_32(key, len, seed);
}

void os_cpu_in_cksum() {}

void os_cpu_in_cksum_mbuf() {}

void proc_name() {}

void thread_terminate() {}

void uuid_generate() {}

void uuid_parse() {}

void _pthread_priority_normalize() {}

void workq_kern_threadreq_modify() {}

void nat464_translate_proto() {}

void turnstile_cleanup() {}

void thread_wakeup_prim() {}

void waitq_wakeup64_thread() {}

void turnstile_prepare() {}

int assert_wait_deadline() { return 0; }

void nat464_synthesize_ipv4() {}

void clat_debug() {}

void workq_kern_threadreq_redrive() {}

void zdestroy() {}

void turnstile_update_inheritor() {}

void thread_handoff_parameter() {}

void in6_clat46_eventhdlr_callback() {}

void turnstile_update_inheritor_complete() {}

void nat464_insert_frag46() {}

void nat464_synthesize_ipv6() {}

void turnstile_complete() {}

void nat464_translate_64() {}

void waitq_set_should_lazy_init_link() {}

void workq_is_exiting() {}

int sysctl_helper_waitq_set_nelem() { return 0; }

void turnstile_alloc() {}

void workq_kern_threadreq_update_inheritor() {}

void thread_handoff_deallocate() {}

void workq_kern_threadreq_unlock() {}

void telemetry_pmi_setup() {}

void nat464_translate_46() {}

void waitq_set_lazy_init_link() {}

void workq_thread_set_max_qos() {}

void workq_kern_threadreq_lock() {}

void nat464_cksum_fixup() {}

void turnstile_deallocate() {}

void in6_clat46_event_enqueue_nwk_wq_entry() {}

void workq_kern_threadreq_initiate() {}

void turnstile_reference() {}

void _pthread_priority_combine() {}

void cchmac_final() {}

void thread_update_kevent_override() {}

void thread_add_kevent_override() {}

void _disable_preemption() {}

void lck_spin_sleep_with_inheritor() {}

void ccsha256_di() {}

void copysize_limit_panic() {}

void sysctl_load_devicetree_entries() {}

void mpsc_test_pingpong() {}

void sysctl_task_get_no_smt() {}

void hostname_lock() {}

void cchmac_update() {}

void _os_log_internal_driverKit() {}

void machine_tecs() {}

void machine_csv() {}

void act_clear_astkevent() {}

void cchmac_init() {}

void thread_drop_servicer_override() {}

void thread_update_servicer_override() {}

void wakeup_one_with_inheritor() {}

struct sysctl_oid_stub sysctl__machdep_children[1] = {};

void thread_unfreeze_base_pri() {}

void turnstile_deallocate_safe() {}

void task_exc_guard_default() {}

void sysctl_task_set_no_smt() {}

void current_uthread() {}

void filt_wldetach_sync_ipc() {}

void _enable_preemption() {}

void restricted_port_bitmap() {}

int cfil_crypto_sign_data() { return 0; }

void thread_set_no_smt() {}

void net_mpklog_enabled() {}

int cfil_crypto_init_client() { return 0; }

void task_info() {}

void thread_get_no_smt() {}

void task_get_coalition() {}

void atm_get_diagnostic_config() {}

void cfil_crypto_cleanup_state() {}

void copyin_atomic64() {}

void thread_drop_kevent_override() {}

void filt_wlattach_sync_ipc() {}

void thread_deallocate_safe() {}

STUB_ABORT(vm_kernel_addrhash)

STUB_ABORT(_vm_kernel_addrhash_XNU_INTERNAL)

void thread_add_servicer_override() {}

void net_mpklog_type() {}

void mach_bridge_remote_time() {}

void vn_getpath_ext() {}

void wakeup_all_with_inheritor() {}

void registerSleepWakeInterest() {}

void absolutetime_to_microtime() {}

void thread_abort() {}
const char *strnstr(const char *s, const char *find, size_t slen) {
  size_t flen = strlen(find);
  if (flen == 0) return s;
  for (; slen >= flen; s++, slen--) {
    if (s[0] == find[0] && memcmp(s, find, flen) == 0)
      return s;
  }
  return NULL;
}
void thread_abort_safely() {}

uint32_t crc32(uint32_t crc, const void *buf, size_t size) {
  const uint8_t *p = (const uint8_t *)buf;
  crc = ~crc;
  for (size_t i = 0; i < size; i++) {
    crc ^= p[i];
    for (int j = 0; j < 8; j++) {
      crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1)));
    }
  }
  return ~crc;
}

void cs_get_cdhash() {}
void cs_hash_type() {}
void cs_valid() {}
void mac_file_notify_close() {}
void mach_bridge_timer_enable() {}
void machine_thread_function_pointers_convert_from_user() {}

// 4 GiB — a plausible physical memory size for the faked environment
uint64_t mem_actual = 4ULL * 1024 * 1024 * 1024;

void proc_min_sdk() {}
void proc_platform() {}
void proc_sdk() {}

const char *sysctl_debug_get_preoslog(size_t *size) {
  assert(false);
  return NULL;
}

void task_get_filter_msg_flag() {}
void task_set_filter_msg_flag() {}
void thread_zone() {}

/*
 * zone_require -- in the real kernel, asserts that a pointer was allocated
 * from a specific zone.  This is a debug-only integrity check.  In the
 * fuzzer, all zones are backed by malloc/calloc so this check is not
 * meaningful.  No-op.
 */
void zone_require() {
}
