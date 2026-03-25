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
#include <stdint.h>

int printf(const char* format, ...);

// Convenience macro — logs which stub was hit before aborting.
// This makes it immediately obvious which unimplemented function
// the fuzzer reached, so you know what to implement next.
#define STUB_ABORT(name) \
  void name() { printf("STUB HIT: " #name "\n"); assert(false); }

__attribute__((visibility("default"))) 
void Assert(const char* file, int line, const char* expression) {
  printf("%s: assert failed on line %d: %s\n", file, line, expression);
  __builtin_trap();
}

STUB_ABORT(IOBSDGetPlatformUUID)

STUB_ABORT(IOMapperInsertPage)

STUB_ABORT(IOPMCopySleepWakeUUIDKey)

STUB_ABORT(IOTaskHasEntitlement)

STUB_ABORT(OSMalloc_Tagalloc)

STUB_ABORT(OSMalloc_Tagfree)

STUB_ABORT(act_set_astbsd)

STUB_ABORT(act_set_astkevent)

STUB_ABORT(addupc_task)

STUB_ABORT(assert_wait)

STUB_ABORT(audit_arg_addr)

STUB_ABORT(audit_arg_cmd)

STUB_ABORT(audit_arg_ctlname)

STUB_ABORT(audit_arg_fd)

STUB_ABORT(audit_arg_file)

STUB_ABORT(audit_arg_pid)

STUB_ABORT(audit_arg_process)

STUB_ABORT(audit_arg_signum)

STUB_ABORT(audit_arg_value64)

STUB_ABORT(audit_syscalls)

STUB_ABORT(bsd_exception)

STUB_ABORT(bsd_timeout)

STUB_ABORT(bsdinit_task)

STUB_ABORT(cc_rand_generate)

STUB_ABORT(check_actforsig)

STUB_ABORT(clear_thread_rwlock_boost)

STUB_ABORT(clock_absolutetime_interval_to_deadline)

STUB_ABORT(clock_continuoustime_interval_to_deadline)

STUB_ABORT(clock_deadline_for_periodic_event)

STUB_ABORT(clock_get_calendar_microtime)

STUB_ABORT(clock_get_calendar_nanotime)

STUB_ABORT(clock_get_uptime)

STUB_ABORT(coalition_get_leader)

STUB_ABORT(coalition_is_leader)

STUB_ABORT(copyin_word)

STUB_ABORT(copyinstr)

STUB_ABORT(copypv)

STUB_ABORT(copywithin)

STUB_ABORT(coredump)

STUB_ABORT(cs_identity_get)

STUB_ABORT(current_task)

STUB_ABORT(deflate)

STUB_ABORT(deflateReset)

STUB_ABORT(enodev)

STUB_ABORT(enodev_strat)

STUB_ABORT(exit_with_reason)

STUB_ABORT(fs_filtops)

STUB_ABORT(fsevent_filtops)

STUB_ABORT(fuulong)

STUB_ABORT(gPEClockFrequencyInfo)

void* g_crypto_funcs = NULL;

STUB_ABORT(get_bsdtask_info)

STUB_ABORT(get_bsdthreadtask_info)

STUB_ABORT(get_signalact)

STUB_ABORT(get_threadtask)

STUB_ABORT(get_useraddr)

STUB_ABORT(hashaddr)

STUB_ABORT(hashbacktrace)

STUB_ABORT(hostname)

STUB_ABORT(hz)

STUB_ABORT(inflate)

STUB_ABORT(inflateReset)

STUB_ABORT(initproc)

STUB_ABORT(ipc_entry_name_mask)

STUB_ABORT(is_kerneltask)

STUB_ABORT(itimerdecr)

STUB_ABORT(itimerfix)

STUB_ABORT(kauth_authorize_generic)

STUB_ABORT(kauth_cred_getgid)

STUB_ABORT(kauth_cred_getruid)

STUB_ABORT(kauth_cred_getsvuid)

STUB_ABORT(kauth_getruid)

STUB_ABORT(kcdata_estimate_required_buffer_size)

STUB_ABORT(kcdata_get_memory_addr)

STUB_ABORT(kcdata_memcpy)

STUB_ABORT(kcdata_memory_static_init)

STUB_ABORT(kdp_get_interface)

STUB_ABORT(kdp_is_in_zone)

STUB_ABORT(kdp_set_gateway_mac)

STUB_ABORT(kdp_set_ip_and_mac_addresses)

STUB_ABORT(kernel_debug_filtered)

STUB_ABORT(kernel_task)

STUB_ABORT(launchd_exit_reason_get_string_desc)

STUB_ABORT(lck_mtx_lock_spin_always)

STUB_ABORT(lck_rw_destroy)

STUB_ABORT(lck_rw_lock_exclusive_to_shared)

STUB_ABORT(lck_rw_lock_shared_to_exclusive)

STUB_ABORT(lck_rw_sleep)

STUB_ABORT(lck_spin_assert)

STUB_ABORT(lck_spin_destroy)

STUB_ABORT(ledger_get_task_entry_info_multiple)

STUB_ABORT(ledger_info)

STUB_ABORT(ledger_template_info)

STUB_ABORT(mac_error_select)

STUB_ABORT(mac_policy_list)

STUB_ABORT(mac_policy_list_conditional_busy)

STUB_ABORT(mac_policy_list_unbusy)

STUB_ABORT(mac_proc_check_ledger)

STUB_ABORT(mac_proc_check_signal)

STUB_ABORT(mac_socket_check_received)

STUB_ABORT(mac_socket_check_stat)

STUB_ABORT(mac_system_enforce)

STUB_ABORT(mach_absolutetime_asleep)

STUB_ABORT(machport_filtops)

STUB_ABORT(max_mem)

STUB_ABORT(mb_map)

STUB_ABORT(memorystatus_filtops)

STUB_ABORT(memorystatus_kevent_init)

STUB_ABORT(msleep)

STUB_ABORT(msleep0)

STUB_ABORT(msleep1)

STUB_ABORT(nanoseconds_to_absolutetime)

STUB_ABORT(nanotime)

STUB_ABORT(pg_rele)

STUB_ABORT(pgfind)

STUB_ABORT(pgrp_iterate)

STUB_ABORT(port_name_to_thread)

STUB_ABORT(proc_get_effective_task_policy)

STUB_ABORT(proc_getcdhash)

STUB_ABORT(proc_iterate)

STUB_ABORT(proc_klist_lock)

STUB_ABORT(proc_klist_unlock)

STUB_ABORT(proc_knote)

STUB_ABORT(proc_list_lock)

STUB_ABORT(proc_list_unlock)

STUB_ABORT(proc_lock)

STUB_ABORT(proc_log_32bit_telemetry)

STUB_ABORT(proc_name_address)

STUB_ABORT(proc_parentdropref)

STUB_ABORT(proc_parentholdref)

STUB_ABORT(proc_pgrp)

STUB_ABORT(proc_self)

STUB_ABORT(proc_set_thread_policy)

STUB_ABORT(proc_signal)

STUB_ABORT(proc_spinlock)

STUB_ABORT(proc_spinunlock)

STUB_ABORT(proc_unlock)

STUB_ABORT(proc_uuid_policy_kernel)

STUB_ABORT(proc_uuid_policy_lookup)

STUB_ABORT(pthread_functions)

STUB_ABORT(pthread_priority_canonicalize)

STUB_ABORT(ptmx_kqops)

STUB_ABORT(ptsd_kqops)

STUB_ABORT(pzfind)

STUB_ABORT(sane_size)

STUB_ABORT(securelevel)

STUB_ABORT(semaphore_timedwait_signal_trap_internal)

STUB_ABORT(semaphore_timedwait_trap_internal)

STUB_ABORT(semaphore_wait_signal_trap_internal)

STUB_ABORT(semaphore_wait_trap_internal)

STUB_ABORT(sendsig)

STUB_ABORT(set_thread_rwlock_boost)

STUB_ABORT(spec_filtops)

STUB_ABORT(subyte)

STUB_ABORT(suulong)

STUB_ABORT(sysctl__debug_children)

STUB_ABORT(sysctl__kern_children)

STUB_ABORT(sysctl__net_children)

STUB_ABORT(sysctl__net_link_generic_system_children)

STUB_ABORT(sysctl__sysctl_children)

STUB_ABORT(task_consume_32bit_log_flag)

STUB_ABORT(task_deallocate)

STUB_ABORT(task_did_exec)

STUB_ABORT(task_hold)

STUB_ABORT(task_is_active)

STUB_ABORT(task_is_exec_copy)

STUB_ABORT(task_is_halting)

STUB_ABORT(task_release)

STUB_ABORT(task_resume_internal)

STUB_ABORT(task_suspend_internal)

STUB_ABORT(task_vtimer_clear)

STUB_ABORT(task_vtimer_set)

STUB_ABORT(task_vtimer_update)

STUB_ABORT(task_wait)

STUB_ABORT(telemetry_timer_event)

STUB_ABORT(thread_add_ipc_override)

STUB_ABORT(thread_add_sync_ipc_override)

STUB_ABORT(thread_block)

STUB_ABORT(thread_block_parameter)

STUB_ABORT(thread_call_cancel)

STUB_ABORT(thread_call_cancel_wait)

STUB_ABORT(thread_call_enter)

STUB_ABORT(thread_call_free)

STUB_ABORT(thread_call_func_cancel)

STUB_ABORT(thread_call_func_delayed)

STUB_ABORT(thread_call_isactive)

STUB_ABORT(thread_drop_ipc_override)

STUB_ABORT(thread_drop_sync_ipc_override)

STUB_ABORT(thread_ends_owning_workloop)

STUB_ABORT(thread_get_ipc_override)

STUB_ABORT(thread_get_tag)

STUB_ABORT(thread_handoff)

STUB_ABORT(thread_owned_workloops_count)

STUB_ABORT(thread_qos_from_pthread_priority)

STUB_ABORT(thread_reference)

STUB_ABORT(thread_rettokern_addr)

STUB_ABORT(thread_set_pending_block_hint)

STUB_ABORT(thread_set_thread_name)

STUB_ABORT(thread_set_voucher_name)

STUB_ABORT(thread_should_abort)

STUB_ABORT(thread_should_halt)

STUB_ABORT(thread_starts_owning_workloop)

STUB_ABORT(thread_tid)

STUB_ABORT(thread_update_ipc_override)

STUB_ABORT(thread_wakeup_thread)

STUB_ABORT(tick)

STUB_ABORT(timeout_with_leeway)

STUB_ABORT(timespec_is_valid)

STUB_ABORT(tsleep)

STUB_ABORT(tsleep0)

STUB_ABORT(tsleep1)

STUB_ABORT(tstoabstime)

STUB_ABORT(tty_filtops)

STUB_ABORT(tty_pgrp)

STUB_ABORT(tvtoabstime)

STUB_ABORT(unix_syscall_return)

STUB_ABORT(untimeout)

STUB_ABORT(vaddlog)

STUB_ABORT(vfs_context_create)

STUB_ABORT(vfs_context_rele)

STUB_ABORT(vm_kernel_slid_base)

STUB_ABORT(vm_kernel_slid_top)

STUB_ABORT(vm_kernel_slide)

STUB_ABORT(vn_stat)

STUB_ABORT(vnode_filtops)

STUB_ABORT(vnode_isfifo)

STUB_ABORT(waitq_assert_wait64)

STUB_ABORT(waitq_assert_wait64_leeway)

STUB_ABORT(waitq_clear_prepost)

STUB_ABORT(waitq_deinit)

STUB_ABORT(waitq_get_prepost_id)

STUB_ABORT(waitq_init)

STUB_ABORT(waitq_is_valid)

STUB_ABORT(waitq_link)

STUB_ABORT(waitq_link_release)

STUB_ABORT(waitq_link_reserve)

STUB_ABORT(waitq_set_alloc)

STUB_ABORT(waitq_set_clear_preposts)

STUB_ABORT(waitq_set_deinit)

STUB_ABORT(waitq_set_init)

STUB_ABORT(waitq_set_is_valid)

STUB_ABORT(waitq_set_unlink_all)

STUB_ABORT(waitq_unlink)

STUB_ABORT(waitq_unlink_by_prepost_id)

STUB_ABORT(waitq_wakeup64_all)

STUB_ABORT(waitq_wakeup64_one)

STUB_ABORT(wqset_id)

STUB_ABORT(wqset_waitq)

STUB_ABORT(zalloc_canblock)

STUB_ABORT(zfill)

STUB_ABORT(kernel_pmap)

STUB_ABORT(kmem_free)

STUB_ABORT(cru2x)

STUB_ABORT(mac_vnode_check_create)

STUB_ABORT(mac_vnode_check_uipc_bind)

STUB_ABORT(mac_vnode_check_uipc_connect)

STUB_ABORT(namei)

STUB_ABORT(nameidone)

STUB_ABORT(vfs_context_ucred)

STUB_ABORT(vn_create)

STUB_ABORT(vnode_authorize)

STUB_ABORT(vnode_put)

STUB_ABORT(vnode_ref)

STUB_ABORT(vnode_rele)

STUB_ABORT(audit_arg_sockaddr)

STUB_ABORT(audit_arg_socket)

STUB_ABORT(audit_arg_value32)

STUB_ABORT(vfs_context_cwd)

STUB_ABORT(vnode_isreg)

STUB_ABORT(vnode_size)

STUB_ABORT(aes_decrypt_aad_gcm)

STUB_ABORT(aes_decrypt_cbc)

STUB_ABORT(aes_decrypt_finalize_gcm)

STUB_ABORT(aes_decrypt_gcm)

STUB_ABORT(aes_decrypt_get_ctx_size_gcm)

STUB_ABORT(aes_decrypt_key)

STUB_ABORT(aes_decrypt_key_gcm)

STUB_ABORT(aes_decrypt_set_iv_gcm)

STUB_ABORT(aes_encrypt_aad_gcm)

STUB_ABORT(aes_encrypt_cbc)

STUB_ABORT(aes_encrypt_finalize_gcm)

STUB_ABORT(aes_encrypt_gcm)

STUB_ABORT(aes_encrypt_get_ctx_size_gcm)

STUB_ABORT(aes_encrypt_inc_iv_gcm)

STUB_ABORT(aes_encrypt_key)

STUB_ABORT(aes_encrypt_key_with_iv_gcm)

STUB_ABORT(aes_encrypt_reset_gcm)

STUB_ABORT(clock_get_system_microtime)

STUB_ABORT(thread_call_enter1_delayed)

STUB_ABORT(panic)

struct os_log_s {
  int a;
};

struct os_log_s _os_log_default;

uint32_t net_flowhash_mh3_x86_32(const void* key, uint32_t len,
                                 const uint32_t seed) {
  assert(false);
  return 1;
}

STUB_ABORT(cc_clear)

STUB_ABORT(cc_cmp_safe)

STUB_ABORT(getsectdatafromheader)

/* On macOS, _mh_execute_header is provided by the linker automatically. */
#ifndef __APPLE__
STUB_ABORT(_mh_execute_header)
#endif

STUB_ABORT(net_flowhash)

STUB_ABORT(os_cpu_in_cksum)

STUB_ABORT(os_cpu_in_cksum_mbuf)

STUB_ABORT(proc_name)

STUB_ABORT(thread_terminate)

STUB_ABORT(uuid_generate)

STUB_ABORT(uuid_parse)

STUB_ABORT(_pthread_priority_normalize)

STUB_ABORT(workq_kern_threadreq_modify)

STUB_ABORT(nat464_translate_proto)

STUB_ABORT(turnstile_cleanup)

STUB_ABORT(thread_wakeup_prim)

STUB_ABORT(waitq_wakeup64_thread)

STUB_ABORT(turnstile_prepare)

STUB_ABORT(assert_wait_deadline)

STUB_ABORT(nat464_synthesize_ipv4)

STUB_ABORT(clat_debug)

STUB_ABORT(workq_kern_threadreq_redrive)

STUB_ABORT(zdestroy)

STUB_ABORT(turnstile_update_inheritor)

STUB_ABORT(thread_handoff_parameter)

STUB_ABORT(in6_clat46_eventhdlr_callback)

STUB_ABORT(turnstile_update_inheritor_complete)

STUB_ABORT(nat464_insert_frag46)

STUB_ABORT(nat464_synthesize_ipv6)

STUB_ABORT(turnstile_complete)

STUB_ABORT(nat464_translate_64)

STUB_ABORT(waitq_set_should_lazy_init_link)

STUB_ABORT(workq_is_exiting)

STUB_ABORT(sysctl_helper_waitq_set_nelem)

STUB_ABORT(turnstile_alloc)

STUB_ABORT(workq_kern_threadreq_update_inheritor)

STUB_ABORT(thread_handoff_deallocate)

STUB_ABORT(workq_kern_threadreq_unlock)

STUB_ABORT(telemetry_pmi_setup)

STUB_ABORT(nat464_translate_46)

STUB_ABORT(waitq_set_lazy_init_link)

STUB_ABORT(workq_thread_set_max_qos)

STUB_ABORT(workq_kern_threadreq_lock)

STUB_ABORT(nat464_cksum_fixup)

STUB_ABORT(turnstile_deallocate)

STUB_ABORT(in6_clat46_event_enqueue_nwk_wq_entry)

STUB_ABORT(workq_kern_threadreq_initiate)

STUB_ABORT(turnstile_reference)

STUB_ABORT(_pthread_priority_combine)

STUB_ABORT(cchmac_final)

STUB_ABORT(thread_update_kevent_override)

STUB_ABORT(thread_add_kevent_override)

STUB_ABORT(_disable_preemption)

STUB_ABORT(lck_spin_sleep_with_inheritor)

STUB_ABORT(ccsha256_di)

STUB_ABORT(copysize_limit_panic)

STUB_ABORT(sysctl_load_devicetree_entries)

STUB_ABORT(mpsc_test_pingpong)

STUB_ABORT(sysctl_task_get_no_smt)

STUB_ABORT(hostname_lock)

STUB_ABORT(cchmac_update)

STUB_ABORT(_os_log_internal_driverKit)

STUB_ABORT(machine_tecs)

STUB_ABORT(machine_csv)

STUB_ABORT(act_clear_astkevent)

STUB_ABORT(cchmac_init)

STUB_ABORT(thread_drop_servicer_override)

STUB_ABORT(thread_update_servicer_override)

STUB_ABORT(wakeup_one_with_inheritor)

STUB_ABORT(sysctl__machdep_children)

STUB_ABORT(thread_unfreeze_base_pri)

STUB_ABORT(turnstile_deallocate_safe)

STUB_ABORT(task_exc_guard_default)

STUB_ABORT(sysctl_task_set_no_smt)

STUB_ABORT(current_uthread)

STUB_ABORT(filt_wldetach_sync_ipc)

STUB_ABORT(_enable_preemption)

STUB_ABORT(restricted_port_bitmap)

STUB_ABORT(cfil_crypto_sign_data)

STUB_ABORT(thread_set_no_smt)

STUB_ABORT(net_mpklog_enabled)

STUB_ABORT(cfil_crypto_init_client)

STUB_ABORT(task_info)

STUB_ABORT(thread_get_no_smt)

STUB_ABORT(task_get_coalition)

STUB_ABORT(atm_get_diagnostic_config)

STUB_ABORT(cfil_crypto_cleanup_state)

STUB_ABORT(copyin_atomic64)

STUB_ABORT(thread_drop_kevent_override)

STUB_ABORT(filt_wlattach_sync_ipc)

STUB_ABORT(thread_deallocate_safe)

STUB_ABORT(vm_kernel_addrhash)

STUB_ABORT(_vm_kernel_addrhash_XNU_INTERNAL)

STUB_ABORT(thread_add_servicer_override)

STUB_ABORT(net_mpklog_type)

STUB_ABORT(mach_bridge_remote_time)

STUB_ABORT(vn_getpath_ext)

STUB_ABORT(wakeup_all_with_inheritor)

STUB_ABORT(registerSleepWakeInterest)

STUB_ABORT(absolutetime_to_microtime)

STUB_ABORT(thread_abort)
STUB_ABORT(strnstr)
STUB_ABORT(thread_abort_safely)

uint32_t crc32(uint32_t crc, const void *buf, size_t size) {
  assert(false);
  return 0;
}

STUB_ABORT(cs_get_cdhash)
STUB_ABORT(cs_hash_type)
STUB_ABORT(cs_valid)
STUB_ABORT(mac_file_notify_close)
STUB_ABORT(mach_bridge_timer_enable)
STUB_ABORT(machine_thread_function_pointers_convert_from_user)

// 4 GiB — a plausible physical memory size for the faked environment
uint64_t mem_actual = 4ULL * 1024 * 1024 * 1024;

STUB_ABORT(proc_min_sdk)
STUB_ABORT(proc_platform)
STUB_ABORT(proc_sdk)

const char *sysctl_debug_get_preoslog(size_t *size) {
  assert(false);
  return NULL;
}

STUB_ABORT(task_get_filter_msg_flag)
STUB_ABORT(task_set_filter_msg_flag)
STUB_ABORT(thread_zone)

/*
 * zone_require -- in the real kernel, asserts that a pointer was allocated
 * from a specific zone.  This is a debug-only integrity check.  In the
 * fuzzer, all zones are backed by malloc/calloc so this check is not
 * meaningful.  No-op.
 */
void zone_require() {
}
