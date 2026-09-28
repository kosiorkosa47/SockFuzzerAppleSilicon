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

// Trivial implementations belong here. More substantial faked
// subsystems should live in their own file.

#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>

#include <kern/assert.h>
#include <libkern/libkern.h>

#include "bsd/net/nwk_wq.h"
#include "bsd/sys/_types/_timeval.h"
#include "bsd/sys/conf.h"
#include "bsd/sys/kdebug_kernel.h"
#include "bsd/sys/kernel_types.h"
#include "bsd/sys/malloc.h"
#include "bsd/sys/resource.h"
#include "bsd/uuid/uuid.h"

#ifndef _KAUTH_CRED_T
#define _KAUTH_CRED_T
struct ucred;
typedef struct ucred *kauth_cred_t;
#endif

struct fileglob;
struct fileproc;
struct flock;
struct knote;
struct pipe;
struct sockaddr;
struct socket;
struct sockopt;
struct vnode;

extern void get_fuzzed_bytes(void* addr, size_t bytes);
extern bool get_fuzzed_bool(void);

int snprintf(char*, size_t, const char*, ...) __printflike(3, 4);
int vsnprintf(char*, size_t, const char*, va_list);

int maxfilesperproc = 10;

bool PE_parse_boot_argn(const char* arg_string, void* arg_ptr, int max_arg) {
  if (!strcmp(arg_string, "ifa_debug")) {
    *(int*)arg_ptr = 0;
    return true;
  }

  if (!strcmp(arg_string, "inaddr_nhash")) {
    *(uint32_t*)arg_ptr = 0;
    return true;
  }

  if (!strcmp(arg_string, "mcache_flags")) {
    *(uint32_t*)arg_ptr = 0;
    return true;
  }

  if (!strcmp(arg_string, "mbuf_debug")) {
    *(uint32_t*)arg_ptr = 0;
    return true;
  }

  if (!strcmp(arg_string, "mleak_sample_factor")) {
    *(uint32_t*)arg_ptr = 0;
    return true;
  }

  // Just return 0 by default.
  memset(arg_ptr, 0, max_arg);

  return false;
}

void* os_log_create() { return (void*)1; }

void pflog_packet() {}

static char fake_vfs_context[256];
void* vfs_context_current() { return fake_vfs_context; }

int csproc_get_platform_binary(void* p) { return 0; }

void uuid_clear(uuid_t uu) { memset(uu, 0, sizeof(uuid_t)); }

int uuid_is_null(const uuid_t uu) {
  return !memcmp(uu, UUID_NULL, sizeof(uuid_t));
}

int uuid_compare(const uuid_t uu1, const uuid_t uu2) {
  return memcmp(uu1, uu2, sizeof(uuid_t));
}

static uint32_t g_uuid_counter = 0;

__attribute__((visibility("default")))
void fake_uuid_reset(void) { g_uuid_counter = 0; }

void uuid_generate_random(uuid_t out) {
  memset(out, 0, sizeof(uuid_t));
  if (++g_uuid_counter == 0) g_uuid_counter = 1;  // skip 0 (UUID_NULL)
  memcpy(out, &g_uuid_counter, sizeof(g_uuid_counter));
}

void uuid_copy(uuid_t dst, const uuid_t src) {
  memcpy(dst, src, sizeof(uuid_t));
}

void uuid_unparse_upper(const uuid_t uu, uuid_string_t out) {
  snprintf(out, sizeof(uuid_string_t),
           "%02X%02X%02X%02X-"
           "%02X%02X-"
           "%02X%02X-"
           "%02X%02X-"
           "%02X%02X%02X%02X%02X%02X",
           uu[0], uu[1], uu[2], uu[3], uu[4], uu[5], uu[6], uu[7], uu[8], uu[9],
           uu[10], uu[11], uu[12], uu[13], uu[14], uu[15]);
}

void uuid_unparse(const uuid_t uu, uuid_string_t out) {
  uuid_unparse_upper(uu, out);
}

extern void* kernproc;

void* vfs_context_proc() { return kernproc; }

int mac_socket_check_accepted(kauth_cred_t cred, struct socket *so) {
  return 0;
}

int mac_socket_check_setsockopt(kauth_cred_t cred, struct socket *so,
                                struct sockopt *sopt) {
  return 0;
}

int mac_socket_check_bind(kauth_cred_t cred, struct socket *so,
                          struct sockaddr *addr) {
  return 0;
}

int mac_file_check_ioctl(kauth_cred_t cred, struct fileglob *fg,
                         unsigned long cmd) {
  return 0;
}

int deflateInit2_() { return 0; }  // Z_OK
int inflateInit2_() { return 0; }  // Z_OK

bool kauth_cred_issuser() { return !get_fuzzed_bool(); }

unsigned long RandomULong() {
  unsigned long val;
  get_fuzzed_bytes(&val, sizeof(val));
  // Avoid returning 0 — XNU treats it as failure in some callers.
  return val ? val : 1;
}

// TODO: threading
int kernel_thread_start() { return 0; }

int cdevsw_add(int major, const struct cdevsw *cdevsw) {
  return 0;
}

void devfs_make_node() {}

bool lck_mtx_try_lock() { return true; }

void kprintf() { return; }

void thread_deallocate() {}

int proc_suser() { return get_fuzzed_bool() ? 1 : 0; }

void _os_log_internal() {}

uint32_t hw_atomic_add(volatile uint32_t *target, uint32_t delta) {
  *target += delta;
  return *target;
}

uint32_t hw_atomic_sub(volatile uint32_t *target, uint32_t delta) {
  *target -= delta;
  return *target;
}

void lck_mtx_destroy() {}

int mac_socket_check_ioctl(kauth_cred_t cred, struct socket *so,
                           unsigned long cmd) {
  return 0;
}

bool proc_is64bit() { return true; }

int priv_check_cred() { return get_fuzzed_bool() ? 1 : 0; }

bool lck_rw_try_lock_exclusive() { return true; }

void* malloc(size_t size);
void free(void* ptr);

// Sentinel address values used by the fuzzer harness.
// USERADDR_FUZZED (1) means "use fuzzed bytes via copyin".
// Any other non-null value is treated as a real userspace pointer.
#define USERADDR_NULL    0
#define USERADDR_FUZZED  1
#define EFAULT_XNU       14

__attribute__((visibility("default"))) bool real_copyout = true;

int copyout(const void* kaddr, user_addr_t udaddr, size_t len) {
  if (!kaddr || len == 0) {
    return 0;
  }
  // Randomly fail to exercise error paths.
  if (get_fuzzed_bool()) {
    return EFAULT_XNU;
  }

  if (!udaddr || udaddr == USERADDR_FUZZED || !real_copyout) {
    // Validate source is readable (ASAN will catch OOB).
    void* buf = malloc(len);
    if (!buf) {
      return EFAULT_XNU;
    }
    memcpy(buf, kaddr, len);
    free(buf);
    return 0;
  }

  memcpy((void*)udaddr, kaddr, len);
  return 0;
}

void* __MALLOC(size_t size, int type, int flags, vm_allocation_site_t* site) {
  void* addr = NULL;
  assert(type < M_LAST);

  if (size == 0) {
    return NULL;
  }

  addr = malloc(size);
  if (!addr) {
    return NULL;
  }

  if (flags & M_ZERO) {
    bzero(addr, size);
  }

  return (addr);
}

void read_frandom(void* buffer, unsigned int numBytes) {
  get_fuzzed_bytes(buffer, numBytes);
}

void read_random(void* buffer, unsigned int numBytes) {
  get_fuzzed_bytes(buffer, numBytes);
}

int ml_get_max_cpus(void) { return 1; }

void lck_rw_assert() {}

uint32_t IOMapperIOVMAlloc() { return 0; }

int proc_uniqueid() { return 0; }

int proc_pid() { return 0; }

void proc_getexecutableuuid(void* p, unsigned char* uuidbuf,
                            unsigned long size) {
  memset(uuidbuf, 0, size);
}

void proc_pidoriginatoruuid(void* buffer, size_t size) {
  memset(buffer, 0, size);
}

void* kauth_cred_proc_ref() { return (void*)1; }

void* kauth_cred_get() { return (void*)1; }

void* proc_ucred() { return (void*)1; }

int suser(void* arg1, void* arg2) {
  (void)arg1;
  (void)arg2;
  return 0;
}

void lck_rw_lock_shared() {}

void lck_rw_done() {}

bool proc_get_effective_thread_policy() {
  // TODO: more options
  return false;
}

void* current_proc() { return kernproc; }

int proc_selfpid() { return 1; }

int tvtohz(void *tvp) {
  long *tv = (long *)tvp;
  return (int)(tv[0] * 100 + tv[1] / 10000);
}

int kauth_cred_getuid() {
  // UUID: root
  return get_fuzzed_bool() ? 1 : 0;
}

const char* proc_best_name() { return "kernproc"; }

void* proc_find() { return kernproc; }

int mac_socket_check_create(kauth_cred_t cred, int domain, int type,
                            int protocol) {
  return 0;
}

int mac_socket_check_accept(kauth_cred_t cred, struct socket *so) {
  return 0;
}

void ovbcopy(const char* from, char* to, size_t nbytes) {
  memmove(to, from, nbytes);
}

int __attribute__((warn_unused_result))
copyin(const user_addr_t uaddr, void *kaddr, size_t len) {
  if (!kaddr) {
    return EFAULT_XNU;
  }
  if (len == 0) {
    return 0;
  }
  // USERADDR_FUZZED means "generate fuzzed bytes"; any other non-null
  // value is treated as a real pointer from the harness.
  if (uaddr == USERADDR_NULL) {
    return EFAULT_XNU;
  }
  if (uaddr != USERADDR_FUZZED) {
    memcpy(kaddr, (void*)uaddr, len);
    return 0;
  }

  if (get_fuzzed_bool()) {
    return EFAULT_XNU;
  }

  get_fuzzed_bytes(kaddr, len);
  return 0;
}

void SHA1Final(unsigned char *digest, void *ctx) {
  get_fuzzed_bytes(digest, 20);  // SHA1 digest is 20 bytes
}

void SHA1Init(void *ctx) {}

void SHA1Update(void *ctx, const void *data, unsigned int len) {}

void lck_grp_attr_free() {}

void lck_grp_free() {}

void lck_rw_lock_exclusive() {}

void timevaladd(struct timeval *t1, const struct timeval *t2) {
  t1->tv_sec += t2->tv_sec;
  t1->tv_usec += t2->tv_usec;
  while (t1->tv_usec >= 1000000) {
    t1->tv_sec++;
    t1->tv_usec -= 1000000;
  }
}

void timevalsub(struct timeval *t1, const struct timeval *t2) {
  t1->tv_sec -= t2->tv_sec;
  t1->tv_usec -= t2->tv_usec;
  while (t1->tv_usec < 0) {
    t1->tv_sec--;
    t1->tv_usec += 1000000;
  }
}

void MD5Init(void *ctx) {}
void MD5Update(void *ctx, const void *data, unsigned int len) {}
void MD5Final(unsigned char* digest, void* ctx) {
  get_fuzzed_bytes(digest, 16);  // MD5 digest is 16 bytes
}

void proc_rele() {}
void wakeup(void* chan) {}

void lck_spin_lock() {}
void lck_spin_unlock() {}
void kauth_cred_unref(void* cred) {}
void lck_rw_unlock_exclusive() {}

bool IS_64BIT_PROCESS() { return true; }

int mac_socket_check_listen(kauth_cred_t cred, struct socket *so) {
  return 0;
}

void kauth_cred_ref() {}

void in_stat_set_activity_bitmap() {}

int mac_socket_check_getsockopt(kauth_cred_t cred, struct socket *so,
                                struct sockopt *sopt) {
  return 0;
}

int mac_pipe_check_ioctl(kauth_cred_t cred, struct pipe *cpipe,
                         unsigned long cmd) {
  return 0;
}

int mac_pipe_check_write(kauth_cred_t cred, struct pipe *cpipe) { return 0; }

int mac_pipe_check_kqfilter(kauth_cred_t cred, struct knote *kn,
                            struct pipe *cpipe) {
  return 0;
}

void mac_pipe_label_init(struct pipe *cpipe) {}

void mac_pipe_label_destroy(struct pipe *cpipe) {}

int mac_pipe_check_read(kauth_cred_t cred, struct pipe *cpipe) { return 0; }

int mac_pipe_check_stat(kauth_cred_t cred, struct pipe *cpipe) { return 0; }

void mac_pipe_label_associate(kauth_cred_t cred, struct pipe *cpipe) {}

int kauth_getuid() { return 0; }

int kauth_getgid() { return 0; }

int mac_pipe_check_select(kauth_cred_t cred, struct pipe *cpipe, int which) {
  return 0;
}

void _aio_close() {}
void unlink1() {}

int mac_socket_check_connect(kauth_cred_t cred, struct socket *so,
                             struct sockaddr *addr) {
  return 0;
}

void ml_thread_policy() {}

int aes_encrypt_key128(const unsigned char *key, void *ctx) {
  memcpy(ctx, key, 16);
  return 0;
}

void OSBacktrace() {}

void lck_grp_attr_setdefault() {}

void wakeup_one() {}

int lck_mtx_try_lock_spin() { return 1; }

void nwk_wq_enqueue(struct nwk_wq_entry* nwk_item) {
  nwk_item->func(nwk_item->arg);
  free(nwk_item);
}

int ppsratecheck() { return 1; }

bool ratecheck() { return true; }

void fulong() {}
void ubc_cs_blob_deallocate() {}
void proc_thread() {}
void munge_user32_stat64() {}
int mac_file_check_lock(kauth_cred_t cred, struct fileglob *fg, int op,
                        struct flock *fl) {
  return 0;
}
void vnode_setsize() {}
void vnode_setnocache() {}
void kauth_authorize_fileop() {}
void VNOP_FSYNC() {}
void tablefull() {}
void vnode_recycle() {}
void ipc_object_copyin() {}
int mac_file_check_inherit(kauth_cred_t cred, struct fileglob *fg) { return 0; }
void vnode_vid() {}
void munge_user32_stat() {}
void VNOP_OFFTOBLK() {}
int mac_file_check_create(kauth_cred_t cred) { return 0; }
void fileport_port_to_fileglob() {}
void VNOP_SETATTR() {}
void vfs_devblocksize() {}
int mac_file_check_library_validation(struct proc *proc, struct fileglob *fg,
                                      off_t slice_offset,
                                      user_long_t error_message,
                                      size_t error_message_size) {
  return 0;
}
void ubc_cs_blob_add() {}
void vn_getpath() {}
void ipc_port_release_send() {}
void proc_kqhashlock_grp() {}
void vn_path_package_check() {}
void VNOP_GETATTR() {}
void ubc_cs_blob_allocate() {}
void audit_sysclose() {}
void vnode_is_openevt() {}
void audit_arg_vnpath_withref() {}
int mac_file_check_fcntl(kauth_cred_t cred, struct fileglob *fg, int cmd,
                         user_long_t arg) {
  return 0;
}
void VNOP_ALLOCATE() {}
void fg_vn_data_free() {}
void VNOP_BLKTOOFF() {}
void vnode_islnk() {}
void VNOP_IOCTL() {}
int mac_vnode_check_truncate(vfs_context_t ctx, kauth_cred_t file_cred,
                             struct vnode *vp) {
  return 0;
}
int mac_file_check_dup(kauth_cred_t cred, struct fileglob *fg, int newfd) {
  return 0;
}
void ubc_cs_blob_get() {}
void audit_arg_vnpath() {}
void get_task_ipcspace() {}
void vn_rdwr() {}
void mac_file_label_destroy(struct fileglob *fg) {}
void fileport_alloc() {}
void vnode_getwithref() {}
void mac_file_label_associate(kauth_cred_t cred, struct fileglob *fg) {}
void sulong() {}
void proc_lck_attr() {}
int mac_vnode_check_write(vfs_context_t ctx, kauth_cred_t file_cred,
                          struct vnode *vp) {
  return 0;
}
void ipc_port_copyout_send() {}
void kauth_filesec_free() {}
void munge_user64_stat64() {}
void munge_user64_stat() {}
void VNOP_EXCHANGE() {}
void vnode_set_openevt() {}
void vn_stat_noauth() {}
void vnode_mount() {}
void open1() {}
void kauth_authorize_fileop_has_listeners() {}
int fp_isguarded(struct fileproc *fp, unsigned int attributes) { return 0; }
void audit_arg_fflags() {}
void mac_vnode_notify_truncate(vfs_context_t ctx, kauth_cred_t file_cred,
                               struct vnode *vp) {}
int fp_guard_exception(proc_t p, int fd, struct fileproc *fp,
                       unsigned int attributes) {
  return 0;
}
void vnode_clear_openevt() {}
void pshm_stat() {}
void proc_knhashlock_grp() {}
void VNOP_BLOCKMAP() {}
void vnode_clearnocache() {}
void VNOP_ADVLOCK() {}
void ubc_cs_blob_revalidate() {}
void guarded_fileproc_free() {}
void audit_arg_text() {}
void vnode_isnocache() {}
void mach_port_deallocate() {}
int mac_file_label_init() { return 0; }
void vn_pathconf() {}
void audit_arg_mode() {}
void mac_socket_check_receive() {}
int mac_socket_check_send(kauth_cred_t cred, struct socket *so,
                          struct sockaddr *addr) {
  return 0;
}

void kernel_debug(uint32_t debugid, uintptr_t arg1, uintptr_t arg2,
    uintptr_t arg3, uintptr_t arg4, uintptr_t arg5) {}

void lck_rw_unlock_shared() {}
// kmem_alloc_contig lives in osfmk_stubs.c, next to kernel_memory_allocate,
// where vm/vm_kern.h supplies the real signature.
uint32_t ipc_control_port_options;

bool current_task_can_use_restricted_in_port() { return true; }

unsigned int
ml_wait_max_cpus(void)
{
  return 1;
}

int fls(unsigned int mask) {
  if (mask == 0) {
    return 0;
  }
  return (sizeof(mask) << 3) - __builtin_clz(mask);
}

int scnprintf(char *buf, size_t size, const char *fmt, ...) {
  if (size == 0) return 0;
  va_list ap;
  va_start(ap, fmt);
  int ret = vsnprintf(buf, size, fmt, ap);
  va_end(ap);
  if (ret < 0) return 0;
  return (ret >= (int)size) ? (int)(size - 1) : ret;
}

rlim_t
proc_limitgetcur(proc_t p, int which, boolean_t to_lock_proc) {
  switch (which) {
    case RLIMIT_NOFILE: return 10;
    case 1: return 0x7fffffffffffffff; /* RLIMIT_DATA - unlimited */
    case 5: return 0x7fffffffffffffff; /* RLIMIT_AS - unlimited */
    default: return 0x7fffffffffffffff; /* safe default */
  }
}

task_t proc_task() { return TASK_NULL; }

vm_offset_t current_percpu_base(void) {
  return 0;
}

int proc_pidversion(proc_t p) {
  return 1;
}

unsigned int kdebug_enable = 0;
void kernel_debug_string_early(const char *message) {
  (void)message;
}

// Content filter (#172): necp_socket_get_content_filter_control_unit and
// cfil_active_count are provided by the real XNU sources (necp.c,
// content_filter.c). No stubs needed — they're compiled in BSD_SOURCES.
