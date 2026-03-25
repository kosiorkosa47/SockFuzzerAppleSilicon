/*
 * Copyright 2024 Google LLC
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

/*
 * Fuzz stub for kern/startup.h
 *
 * This header replaces the real XNU kern/startup.h in the fuzzer build.
 * It is found first because fuzz/include/ precedes the XNU header paths
 * in the compiler include search order (see CMakeLists.txt XNU_INCLUDES).
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * The real kern/startup.h provides a kernel-boot startup subsystem that
 * registers initializer functions (via STARTUP / STARTUP_ARG macros) into
 * Mach-O sections, then iterates them in order during early boot.  In the
 * userspace fuzzer environment:
 *
 *   - There is no kernel boot sequence.
 *   - The Mach-O section-based registration is unnecessary.
 *   - Zone and lock initialization is handled lazily: zones start as NULL
 *     and zalloc() allocates a safe default when it encounters a NULL zone.
 *     Lock operations are stubbed as no-ops in osfmk_stubs.c.
 *
 * HOW MACROS ARE STUBBED
 * ----------------------
 *   __startup_func   -> empty (no special section placement)
 *   __startup_data   -> empty (no special section placement)
 *   STARTUP(...)     -> empty (no registration; function never called)
 *   STARTUP_ARG(...) -> empty (same)
 *
 * The key consequence: macros like ZONE_DECLARE (in kern/zalloc.h),
 * LCK_GRP_DECLARE (in kern/lock_group.h), and TUNABLE (in the real
 * startup.h) all use STARTUP_ARG internally.  When STARTUP_ARG expands
 * to nothing, these macros still declare the variable and any ancillary
 * structs, but the startup registration call vanishes.  The variable is
 * left at its zero-initialized default (NULL for zone_t pointers, zero-
 * filled for lck_grp_t structs).  This is safe because:
 *
 *   - zalloc()/zalloc_flags() handle NULL zones gracefully (see zalloc.c).
 *   - All lock operations (lck_mtx_lock, lck_rw_lock, etc.) are no-ops.
 *   - TUNABLE values use their specified default_value.
 *
 * SECURITY_READ_ONLY_EARLY / SECURITY_READ_ONLY_LATE
 * --------------------------------------------------
 * In the real kernel these place variables in read-only sections after boot.
 * We define them to produce ordinary writable variables so zone pointers
 * and other "late-init" globals can be modified at any time.  The detailed
 * definitions are in fuzz/include/libkern/section_keywords.h.
 *
 * ZONE_DECLARE / LCK_GRP_DECLARE / LCK_MTX_DECLARE
 * -------------------------------------------------
 * These are NOT overridden here.  The real definitions in kern/zalloc.h
 * and kern/locks.h use STARTUP_ARG (stubbed empty) and __startup_data
 * (stubbed empty), so they expand to just a variable declaration and an
 * unused spec struct.  Zones start as NULL and are handled gracefully by
 * zalloc(); locks are no-ops; no further initialization is needed.
 */

#ifndef _KERN_STARTUP_H_FUZZ_
#define _KERN_STARTUP_H_FUZZ_

/* --- Startup subsystem IDs (must match real values for struct compat) --- */
enum startup_subsystem_id {
    STARTUP_SUB_NONE = 0, STARTUP_SUB_TUNABLES, STARTUP_SUB_LOCKS_EARLY,
    STARTUP_SUB_KPRINTF, STARTUP_SUB_PMAP_STEAL, STARTUP_SUB_VM_KERNEL,
    STARTUP_SUB_KMEM, STARTUP_SUB_KMEM_ALLOC, STARTUP_SUB_ZALLOC,
    STARTUP_SUB_PERCPU, STARTUP_SUB_LOCKS, STARTUP_SUB_CODESIGNING,
    STARTUP_SUB_OSLOG, STARTUP_SUB_MACH_IPC, STARTUP_SUB_SYSCTL,
    STARTUP_SUB_EARLY_BOOT, STARTUP_SUB_LAST,
};

/* --- Startup rank constants (used in macro expansions, must exist) --- */
#define STARTUP_RANK_FIRST   0
#define STARTUP_RANK_SECOND  1
#define STARTUP_RANK_THIRD   2
#define STARTUP_RANK_FOURTH  3
#define STARTUP_RANK_MIDDLE  127
#define STARTUP_RANK_LAST    255

/*
 * Core startup macros -- all no-ops.
 *
 * __startup_func: In the real kernel, marks a function for placement in a
 *   special text section and DCE (dead-code elimination) after boot.  Here
 *   it is empty; functions remain in the normal text section.
 *
 * __startup_data: Marks data for a special data section.  Empty here.
 *
 * STARTUP / STARTUP_ARG: Register a function to be called during kernel
 *   boot at a specific subsystem/rank.  Empty here -- the fuzzer does not
 *   execute the kernel boot sequence.  Zones, locks, and tunables declared
 *   with macros that depend on STARTUP_ARG will simply have their variables
 *   zero-initialized instead.
 */
#define __startup_func
#define __startup_data
#define STARTUP(subsystem, rank, func)
#define STARTUP_ARG(subsystem, rank, func, arg)
#define __STARTUP(n, l, s, r, f)
#define __STARTUP_ARG(n, l, s, r, f, a)
#define __STARTUP1(n, l, s, r, f)

/*
 * __PLACE_IN_SECTION -- in the real kernel, controls Mach-O section placement
 * for variables (e.g., __DATA,__lock_grp).  Our section_keywords.h stub
 * provides the real definition, but some translation units include
 * kern/startup.h (via locks.h -> lock_group.h) before section_keywords.h.
 * Provide a fallback so macros like LCK_GRP_DECLARE_ATTR that use
 * __PLACE_IN_SECTION can expand correctly in those units.
 */
#ifndef __PLACE_IN_SECTION
#define __PLACE_IN_SECTION(_seg_sect) __attribute__((section(_seg_sect)))
#endif

/*
 * LCK_MTX_DECLARE -- declare a statically-initialized mutex.
 *
 * NOT overridden here.  The real definition in kern/locks.h uses
 * STARTUP_ARG (which we stub as empty) and __startup_data (also empty),
 * so it expands to just a variable declaration and an unused spec struct.
 * Since all lock operations are no-ops in the fuzzer, this is sufficient.
 */

/*
 * TUNABLE / TUNABLE_WRITEABLE -- declare a kernel tunable with a default.
 *
 * In the real kernel, TUNABLE declares a variable initialized from a boot-arg.
 * We simply declare the variable with its default value.  The boot-arg
 * parsing infrastructure (__TUNABLE, startup_tunable_spec) is not needed.
 */
#define TUNABLE(type, var, name, defval)          type var = defval
#define TUNABLE_WRITEABLE(type, var, name, defval) type var = defval

/*
 * kernel_startup_initialize_upto / kernel_startup_tunable_init
 *
 * Called by the kernel during boot to run initializers up to a given
 * subsystem.  No-ops here.
 */
static inline void kernel_startup_initialize_upto(int s) { (void)s; }
static inline void kernel_startup_tunable_init(void) {}

/*
 * SECURITY_READ_ONLY_EARLY / SECURITY_READ_ONLY_LATE
 *
 * In the real kernel, these place variables in sections that become
 * read-only after boot.  For the fuzzer we need them writable.
 * The canonical definitions are in fuzz/include/libkern/section_keywords.h;
 * we provide fallback definitions here for files that include startup.h
 * before section_keywords.h.
 */
#ifndef SECURITY_READ_ONLY_EARLY
#define SECURITY_READ_ONLY_EARLY(_t) const _t __attribute__((used))
#endif
#ifndef SECURITY_READ_ONLY_LATE
#define SECURITY_READ_ONLY_LATE(_t)  _t __attribute__((used))
#endif

#endif /* _KERN_STARTUP_H_FUZZ_ */

/* --- Types needed outside the include guard (for osfmk_stubs.c etc.) --- */
typedef enum startup_subsystem_id startup_subsystem_id_t;
extern startup_subsystem_id_t startup_phase;
