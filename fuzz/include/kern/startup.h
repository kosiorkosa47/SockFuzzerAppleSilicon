/*
 * Copyright 2024 Google LLC
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the "License"). You may not use this file except in
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
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

/*
 * Portable startup registration for the userspace fuzzer.
 *
 * XNU normally stores startup entries in a Mach-O section. The fuzzer uses
 * constructor functions to register the same entries in a fixed table, then
 * runs them in subsystem and rank order during initialize_network(). This is
 * required for static zones to receive their declared size and flags before
 * the networking stack starts allocating objects from them.
 */

#ifndef _KERN_STARTUP_H_FUZZ_
#define _KERN_STARTUP_H_FUZZ_

#include <stdbool.h>
#include <stdint.h>

typedef uint32_t startup_subsystem_id_t;
enum {
  STARTUP_SUB_NONE = 0,
  STARTUP_SUB_TUNABLES,
  STARTUP_SUB_LOCKS_EARLY,
  STARTUP_SUB_KPRINTF,
  STARTUP_SUB_PMAP_STEAL,
  STARTUP_SUB_VM_KERNEL,
  STARTUP_SUB_KMEM,
  STARTUP_SUB_KMEM_ALLOC,
  STARTUP_SUB_ZALLOC,
  STARTUP_SUB_PERCPU,
  STARTUP_SUB_LOCKS,
  STARTUP_SUB_CODESIGNING,
  STARTUP_SUB_OSLOG,
  STARTUP_SUB_MACH_IPC,
  STARTUP_SUB_SYSCTL,
  STARTUP_SUB_EARLY_BOOT,
  STARTUP_SUB_LOCKDOWN = UINT32_MAX,
};

typedef uint32_t startup_rank_t;
#define STARTUP_RANK_NTH(n) ((startup_rank_t)(n))
#define STARTUP_RANK_FIRST STARTUP_RANK_NTH(0)
#define STARTUP_RANK_SECOND STARTUP_RANK_NTH(1)
#define STARTUP_RANK_THIRD STARTUP_RANK_NTH(2)
#define STARTUP_RANK_FOURTH STARTUP_RANK_NTH(3)
#define STARTUP_RANK_MIDDLE ((startup_rank_t)0x7fffffffU)
#define STARTUP_RANK_LATE_NTH(n) \
  ((startup_rank_t)(STARTUP_RANK_MIDDLE + 1U + (n)))
#define STARTUP_RANK_LAST ((startup_rank_t)UINT32_MAX)

#define __startup_func
#define __startup_data

void fuzz_startup_register(startup_subsystem_id_t subsystem,
                           startup_rank_t rank,
                           void (*function)(const void *),
                           const void *argument);

#define __FUZZ_STARTUP_NAME_2(name, line) \
  __fuzz_startup_register_##name##line
#define __FUZZ_STARTUP_NAME_1(name, line) \
  __FUZZ_STARTUP_NAME_2(name, line)

#define __STARTUP_FUNC_CAST(function, argument) \
  ((void (*)(const void *))(function))

#define __STARTUP1(name, line, subsystem, rank, function, unused, argument) \
  static void __FUZZ_STARTUP_NAME_1(name, line)(void) \
      __attribute__((constructor)); \
  static void __FUZZ_STARTUP_NAME_1(name, line)(void) \
  { \
    fuzz_startup_register(STARTUP_SUB_##subsystem, (startup_rank_t)(rank), \
                          __STARTUP_FUNC_CAST(function, unused), \
                          (const void *)(argument)); \
  }

#define __STARTUP(name, line, subsystem, rank, function) \
  __STARTUP1(name, line, subsystem, rank, function, , NULL)

#define __STARTUP_ARG(name, line, subsystem, rank, function, argument) \
  __STARTUP1(name, line, subsystem, rank, function, argument, argument)

#define STARTUP(subsystem, rank, function) \
  __STARTUP(function, __LINE__, subsystem, rank, function)

#define STARTUP_ARG(subsystem, rank, function, argument) \
  __STARTUP_ARG(function, __LINE__, subsystem, rank, function, argument)

#ifndef __PLACE_IN_SECTION
#define __PLACE_IN_SECTION(_seg_sect) __attribute__((section(_seg_sect)))
#endif

/* Tunables retain their declared defaults in the fuzzer environment. */
#define TUNABLE(type, variable, name, default_value) \
  type variable = default_value
#define TUNABLE_WRITEABLE(type, variable, name, default_value) \
  type variable = default_value

struct startup_tunable_spec {
  const char *name;
  void *variable_address;
  int variable_length;
  bool variable_is_bool;
};

extern startup_subsystem_id_t startup_phase;
void kernel_startup_initialize_upto(startup_subsystem_id_t subsystem);
static inline void
kernel_startup_tunable_init(const struct startup_tunable_spec *specification)
{
  (void)specification;
}

#ifndef SECURITY_READ_ONLY_EARLY
#define SECURITY_READ_ONLY_EARLY(_t) const _t __attribute__((used))
#endif
#ifndef SECURITY_READ_ONLY_LATE
#define SECURITY_READ_ONLY_LATE(_t)  _t __attribute__((used))
#endif

#endif /* _KERN_STARTUP_H_FUZZ_ */
