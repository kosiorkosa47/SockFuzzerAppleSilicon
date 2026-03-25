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
 * Stub i386/fpu.h for arm64 cross-compilation.
 * The real header contains x86 inline asm (xgetbv/xsetbv).
 */
#ifndef _I386_FPU_H_
#define _I386_FPU_H_

#include <kern/thread.h>
#include <mach/kern_return.h>

typedef enum {
    UNDEFINED = 0,
    FP,
    SSE,
    YMM,
    ZMM,
    CPUID_LEAF7_FEATURES = 0xFF,
    AVX512 = (1 << 8),
    STATE64_FULL = (1 << 9),
    AVX512_FULL = AVX512 | STATE64_FULL,
} xstate_t;

static inline uint64_t xgetbv(uint32_t c) { (void)c; return 0; }
static inline void xsetbv(uint32_t mask_hi, uint32_t mask_lo) { (void)mask_hi; (void)mask_lo; }

extern void init_fpu(void);
extern void fpu_module_init(void);

#endif /* _I386_FPU_H_ */
