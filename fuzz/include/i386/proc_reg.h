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
 * Stub proc_reg.h for arm64 cross-compilation of XNU userspace fuzzer.
 *
 * The real i386/proc_reg.h contains x86 inline assembly that cannot be
 * compiled on arm64 (invalid asm constraints).  Since the fuzzer never
 * executes any of those functions, we provide a minimal stub that
 * includes only the constant definitions.
 */
#ifndef _I386_PROC_REG_H_
#define _I386_PROC_REG_H_

/* Pull in MSR / CR / EFLAGS definitions only (no asm) by including the
 * real header with a guard that prevents the inline-asm functions from
 * being compiled.  We simply define the guard and provide empty stubs
 * where needed.  */

/* Model Specific Registers and control register bits are plain #defines
 * that don't depend on architecture.  We need a handful that the rest
 * of XNU headers reference.  For the fuzzer build we don't need any of
 * them, so just provide the include-guard to satisfy transitive includes. */

/* CR0 bits */
#define CR0_PG  0x80000000
#define CR0_PE  0x00000001

/* CR4 bits */
#define CR4_PAE 0x00000020
#define CR4_OSXSAVE 0x00040000

/* EFLAGS bits */
#define EFL_CF  0x00000001
#define EFL_IF  0x00000200

/* XCR0 / XFEM bits */
#define XCR0_SSE (1ULL << 1)
#define XCR0_YMM (1ULL << 2)
#define XFEM_SSE  XCR0_SSE
#define XFEM_YMM  XCR0_YMM
#define XFEM_BNDREGS   (1ULL << 3)
#define XFEM_BNDCSR    (1ULL << 4)
#define XFEM_ZMM_H     (1ULL << 5)
#define XFEM_ZMM       (1ULL << 6)
#define XFEM_K         (1ULL << 7)

/* MSR numbers (a few commonly referenced) */
#define MSR_IA32_TSC_AUX     0x000000c0000103

/* MAX_CPUS — referenced by kern/processor.h */
#ifndef MAX_CPUS
#define MAX_CPUS  64
#endif
/* MAX_PSETS — referenced by kern/processor.h */
#ifndef MAX_PSETS
#define MAX_PSETS  MAX_CPUS
#endif

/* XCR0 register number */
#define XCR0 0

/* LBR (Last Branch Record) types needed by i386/thread.h */
#define X86_MAX_LBRS 32
struct x86_lbr_record {
    uint64_t from_rip;
    uint64_t to_rip;
    uint64_t info;
};
typedef struct x86_lbrs {
    uint64_t lbr_tos;
    struct x86_lbr_record lbrs[X86_MAX_LBRS];
} x86_lbrs_t;

/* Provide no-op stubs for inline functions that header consumers might
 * reference in sizeof / typeof expressions but never actually call. */
static inline unsigned long long
rdtsc64(void) { return 0; }

static inline void
wrmsr64(unsigned int msr, unsigned long long val) { (void)msr; (void)val; }

static inline unsigned long long
rdmsr64(unsigned int msr) { (void)msr; return 0; }

#endif /* _I386_PROC_REG_H_ */
