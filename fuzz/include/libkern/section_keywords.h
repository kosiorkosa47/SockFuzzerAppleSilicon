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
 * Stub section_keywords.h for arm64 userspace fuzzer build.
 *
 * The real header places SECURITY_READ_ONLY_LATE variables in
 * __DATA,__const which becomes read-only after loading on macOS.
 * For the fuzzer, we need these variables writable so zones can be
 * initialized at startup.  This stub redirects everything to regular
 * __DATA sections.
 */
#ifndef _SECTION_KEYWORDS_H_
#define _SECTION_KEYWORDS_H_

#ifdef __APPLE__
#define __PLACE_IN_SECTION(_seg_sect) __attribute__((section(_seg_sect)))
#else
#define __PLACE_IN_SECTION(_seg_sect) __attribute__((section(_seg_sect)))
#endif

#define __SECTION_START_SYM(seg, sect) asm("section$start$" seg "$" sect)
#define __SECTION_END_SYM(seg, sect) asm("section$end$" seg "$" sect)

/* Redirect everything to writable __DATA segments. */
#define __security_const_early const
#define __security_const_late
#define __security_read_write

#define SECURITY_READ_ONLY_SPECIAL_SECTION(_t, __segment__section) \
    _t __PLACE_IN_SECTION(__segment__section)

#define SECURITY_READ_ONLY_EARLY(_t) const _t __attribute__((used))
#define SECURITY_READ_ONLY_LATE(_t)  _t __attribute__((used))
#define SECURITY_READ_WRITE(_t)      _t __attribute__((used))

#define MARK_AS_HIBERNATE_TEXT
#define MARK_AS_HIBERNATE_DATA
#define MARK_AS_HIBERNATE_DATA_CONST_LATE

#endif /* _SECTION_KEYWORDS_H_ */
