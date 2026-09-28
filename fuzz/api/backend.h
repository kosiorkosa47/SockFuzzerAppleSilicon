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

#ifndef FUZZ_BACKEND_H_
#define FUZZ_BACKEND_H_

bool init_proc(void);
bool configure_loopback_address(void);
void drain_loopback_input(void);
size_t necp_aggregate_result_size(void);
void clear_all();
void* get_mbuf_data(const char* data, size_t size, int pktflags);
void* get_mbuf_data_chained(const char* data, size_t size, int pktflags,
                             const uint32_t* split_points, int num_splits);
void ip_input_wrapper(void* m);

// Item 10: PF ioctl bridge, implemented in fuzz/api/ioctl.c. Keep these
// structure definitions identical to the ones there.
struct fuzz_pf_rule_spec {
  char ifname[16];
  uint32_t ioc_action;
  uint32_t ticket;
  uint32_t pool_ticket;
  uint32_t nr;
  uint32_t rule_action;
  uint32_t direction;
  uint32_t af;
  uint32_t proto;
  uint32_t rule_flag;
  uint8_t src_addr[16];
  uint8_t dst_addr[16];
  uint16_t src_port;
  uint16_t dst_port;
  uint8_t keep_state;
  uint8_t quick;
};

struct fuzz_pf_kill_spec {
  char ifname[16];
  uint32_t af;
  uint32_t proto;
  uint8_t src_addr[16];
  uint8_t dst_addr[16];
  uint16_t src_port;
  uint16_t dst_port;
};

int pf_ioctl_rule(unsigned long cmd, const struct fuzz_pf_rule_spec* spec);
int pf_ioctl_kill_states(unsigned long cmd,
                         const struct fuzz_pf_kill_spec* spec);
int pf_ioctl_no_payload(unsigned long cmd);
void pf_flush_all(void);
void pf_enable_purge_thread(void);
void ip6_input_wrapper(void* m);

#endif  // FUZZ_BACKEND_H_
