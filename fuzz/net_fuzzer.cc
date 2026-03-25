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

#include <fuzzer/FuzzedDataProvider.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <iostream>
#include <memory>
#include <vector>

#include "net_fuzzer.pb.h"
#include "src/libfuzzer/libfuzzer_macro.h"

extern "C" {
#include "api/backend.h"
#include "api/syscall_wrappers.h"
#include "types.h"
}

// TODO(upstream): support multiple addresses of each type below,
// not just one of each type
void get_in6_addr(struct in6_addr *sai, enum In6Addr addr) {
  memset(sai, 0, sizeof(*sai));
  switch (addr) {
    case IN6_ADDR_SELF: {
      sai->__u6_addr.__u6_addr32[0] = 16810238;
      sai->__u6_addr.__u6_addr32[1] = 0;
      sai->__u6_addr.__u6_addr32[2] = 0;
      sai->__u6_addr.__u6_addr32[3] = 16777216;
      // assert(IN6_IS_ADDR_SELF(sai));
      break;
    }
    case IN6_ADDR_LINK_LOCAL: {
      sai->s6_addr[0] = 0xfe;
      sai->s6_addr[1] = 0x80;
      // TODO(upstream): set other fields?
      assert(IN6_IS_ADDR_LINKLOCAL(sai));
      break;
    }
    case IN6_ADDR_LOOPBACK: {
      *sai = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
      assert(IN6_IS_ADDR_LOOPBACK(sai));
      break;
    }
    case IN6_ADDR_REAL: {
      sai->s6_addr[15] = 2;  // arbitrary non-zero
      break;
    }
    case MAYBE_LOCALHOST: {
      sai->s6_addr[15] = 1;  // ::1 = loopback
      break;
    }
    case IN6_ADDR_V4COMPAT: {
      sai->s6_addr[12] = 1;
      assert(IN6_IS_ADDR_V4COMPAT(sai));
      break;
    }
    case IN6_ADDR_V4MAPPED: {
      *(uint32_t *)&sai->s6_addr[8] = 0xffff0000;
      assert(IN6_IS_ADDR_V4MAPPED(sai));
      break;
    }
    case IN6_ADDR_6TO4: {
      sai->s6_addr16[0] = ntohs(0x2002);
      assert(IN6_IS_ADDR_6TO4(sai));
      break;
    }
    case IN6_ADDR_LINKLOCAL: {
      sai->s6_addr[0] = 0xfe;
      sai->s6_addr[1] = 0x80;
      assert(IN6_IS_ADDR_LINKLOCAL(sai));
      break;
    }
    case IN6_ADDR_SITELOCAL: {
      sai->s6_addr[0] = 0xfe;
      sai->s6_addr[1] = 0xc0;
      assert(IN6_IS_ADDR_SITELOCAL(sai));
      break;
    }
    case IN6_ADDR_MULTICAST: {
      sai->s6_addr[0] = 0xff;
      assert(IN6_IS_ADDR_MULTICAST(sai));
      break;
    }
    case IN6_ADDR_UNIQUE_LOCAL: {
      sai->s6_addr[0] = 0xfc;
      assert(IN6_IS_ADDR_UNIQUE_LOCAL(sai));
      break;
    }
    case IN6_ADDR_MC_NODELOCAL: {
      sai->s6_addr[0] = 0xff;
      sai->s6_addr[1] = __IPV6_ADDR_SCOPE_NODELOCAL;
      assert(IN6_IS_ADDR_MC_NODELOCAL(sai));
      break;
    }
    case IN6_ADDR_MC_INTFACELOCAL: {
      sai->s6_addr[0] = 0xff;
      sai->s6_addr[1] = __IPV6_ADDR_SCOPE_INTFACELOCAL;
      assert(IN6_IS_ADDR_MC_INTFACELOCAL(sai));
      break;
    }
    case IN6_ADDR_MC_LINKLOCAL: {
      sai->s6_addr[0] = 0xff;
      sai->s6_addr[1] = __IPV6_ADDR_SCOPE_LINKLOCAL;
      assert(IN6_IS_ADDR_MC_LINKLOCAL(sai));
      break;
    }
    case IN6_ADDR_MC_SITELOCAL: {
      sai->s6_addr[0] = 0xff;
      sai->s6_addr[1] = __IPV6_ADDR_SCOPE_SITELOCAL;
      assert(IN6_IS_ADDR_MC_SITELOCAL(sai));
      break;
    }
    case IN6_ADDR_MC_ORGLOCAL: {
      sai->s6_addr[0] = 0xff;
      sai->s6_addr[1] = __IPV6_ADDR_SCOPE_ORGLOCAL;
      assert(IN6_IS_ADDR_MC_ORGLOCAL(sai));
      break;
    }
    case IN6_ADDR_MC_GLOBAL: {
      sai->s6_addr[0] = 0xff;
      sai->s6_addr[1] = __IPV6_ADDR_SCOPE_GLOBAL;
      assert(IN6_IS_ADDR_MC_GLOBAL(sai));
      break;
    }
    case IN6_ADDR_UNSPECIFIED:
    case IN6_ADDR_ANY: {
      assert(IN6_IS_ADDR_UNSPECIFIED(sai));
      break;
    }
    case IN6_ADDR_LOCAL_ADDRESS: {
      // Discovered this address dynamically
      // fe80:0001:0000:0000:a8aa:aaaa:aaaa:aaaa
      sai->s6_addr[0] = 0xfe;
      sai->s6_addr[1] = 0x80;
      sai->s6_addr[2] = 0x00;
      sai->s6_addr[3] = 0x01;
      sai->s6_addr[8] = 0xa8;
      sai->s6_addr[9] = 0xaa;
      sai->s6_addr[10] = 0xaa;
      sai->s6_addr[11] = 0xaa;
      sai->s6_addr[12] = 0xaa;
      sai->s6_addr[13] = 0xaa;
      sai->s6_addr[14] = 0xaa;
      sai->s6_addr[15] = 0xaa;
      break;
    }
  }
}

void get_sockaddr6(struct sockaddr_in6 *sai, const SockAddr6 &sa6) {
  sai->sin6_len = sizeof(struct sockaddr_in6);
  sai->sin6_family = (sa_family_t)AF_INET6;  // sa6.family();
  sai->sin6_port = (in_port_t)sa6.port();
  sai->sin6_flowinfo = sa6.flow_info();
  get_in6_addr(&sai->sin6_addr, sa6.sin6_addr());
  sai->sin6_scope_id = sa6.sin6_scope_id();
}

std::string get_sockaddr(const SockAddr &sockaddr) {
  std::string dat;
  switch (sockaddr.sockaddr_case()) {
    case SockAddr::kSockaddrGeneric: {
      const SockAddrGeneric &sag = sockaddr.sockaddr_generic();
      // data size + sizeof(sa_len) + sizeof(sa_family)
      struct sockaddr_generic sag_s = {
          .sa_len = (uint8_t)(sizeof(sockaddr_generic) + sag.sa_data().size()),
          .sa_family = (uint8_t)sag.sa_family(),
      };

      dat = std::string((char *)&sag_s, (char *)&sag_s + sizeof(sag_s));
      dat += sag.sa_data();
      break;
    }
    case SockAddr::kSockaddr4: {
      struct sockaddr_in sai = {
          .sin_len = sizeof(struct sockaddr_in),
          .sin_family =
              AF_INET,  // (unsigned char)sockaddr.sockaddr4().sin_family(),
          .sin_port = (unsigned short)sockaddr.sockaddr4().sin_port(),
          .sin_addr = {(unsigned int)sockaddr.sockaddr4().sin_addr()},
          .sin_zero = {},
      };
      dat = std::string((char *)&sai, (char *)&sai + sizeof(sai));
      break;
    }
    case SockAddr::kSockaddr6: {
      struct sockaddr_in6 sai = {};
      get_sockaddr6(&sai, sockaddr.sockaddr6());
      dat = std::string((char *)&sai, (char *)&sai + sizeof(sai));
      break;
    }
    case SockAddr::kSockaddrUn: {
      struct sockaddr_un sun = {};
      sun.sun_len = sizeof(struct sockaddr_un);
      sun.sun_family = AF_UNIX;
      const SockAddrUn &un = sockaddr.sockaddr_un();
      if (un.has_typed_path()) {
        const char *path = "/tmp/fuzz.sock";
        switch (un.typed_path()) {
          case UNIX_PATH_EMPTY: path = ""; break;
          case UNIX_PATH_TMP_SOCK: path = "/tmp/fuzz.sock"; break;
          case UNIX_PATH_VAR_RUN: path = "/var/run/fuzz.sock"; break;
          case UNIX_PATH_ABSTRACT: path = ""; sun.sun_path[0] = '\0';
            memcpy(sun.sun_path + 1, "abstract", 8); break;
          case UNIX_PATH_LONG: memset(sun.sun_path, 'A', SUN_PATH_LEN - 1); break;
          case UNIX_PATH_DEVNULL: path = "/dev/null"; break;
        }
        if (un.typed_path() != UNIX_PATH_ABSTRACT &&
            un.typed_path() != UNIX_PATH_LONG) {
          size_t plen = strlen(path);
          memcpy(sun.sun_path, path, std::min(plen, (size_t)(SUN_PATH_LEN - 1)));
        }
      } else if (un.has_custom_path()) {
        size_t pathlen = std::min(un.custom_path().size(),
                                  (size_t)(SUN_PATH_LEN - 1));
        memcpy(sun.sun_path, un.custom_path().data(), pathlen);
      }
      dat = std::string((char *)&sun, (char *)&sun + sizeof(sun));
      break;
    }
    case SockAddr::kSockaddrCtl: {
      // struct sockaddr_ctl: sa_len, sa_family(AF_SYSTEM), ss_sysaddr(2=SYSPROTO_CONTROL),
      // sc_id, sc_unit, sc_reserved[5]
      struct {
        uint8_t sc_len;
        uint8_t sc_family;
        uint16_t ss_sysaddr;
        uint32_t sc_id;
        uint32_t sc_unit;
        uint32_t sc_reserved[5];
      } sctl = {};
      sctl.sc_len = sizeof(sctl);
      sctl.sc_family = 32;  // AF_SYSTEM
      sctl.ss_sysaddr = 2;  // SYSPROTO_CONTROL
      sctl.sc_id = sockaddr.sockaddr_ctl().sc_id();
      sctl.sc_unit = sockaddr.sockaddr_ctl().sc_unit();
      dat = std::string((char *)&sctl, (char *)&sctl + sizeof(sctl));
      break;
    }
    case SockAddr::SOCKADDR_NOT_SET: {
      break;
    }
  }
  return dat;
}

std::string get_ip6_hdr(const Ip6Hdr &hdr, uint16_t expected_size) {
  struct ip6_hdr ip6_hdr;
  memset(&ip6_hdr, 0, sizeof(ip6_hdr));
  get_in6_addr(&ip6_hdr.ip6_src, hdr.ip6_src());
  get_in6_addr(&ip6_hdr.ip6_dst, hdr.ip6_dst());
  ip6_hdr.ip6_ctlun.ip6_un2_vfc = IPV6_VERSION;
  // TODO: IPv6 flow label handling needs investigation
  // ip6_hdr.ip6_ctlun.ip6_un1.ip6_un1_flow = hdr.ip6_hdrctl().ip6_un1_flow();
  ip6_hdr.ip6_ctlun.ip6_un1.ip6_un1_plen =
      __builtin_bswap16(expected_size);  // hdr.ip6_hdrctl().ip6_un1_plen();
  ip6_hdr.ip6_ctlun.ip6_un1.ip6_un1_nxt = hdr.ip6_hdrctl().ip6_un1_nxt();
  ip6_hdr.ip6_ctlun.ip6_un1.ip6_un1_hlim = hdr.ip6_hdrctl().ip6_un1_hlim();
  std::string dat((char *)&ip6_hdr, (char *)&ip6_hdr + sizeof(ip6_hdr));
  return dat;
}

std::string get_ip_hdr(const IpHdr &hdr, size_t expected_size) {
  // Build IP options (B10) — pad to 4-byte boundary.
  std::string options;
  if (hdr.has_ip_options() && !hdr.ip_options().empty()) {
    options = hdr.ip_options();
    if (options.size() > 40) options.resize(40);  // MAX_IPOPTLEN
    while (options.size() % 4 != 0) options.push_back('\0');  // pad
  }

  struct in_addr ip_src = {.s_addr = (unsigned int)hdr.ip_src()};
  struct in_addr ip_dst = {.s_addr = (unsigned int)hdr.ip_dst()};
  uint8_t ihl = 5 + (options.size() / 4);
  struct ip ip_hdr = {
      .ip_hl = ihl,
      .ip_v = IPV4,
      .ip_tos = (u_char)hdr.ip_tos(),
      .ip_len = (u_short)__builtin_bswap16(expected_size + options.size()),
      .ip_id = (u_short)hdr.ip_id(),
      .ip_off = (u_short)hdr.ip_off(),
      .ip_ttl = (u_char)hdr.ip_ttl(),
      .ip_p = (u_char)hdr.ip_p(),
      .ip_sum = 0,
      .ip_src = ip_src,
      .ip_dst = ip_dst,
  };
  std::string dat((char *)&ip_hdr, (char *)&ip_hdr + sizeof(ip_hdr));
  dat += options;
  return dat;
}

// message TcpHdr {
//   required Port th_sport = 1;
//   required Port th_dport = 2;
//   required uint32 th_seq = 3;
//   required uint32 th_ack = 4;
//   required uint32 th_off = 5;
//   repeated TcpFlag th_flags = 6;
//   required uint32 th_win = 7;
//   required uint32 th_sum = 8;
//   required uint32 th_urp = 9;
// }

std::string get_tcp_hdr(const TcpHdr &hdr) {
  struct tcphdr tcphdr = {
      .th_sport = (unsigned short)hdr.th_sport(),
      .th_dport = (unsigned short)hdr.th_dport(),
      .th_seq = __builtin_bswap32(hdr.th_seq()),
      .th_ack = __builtin_bswap32(hdr.th_ack()),
      .th_off = hdr.th_off(),
      .th_flags = 0,
      .th_win = (unsigned short)hdr.th_win(),
      .th_sum = 0,
      .th_urp = (unsigned short)hdr.th_urp(),
  };

  for (const int flag : hdr.th_flags()) {
    tcphdr.th_flags ^= flag;
  }

  // Prefer pure syn
  if (hdr.is_pure_syn()) {
    tcphdr.th_flags &= ~(TH_RST | TH_ACK);
    tcphdr.th_flags |= TH_SYN;
  } else if (hdr.is_pure_ack()) {
    tcphdr.th_flags &= ~(TH_RST | TH_SYN);
    tcphdr.th_flags |= TH_ACK;
  }

  // Serialize TCP options (B1): kind + len + data for each option.
  std::string tcp_opts;
  for (const auto &opt : hdr.options()) {
    uint8_t kind = (uint8_t)opt.kind();
    tcp_opts.push_back(kind);
    if (kind == 0 || kind == 1) continue;  // EOL / NOP — no length byte
    uint8_t len = 2 + opt.data().size();
    tcp_opts.push_back(len);
    tcp_opts += opt.data();
  }
  // Pad to 4-byte boundary.
  while (tcp_opts.size() % 4 != 0) tcp_opts.push_back('\0');
  if (tcp_opts.size() > 40) tcp_opts.resize(40);  // MAX_TCPOPTLEN

  // Set th_off to account for options.
  tcphdr.th_off = (sizeof(tcphdr) + tcp_opts.size()) / 4;

  std::string dat((char *)&tcphdr, (char *)&tcphdr + sizeof(tcphdr));
  dat += tcp_opts;
  return dat;
}

std::string get_icmp6_hdr(const Icmp6Hdr &hdr) {
  struct icmp6_hdr icmp6_hdr = {
      .icmp6_type = (uint8_t)hdr.icmp6_type(),
      .icmp6_code = (uint8_t)hdr.icmp6_code(),
      .icmp6_cksum = 0,
  };
  icmp6_hdr.icmp6_dataun.icmp6_un_data32[0] = hdr.icmp6_dataun();

  std::string dat((char *)&icmp6_hdr, (char *)&icmp6_hdr + sizeof(icmp6_hdr));
  return dat;
}

std::string get_ip6_route_hdr(const Ip6RtHdr &hdr) {
  struct ip6_rthdr ip6_rthdr = {
      .ip6r_nxt = (uint8_t)hdr.ip6r_nxt(),
      .ip6r_len = (uint8_t)hdr.ip6r_len(),
      .ip6r_type = (uint8_t)hdr.ip6r_type(),
      .ip6r_segleft = (uint8_t)hdr.ip6r_segleft(),
  };

  std::string dat((char *)&ip6_rthdr, (char *)&ip6_rthdr + sizeof(ip6_rthdr));
  return dat;
}

std::string get_ip6_route0_hdr(const Ip6Rt0Hdr &hdr) {
  struct ip6_rthdr0 ip6_rthdr0 = {};
  ip6_rthdr0.ip6r0_nxt = hdr.ip6r0_nxt();
  ip6_rthdr0.ip6r0_len = hdr.ip6r0_len();
  ip6_rthdr0.ip6r0_type = hdr.ip6r0_type();
  ip6_rthdr0.ip6r0_segleft = hdr.ip6r0_segleft();
  ip6_rthdr0.ip6r0_reserved = hdr.ip6r0_reserved();
  // ip6r0_slmap is 3 bytes — copy only 3 to avoid overflowing into ip6r0_addr.
  {
    uint32_t slmap = hdr.ip6r0_slmap();
    memcpy(ip6_rthdr0.ip6r0_slmap, &slmap, sizeof(ip6_rthdr0.ip6r0_slmap));
  }

  int i = 0;
  for (int in6addr : hdr.ip6r0_addr()) {
    if (i >= 23) {
      break;
    }

    get_in6_addr(&ip6_rthdr0.ip6r0_addr[i], (In6Addr)in6addr);

    i++;
  }

  std::string dat((char *)&ip6_rthdr0,
                  (char *)&ip6_rthdr0 + sizeof(ip6_rthdr0));
  return dat;
}

std::string get_ip6_frag_hdr(const Ip6FragHdr &hdr) {
  struct ip6_frag ip6_frag = {
      .ip6f_nxt = (uint8_t)hdr.ip6f_nxt(),
      .ip6f_reserved = (uint8_t)hdr.ip6f_reserved(),
      .ip6f_offlg = (uint16_t)hdr.ip6f_offlg(),
      .ip6f_ident = hdr.ip6f_ident(),
  };

  std::string dat((char *)&ip6_frag, (char *)&ip6_frag + sizeof(ip6_frag));
  return dat;
}

std::string get_ip6_ext(const Ip6Ext &hdr) {
  struct ip6_ext ip6_ext = {
      .ip6e_nxt = (uint8_t)hdr.ip6e_nxt(),
      .ip6e_len = (uint8_t)hdr.ip6e_len(),
  };

  std::string dat((char *)&ip6_ext, (char *)&ip6_ext + sizeof(ip6_ext));
  return dat;
}

std::string GetNecpClient(const NecpClientId &necp_client_id) {
  switch (necp_client_id) {
    case CLIENT_0: {
      return "0000000000000000";
    }
    case CLIENT_1: {
      return "1111111111111111";
    }
    case CLIENT_2: {
      return "2222222222222222";
    }
  }
  assert(false);
  return "";
}

extern "C" {

static FuzzedDataProvider *fdp = nullptr;

// These are callbacks to let the C-based backend access the fuzzed input
// stream.
void get_fuzzed_bytes(void *addr, size_t bytes) {
  // If we didn't initialize the fdp just clear the bytes.
  if (!fdp) {
    memset(addr, 0, bytes);
    return;
  }
  memset(addr, 0, bytes);
  std::vector<uint8_t> dat = fdp->ConsumeBytes<uint8_t>(bytes);
  memcpy(addr, dat.data(), dat.size());
}

bool get_fuzzed_bool(void) {
  // If we didn't initialize the fdp just return false.
  if (!fdp) {
    return false;
  }
  return fdp->ConsumeBool();
}

int get_fuzzed_int32(int low, int high) {
  if (!fdp) {
    return low;
  }
  return fdp->ConsumeIntegralInRange<int>(low, high);
}

unsigned int get_fuzzed_uint32(unsigned int low, unsigned int high) {
  if (!fdp) {
    return low;
  }
  return fdp->ConsumeIntegralInRange<unsigned int>(low, high);
}

unsigned int get_remaining_bytes() {
  if (!fdp) return 0;
  return fdp->remaining_bytes();
}

static bool ready = false;

bool initialize_network(void);

extern unsigned long ioctls[];
extern int num_ioctls;
extern const unsigned long siocaifaddr_in6_64;
extern const unsigned long siocsifflags;
extern const unsigned long siocsifmtu_val;
extern const unsigned long siocaddmulti_val;
extern const unsigned long siocdelmulti_val;
extern const unsigned long siocprotoattach_val;
extern const unsigned long siocprotodetach_val;
extern const unsigned long siocsifaddr_val;
extern const unsigned long diocstart_val;
extern const unsigned long diocstop_val;
extern const unsigned long siocsetroutermode_val;
extern const unsigned long siocsifvlan_val;

// Enable this when copyout should work.
extern bool real_copyout;

void get_in6_addrlifetime_64(struct in6_addrlifetime_64 *sai,
                             const In6AddrLifetime_64 &msg) {
  sai->ia6t_expire = msg.ia6t_expire();
  sai->ia6t_preferred = msg.ia6t_preferred();
  sai->ia6t_vltime = msg.ia6t_vltime();
  sai->ia6t_pltime = msg.ia6t_pltime();
}

void get_ifr_name(void *dest, const IfrName name) {
  switch (name) {
    case LO0:
      memcpy(dest, "lo0", sizeof("lo0"));
      break;
    case STF0:
      memcpy(dest, "stf0", sizeof("stf0"));
      break;
    case EN0:
      memcpy(dest, "en0", sizeof("en0"));
      break;
    case BRIDGE0:
      memcpy(dest, "bridge0", sizeof("bridge0"));
      break;
    case FAKE0:
      memcpy(dest, "fake0", sizeof("fake0"));
      break;
  }
}

// NECP client wrappers
// TODO(upstream): move these to their own file
void necp_client_add(int fd, NecpClientId client_id, unsigned char *data,
                     size_t size) {
  std::string client_id_s = GetNecpClient(client_id);
  int retval = 0;
  necp_client_action_wrapper(fd, NECP_CLIENT_ACTION_ADD,
                             // parameters
                             (unsigned char *)client_id_s.data(),
                             client_id_s.size(), data, size, &retval);
}

// TODO(upstream): support flow_ifnet_stats
void necp_client_remove(int fd, NecpClientId client_id) {
  std::string client_id_s = GetNecpClient(client_id);
  int retval = 0;
  necp_client_action_wrapper(fd, NECP_CLIENT_ACTION_REMOVE,
                             (unsigned char *)client_id_s.data(),
                             client_id_s.size(), nullptr, 0, &retval);
}

void necp_client_copy_parameters(int fd, NecpClientId client_id,
                                 uint32_t copyout_size) {
  std::string client_id_s = GetNecpClient(client_id);
  copyout_size %= 4096;
  if (copyout_size == 0) copyout_size = 16;  // avoid zero-size allocation
  std::unique_ptr<uint8_t[]> copyout_buffer(new uint8_t[copyout_size]);
  int retval = 0;
  necp_client_action_wrapper(fd, NECP_CLIENT_ACTION_COPY_PARAMETERS,
                             (unsigned char *)client_id_s.data(),
                             client_id_s.size(), copyout_buffer.get(),
                             copyout_size, &retval);
}

void necp_client_agent(
    int fd, NecpClientId client_id,
    const ::google::protobuf::RepeatedPtrField<::NecpTlv> &necp_tlv) {
  std::string client_id_s = GetNecpClient(client_id);
  std::string parameters;
  for (const NecpTlv &tlv : necp_tlv) {
    // std::string dat((char *)&icmp6_hdr, (char *)&icmp6_hdr +
    // sizeof(icmp6_hdr));
    struct necp_tlv_header header = {
        .type = (uint8_t)tlv.necp_type(),
        .length = (uint32_t)tlv.data().size(),
    };
    std::string tlv_s((char *)&header, (char *)&header + sizeof(header));
    tlv_s += tlv.data();
    parameters += tlv_s;
  }
  int retval = 0;
  necp_client_action_wrapper(fd, NECP_CLIENT_ACTION_AGENT,
                             (unsigned char *)client_id_s.data(),
                             client_id_s.size(), (uint8_t *)parameters.data(),
                             parameters.size(), &retval);
}

void DoNecpClientAction(const NecpClientAction &necp_client_action) {
  switch (necp_client_action.action_case()) {
    case NecpClientAction::kAdd: {
      necp_client_add(necp_client_action.necp_fd(),
                      necp_client_action.client_id(),
                      (unsigned char *)necp_client_action.add().buffer().data(),
                      necp_client_action.add().buffer().size());
      break;
    }
    case NecpClientAction::kRemove: {
      necp_client_remove(necp_client_action.necp_fd(),
                         necp_client_action.client_id());
      break;
    }
    case NecpClientAction::kCopyParameters: {
      necp_client_copy_parameters(
          necp_client_action.necp_fd(), necp_client_action.client_id(),
          necp_client_action.copy_parameters().copyout_size());
      break;
    }
    case NecpClientAction::kAgent: {
      necp_client_agent(necp_client_action.necp_fd(),
                        necp_client_action.client_id(),
                        necp_client_action.agent().necp_tlv());
      break;
    }
    case NecpClientAction::ACTION_NOT_SET: {
      break;
    }
  }
}

void DoTcpInput(const TcpPacket &tcp_packet) {
  std::string ip_hdr_s = get_ip_hdr(tcp_packet.ip_hdr(), 0);  // size filled below
  std::string tcp_hdr_s = get_tcp_hdr(tcp_packet.tcp_hdr());
  size_t total_size = ip_hdr_s.size() + tcp_hdr_s.size() + tcp_packet.data().size();
  // Rewrite ip_len with correct total.
  ip_hdr_s = get_ip_hdr(tcp_packet.ip_hdr(), total_size);
  std::string packet_s = ip_hdr_s + tcp_hdr_s + tcp_packet.data();

  if (packet_s.empty()) {
    return;
  }

  // TODO(upstream): fuzz structure of mbuf itself
  void *mbuf_data = get_mbuf_data(packet_s.data(), packet_s.size(), PKTF_LOOP);
  if (!mbuf_data) {
    return;
  }

  ip_input_wrapper(mbuf_data);
}

void DoTcp6Input(const Tcp6Packet &tcp6_packet) {
  std::string tcp_hdr_s = get_tcp_hdr(tcp6_packet.tcp_hdr());
  size_t expected_size = tcp_hdr_s.size() + tcp6_packet.data().size();
  std::string packet_s = get_ip6_hdr(tcp6_packet.ip6_hdr(), expected_size);
  packet_s += tcp_hdr_s;
  packet_s += tcp6_packet.data();

  if (packet_s.empty()) {
    return;
  }

  void *mbuf_data = get_mbuf_data(packet_s.data(), packet_s.size(), PKTF_LOOP);
  if (!mbuf_data) {
    return;
  }

  ip6_input_wrapper(mbuf_data);
}

void DoIp4Packet(const Ip4Packet &packet) {
  size_t expected_size = sizeof(struct ip) + packet.data().size();
  std::string packet_s = get_ip_hdr(packet.ip_hdr(), expected_size);
  packet_s += packet.data();

  void *mbuf_data = get_mbuf_data(packet_s.data(), packet_s.size(), PKTF_LOOP);
  if (!mbuf_data) {
    return;
  }

  ip_input_wrapper(mbuf_data);
}

void DoIp6Packet(const Ip6Packet &packet) {
  std::string ext_data;

  // Build extension header chain.
  for (const auto &ext : packet.ext_headers()) {
    switch (ext.header_case()) {
      case Ip6ExtHeader::kRouting:
        ext_data += get_ip6_route_hdr(ext.routing());
        break;
      case Ip6ExtHeader::kFragment:
        ext_data += get_ip6_frag_hdr(ext.fragment());
        break;
      case Ip6ExtHeader::kHopByHop:
        ext_data += get_ip6_ext(ext.hop_by_hop());
        break;
      case Ip6ExtHeader::kDestination:
        ext_data += get_ip6_ext(ext.destination());
        break;
      case Ip6ExtHeader::kRaw:
        ext_data += ext.raw();
        break;
      case Ip6ExtHeader::HEADER_NOT_SET:
        break;
    }
  }

  size_t expected_size = ext_data.size() + packet.data().size();
  std::string packet_s = get_ip6_hdr(packet.ip6_hdr(), expected_size);
  packet_s += ext_data;
  packet_s += packet.data();

  void *mbuf_data = get_mbuf_data(packet_s.data(), packet_s.size(), PKTF_LOOP);
  if (!mbuf_data) {
    return;
  }

  ip6_input_wrapper(mbuf_data);
}

void DoUdpInput(const UdpPacket &udp_packet) {
  struct udphdr udphdr = {
      .uh_sport = (u_int16_t)udp_packet.udp_hdr().uh_sport(),
      .uh_dport = (u_int16_t)udp_packet.udp_hdr().uh_dport(),
      .uh_ulen = __builtin_bswap16(sizeof(struct udphdr) +
                                    udp_packet.data().size()),
      .uh_sum = 0,
  };
  size_t expected_size =
      sizeof(struct ip) + sizeof(struct udphdr) + udp_packet.data().size();
  std::string packet_s = get_ip_hdr(udp_packet.ip_hdr(), expected_size);
  packet_s += std::string((char *)&udphdr, (char *)&udphdr + sizeof(udphdr));
  packet_s += udp_packet.data();

  if (packet_s.empty()) return;
  void *mbuf_data = get_mbuf_data(packet_s.data(), packet_s.size(), PKTF_LOOP);
  if (!mbuf_data) return;
  ip_input_wrapper(mbuf_data);
}

void DoUdp6Input(const Udp6Packet &udp6_packet) {
  struct udphdr udphdr = {
      .uh_sport = (u_int16_t)udp6_packet.udp_hdr().uh_sport(),
      .uh_dport = (u_int16_t)udp6_packet.udp_hdr().uh_dport(),
      .uh_ulen = __builtin_bswap16(sizeof(struct udphdr) +
                                    udp6_packet.data().size()),
      .uh_sum = 0,
  };
  size_t expected_size =
      sizeof(struct udphdr) + udp6_packet.data().size();
  std::string packet_s = get_ip6_hdr(udp6_packet.ip6_hdr(), expected_size);
  packet_s += std::string((char *)&udphdr, (char *)&udphdr + sizeof(udphdr));
  packet_s += udp6_packet.data();

  if (packet_s.empty()) return;
  void *mbuf_data = get_mbuf_data(packet_s.data(), packet_s.size(), PKTF_LOOP);
  if (!mbuf_data) return;
  ip6_input_wrapper(mbuf_data);
}

void DoIcmp4Input(const Icmp4Packet &icmp4_packet) {
  struct icmp_hdr hdr = {
      .icmp_type = (uint8_t)icmp4_packet.icmp_hdr().icmp_type(),
      .icmp_code = (uint8_t)icmp4_packet.icmp_hdr().icmp_code(),
      .icmp_cksum = 0,
      .icmp_data = icmp4_packet.icmp_hdr().icmp_data(),
  };
  size_t expected_size =
      sizeof(struct ip) + sizeof(struct icmp_hdr) + icmp4_packet.data().size();
  std::string packet_s = get_ip_hdr(icmp4_packet.ip_hdr(), expected_size);
  packet_s += std::string((char *)&hdr, (char *)&hdr + sizeof(hdr));
  packet_s += icmp4_packet.data();

  if (packet_s.empty()) return;
  void *mbuf_data = get_mbuf_data(packet_s.data(), packet_s.size(), PKTF_LOOP);
  if (!mbuf_data) return;
  ip_input_wrapper(mbuf_data);
}

void DoIcmp6Input(const Icmp6Packet &icmp6_packet) {
  size_t expected_size =
      sizeof(struct icmp6_hdr) + icmp6_packet.data().size();
  std::string packet_s = get_ip6_hdr(icmp6_packet.ip6_hdr(), expected_size);
  packet_s += get_icmp6_hdr(icmp6_packet.icmp6_hdr());
  packet_s += icmp6_packet.data();

  if (packet_s.empty()) return;
  void *mbuf_data = get_mbuf_data(packet_s.data(), packet_s.size(), PKTF_LOOP);
  if (!mbuf_data) return;
  ip6_input_wrapper(mbuf_data);
}

void DoIpInput(const Packet &packet) {
  switch (packet.packet_case()) {
    case Packet::kTcpPacket: {
      DoTcpInput(packet.tcp_packet());
      break;
    }
    case Packet::kTcp6Packet: {
      DoTcp6Input(packet.tcp6_packet());
      break;
    }
    case Packet::kIp4Packet: {
      DoIp4Packet(packet.ip4_packet());
      break;
    }
    case Packet::kIp6Packet: {
      DoIp6Packet(packet.ip6_packet());
      break;
    }
    case Packet::kUdpPacket: {
      DoUdpInput(packet.udp_packet());
      break;
    }
    case Packet::kUdp6Packet: {
      DoUdp6Input(packet.udp6_packet());
      break;
    }
    case Packet::kIcmp4Packet: {
      DoIcmp4Input(packet.icmp4_packet());
      break;
    }
    case Packet::kIcmp6Packet: {
      DoIcmp6Input(packet.icmp6_packet());
      break;
    }
    case Packet::kRawIp4: {
      void *mbuf_data = get_mbuf_data(packet.raw_ip4().data(),
                                      packet.raw_ip4().size(), PKTF_LOOP);
      if (!mbuf_data) {
        return;
      }

      ip_input_wrapper(mbuf_data);
      break;
    }
    case Packet::kRawIp6: {
      void *mbuf_data = get_mbuf_data(packet.raw_ip6().data(),
                                      packet.raw_ip6().size(), PKTF_LOOP);
      if (!mbuf_data) {
        return;
      }

      ip6_input_wrapper(mbuf_data);
      break;
    }
    case Packet::PACKET_NOT_SET: {
      break;
    }
  }
}

// ---------------------------------------------------------------------------
// Command handlers — one function per command type for readability.
// Each handler returns void; side effects flow through the kernel stubs.
// ---------------------------------------------------------------------------

void HandleSocket(const Command &command, std::set<int> &open_fds) {
  int fd = 0;
  int err = socket_wrapper(command.socket().domain(),
                           command.socket().so_type(),
                           command.socket().protocol(), &fd);
  if (err == 0) {
    assert(open_fds.find(fd) == open_fds.end());
    open_fds.insert(fd);
  }
}

void HandleSetSockOpt(const Command &command) {
  int s = command.set_sock_opt().fd();
  int level = command.set_sock_opt().level();
  int name = command.set_sock_opt().name();

  std::string val_data;
  if (command.set_sock_opt().has_val()) {
    const SockOptVal &sov = command.set_sock_opt().val();
    switch (sov.val_case()) {
      case SockOptVal::kRaw:
        val_data = sov.raw();
        break;
      case SockOptVal::kIntVal: {
        int32_t v = sov.int_val().value();
        val_data = std::string((char *)&v, (char *)&v + sizeof(v));
        break;
      }
      case SockOptVal::kLinger: {
        struct linger l = {
            .l_onoff = sov.linger().l_onoff(),
            .l_linger = sov.linger().l_linger(),
        };
        val_data = std::string((char *)&l, (char *)&l + sizeof(l));
        break;
      }
      case SockOptVal::kMreq: {
        struct ip_mreq m = {};
        m.imr_multiaddr.s_addr = (unsigned int)sov.mreq().imr_multiaddr();
        m.imr_interface.s_addr = (unsigned int)sov.mreq().imr_interface();
        val_data = std::string((char *)&m, (char *)&m + sizeof(m));
        break;
      }
      case SockOptVal::kTimeval: {
        struct timeval tv = {
            .tv_sec = (long)sov.timeval().tv_sec(),
            .tv_usec = (int)sov.timeval().tv_usec(),
        };
        val_data = std::string((char *)&tv, (char *)&tv + sizeof(tv));
        break;
      }
      case SockOptVal::kIpv6Mreq: {
        struct {
          struct in6_addr ipv6mr_multiaddr;
          unsigned int ipv6mr_interface;
        } m6 = {};
        get_in6_addr(&m6.ipv6mr_multiaddr, sov.ipv6_mreq().ipv6mr_multiaddr());
        m6.ipv6mr_interface = sov.ipv6_mreq().ipv6mr_interface();
        val_data = std::string((char *)&m6, (char *)&m6 + sizeof(m6));
        break;
      }
      case SockOptVal::kIn6Pktinfo: {
        struct {
          struct in6_addr ipi6_addr;
          unsigned int ipi6_ifindex;
        } pi = {};
        get_in6_addr(&pi.ipi6_addr, sov.in6_pktinfo().ipi6_addr());
        pi.ipi6_ifindex = sov.in6_pktinfo().ipi6_ifindex();
        val_data = std::string((char *)&pi, (char *)&pi + sizeof(pi));
        break;
      }
      case SockOptVal::VAL_NOT_SET:
        break;
    }
  }

  setsockopt_wrapper(s, level, name, (caddr_t)val_data.data(),
                     val_data.size(), nullptr);
}

void HandleGetSockOpt(const Command &command) {
  int s = command.get_sock_opt().fd();
  int level = command.get_sock_opt().level();
  int name = command.get_sock_opt().name();
  socklen_t size = command.get_sock_opt().size();
  if (size > 4096) {
    return;
  }
  std::unique_ptr<char[]> val(new char[size]);
  getsockopt_wrapper(s, level, name, val.get(), &size, nullptr);
}

void HandleIoctl(const Command &command) {
  uint32_t fd = command.ioctl().fd();
  uint32_t idx = command.ioctl().ioctl_idx();
  if (idx == 0 || idx > (uint32_t)num_ioctls) {
    return;
  }
  uint32_t com = ioctls[idx - 1];
  real_copyout = false;
  ioctl_wrapper(fd, com, /*data=*/(caddr_t)1, nullptr);
  real_copyout = true;
}

void HandleIoctlReal(const Command &command) {
  switch (command.ioctl_real().ioctl_case()) {
    case IoctlReal::kSiocaifaddrIn664: {
      const In6_AliasReq_64 &req = command.ioctl_real().siocaifaddr_in6_64();
      struct in6_aliasreq_64 alias = {};
      memcpy(alias.ifra_name, req.ifra_name().data(),
             std::min(req.ifra_name().size(), sizeof(alias.ifra_name)));
      get_sockaddr6(&alias.ifra_addr, req.ifra_addr());
      get_sockaddr6(&alias.ifra_dstaddr, req.ifra_dstaddr());
      get_sockaddr6(&alias.ifra_prefixmask, req.ifra_prefixmask());
      for (int flag : req.ifra_flags()) {
        alias.ifra_flags ^= flag;
      }
      get_in6_addrlifetime_64(&alias.ifra_lifetime, req.ifra_lifetime());
      ioctl_wrapper(command.ioctl_real().fd(), siocaifaddr_in6_64,
                    (caddr_t)&alias, nullptr);
      break;
    }
    case IoctlReal::kSiocsifflags: {
      struct ifreq ifreq = {};
      for (int flag : command.ioctl_real().siocsifflags().flags()) {
        ifreq.ifr_flags |= flag;
      }
      get_ifr_name(ifreq.ifr_name, command.ioctl_real().siocsifflags().ifr_name());
      ioctl_wrapper(command.ioctl_real().fd(), siocsifflags,
                    (caddr_t)&ifreq, nullptr);
      break;
    }
    case IoctlReal::kSiocsifmtu: {
      struct ifreq ifreq = {};
      get_ifr_name(ifreq.ifr_name, command.ioctl_real().siocsifmtu().ifr_name());
      ifreq.ifr_ifru.ifru_mtu = command.ioctl_real().siocsifmtu().ifr_mtu();
      ioctl_wrapper(command.ioctl_real().fd(), siocsifmtu_val,
                    (caddr_t)&ifreq, nullptr);
      break;
    }
    case IoctlReal::kSiocaddmulti:
    case IoctlReal::kSiocdelmulti: {
      const IfReqMulti &multi = (command.ioctl_real().ioctl_case() ==
                                  IoctlReal::kSiocaddmulti)
                                    ? command.ioctl_real().siocaddmulti()
                                    : command.ioctl_real().siocdelmulti();
      struct ifreq ifreq = {};
      get_ifr_name(ifreq.ifr_name, multi.ifr_name());
      std::string addr_s = get_sockaddr(multi.ifr_addr());
      if (!addr_s.empty()) {
        memcpy(&ifreq.ifr_ifru.ifru_addr, addr_s.data(),
               std::min(addr_s.size(), sizeof(ifreq.ifr_ifru.ifru_addr)));
      }
      unsigned long cmd = (command.ioctl_real().ioctl_case() ==
                           IoctlReal::kSiocaddmulti)
                              ? siocaddmulti_val
                              : siocdelmulti_val;
      ioctl_wrapper(command.ioctl_real().fd(), cmd, (caddr_t)&ifreq, nullptr);
      break;
    }
    case IoctlReal::kSiocprotoattach:
    case IoctlReal::kSiocprotodetach: {
      const IfReqFlags &pf = (command.ioctl_real().ioctl_case() ==
                               IoctlReal::kSiocprotoattach)
                                 ? command.ioctl_real().siocprotoattach()
                                 : command.ioctl_real().siocprotodetach();
      struct ifreq ifreq = {};
      get_ifr_name(ifreq.ifr_name, pf.ifr_name());
      unsigned long cmd = (command.ioctl_real().ioctl_case() ==
                           IoctlReal::kSiocprotoattach)
                              ? siocprotoattach_val
                              : siocprotodetach_val;
      ioctl_wrapper(command.ioctl_real().fd(), cmd, (caddr_t)&ifreq, nullptr);
      break;
    }
    case IoctlReal::kSiocsifaddr: {
      struct ifreq ifreq = {};
      get_ifr_name(ifreq.ifr_name,
                   command.ioctl_real().siocsifaddr().ifr_name());
      std::string addr_s =
          get_sockaddr(command.ioctl_real().siocsifaddr().ifr_addr());
      if (!addr_s.empty()) {
        memcpy(&ifreq.ifr_ifru.ifru_addr, addr_s.data(),
               std::min(addr_s.size(), sizeof(ifreq.ifr_ifru.ifru_addr)));
      }
      ioctl_wrapper(command.ioctl_real().fd(), siocsifaddr_val,
                    (caddr_t)&ifreq, nullptr);
      break;
    }
    case IoctlReal::kSiocsetroutermode: {
      struct ifreq ifreq = {};
      get_ifr_name(ifreq.ifr_name,
                   command.ioctl_real().siocsetroutermode().ifr_name());
      ifreq.ifr_ifru.ifru_intval =
          command.ioctl_real().siocsetroutermode().mode();
      ioctl_wrapper(command.ioctl_real().fd(), siocsetroutermode_val,
                    (caddr_t)&ifreq, nullptr);
      break;
    }
    case IoctlReal::kSiocsifvlan: {
      struct ifreq ifreq = {};
      get_ifr_name(ifreq.ifr_name,
                   command.ioctl_real().siocsifvlan().ifr_name());
      ioctl_wrapper(command.ioctl_real().fd(), siocsifvlan_val,
                    (caddr_t)&ifreq, nullptr);
      break;
    }
    case IoctlReal::kDiocaddrule:
    case IoctlReal::kDiocchangerule: {
      real_copyout = false;
      unsigned long cmd = (command.ioctl_real().ioctl_case() == IoctlReal::kDiocaddrule)
                              ? diocstart_val
                              : diocstop_val;
      ioctl_wrapper(command.ioctl_real().fd(), cmd, (caddr_t)1, nullptr);
      real_copyout = true;
      break;
    }
    case IoctlReal::kDiockillstates: {
      real_copyout = false;
      ioctl_wrapper(command.ioctl_real().fd(), diocstop_val, (caddr_t)1, nullptr);
      real_copyout = true;
      break;
    }
    case IoctlReal::IOCTL_NOT_SET:
      break;
  }
}

void HandleConnectx(const Command &command, std::vector<uint32_t> &cids) {
  bool has_srcaddr = command.connectx().endpoints().has_sae_srcaddr();

  std::string srcaddr_s;
  if (has_srcaddr) {
    srcaddr_s = get_sockaddr(command.connectx().endpoints().sae_srcaddr());
  }
  std::string dstaddr_s =
      get_sockaddr(command.connectx().endpoints().sae_dstaddr());

  void *srcaddr = (void *)srcaddr_s.data();
  uint32_t srcsize = srcaddr_s.size();
  if (!has_srcaddr) {
    srcaddr = nullptr;
    assert(!srcsize);
  }

  void *dstaddr = (void *)dstaddr_s.data();
  uint32_t dstsize = dstaddr_s.size();

  uint32_t connectx_flags = 0;
  for (const int flag : command.connectx().flags()) {
    connectx_flags |= flag;
  }
  uint32_t cid = 0;

  struct user64_sa_endpoints endpoints = {
      .sae_srcif = static_cast<unsigned int>(
          command.connectx().endpoints().sae_srcif()),
      .sae_srcaddr = (user64_addr_t)srcaddr,
      .sae_srcaddrlen = srcsize,
      .sae_dstaddr = (user64_addr_t)dstaddr,
      .sae_dstaddrlen = dstsize};

  size_t len = 0;
  // TODO(upstream): add IOV mocking
  connectx_wrapper(command.connectx().socket(), &endpoints,
                   command.connectx().associd(), connectx_flags, nullptr, 0,
                   &len, &cid, nullptr);
  cids.push_back(cid);
}

void HandleDisconnectx(const Command &command,
                       const std::vector<uint32_t> &cids) {
  uint32_t cid = 0;
  if (!cids.empty()) {
    cid = cids[command.disconnectx().cid() % cids.size()];
  } else {
    cid = command.disconnectx().cid();
  }
  disconnectx_wrapper(command.disconnectx().fd(),
                      command.disconnectx().associd(), cid, nullptr);
}

void HandleSocketpair(const Command &command, std::set<int> &open_fds) {
  int rsv[2] = {};
  int retval = 0;
  int ret = socketpair_wrapper(command.socketpair().domain(),
                               command.socketpair().type(),
                               command.socketpair().protocol(), rsv, &retval);
  if (!ret) {
    assert(open_fds.find(rsv[0]) == open_fds.end());
    open_fds.insert(rsv[0]);
    assert(open_fds.find(rsv[1]) == open_fds.end());
    open_fds.insert(rsv[1]);
  }
}

void HandlePipe(std::set<int> &open_fds) {
  int rsv[2] = {};
  int ret = pipe_wrapper(rsv);
  if (!ret) {
    assert(open_fds.find(rsv[0]) == open_fds.end());
    open_fds.insert(rsv[0]);
    assert(open_fds.find(rsv[1]) == open_fds.end());
    open_fds.insert(rsv[1]);
  }
}

void HandleSendmsg(const Command &command, int &retval) {
  const Sendmsg &sm = command.sendmsg();

  std::string sockaddr_s;
  if (sm.has_to()) {
    sockaddr_s = get_sockaddr(sm.to());
  }

  // Build iovec array from proto data + extra_iovs (B8: scatter-gather).
  int niov = 1 + sm.extra_iovs_size();
  if (niov > 8) niov = 8;  // cap to avoid excessive allocation
  struct {
    user64_addr_t iov_base;
    uint64_t iov_len;
  } iovs[8] = {};
  iovs[0].iov_base = (user64_addr_t)sm.data().data();
  iovs[0].iov_len = sm.data().size();
  for (int i = 1; i < niov; i++) {
    iovs[i].iov_base = (user64_addr_t)sm.extra_iovs(i - 1).data();
    iovs[i].iov_len = sm.extra_iovs(i - 1).size();
  }

  user64_msghdr msg = {};
  if (!sockaddr_s.empty()) {
    msg.msg_name = (user64_addr_t)sockaddr_s.data();
    msg.msg_namelen = sockaddr_s.size();
  }
  msg.msg_iov = (user64_addr_t)iovs;
  msg.msg_iovlen = niov;

  if (sm.has_control() && !sm.control().empty()) {
    msg.msg_control = (user64_addr_t)sm.control().data();
    msg.msg_controllen = sm.control().size();
  }

  sendmsg_wrapper(sm.s(), (caddr_t)&msg, sm.flags(), &retval);
}

// ---------------------------------------------------------------------------
// Main fuzzer entry point
// ---------------------------------------------------------------------------

// C1: Fork server integration.
// Set SOCKFUZZER_FORK_MODE=1 to run each iteration in an isolated child
// process. This provides perfect state isolation at the cost of ~2x overhead.
// Useful for crash reproduction and validation campaigns.
#include "fuzz/snapshot/fork_server.h"
static bool fork_server_initialized = false;

DEFINE_BINARY_PROTO_FUZZER(const Session &session) {
  if (!ready) {
    initialize_network();
    init_proc();
    ready = true;
    fork_server_init();
    fork_server_initialized = true;
  }

  FuzzedDataProvider dp((const uint8_t *)session.data_provider().data(),
                        session.data_provider().size());
  fdp = &dp;

  std::vector<uint32_t> cids;
  std::set<int> open_fds;

  for (const Command &command : session.commands()) {
    int retval = 0;
    switch (command.command_case()) {
      case Command::kSocket:
        HandleSocket(command, open_fds);
        break;
      case Command::kClose:
        open_fds.erase(command.close().fd());
        close_wrapper(command.close().fd(), nullptr);
        break;
      case Command::kSetSockOpt:
        HandleSetSockOpt(command);
        break;
      case Command::kGetSockOpt:
        HandleGetSockOpt(command);
        break;
      case Command::kBind: {
        std::string sockaddr_s = get_sockaddr(command.bind().sockaddr());
        bind_wrapper(command.bind().fd(), (caddr_t)sockaddr_s.data(),
                     sockaddr_s.size(), nullptr);
        break;
      }
      case Command::kIoctl:
        HandleIoctl(command);
        break;
      case Command::kAccept: {
        std::string sockaddr_s = get_sockaddr(command.accept().sockaddr());
        socklen_t size = sockaddr_s.size();
        accept_wrapper(command.accept().fd(), (caddr_t)sockaddr_s.data(),
                       &size, &retval);
        break;
      }
      case Command::kIpInput:
        DoIpInput(command.ip_input());
        break;
      case Command::kIoctlReal:
        HandleIoctlReal(command);
        break;
      case Command::kConnectx:
        HandleConnectx(command, cids);
        break;
      case Command::kConnect: {
        std::string sockaddr_s = get_sockaddr(command.connect().sockaddr());
        connect_wrapper(command.connect().fd(), (caddr_t)sockaddr_s.data(),
                        sockaddr_s.size(), nullptr);
        break;
      }
      case Command::kListen:
        listen_wrapper(command.listen().socket(), command.listen().backlog(),
                       nullptr);
        break;
      case Command::kDisconnectx:
        HandleDisconnectx(command, cids);
        break;
      case Command::kClearAll:
        clear_all();
        break;
      case Command::kNecpMatchPolicy: {
        std::unique_ptr<uint8_t[]> params(
            new uint8_t[command.necp_match_policy().parameters().size()]);
        memcpy(params.get(),
               command.necp_match_policy().parameters().data(),
               command.necp_match_policy().parameters().size());
        necp_match_policy_wrapper(
            params.get(),
            command.necp_match_policy().parameters().size(),
            /*returned_result=*/nullptr, &retval);
        break;
      }
      case Command::kNecpOpen: {
        int flags = 0;
        for (int flag : command.necp_open().flags()) {
          flags |= flag;
        }
        int fd = 0;
        int err = necp_open_wrapper(flags, &fd);
        if (err == 0) {
          assert(open_fds.find(fd) == open_fds.end());
          open_fds.insert(fd);
        }
        break;
      }
      case Command::kNecpClientAction:
        DoNecpClientAction(command.necp_client_action());
        break;
      case Command::kNecpSessionOpen: {
        int fd = 0;
        int err = necp_session_open_wrapper(0, &fd);
        if (err == 0) {
          assert(open_fds.find(fd) == open_fds.end());
          open_fds.insert(fd);
        }
        break;
      }
      case Command::kNecpSessionAction: {
        size_t out_buffer_size =
            command.necp_session_action().out_buffer_size() % 4096;
        if (out_buffer_size == 0) out_buffer_size = 16;
        std::unique_ptr<uint8_t[]> out_buffer(new uint8_t[out_buffer_size]);
        necp_session_action_wrapper(
            command.necp_session_action().necp_fd(),
            command.necp_session_action().action(),
            (uint8_t *)command.necp_session_action().in_buffer().data(),
            command.necp_session_action().in_buffer().size(),
            out_buffer.get(), out_buffer_size, &retval);
        break;
      }
      case Command::kAcceptNocancel: {
        std::string sockaddr_s = get_sockaddr(command.accept_nocancel().name());
        socklen_t size = sockaddr_s.size();
        accept_nocancel_wrapper(command.accept_nocancel().s(),
                                (caddr_t)sockaddr_s.data(), &size, &retval);
        break;
      }
      case Command::kConnectNocancel: {
        std::string sockaddr_s =
            get_sockaddr(command.connect_nocancel().name());
        socklen_t size = sockaddr_s.size();
        connect_nocancel_wrapper(command.connect_nocancel().s(),
                                 (caddr_t)sockaddr_s.data(), size, &retval);
        break;
      }
      case Command::kGetpeername: {
        std::string sockaddr_s = get_sockaddr(command.getpeername().asa());
        socklen_t size = sockaddr_s.size();
        getpeername_wrapper(command.getpeername().fdes(),
                            (caddr_t)sockaddr_s.data(), &size, &retval);
        break;
      }
      case Command::kGetsockname: {
        std::string sockaddr_s = get_sockaddr(command.getsockname().asa());
        socklen_t size = sockaddr_s.size();
        getsockname_wrapper(command.getsockname().fdes(),
                            (caddr_t)sockaddr_s.data(), &size, &retval);
        break;
      }
      case Command::kPeeloff:
        peeloff_wrapper(command.peeloff().s(), command.peeloff().aid(),
                        &retval);
        break;
      case Command::kRecvfrom: {
        std::string sockaddr_s = get_sockaddr(command.recvfrom().from());
        int size = sockaddr_s.size();
        size_t bufsize = command.recvfrom().buf().size();
        std::unique_ptr<char[]> recvbuf(new char[bufsize]);
        recvfrom_wrapper(
            command.recvfrom().s(), (caddr_t)recvbuf.get(),
            bufsize, command.recvfrom().flags(),
            (struct sockaddr *)sockaddr_s.data(), &size, &retval);
        break;
      }
      case Command::kRecvfromNocancel: {
        std::string sockaddr_s =
            get_sockaddr(command.recvfrom_nocancel().from());
        int size = sockaddr_s.size();
        size_t bufsize = command.recvfrom_nocancel().buf().size();
        std::unique_ptr<char[]> recvbuf(new char[bufsize]);
        recvfrom_nocancel_wrapper(
            command.recvfrom_nocancel().s(),
            (caddr_t)recvbuf.get(), bufsize,
            command.recvfrom_nocancel().flags(),
            (struct sockaddr *)sockaddr_s.data(), &size, &retval);
        break;
      }
      case Command::kRecvmsg: {
        uint32_t buf_size = command.recvmsg().buf_size() % 4096;
        uint32_t name_size = command.recvmsg().name_size() % 256;
        uint32_t control_size = command.recvmsg().control_size() % 1024;
        if (buf_size == 0) buf_size = 128;

        std::unique_ptr<char[]> buf(new char[buf_size]);
        std::unique_ptr<char[]> name(new char[name_size + 1]);
        std::unique_ptr<char[]> control(new char[control_size + 1]);

        struct {
          user64_addr_t iov_base;
          uint64_t iov_len;
        } iov = {};
        iov.iov_base = (user64_addr_t)buf.get();
        iov.iov_len = buf_size;

        user64_msghdr msg = {};
        msg.msg_name = name_size > 0 ? (user64_addr_t)name.get() : 0;
        msg.msg_namelen = name_size;
        msg.msg_iov = (user64_addr_t)&iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control_size > 0 ? (user64_addr_t)control.get() : 0;
        msg.msg_controllen = control_size;

        recvmsg_wrapper(command.recvmsg().s(), (struct msghdr *)&msg,
                        command.recvmsg().flags(), &retval);
        break;
      }
      case Command::kSendto: {
        std::string sockaddr_s = get_sockaddr(command.sendto().to());
        socklen_t size = sockaddr_s.size();
        sendto_wrapper(command.sendto().s(),
                       (caddr_t)command.sendto().buf().data(),
                       command.sendto().buf().size(), command.sendto().flags(),
                       (caddr_t)sockaddr_s.data(), size, &retval);
        break;
      }
      case Command::kSocketpair:
        HandleSocketpair(command, open_fds);
        break;
      case Command::kPipe:
        HandlePipe(open_fds);
        break;
      case Command::kShutdown:
        shutdown_wrapper(command.shutdown().s(), command.shutdown().how(),
                         &retval);
        break;
      case Command::kSendmsg:
        HandleSendmsg(command, retval);
        break;
      case Command::kPfControl: {
        unsigned long cmd = (command.pf_control().action() == PF_START)
                                ? diocstart_val : diocstop_val;
        ioctl_wrapper(command.pf_control().fd(), cmd, nullptr, nullptr);
        break;
      }
      case Command::kMptcpSocket: {
        // AF_MULTIPATH = 39 in XNU
        int fd = 0;
        int err = socket_wrapper(39, command.mptcp_socket().so_type(), 0, &fd);
        if (err == 0) {
          assert(open_fds.find(fd) == open_fds.end());
          open_fds.insert(fd);
        }
        break;
      }
#define SOL_SOCKET_XNU 0xffff
#define MPTCP_SERVICE_TYPE_OPT 0x0213  // 531
      case Command::kMptcpSetsockopt: {
        int svc_type = command.mptcp_setsockopt().service_type();
        setsockopt_wrapper(command.mptcp_setsockopt().fd(),
                           SOL_SOCKET_XNU,
                           MPTCP_SERVICE_TYPE_OPT,
                           (caddr_t)&svc_type, sizeof(svc_type), nullptr);
        break;
      }
      case Command::kSendtoNocancel: {
        std::string sockaddr_s;
        if (command.sendto_nocancel().has_to()) {
          sockaddr_s = get_sockaddr(command.sendto_nocancel().to());
        }
        socklen_t size = sockaddr_s.size();
        sendto_nocancel_wrapper(command.sendto_nocancel().s(),
                       (caddr_t)command.sendto_nocancel().buf().data(),
                       command.sendto_nocancel().buf().size(),
                       command.sendto_nocancel().flags(),
                       (caddr_t)sockaddr_s.data(), size, &retval);
        break;
      }
      case Command::kKqueue: {
        int fd = 0;
        int err = kqueue_wrapper(&fd);
        if (err == 0) {
          assert(open_fds.find(fd) == open_fds.end());
          open_fds.insert(fd);
        }
        break;
      }
      case Command::kTcpSession: {
        // F1: TCP state machine aware sequences.
        // Create a TCP socket, walk it to the requested state, then
        // optionally inject a packet or set a socket option in that state.
        int domain = command.tcp_session().has_domain()
                         ? command.tcp_session().domain() : 2;  // AF_INET
        int fd = 0;
        if (socket_wrapper(domain, 1 /*SOCK_STREAM*/, 6 /*IPPROTO_TCP*/, &fd))
          break;
        open_fds.insert(fd);

        // Bind to a port.
        struct sockaddr_in sin = {};
        sin.sin_len = sizeof(sin);
        sin.sin_family = 2;  // AF_INET
        sin.sin_port = (unsigned short)command.tcp_session().port();
        sin.sin_addr.s_addr = 0;  // INADDR_ANY
        bind_wrapper(fd, (caddr_t)&sin, sizeof(sin), nullptr);

        int st = command.tcp_session().session_type();
        if (st >= TCP_LISTEN) {
          listen_wrapper(fd, 5, nullptr);
        }
        if (st >= TCP_SYN_RCVD && command.tcp_session().has_extra_packet()) {
          DoIpInput(command.tcp_session().extra_packet());
        }
        if (st >= TCP_ESTABLISHED) {
          // Inject a SYN+ACK to complete handshake (best effort).
          if (command.tcp_session().has_extra_packet()) {
            DoIpInput(command.tcp_session().extra_packet());
          }
        }
        if (st == TCP_CLOSE_WAIT || st == TCP_FIN_WAIT_1 ||
            st == TCP_FIN_WAIT_2 || st == TCP_TIME_WAIT ||
            st == TCP_CLOSING || st == TCP_LAST_ACK) {
          // Inject FIN or close to advance state.
          if (command.tcp_session().has_extra_packet()) {
            DoIpInput(command.tcp_session().extra_packet());
          }
          if (st == TCP_FIN_WAIT_1 || st == TCP_LAST_ACK) {
            close_wrapper(fd, nullptr);
            open_fds.erase(fd);
          }
        }
        // Apply optional socket option in this state.
        if (command.tcp_session().has_extra_sockopt()) {
          const SetSocketOpt &sopt = command.tcp_session().extra_sockopt();
          int level = sopt.level();
          int name = sopt.name();
          std::string val_data;
          if (sopt.has_val() && sopt.val().has_raw()) {
            val_data = sopt.val().raw();
          } else if (sopt.has_val() && sopt.val().has_int_val()) {
            int32_t v = sopt.val().int_val().value();
            val_data = std::string((char *)&v, (char *)&v + sizeof(v));
          }
          setsockopt_wrapper(fd, level, name, (caddr_t)val_data.data(),
                             val_data.size(), nullptr);
        }
        break;
      }
      case Command::COMMAND_NOT_SET:
        break;
    }
  }

  for (int fd : open_fds) {
    close_wrapper(fd, nullptr);
  }

  clear_all();
}
}
