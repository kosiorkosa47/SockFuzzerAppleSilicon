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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <memory>
#include <vector>

#include "net_fuzzer.pb.h"
#include "src/libfuzzer/libfuzzer_macro.h"

extern "C" {
#include "api/backend.h"
#include "api/syscall_wrappers.h"
#include "types.h"

void fake_time_advance(void);
}

// XNU protocol/level constants — avoid magic numbers in handlers.
#define XNU_SOL_SOCKET    0xffff
#define XNU_IPPROTO_TCP   6
#define XNU_IPPROTO_IP    0
#define XNU_IPPROTO_IPV6  41
#define XNU_AF_INET       2
#define XNU_AF_INET6      30
#define XNU_AF_UNIX       1
#define XNU_AF_SYSTEM     32
#define XNU_AF_MULTIPATH  39
#define XNU_SOCK_STREAM   1
#define XNU_SOCK_DGRAM    2
#define XNU_MAX_OPEN_FDS  10

// Helper: combine repeated MsgFlag enum into bitmask.
template <typename T>
int combine_flags(const T &flags) {
  int result = 0;
  for (int f : flags) result |= f;
  return result;
}

// Host to network byte order conversions, written with compiler builtins so
// that no extra system headers have to be pulled into this translation unit
// (the XNU headers below already own most of the usual names).
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define FUZZ_HTONS(x) ((uint16_t)(x))
#define FUZZ_HTONL(x) ((uint32_t)(x))
#else
#define FUZZ_HTONS(x) __builtin_bswap16((uint16_t)(x))
#define FUZZ_HTONL(x) __builtin_bswap32((uint32_t)(x))
#endif

// Socket options and flow divert wire constants that the harness does not
// get from XNU headers. See bsd/sys/socket.h and
// bsd/netinet/flow_divert_proto.h.
#define XNU_SO_CFIL_SOCK_ID 0x1110
#define XNU_SO_FLOW_DIVERT_TOKEN 0x1106
#define XNU_FLOW_DIVERT_TLV_CTL_UNIT 10
#define XNU_FLOW_DIVERT_TLV_AGGREGATE_UNIT 26
#define XNU_FLOW_DIVERT_GROUP_COUNT_MAX 31

// InAddr and Port are curated-or-raw oneofs in the grammar. Every conversion
// into an on-the-wire structure goes through these helpers so that the byte
// swap is applied exactly once, and in the same way, at every use site.
static uint32_t in_addr_host(const InAddr &addr) {
  switch (addr.value_case()) {
    case InAddr::kRaw:
      return addr.raw();
    case InAddr::kCurated:
      return (uint32_t)addr.curated();
    default:
      return 0;
  }
}

// Returns an in_addr whose s_addr is already in network byte order.
static struct in_addr get_in_addr(const InAddr &addr) {
  struct in_addr out;
  out.s_addr = FUZZ_HTONL(in_addr_host(addr));
  return out;
}

// One flow divert TLV: a one byte type, a four byte big-endian length, then
// the value. Only 32-bit values are needed here.
static std::string FlowDivertTlv(uint8_t type, uint32_t value) {
  std::string tlv(1, (char)type);
  uint32_t len = FUZZ_HTONL(sizeof(value));
  tlv.append((const char *)&len, sizeof(len));
  uint32_t be_value = FUZZ_HTONL(value);
  tlv.append((const char *)&be_value, sizeof(be_value));
  return tlv;
}

static uint16_t port_host(const Port &port) {
  switch (port.value_case()) {
    case Port::kRaw:
      return (uint16_t)port.raw();
    case Port::kCurated:
      return (uint16_t)port.curated();
    default:
      return 0;
  }
}

// Returns a port already in network byte order.
static uint16_t get_port(const Port &port) {
  return FUZZ_HTONS(port_host(port));
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
      memset(sai, 0, sizeof(*sai));
      sai->s6_addr[15] = 1;  // ::1
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
  sai->sin6_port = (in_port_t)get_port(sa6.port());
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
          .sin_port = get_port(sockaddr.sockaddr4().sin_port()),
          .sin_addr = get_in_addr(sockaddr.sockaddr4().sin_addr()),
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
      sctl.sc_family = XNU_AF_SYSTEM;
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

  struct in_addr ip_src = get_in_addr(hdr.ip_src());
  struct in_addr ip_dst = get_in_addr(hdr.ip_dst());
  bool malform = hdr.has_malform_header() && hdr.malform_header();
  uint8_t ihl = malform ? (uint8_t)hdr.ip_hl() : (uint8_t)(5 + (options.size() / 4));
  struct ip ip_hdr = {
      .ip_hl = ihl,
      .ip_v = malform ? (u_int)hdr.ip_v() : IPV4,
      .ip_tos = (u_char)hdr.ip_tos(),
      .ip_len = (u_short)__builtin_bswap16(sizeof(ip_hdr) + options.size() + expected_size),
      .ip_id = (u_short)hdr.ip_id(),
      .ip_off = __builtin_bswap16((u_short)hdr.ip_off()),
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
      .th_sport = get_port(hdr.th_sport()),
      .th_dport = get_port(hdr.th_dport()),
      .th_seq = __builtin_bswap32(hdr.th_seq()),
      .th_ack = __builtin_bswap32(hdr.th_ack()),
      .th_off = hdr.th_off(),
      .th_flags = 0,
      .th_win = __builtin_bswap16((unsigned short)hdr.th_win()),
      .th_sum = 0,
      .th_urp = __builtin_bswap16((unsigned short)hdr.th_urp()),
  };

  for (const int flag : hdr.th_flags()) {
    tcphdr.th_flags |= flag;
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
      .ip6f_offlg = __builtin_bswap16((uint16_t)hdr.ip6f_offlg()),
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
extern const unsigned long diocaddrule_val;
extern const unsigned long diocchangerule_val;
extern const unsigned long diockillstates_val;

extern int kevent_wrapper(int kq, void* changelist, int nchanges,
                          void* eventlist, int nevents, int* retval);

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

// Item 12: one place that turns packet bytes into an mbuf. Every packet
// type goes through here, so MbufLayout is honored no matter which arm of the
// Packet oneof the grammar chose, and the receive interface and packet flags
// are decided once. Returns NULL when the chain could not be built, and the
// callers must not inject anything in that case.
static void *BuildPacketMbuf(const std::string &bytes, const Packet &packet) {
  if (bytes.empty()) return nullptr;
  if (packet.has_mbuf_layout() &&
      packet.mbuf_layout().split_points_size() > 0) {
    std::vector<uint32_t> splits(packet.mbuf_layout().split_points().begin(),
                                 packet.mbuf_layout().split_points().end());
    return get_mbuf_data_chained(bytes.data(), bytes.size(), PKTF_LOOP,
                                 splits.data(), (int)splits.size());
  }
  return get_mbuf_data(bytes.data(), bytes.size(), PKTF_LOOP);
}

void DoTcpInput(const TcpPacket &tcp_packet, const Packet &packet) {
  std::string tcp_hdr_s = get_tcp_hdr(tcp_packet.tcp_hdr());
  size_t payload_size = tcp_hdr_s.size() + tcp_packet.data().size();
  std::string ip_hdr_s = get_ip_hdr(tcp_packet.ip_hdr(), payload_size);
  std::string packet_s = ip_hdr_s + tcp_hdr_s + tcp_packet.data();

  void *mbuf_data = BuildPacketMbuf(packet_s, packet);
  if (!mbuf_data) {
    return;
  }

  ip_input_wrapper(mbuf_data);
}

void DoTcp6Input(const Tcp6Packet &tcp6_packet, const Packet &packet) {
  std::string tcp_hdr_s = get_tcp_hdr(tcp6_packet.tcp_hdr());
  size_t expected_size = tcp_hdr_s.size() + tcp6_packet.data().size();
  std::string packet_s = get_ip6_hdr(tcp6_packet.ip6_hdr(), expected_size);
  packet_s += tcp_hdr_s;
  packet_s += tcp6_packet.data();

  void *mbuf_data = BuildPacketMbuf(packet_s, packet);
  if (!mbuf_data) {
    return;
  }

  ip6_input_wrapper(mbuf_data);
}

void DoIp4Packet(const Ip4Packet &ip4_packet, const Packet &packet) {
  size_t payload_size = ip4_packet.data().size();
  std::string packet_s = get_ip_hdr(ip4_packet.ip_hdr(), payload_size);
  packet_s += ip4_packet.data();

  void *mbuf_data = BuildPacketMbuf(packet_s, packet);
  if (!mbuf_data) {
    return;
  }

  ip_input_wrapper(mbuf_data);
}

void DoIp6Packet(const Ip6Packet &ip6_packet, const Packet &packet) {
  std::string ext_data;

  // Build extension header chain.
  for (const auto &ext : ip6_packet.ext_headers()) {
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

  size_t expected_size = ext_data.size() + ip6_packet.data().size();
  std::string packet_s = get_ip6_hdr(ip6_packet.ip6_hdr(), expected_size);
  packet_s += ext_data;
  packet_s += ip6_packet.data();

  void *mbuf_data = BuildPacketMbuf(packet_s, packet);
  if (!mbuf_data) {
    return;
  }

  ip6_input_wrapper(mbuf_data);
}

void DoUdpInput(const UdpPacket &udp_packet, const Packet &packet) {
  struct udphdr udphdr = {
      .uh_sport = get_port(udp_packet.udp_hdr().uh_sport()),
      .uh_dport = get_port(udp_packet.udp_hdr().uh_dport()),
      .uh_ulen = __builtin_bswap16(sizeof(struct udphdr) +
                                    udp_packet.data().size()),
      .uh_sum = 0,
  };
  size_t payload_size = sizeof(struct udphdr) + udp_packet.data().size();
  std::string packet_s = get_ip_hdr(udp_packet.ip_hdr(), payload_size);
  packet_s += std::string((char *)&udphdr, (char *)&udphdr + sizeof(udphdr));
  packet_s += udp_packet.data();

  void *mbuf_data = BuildPacketMbuf(packet_s, packet);
  if (!mbuf_data) return;
  ip_input_wrapper(mbuf_data);
}

void DoUdp6Input(const Udp6Packet &udp6_packet, const Packet &packet) {
  struct udphdr udphdr = {
      .uh_sport = get_port(udp6_packet.udp_hdr().uh_sport()),
      .uh_dport = get_port(udp6_packet.udp_hdr().uh_dport()),
      .uh_ulen = __builtin_bswap16(sizeof(struct udphdr) +
                                    udp6_packet.data().size()),
      .uh_sum = 0,
  };
  size_t expected_size =
      sizeof(struct udphdr) + udp6_packet.data().size();
  std::string packet_s = get_ip6_hdr(udp6_packet.ip6_hdr(), expected_size);
  packet_s += std::string((char *)&udphdr, (char *)&udphdr + sizeof(udphdr));
  packet_s += udp6_packet.data();

  void *mbuf_data = BuildPacketMbuf(packet_s, packet);
  if (!mbuf_data) return;
  ip6_input_wrapper(mbuf_data);
}

void DoIcmp4Input(const Icmp4Packet &icmp4_packet, const Packet &packet) {
  struct icmp_hdr hdr = {
      .icmp_type = (uint8_t)icmp4_packet.icmp_hdr().icmp_type(),
      .icmp_code = (uint8_t)icmp4_packet.icmp_hdr().icmp_code(),
      .icmp_cksum = 0,
      .icmp_data = icmp4_packet.icmp_hdr().icmp_data(),
  };
  size_t payload_size =
      sizeof(struct icmp_hdr) + icmp4_packet.data().size();
  std::string packet_s = get_ip_hdr(icmp4_packet.ip_hdr(), payload_size);
  packet_s += std::string((char *)&hdr, (char *)&hdr + sizeof(hdr));
  packet_s += icmp4_packet.data();

  void *mbuf_data = BuildPacketMbuf(packet_s, packet);
  if (!mbuf_data) return;
  ip_input_wrapper(mbuf_data);
}

void DoIcmp6Input(const Icmp6Packet &icmp6_packet, const Packet &packet) {
  size_t expected_size =
      sizeof(struct icmp6_hdr) + icmp6_packet.data().size();
  std::string packet_s = get_ip6_hdr(icmp6_packet.ip6_hdr(), expected_size);
  packet_s += get_icmp6_hdr(icmp6_packet.icmp6_hdr());
  packet_s += icmp6_packet.data();

  void *mbuf_data = BuildPacketMbuf(packet_s, packet);
  if (!mbuf_data) return;
  ip6_input_wrapper(mbuf_data);
}

void DoIpInput(const Packet &packet) {
  switch (packet.packet_case()) {
    case Packet::kTcpPacket:
      DoTcpInput(packet.tcp_packet(), packet);
      break;
    case Packet::kTcp6Packet:
      DoTcp6Input(packet.tcp6_packet(), packet);
      break;
    case Packet::kIp4Packet:
      DoIp4Packet(packet.ip4_packet(), packet);
      break;
    case Packet::kIp6Packet:
      DoIp6Packet(packet.ip6_packet(), packet);
      break;
    case Packet::kUdpPacket:
      DoUdpInput(packet.udp_packet(), packet);
      break;
    case Packet::kUdp6Packet:
      DoUdp6Input(packet.udp6_packet(), packet);
      break;
    case Packet::kIcmp4Packet:
      DoIcmp4Input(packet.icmp4_packet(), packet);
      break;
    case Packet::kIcmp6Packet:
      DoIcmp6Input(packet.icmp6_packet(), packet);
      break;
    case Packet::kRawIp4: {
      void *mbuf_data = BuildPacketMbuf(packet.raw_ip4(), packet);
      if (!mbuf_data) return;
      ip_input_wrapper(mbuf_data);
      break;
    }
    case Packet::kRawIp6: {
      void *mbuf_data = BuildPacketMbuf(packet.raw_ip6(), packet);
      if (!mbuf_data) return;
      ip6_input_wrapper(mbuf_data);
      break;
    }
    case Packet::PACKET_NOT_SET:
      break;
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

// Extract SockOptVal bytes from a proto val message.
std::string BuildSockOptVal(const SockOptVal &sov) {
  std::string val_data;
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
        m.imr_multiaddr = get_in_addr(sov.mreq().imr_multiaddr());
        m.imr_interface = get_in_addr(sov.mreq().imr_interface());
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
  return val_data;
}

void HandleSetSockOpt(const Command &command) {
  int s = command.set_sock_opt().fd();
  const SetSocketOpt &sopt = command.set_sock_opt();

  int level = 0, name = 0;
  std::string val_data;

  switch (sopt.opt_case()) {
    case SetSocketOpt::kLegacy:
      level = sopt.legacy().level();
      name = sopt.legacy().name();
      if (sopt.legacy().has_val())
        val_data = BuildSockOptVal(sopt.legacy().val());
      break;
    case SetSocketOpt::kSolSocket:
      level = XNU_SOL_SOCKET;
      name = sopt.sol_socket().name();
      if (sopt.sol_socket().has_val())
        val_data = BuildSockOptVal(sopt.sol_socket().val());
      break;
    case SetSocketOpt::kTcp:
      level = XNU_IPPROTO_TCP;
      name = sopt.tcp().name();
      if (sopt.tcp().has_val())
        val_data = BuildSockOptVal(sopt.tcp().val());
      break;
    case SetSocketOpt::kIp:
      level = XNU_IPPROTO_IP;
      name = sopt.ip().name();
      if (sopt.ip().has_val())
        val_data = BuildSockOptVal(sopt.ip().val());
      break;
    case SetSocketOpt::kIpv6:
      level = XNU_IPPROTO_IPV6;
      name = sopt.ipv6().name();
      if (sopt.ipv6().has_val())
        val_data = BuildSockOptVal(sopt.ipv6().val());
      break;
    case SetSocketOpt::OPT_NOT_SET:
      return;
  }

  setsockopt_wrapper(s, level, name, (caddr_t)val_data.data(),
                     val_data.size(), nullptr);
}

void HandleGetSockOpt(const Command &command) {
  int s = command.get_sock_opt().fd();
  const GetSocketOpt &gopt = command.get_sock_opt();

  int level = 0, name = 0;
  switch (gopt.opt_case()) {
    case GetSocketOpt::kLegacy:
      level = gopt.legacy().level();
      name = gopt.legacy().name();
      break;
    case GetSocketOpt::kSolSocket:
      level = XNU_SOL_SOCKET;
      name = gopt.sol_socket().name();
      break;
    case GetSocketOpt::kTcp:
      level = XNU_IPPROTO_TCP;
      name = gopt.tcp().name();
      break;
    case GetSocketOpt::kIp:
      level = XNU_IPPROTO_IP;
      name = gopt.ip().name();
      break;
    case GetSocketOpt::kIpv6:
      level = XNU_IPPROTO_IPV6;
      name = gopt.ipv6().name();
      break;
    case GetSocketOpt::OPT_NOT_SET:
      return;
  }

  socklen_t size = gopt.size();
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

// Item 10: turn a PfAddr from the grammar into the 16 byte address plus port
// that a PF rule address holds. The port in the message wins over any port
// carried by the sockaddr.
static void GetPfAddr(const PfAddr &pf_addr, uint8_t out[16], uint16_t *port) {
  memset(out, 0, 16);
  *port = (uint16_t)pf_addr.port();
  if (!pf_addr.has_addr()) return;
  const SockAddr &sa = pf_addr.addr();
  if (sa.has_sockaddr4()) {
    struct in_addr a = get_in_addr(sa.sockaddr4().sin_addr());
    memcpy(out, &a.s_addr, sizeof(a.s_addr));
    if (!pf_addr.has_port()) *port = port_host(sa.sockaddr4().sin_port());
  } else if (sa.has_sockaddr6()) {
    struct in6_addr a6 = {};
    get_in6_addr(&a6, sa.sockaddr6().sin6_addr());
    memcpy(out, &a6, sizeof(a6));
    if (!pf_addr.has_port()) *port = port_host(sa.sockaddr6().port());
  }
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
        alias.ifra_flags |= flag;
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
      ifreq.ifr_ifru.ifru_intval = command.ioctl_real().siocsifvlan().vlr_tag();
      ioctl_wrapper(command.ioctl_real().fd(), siocsifvlan_val,
                    (caddr_t)&ifreq, nullptr);
      break;
    }
    case IoctlReal::kDiocaddrule:
    case IoctlReal::kDiocchangerule: {
      // Item 10: build a real struct pfioc_rule and go straight to pfioctl.
      // The previous code handed a sentinel pointer to a socket ioctl, which
      // never reached PF, so none of the rule fields meant anything.
      bool add = command.ioctl_real().ioctl_case() == IoctlReal::kDiocaddrule;
      const PfIoctlRule &r = add ? command.ioctl_real().diocaddrule()
                                 : command.ioctl_real().diocchangerule();
      struct fuzz_pf_rule_spec spec = {};
      get_ifr_name(spec.ifname, r.ifname());
      spec.ioc_action = r.ioc_action();
      spec.ticket = r.ticket();
      spec.pool_ticket = r.pool_ticket();
      spec.nr = r.nr();
      spec.rule_action = r.action();
      spec.direction = r.direction();
      spec.af = r.af();
      spec.proto = r.proto();
      spec.rule_flag = r.rule_flag();
      spec.keep_state = (uint8_t)r.keep_state();
      spec.quick = r.quick() ? 1 : 0;
      GetPfAddr(r.src(), spec.src_addr, &spec.src_port);
      GetPfAddr(r.dst(), spec.dst_addr, &spec.dst_port);
      pf_ioctl_rule(add ? diocaddrule_val : diocchangerule_val, &spec);
      break;
    }
    case IoctlReal::kDiockillstates: {
      const PfIoctlKillStates &k = command.ioctl_real().diockillstates();
      struct fuzz_pf_kill_spec spec = {};
      get_ifr_name(spec.ifname, k.ifname());
      spec.af = k.af();
      spec.proto = k.proto();
      GetPfAddr(k.src(), spec.src_addr, &spec.src_port);
      GetPfAddr(k.dst(), spec.dst_addr, &spec.dst_port);
      pf_ioctl_kill_states(diockillstates_val, &spec);
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

  sendmsg_wrapper(sm.s(), (caddr_t)&msg, combine_flags(sm.flags()), &retval);
}

// ---------------------------------------------------------------------------
// Main fuzzer entry point
// ---------------------------------------------------------------------------

// C1: Fork server integration.
// Set SOCKFUZZER_FORK_MODE=1 to run each iteration in an isolated child
// process. This provides perfect state isolation at the cost of ~2x overhead.
// Useful for crash reproduction and validation campaigns.
// C1: Fork server — design doc only. Full integration deferred.
// --- Item 9: reach the TCP states the grammar advertises ---
//
// The old handler only created a listening socket and injected at most one
// packet, so nothing past LISTEN was reachable: a synthetic peer cannot
// complete a handshake because the server side chooses an initial sequence
// number the harness never gets to see. Here a second real socket connects
// over the loopback interface, so the kernel performs the whole three way
// handshake by itself. The resulting child socket then hands us the real
// 4-tuple and the live sequence numbers through TCP_INFO, which is what
// makes state specific injected segments possible at all.

// XNU private socket option, see bsd/netinet/tcp.h.
#define XNU_TCP_INFO 0x200
// _IOW('f', 126, int), see bsd/sys/filio.h. The harness deliberately does
// not include the kernel ioctl macros, so the encoded value is spelled out.
#define XNU_FIONBIO 0x8004667eUL
#define XNU_SHUT_WR 1
// 127.0.0.1 in host byte order.
#define XNU_LOOPBACK4 0x7f000001u
// 24.130.58.208: a remote with no route in the harness, so replies sent to
// it are dropped instead of being looped back at us.
#define XNU_UNROUTABLE4 0x188a3ad0u

// Leading fields of XNU's struct tcp_info (bsd/netinet/tcp.h), which is
// declared under "#pragma pack(4)". Only this prefix is needed, and
// sooptcopyout truncates to whatever buffer size the caller passes in.
#pragma pack(4)
struct fuzz_tcp_info_prefix {
  uint8_t tcpi_state;
  uint8_t tcpi_options;
  uint8_t tcpi_snd_wscale;
  uint8_t tcpi_rcv_wscale;
  uint32_t tcpi_flags;
  uint32_t tcpi_rto;
  uint32_t tcpi_snd_mss;
  uint32_t tcpi_rcv_mss;
  uint32_t tcpi_rttcur;
  uint32_t tcpi_srtt;
  uint32_t tcpi_rttvar;
  uint32_t tcpi_rttbest;
  uint32_t tcpi_snd_ssthresh;
  uint32_t tcpi_snd_cwnd;
  uint32_t tcpi_rcv_space;
  uint32_t tcpi_snd_wnd;
  uint32_t tcpi_snd_nxt;
  uint32_t tcpi_rcv_nxt;
};
#pragma pack()

// A live connection as the kernel sees it. Addresses and ports stay in
// network byte order so they can be copied straight into a header; the
// sequence numbers are in host byte order.
struct TcpConnState {
  bool valid = false;
  bool v6 = false;
  uint32_t local4 = 0;
  uint32_t remote4 = 0;
  uint16_t local_port = 0;
  uint16_t remote_port = 0;
  uint32_t snd_nxt = 0;
  uint32_t rcv_nxt = 0;
  uint8_t state = 0;
};

static void SetNonBlocking(int fd) {
  int on = 1;
  ioctl_wrapper(fd, XNU_FIONBIO, (caddr_t)&on, nullptr);
}

// Reads the 4-tuple and the sequence numbers of a connected socket.
// Returns false when the socket is not connected, in which case no injected
// segment can be aimed at it.
static bool ReadTcpConnState(int fd, TcpConnState *out) {
  uint8_t local[sizeof(struct sockaddr_in6)] = {};
  uint8_t remote[sizeof(struct sockaddr_in6)] = {};
  socklen_t len = sizeof(local);
  if (getsockname_wrapper(fd, (caddr_t)local, &len, nullptr)) return false;
  len = sizeof(remote);
  if (getpeername_wrapper(fd, (caddr_t)remote, &len, nullptr)) return false;

  struct fuzz_tcp_info_prefix ti = {};
  socklen_t ti_len = sizeof(ti);
  if (getsockopt_wrapper(fd, XNU_IPPROTO_TCP, XNU_TCP_INFO, (caddr_t)&ti,
                         &ti_len, nullptr))
    return false;

  const struct sockaddr *lsa = (const struct sockaddr *)local;
  const struct sockaddr *rsa = (const struct sockaddr *)remote;
  out->v6 = (lsa->sa_family == XNU_AF_INET6);
  if (!out->v6) {
    const struct sockaddr_in *l = (const struct sockaddr_in *)local;
    const struct sockaddr_in *r = (const struct sockaddr_in *)remote;
    out->local4 = l->sin_addr.s_addr;
    out->remote4 = r->sin_addr.s_addr;
    out->local_port = l->sin_port;
    out->remote_port = r->sin_port;
  } else {
    const struct sockaddr_in6 *l = (const struct sockaddr_in6 *)local;
    const struct sockaddr_in6 *r = (const struct sockaddr_in6 *)remote;
    out->local_port = l->sin6_port;
    out->remote_port = r->sin6_port;
  }
  (void)rsa;
  out->snd_nxt = ti.tcpi_snd_nxt;
  out->rcv_nxt = ti.tcpi_rcv_nxt;
  out->state = ti.tcpi_state;
  out->valid = true;
  return true;
}

// Injects one bare IPv4 TCP segment. Checksums are left at zero because the
// harness stubs the checksum routines out to always return 0.
static void InjectTcp4(uint32_t src_ip_net, uint16_t src_port_net,
                       uint32_t dst_ip_net, uint16_t dst_port_net, uint32_t seq,
                       uint32_t ack, uint8_t flags, uint16_t win) {
  struct tcphdr th = {};
  th.th_sport = src_port_net;
  th.th_dport = dst_port_net;
  th.th_seq = FUZZ_HTONL(seq);
  th.th_ack = FUZZ_HTONL(ack);
  th.th_off = 5;
  th.th_flags = flags;
  th.th_win = FUZZ_HTONS(win);
  th.th_sum = 0;
  th.th_urp = 0;

  struct ip ih = {};
  ih.ip_hl = 5;
  ih.ip_v = IPV4;
  ih.ip_tos = 0;
  ih.ip_len = (u_short)FUZZ_HTONS(sizeof(ih) + sizeof(th));
  ih.ip_id = 0;
  ih.ip_off = 0;
  ih.ip_ttl = 64;
  ih.ip_p = XNU_IPPROTO_TCP;
  ih.ip_sum = 0;
  ih.ip_src.s_addr = src_ip_net;
  ih.ip_dst.s_addr = dst_ip_net;

  std::string pkt((char *)&ih, (char *)&ih + sizeof(ih));
  pkt.append((char *)&th, (char *)&th + sizeof(th));
  void *m = get_mbuf_data(pkt.data(), pkt.size(), PKTF_LOOP);
  if (m) ip_input_wrapper(m);
}

// Sends one segment that looks like it came from the peer of conn.
static void InjectFromPeer(const TcpConnState &conn, uint8_t flags,
                           uint32_t seq_delta, uint32_t ack_delta) {
  if (!conn.valid || conn.v6) return;
  InjectTcp4(conn.remote4, conn.remote_port, conn.local4, conn.local_port,
             conn.rcv_nxt + seq_delta, conn.snd_nxt + ack_delta, flags, 8192);
}

// Builds a sockaddr for the loopback address of the requested domain.
static std::string BuildLoopbackSockaddr(int domain, uint16_t port_net) {
  if (domain == XNU_AF_INET6) {
    struct sockaddr_in6 sin6 = {};
    sin6.sin6_len = sizeof(sin6);
    sin6.sin6_family = (sa_family_t)XNU_AF_INET6;
    sin6.sin6_port = port_net;
    sin6.sin6_addr.s6_addr[15] = 1;  // ::1
    return std::string((char *)&sin6, (char *)&sin6 + sizeof(sin6));
  }
  struct sockaddr_in sin = {};
  sin.sin_len = sizeof(sin);
  sin.sin_family = (sa_family_t)XNU_AF_INET;
  sin.sin_port = port_net;
  sin.sin_addr.s_addr = FUZZ_HTONL(XNU_LOOPBACK4);
  return std::string((char *)&sin, (char *)&sin + sizeof(sin));
}

// Applies TcpSession.extra_sockopt to fd. Shared with the generic
// SetSocketOpt handler through BuildSockOptVal.
static void ApplyExtraSockopt(const SetSocketOpt &sopt, int fd) {
  int level = 0, name = 0;
  std::string val_data;
  if (sopt.has_legacy()) {
    level = sopt.legacy().level();
    name = sopt.legacy().name();
    if (sopt.legacy().has_val()) val_data = BuildSockOptVal(sopt.legacy().val());
  } else if (sopt.has_sol_socket()) {
    level = XNU_SOL_SOCKET;
    name = sopt.sol_socket().name();
    if (sopt.sol_socket().has_val())
      val_data = BuildSockOptVal(sopt.sol_socket().val());
  } else if (sopt.has_tcp()) {
    level = XNU_IPPROTO_TCP;
    name = sopt.tcp().name();
    if (sopt.tcp().has_val()) val_data = BuildSockOptVal(sopt.tcp().val());
  }
  if (level || name) {
    setsockopt_wrapper(fd, level, name, (caddr_t)val_data.data(),
                       val_data.size(), nullptr);
  }
}

// True once lo0 owns 127.0.0.1. Set during one time initialization, while no
// FuzzedDataProvider is installed: the privilege checks the interface ioctls
// go through are fed by the data provider, so configuring the address from
// inside an iteration would succeed only for some inputs.
static bool loopback_ready = false;

// Ports for the harness built handshake. They are chosen here instead of
// being read back with getsockname, because getsockname answers through
// copyout, which this harness deliberately fails at random. Rotating the
// value keeps sockets left behind in TIME_WAIT from blocking later sessions.
static uint16_t NextSessionPort() {
  static uint16_t next = 20000;
  if (next < 20000 || next >= 60000) next = 20000;
  return next++;
}

static void HandleTcpSession(const TcpSession &ts, std::set<int> &open_fds) {
  int domain = ts.has_domain() ? ts.domain() : XNU_AF_INET;
  if (domain != XNU_AF_INET6) domain = XNU_AF_INET;
  int st = ts.session_type();

  // Setting up the connection has to be reliable, otherwise none of the
  // states below are reachable: the fake copyin/copyout and the fake
  // privilege checks fail at random while a data provider is installed.
  // Detach it for the plumbing and put it back before anything that is
  // actually meant to be fuzzed.
  FuzzedDataProvider *saved_fdp = fdp;
  fdp = nullptr;

  int listener = -1;
  if (socket_wrapper(domain, XNU_SOCK_STREAM, XNU_IPPROTO_TCP, &listener) ||
      listener < 0) {
    fdp = saved_fdp;
    return;
  }
  open_fds.insert(listener);
  // Non-blocking everywhere: a blocking accept or connect would wedge the
  // single fake thread this harness runs on.
  SetNonBlocking(listener);

  uint16_t listen_port = port_host(ts.port());
  if (listen_port == 0) listen_port = NextSessionPort();
  std::string bind_addr =
      BuildLoopbackSockaddr(domain, FUZZ_HTONS(listen_port));
  if (bind_wrapper(listener, (caddr_t)bind_addr.data(), bind_addr.size(),
                   nullptr)) {
    // The requested port may be taken or privileged; take a fresh one so the
    // rest of the sequence still runs.
    listen_port = NextSessionPort();
    bind_addr = BuildLoopbackSockaddr(domain, FUZZ_HTONS(listen_port));
    bind_wrapper(listener, (caddr_t)bind_addr.data(), bind_addr.size(),
                 nullptr);
  }

  listen_wrapper(listener, 5, nullptr);

  int client = -1;
  int child = -1;
  TcpConnState conn;

  if (st >= TCP_SYN_RCVD && loopback_ready) {
    if (socket_wrapper(domain, XNU_SOCK_STREAM, XNU_IPPROTO_TCP, &client) == 0 &&
        client >= 0) {
      open_fds.insert(client);
      SetNonBlocking(client);
      // Bind the client too, so the whole 4-tuple is known without asking
      // the kernel for it.
      uint16_t client_port = NextSessionPort();
      std::string client_addr =
          BuildLoopbackSockaddr(domain, FUZZ_HTONS(client_port));
      bind_wrapper(client, (caddr_t)client_addr.data(), client_addr.size(),
                   nullptr);
      if (domain == XNU_AF_INET) {
        connect_tcp4_for_handshake(client, client_addr.data(), bind_addr.data(),
                                   bind_addr.size());
      } else {
        connect_wrapper(client, (caddr_t)bind_addr.data(), bind_addr.size(),
                        nullptr);
      }
      drain_loopback_input_for_tcp_handshake();
      // Deliver what the stack just queued on lo0, which is what lets the
      // three way handshake actually complete. Ask accept for no peer
      // address: that would be one more copyout that can fail at random.
      int accepted = -1;
      accept_wrapper(listener, nullptr, nullptr, &accepted);
      // SockFuzzer's upstream PCB lookup patch puts every PCB in one hash
      // bucket and replaces tuple comparisons with fuzzed choices. With the
      // data provider detached it used to select the connecting client for
      // the inbound SYN, so tcp_input rejected the segment at its tuple
      // consistency check before sonewconn. The tuple-aware drain keeps the
      // fuzzed lookup for normal inputs but selects the matching listener,
      // client, and child while this deterministic handshake runs.
      if (accepted >= 0) {
        child = accepted;
        open_fds.insert(child);
        // Snapshot the tuple and the sequence numbers while the connection
        // is still ESTABLISHED; the steps below may close the socket.
        ReadTcpConnState(child, &conn);
      }
    }
  }

  // Everything from here on is fair game for the fuzzer again.
  fdp = saved_fdp;

  // SYN_RCVD needs a half open connection, which a cooperative peer can
  // never produce: inject a SYN from an address with no route, so the
  // SYN-ACK is dropped and the socket stays in SYN_RCVD.
  if (st == TCP_SYN_RCVD && domain == XNU_AF_INET) {
    InjectTcp4(FUZZ_HTONL(XNU_UNROUTABLE4), FUZZ_HTONS(12345),
               FUZZ_HTONL(XNU_LOOPBACK4), FUZZ_HTONS(listen_port), 0x1000, 0,
               TH_SYN, 8192);
  }

  // Drive the connection towards the requested state. With a real peer on
  // the other end both sides react immediately, so the states are walked
  // through rather than parked in, which is exactly what exercises the
  // transitions.
  switch (st) {
    case TCP_CLOSE_WAIT:
      // Peer closes its write side: the child sees a FIN and lands in
      // CLOSE_WAIT, where it stays because the child never closes.
      if (client >= 0) shutdown_wrapper(client, XNU_SHUT_WR, nullptr);
      break;
    case TCP_FIN_WAIT_1:
    case TCP_FIN_WAIT_2:
      // The child closes its write side first.
      if (child >= 0) shutdown_wrapper(child, XNU_SHUT_WR, nullptr);
      break;
    case TCP_TIME_WAIT:
      if (child >= 0) shutdown_wrapper(child, XNU_SHUT_WR, nullptr);
      if (client >= 0) shutdown_wrapper(client, XNU_SHUT_WR, nullptr);
      break;
    case TCP_CLOSING:
      // TODO: a real simultaneous close needs a peer that does not ACK our
      // FIN, which cannot be expressed with a live loopback socket on the
      // other end: the kernel ACKs for us before we regain control. The FIN
      // injected below therefore reaches the FIN handling code but usually
      // lands in FIN_WAIT_2 rather than CLOSING. Reaching CLOSING for real
      // needs an output hook that swallows the peer's ACK.
      if (child >= 0) shutdown_wrapper(child, XNU_SHUT_WR, nullptr);
      InjectFromPeer(conn, TH_FIN | TH_ACK, 0, 0);
      break;
    case TCP_LAST_ACK:
      // Peer FINs first, then the child closes: the child goes through
      // CLOSE_WAIT into LAST_ACK.
      if (client >= 0) shutdown_wrapper(client, XNU_SHUT_WR, nullptr);
      if (child >= 0) shutdown_wrapper(child, XNU_SHUT_WR, nullptr);
      break;
    default:
      break;
  }

  // One state specific segment from the peer, built from the real tuple.
  switch (st) {
    case TCP_ESTABLISHED:
    case TCP_CLOSE_WAIT:
    case TCP_LAST_ACK:
      InjectFromPeer(conn, TH_ACK, 0, 0);
      break;
    case TCP_FIN_WAIT_1:
    case TCP_FIN_WAIT_2:
      InjectFromPeer(conn, TH_FIN | TH_ACK, 0, 1);
      break;
    case TCP_TIME_WAIT:
      InjectFromPeer(conn, TH_RST, 0, 1);
      break;
    default:
      break;
  }

  // Socket options are applied to the connected child when there is one,
  // because that is where the interesting TCP state lives.
  if (ts.has_extra_sockopt())
    ApplyExtraSockopt(ts.extra_sockopt(), child >= 0 ? child : listener);

  // Whatever the grammar wanted to inject on top of the state above.
  if (ts.has_extra_packet()) DoIpInput(ts.extra_packet());

  // Let the stack finish whatever exchange the steps above started.
  drain_loopback_input();

  if (st == TCP_FIN_WAIT_1 || st == TCP_LAST_ACK) {
    if (child >= 0) {
      close_wrapper(child, nullptr);
      open_fds.erase(child);
    }
  }
}

// Set SOCKFUZZER_FORK_MODE=1 for fork-per-iteration (when linked).
static void maybe_init_fork_server() {
  // Placeholder — fork_server.c is not yet compiled into the fuzzer.
  // See docs/SNAPSHOT_RESET.md for the design.
}

static void TearDownIteration(std::set<int> &open_fds,
                              std::vector<uint32_t> &cids,
                              bool resume_input) {
  FuzzedDataProvider *saved_fdp = fdp;
  fdp = nullptr;

  // Scan the whole synthetic descriptor table. This also closes descriptors
  // returned by paths that failed to update open_fds.
  for (int fd = XNU_MAX_OPEN_FDS - 1; fd >= 0; --fd) {
    close_wrapper(fd, nullptr);
  }

  open_fds.clear();
  cids.clear();
  clear_all();

  if (resume_input) {
    fdp = saved_fdp;
  }
}

DEFINE_BINARY_PROTO_FUZZER(const Session &session) {
  if (!ready) {
    initialize_network();
    init_proc();
    ready = true;
    maybe_init_fork_server();
    // lo0 has no address until we give it one, and without an address there
    // is no route to 127.0.0.1 and no local connection can be established.
    // Interface addresses survive clear_all(), so once per process is enough.
    loopback_ready = configure_loopback_address();
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
        if (retval >= 0) { open_fds.insert(retval); }
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
        TearDownIteration(open_fds, cids, true);
        break;
      case Command::kNecpMatchPolicy: {
        // Item 11: XNU rejects this call outright when either the parameter
        // buffer or the result buffer is empty, so both have to be real.
        // The result buffer must be at least as large as XNU's
        // struct necp_aggregate_result, which it copies out in full.
        std::string params = command.necp_match_policy().parameters();
        if (params.empty()) params.push_back('\0');
        std::vector<uint8_t> result(necp_aggregate_result_size());
        std::unique_ptr<uint8_t[]> params_buf(new uint8_t[params.size()]);
        memcpy(params_buf.get(), params.data(), params.size());
        necp_match_policy_wrapper(params_buf.get(), params.size(),
                                  (struct necp_aggregate_result *)result.data(),
                                  &retval);
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
        if (retval >= 0) { open_fds.insert(retval); }
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
      case Command::kPeeloff: {
        // XNU's peeloff() leaves *retval untouched on failure, so the shared
        // retval (reset to 0 each command) used to look like a successful
        // descriptor 0. That inserted a never-opened fd into open_fds and made
        // a later genuine fd 0 trip the duplicate-fd assertion. Check the
        // error first, the same way the necp_open case does, and keep the
        // result in a local so no stale value can leak in.
        int peeled_fd = -1;
        int peeloff_err = peeloff_wrapper(command.peeloff().s(),
                                          command.peeloff().aid(), &peeled_fd);
        if (peeloff_err == 0 && peeled_fd >= 0) {
          open_fds.insert(peeled_fd);
        }
        break;
      }
      case Command::kRecvfrom: {
        std::string sockaddr_s = get_sockaddr(command.recvfrom().from());
        int size = sockaddr_s.size();
        size_t bufsize = command.recvfrom().buf().size();
        std::unique_ptr<char[]> recvbuf(new char[bufsize]);
        recvfrom_wrapper(
            command.recvfrom().s(), (caddr_t)recvbuf.get(),
            bufsize, combine_flags(command.recvfrom().flags()),
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
            combine_flags(command.recvfrom_nocancel().flags()),
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
                       command.sendto().buf().size(), combine_flags(command.sendto().flags()),
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
                                ? diocstart_val
                                : diocstop_val;
        pf_ioctl_no_payload(cmd);
        break;
      }
      case Command::kMptcpSocket: {
        // AF_MULTIPATH = 39 in XNU
        int fd = 0;
        int err = socket_wrapper(XNU_AF_MULTIPATH, command.mptcp_socket().so_type(), 0, &fd);
        if (err == 0) {
          assert(open_fds.find(fd) == open_fds.end());
          open_fds.insert(fd);
        }
        break;
      }
      case Command::kMptcpSetsockopt: {
        int svc_type = command.mptcp_setsockopt().service_type();
        setsockopt_wrapper(command.mptcp_setsockopt().fd(),
                           XNU_SOL_SOCKET,
                           0x0213,  // MPTCP_SERVICE_TYPE_OPT
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
                       combine_flags(command.sendto_nocancel().flags()),
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
        HandleTcpSession(command.tcp_session(), open_fds);
        break;
      }
      case Command::kCfilQuery: {
        // Item 11: SO_CFIL_SOCK_ID is get-only. Setting it, as this used to
        // do, could never reach cfil at all. Reading it calls through to
        // cfil_sock_id_from_socket, which is the real code.
        uint64_t sock_id = 0;
        socklen_t sock_id_len = sizeof(sock_id);
        getsockopt_wrapper(command.cfil_query().fd(), XNU_SOL_SOCKET,
                           XNU_SO_CFIL_SOCK_ID, (caddr_t)&sock_id,
                           &sock_id_len, nullptr);
        break;
      }
      case Command::kFlowDivertConnect: {
        // Item 11: SO_FLOW_DIVERT_TOKEN wants a TLV stream, not four raw
        // bytes. Without a control unit TLV in range, XNU stops in the token
        // parser and never reaches flow_divert_pcb_init_internal.
        const FlowDivertConnect &fdc = command.flow_divert_connect();
        uint32_t ctl_unit =
            1 + (fdc.ctl_unit() % (XNU_FLOW_DIVERT_GROUP_COUNT_MAX - 1));
        std::string token =
            FlowDivertTlv(XNU_FLOW_DIVERT_TLV_CTL_UNIT, ctl_unit);
        if (fdc.has_aggregate_unit()) {
          token += FlowDivertTlv(XNU_FLOW_DIVERT_TLV_AGGREGATE_UNIT,
                                 fdc.aggregate_unit());
        }
        setsockopt_wrapper(fdc.fd(), XNU_SOL_SOCKET,
                           XNU_SO_FLOW_DIVERT_TOKEN, (caddr_t)token.data(),
                           token.size(), nullptr);
        if (fdc.has_target()) {
          std::string addr_s = get_sockaddr(fdc.target());
          connect_wrapper(fdc.fd(), (caddr_t)addr_s.data(), addr_s.size(),
                          nullptr);
        }
        break;
      }
      case Command::kKeventCmd: {
        const Kevent &kev = command.kevent_cmd();
        // Build changelist from proto
        int nchanges = std::min((int)kev.changes_size(), 8);
        struct {
          uint64_t ident;
          int16_t filter;
          uint16_t flags;
          uint32_t fflags;
          int64_t data;
          uint64_t udata;
          uint64_t ext[2];
        } changelist[8] = {};
        for (int i = 0; i < nchanges; i++) {
          changelist[i].ident = kev.changes(i).ident();
          changelist[i].filter = (int16_t)kev.changes(i).filter();
          int flags = 0;
          for (int f : kev.changes(i).flags()) flags |= f;
          changelist[i].flags = (uint16_t)flags;
          changelist[i].fflags = kev.changes(i).fflags();
          changelist[i].data = kev.changes(i).data();
          changelist[i].udata = kev.changes(i).udata();
        }
        // Allocate event buffer
        int nevents = kev.nevents() % 8;
        struct {
          uint64_t ident;
          int16_t filter;
          uint16_t flags;
          uint32_t fflags;
          int64_t data;
          uint64_t udata;
          uint64_t ext[2];
        } eventlist[8] = {};
        kevent_wrapper(kev.kq(), changelist, nchanges,
                       eventlist, nevents, &retval);
        break;
      }
      case Command::COMMAND_NOT_SET:
        break;
    }
    fake_time_advance();
  }

  TearDownIteration(open_fds, cids, false);
}
}
