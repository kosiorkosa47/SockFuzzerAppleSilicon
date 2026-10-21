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

#include <sys/proc_internal.h>
#include <sys/filedesc.h>

#include "bsd/sys/_types/_size_t.h"
#include "bsd/sys/kpi_mbuf.h"
#include "bsd/sys/kpi_socket.h"
#include "bsd/sys/malloc.h"
#include "bsd/sys/protosw.h"
#include "bsd/sys/resourcevar.h"

extern ifnet_t lo_ifp;

void kernel_startup_bootstrap();
void inpcb_timeout(void*, void*);
void key_timehandler(void);
void frag_timeout(void);
void nd6_slowtimo(void);
void nd6_timeout(void);
void in6_tmpaddrtimer(void);
void mp_timeout(void);
void igmp_timeout(void);
void tcp_fuzzer_reset(void);
void tcp_fuzzer_reap(void);
void in6_rtqtimo(void*);
void frag6_timeout();
void mld_timeout();
int ioctl_wrapper(int fd, unsigned long com, char* data, int* retval);
void ip_input(mbuf_t m);
void ip6_input(mbuf_t m);
struct mbuf* mbuf_create(const uint8_t* data, size_t size, bool is_header,
                         bool force_ext, int m_type, int pktflags);
void mcache_init(void);
void mbinit(void);
void eventhandler_init(void);
void dlil_init(void);
void socketinit(void);
void domaininit(void);
void domain_timeout(void*);
void loopattach(void);
void ether_family_init(void);
void tcp_cc_init(void);
void net_init_run(void);
errno_t necp_init(void);
void in_rtqtimo(void* targ);
void in_rtqdrain(void);
void in6_rtqdrain(void);
void* nstat_idle_check(void* p0, void* p1);

extern int dlil_verbose;

struct proc proc0;
struct filedesc filedesc0;
struct plimit plimit0;
proc_t kernproc;
int cmask = CMASK;

__attribute__((visibility("default"))) bool init_proc(void) {
  kernproc = &proc0;
  kernproc->p_fd = &filedesc0;
  // Permitting 10 open files should be more than enough
  // without blowing up execution time. If you change this
  // number you probably want to change the fd enum in the
  // protobuf file.
  plimit0.pl_rlimit[RLIMIT_NOFILE].rlim_cur = 10;
  plimit0.pl_rlimit[RLIMIT_NOFILE].rlim_max = 10;
  kernproc->p_limit = &plimit0;
  filedesc0.fd_cmask = cmask;
  // Must be 0 as in bsd_init.c. kern_event.c compares against it as u_int,
  // so -1 made every fd look in range of the NULL fd_knlist.
  filedesc0.fd_knlistsize = 0;
  filedesc0.fd_knlist = NULL;
  filedesc0.fd_knhash = NULL;
  filedesc0.fd_knhashmask = 0;
  // Increase sb_max
  sb_max = 8192*1024 * 4;
  dlil_verbose = 0;
  return true;
}

int socket_wrapper(int domain, int type, int protocol, int* retval);
int close_wrapper(int fd, int* retval);

// These come last on purpose: sys/mbuf.h, which they drag in, turns m_type
// into a macro and that collides with the forward declarations above.
#include <sys/sockio.h>
#include <net/if.h>
#include <net/dlil.h>
#include <net/classq/classq.h>
#include <net/kpi_interface.h>
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/necp.h>
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>
#include <netinet/ip6.h>

void proto_input_run(void);
extern bool get_fuzzed_bool(void);

struct fuzz_tcp4_lookup_context {
  enum {
    FUZZ_TCP4_LOOKUP_OFF,
    FUZZ_TCP4_LOOKUP_INPUT,
    FUZZ_TCP4_LOOKUP_CONNECT,
  } mode;
  bool valid;
  bool input_selected;
  bool is_v6;
  struct in_addr src;
  struct in_addr dst;
  struct in6_addr src6;
  struct in6_addr dst6;
  uint16_t sport;
  uint16_t dport;
};

static struct fuzz_tcp4_lookup_context tcp4_lookup_context;

bool fuzz_pcb_lookup_should_skip(struct inpcb* inp) {
  if (tcp4_lookup_context.mode == FUZZ_TCP4_LOOKUP_OFF ||
      !tcp4_lookup_context.valid) {
    return get_fuzzed_bool();
  }

  // The hook fires for both families (in6_pcb.c includes the same shadow
  // header), so match on the pcb's own family, not the context's.
  bool pcb_v6 = (inp->inp_vflag & INP_IPV6) != 0;
  if (pcb_v6 != tcp4_lookup_context.is_v6) {
    return true;  // wrong family for this handshake: skip it
  }

  bool exact, listener;
  if (pcb_v6) {
    exact =
        IN6_ARE_ADDR_EQUAL(&inp->in6p_faddr, &tcp4_lookup_context.src6) &&
        IN6_ARE_ADDR_EQUAL(&inp->in6p_laddr, &tcp4_lookup_context.dst6) &&
        inp->inp_fport == tcp4_lookup_context.sport &&
        inp->inp_lport == tcp4_lookup_context.dport;
    listener =
        IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_faddr) && inp->inp_fport == 0 &&
        inp->inp_lport == tcp4_lookup_context.dport &&
        (IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_laddr) ||
         IN6_ARE_ADDR_EQUAL(&inp->in6p_laddr, &tcp4_lookup_context.dst6));
  } else {
    exact =
        inp->inp_faddr.s_addr == tcp4_lookup_context.src.s_addr &&
        inp->inp_laddr.s_addr == tcp4_lookup_context.dst.s_addr &&
        inp->inp_fport == tcp4_lookup_context.sport &&
        inp->inp_lport == tcp4_lookup_context.dport;
    listener =
        inp->inp_faddr.s_addr == INADDR_ANY && inp->inp_fport == 0 &&
        inp->inp_lport == tcp4_lookup_context.dport &&
        (inp->inp_laddr.s_addr == INADDR_ANY ||
         inp->inp_laddr.s_addr == tcp4_lookup_context.dst.s_addr);
  }

  if (tcp4_lookup_context.mode == FUZZ_TCP4_LOOKUP_CONNECT) {
    return !exact;
  }

  if (!tcp4_lookup_context.input_selected && (exact || listener)) {
    tcp4_lookup_context.input_selected = true;
    return false;
  }

  // After tcp_input selects its socket, nested collision checks must only
  // find an existing connected PCB with the same tuple. In particular, the
  // new child and its listener are not collisions.
  bool connected = pcb_v6 ? !IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_faddr)
                          : inp->inp_faddr.s_addr != INADDR_ANY;
  if (tcp4_lookup_context.input_selected && exact && connected) {
    return false;
  }
  return true;
}

// Only used on the handshake path, where the stack built the segment itself
// over loopback, so TCP follows the fixed IPv6 header with no extensions.
static void set_tcp6_lookup_context(struct mbuf* m) {
  struct ip6_hdr ip6_header;
  struct tcphdr tcp_header;
  if (m_pktlen(m) < sizeof(ip6_header) + sizeof(tcp_header)) {
    return;
  }
  m_copydata(m, 0, sizeof(ip6_header), &ip6_header);
  if (ip6_header.ip6_nxt != IPPROTO_TCP) {
    return;
  }
  m_copydata(m, sizeof(ip6_header), sizeof(tcp_header), &tcp_header);
  tcp4_lookup_context.is_v6 = true;
  tcp4_lookup_context.src6 = ip6_header.ip6_src;
  tcp4_lookup_context.dst6 = ip6_header.ip6_dst;
  tcp4_lookup_context.sport = tcp_header.th_sport;
  tcp4_lookup_context.dport = tcp_header.th_dport;
  tcp4_lookup_context.valid = true;
}

static void set_tcp4_lookup_context(struct mbuf* m) {
  struct ip ip_header;
  struct tcphdr tcp_header;
  tcp4_lookup_context.valid = false;
  tcp4_lookup_context.input_selected = false;
  tcp4_lookup_context.is_v6 = false;

  if (m == NULL || m_pktlen(m) < 1) {
    return;
  }
  uint8_t version;
  m_copydata(m, 0, 1, &version);
  if ((version >> 4) == 6) {
    set_tcp6_lookup_context(m);
    return;
  }
  if (m_pktlen(m) < sizeof(ip_header) + sizeof(tcp_header)) {
    return;
  }
  m_copydata(m, 0, sizeof(ip_header), &ip_header);
  if (ip_header.ip_v != IPVERSION ||
      ip_header.ip_hl < sizeof(ip_header) / sizeof(uint32_t)) {
    return;
  }
  size_t tcp_offset = (size_t)ip_header.ip_hl * sizeof(uint32_t);
  if (m_pktlen(m) < tcp_offset + sizeof(tcp_header)) {
    return;
  }
  m_copydata(m, (int)tcp_offset, sizeof(tcp_header), &tcp_header);
  tcp4_lookup_context.src = ip_header.ip_src;
  tcp4_lookup_context.dst = ip_header.ip_dst;
  tcp4_lookup_context.sport = tcp_header.th_sport;
  tcp4_lookup_context.dport = tcp_header.th_dport;
  tcp4_lookup_context.valid = true;
}

__attribute__((visibility("default"))) int connect_tcp4_for_handshake(
    int fd, const void* local_addr, const void* remote_addr,
    size_t remote_len) {
  const struct sockaddr_in* local = local_addr;
  const struct sockaddr_in* remote = remote_addr;
  tcp4_lookup_context.mode = FUZZ_TCP4_LOOKUP_CONNECT;
  tcp4_lookup_context.valid = true;
  tcp4_lookup_context.input_selected = false;
  tcp4_lookup_context.is_v6 = false;
  tcp4_lookup_context.src = remote->sin_addr;
  tcp4_lookup_context.dst = local->sin_addr;
  tcp4_lookup_context.sport = remote->sin_port;
  tcp4_lookup_context.dport = local->sin_port;
  int error = connect_wrapper(fd, (char*)remote_addr, remote_len, NULL);
  tcp4_lookup_context.mode = FUZZ_TCP4_LOOKUP_OFF;
  tcp4_lookup_context.valid = false;
  tcp4_lookup_context.input_selected = false;
  return error;
}

__attribute__((visibility("default"))) int connect_tcp6_for_handshake(
    int fd, const void* local_addr, const void* remote_addr,
    size_t remote_len) {
  const struct sockaddr_in6* local = local_addr;
  const struct sockaddr_in6* remote = remote_addr;
  tcp4_lookup_context.mode = FUZZ_TCP4_LOOKUP_CONNECT;
  tcp4_lookup_context.valid = true;
  tcp4_lookup_context.input_selected = false;
  tcp4_lookup_context.is_v6 = true;
  tcp4_lookup_context.src6 = remote->sin6_addr;
  tcp4_lookup_context.dst6 = local->sin6_addr;
  tcp4_lookup_context.sport = remote->sin6_port;
  tcp4_lookup_context.dport = local->sin6_port;
  int error = connect_wrapper(fd, (char*)remote_addr, remote_len, NULL);
  tcp4_lookup_context.mode = FUZZ_TCP4_LOOKUP_OFF;
  tcp4_lookup_context.valid = false;
  tcp4_lookup_context.input_selected = false;
  return error;
}

// necp_match_policy copies out a whole struct necp_aggregate_result, whose
// definition is not visible to the harness. Callers use this to size the
// output buffer they hand to the syscall.
__attribute__((visibility("default"))) size_t necp_aggregate_result_size(void) {
  return sizeof(struct necp_aggregate_result);
}

// The harness starts no kernel threads: kernel_thread_start is a stub. So
// every packet the stack sends out over lo0 is queued on the DLIL main input
// queue and then never delivered, which is why nothing the kernel emits has
// ever come back in. This performs the work one pass of the main input thread
// would have done, repeatedly, because delivering a segment usually makes the
// stack emit the next one. Without it a local TCP handshake can never finish
// inside a single iteration, and the queued mbufs simply leak.
static void drain_loopback_input_internal(bool tuple_aware) {
  struct dlil_main_threading_info* inpm =
      (struct dlil_main_threading_info*)dlil_main_input_thread;
  if (inpm == NULL) {
    return;
  }
  tcp4_lookup_context.mode = tuple_aware ? FUZZ_TCP4_LOOKUP_INPUT
                                         : FUZZ_TCP4_LOOKUP_OFF;
  tcp4_lookup_context.valid = false;
  tcp4_lookup_context.input_selected = false;
  struct dlil_threading_info* inp = &inpm->inp;

  // Bounded so that a stack which keeps answering itself cannot spin forever.
  for (int pass = 0; pass < 8; pass++) {
    classq_pkt_t pkt = CLASSQ_PKT_INITIALIZER(pkt);
    struct mbuf* m = NULL;
    struct mbuf* m_loop = NULL;
    uint32_t m_cnt = 0;
    uint32_t m_cnt_loop = 0;
    int proto_req;

    lck_mtx_lock(&inp->dlth_lock);
    inp->dlth_flags &= ~DLIL_INPUT_WAITING;
    proto_req = (inp->dlth_flags &
                 (DLIL_PROTO_WAITING | DLIL_PROTO_REGISTER)) != 0;
    m_cnt = qlen(&inp->dlth_pkts);
    _getq_all(&inp->dlth_pkts, &pkt, NULL, NULL, NULL);
    m = pkt.cp_mbuf;
    m_cnt_loop = qlen(&inpm->lo_rcvq_pkts);
    _getq_all(&inpm->lo_rcvq_pkts, &pkt, NULL, NULL, NULL);
    m_loop = pkt.cp_mbuf;
    inp->dlth_wtot = 0;
    lck_mtx_unlock(&inp->dlth_lock);

    if (m == NULL && m_loop == NULL && !proto_req) {
      break;
    }
    // proto_register_input only queues the registration; the input thread is
    // what actually installs it. Until this runs, proto_input has no handler
    // for PF_INET or PF_INET6 and every packet arriving over lo0 is freed,
    // so it has to happen before anything is delivered.
    if (proto_req) {
      proto_input_run();
      tcp4_lookup_context.valid = false;
      tcp4_lookup_context.input_selected = false;
    }
    if (m_loop != NULL) {
      if (tuple_aware) {
        set_tcp4_lookup_context(m_loop);
      }
      dlil_input_packet_list_extended(lo_ifp, m_loop, m_cnt_loop,
                                      IFNET_MODEL_INPUT_POLL_OFF);
    }
    if (m != NULL) {
      dlil_input_packet_list_extended(NULL, m, m_cnt,
                                      IFNET_MODEL_INPUT_POLL_OFF);
    }
  }
  tcp4_lookup_context.mode = FUZZ_TCP4_LOOKUP_OFF;
  tcp4_lookup_context.valid = false;
  tcp4_lookup_context.input_selected = false;
}

__attribute__((visibility("default"))) void drain_loopback_input(void) {
  drain_loopback_input_internal(false);
}

__attribute__((visibility("default"))) void
drain_loopback_input_for_tcp_handshake(void) {
  drain_loopback_input_internal(true);
}

// Give the loopback interface an IPv4 address plus the matching netmask.
// In a real system this comes from userland configuration, which does not
// exist in the harness, so without it there is no route to 127.0.0.1 and
// no connection can ever be established locally. Returns true if lo0 now
// owns 127.0.0.1. Interface addresses survive clear_all(), so one call is
// enough for the lifetime of the process.
__attribute__((visibility("default"))) bool configure_loopback_address(void) {
  int fd = -1;
  if (socket_wrapper(AF_INET, SOCK_DGRAM, 0, &fd) != 0 || fd < 0) {
    return false;
  }

  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  strlcpy(ifr.ifr_name, "lo0", sizeof(ifr.ifr_name));
  ifr.ifr_flags = (short)(IFF_UP | IFF_LOOPBACK | IFF_RUNNING | IFF_MULTICAST);
  ioctl_wrapper(fd, SIOCSIFFLAGS, (char*)&ifr, NULL);

  struct sockaddr_in* sin;

  memset(&ifr.ifr_ifru, 0, sizeof(ifr.ifr_ifru));
  sin = (struct sockaddr_in*)&ifr.ifr_addr;
  sin->sin_len = sizeof(*sin);
  sin->sin_family = AF_INET;
  sin->sin_addr.s_addr = htonl(0xff000000u);  // 255.0.0.0
  ioctl_wrapper(fd, SIOCSIFNETMASK, (char*)&ifr, NULL);

  memset(&ifr.ifr_ifru, 0, sizeof(ifr.ifr_ifru));
  sin = (struct sockaddr_in*)&ifr.ifr_addr;
  sin->sin_len = sizeof(*sin);
  sin->sin_family = AF_INET;
  sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  int err = ioctl_wrapper(fd, SIOCSIFADDR, (char*)&ifr, NULL);

  close_wrapper(fd, NULL);
  return err == 0;
}

// Give lo0 the IPv6 loopback address ::1, so the stack has a route for
// AF_INET6 the way configure_loopback_address does for AF_INET. loopattach()
// does not plumb IPv6, so attach the protocol first (SIOCPROTOATTACH_IN6,
// which calls in6_domifattach) and then add the address with SIOCAIFADDR_IN6.
// Returns true if lo0 now owns ::1.
__attribute__((visibility("default"))) bool configure_loopback_address_in6(void) {
  int fd = -1;
  if (socket_wrapper(AF_INET6, SOCK_DGRAM, 0, &fd) != 0 || fd < 0) {
    return false;
  }

  struct in6_aliasreq ifra;
  memset(&ifra, 0, sizeof(ifra));
  strlcpy(ifra.ifra_name, "lo0", sizeof(ifra.ifra_name));

  // Attach the IPv6 protocol to lo0. Harmless if it is already attached.
  ioctl_wrapper(fd, SIOCPROTOATTACH_IN6, (char*)&ifra, NULL);

  struct sockaddr_in6* sin6 = &ifra.ifra_addr;
  sin6->sin6_len = sizeof(*sin6);
  sin6->sin6_family = AF_INET6;
  sin6->sin6_addr = in6addr_loopback;  // ::1

  struct sockaddr_in6* mask = &ifra.ifra_prefixmask;
  mask->sin6_len = sizeof(*mask);
  mask->sin6_family = AF_INET6;
  memset(&mask->sin6_addr, 0xff, sizeof(mask->sin6_addr));  // /128

  ifra.ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;
  ifra.ifra_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;

  int err = ioctl_wrapper(fd, SIOCAIFADDR_IN6, (char*)&ifra, NULL);

  close_wrapper(fd, NULL);
  return err == 0;
}

extern void kmem_mb_reset_pages(void);
extern void fake_time_reset(void);
extern void fake_uuid_reset(void);
extern void zone_tracking_reset(void);
extern char fake_thread[];
extern char fake_uthread[];

__attribute__((visibility("default"))) void clear_all() {
  // Deliver or free whatever the stack left queued on the loopback input
  // queue. Nothing else ever empties it, so without this the mbufs leak.
  drain_loopback_input();

  // Run kernel timers to drain pending work.
  inpcb_timeout(NULL, NULL);
  key_timehandler();
  frag_timeout();
  nd6_slowtimo();
  nd6_timeout();
  in6_tmpaddrtimer();
  mp_timeout();
  igmp_timeout();
  // Reap time-wait and dead TCP pcbs before the clock is wound back, or
  // their 2MSL deadline is never reached and they carry into the next input.
  tcp_fuzzer_reap();
  tcp_fuzzer_reset();
  frag6_timeout();
  mld_timeout();

  // Drop cloned host routes (C4). The rtqtimo timers delete them only once
  // rt_expire passes, an hour out, which the fake clock never reaches. The
  // drain variants delete every RTPRF_OURS route regardless of expiry; a
  // route a pcb still references is not RTPRF_OURS and is left alone.
  in6_rtqdrain();
  in_rtqdrain();

  nstat_idle_check(NULL, NULL);
  domain_timeout(NULL);

  // C5: Interface address cleanup.
  // Addresses added via SIOCAIFADDR_IN6_64 persist across iterations.
  // A full cleanup would require tracking added addresses and removing
  // them via SIOCDIFADDR_IN6. For now, the route timer expiry above
  // handles the most common side-effect (stale routes to added addresses).

  // Drop PF states and rules and stop PF, so that one iteration cannot leave
  // filtering state behind for the next one. The previous call went through a
  // socket ioctl on descriptor 0 and never reached PF at all.
  pf_flush_all();

  // Reset subsystem state for next iteration.
  kmem_mb_reset_pages();
  fake_time_reset();
  fake_uuid_reset();
  zone_tracking_reset();
  memset(fake_thread, 0, 8192);
  memset(fake_uthread, 0, 4096);
}

#define MT_DATA 1

// Create a chained mbuf from data split at the given offsets.
// This enables fuzzing of m_pullup, m_pulldown, m_copydata at mbuf boundaries.
// Uses mbuf KPI functions (mbuf_setnext, mbuf_pkthdr_setlen) to avoid
// directly accessing struct mbuf internals which are opaque in this TU.
extern errno_t mbuf_setnext(mbuf_t mbuf, mbuf_t next);
extern void mbuf_pkthdr_setlen(mbuf_t mbuf, size_t len);
extern void m_freem(mbuf_t m);

__attribute__((visibility("default"))) mbuf_t get_mbuf_data_chained(
    const char* data, size_t size, int pktflags,
    const uint32_t* split_points, int num_splits) {
  // Split points are absolute offsets into the packet. The old code treated
  // them as segment lengths, which meant the chain could stop short of the
  // packet while the header still claimed the full length.
  enum { MAX_SPLITS = 16 };
  size_t offsets[MAX_SPLITS];
  int count = 0;

  if (split_points != NULL && size > 1) {
    for (int i = 0; i < num_splits && count < MAX_SPLITS; i++) {
      size_t off = (size_t)(split_points[i] % size);
      if (off == 0) {
        continue;
      }
      int duplicate = 0;
      for (int j = 0; j < count; j++) {
        if (offsets[j] == off) {
          duplicate = 1;
          break;
        }
      }
      if (!duplicate) {
        offsets[count++] = off;
      }
    }
    // Sort so the segments come out in packet order.
    for (int i = 1; i < count; i++) {
      size_t v = offsets[i];
      int j = i - 1;
      while (j >= 0 && offsets[j] > v) {
        offsets[j + 1] = offsets[j];
        j--;
      }
      offsets[j + 1] = v;
    }
  }

  if (count == 0) {
    mbuf_t m = (mbuf_t)mbuf_create((const uint8_t*)data, size, true, false,
                                   MT_DATA, pktflags);
    if (m != NULL) {
      mbuf_pkthdr_setrcvif(m, lo_ifp);
    }
    return m;
  }

  mbuf_t head = NULL;
  mbuf_t prev = NULL;
  size_t start = 0;
  for (int i = 0; i <= count; i++) {
    size_t end = (i < count) ? offsets[i] : size;
    size_t seg_len = end - start;
    mbuf_t seg = (mbuf_t)mbuf_create((const uint8_t*)(data + start), seg_len,
                                     head == NULL, false, MT_DATA,
                                     head == NULL ? pktflags : 0);
    if (seg == NULL) {
      // Never hand back a chain shorter than the length in its header: the
      // stack would read past the data it was given.
      if (head != NULL) {
        m_freem(head);
      }
      return NULL;
    }
    if (head == NULL) {
      head = seg;
    } else {
      mbuf_setnext(prev, seg);
    }
    prev = seg;
    start = end;
  }

  mbuf_pkthdr_setlen(head, size);
  mbuf_pkthdr_setrcvif(head, lo_ifp);
  return head;
}

__attribute__((visibility("default"))) struct mbuf* get_mbuf_data(
    const char* data, size_t size, int pktflags) {
  struct mbuf* mbuf_data =
      mbuf_create((const uint8_t*)data, size, true, false, MT_DATA, pktflags);
  if (mbuf_data == NULL) {
    // The allocation can fail, and the receive interface must not be stored
    // through a null pointer before the caller gets a chance to check.
    return NULL;
  }

  // The receive interface is always loopback: the harness never creates an
  // ethernet interface, so there is nothing else to point at.
  mbuf_pkthdr_setrcvif((mbuf_t)mbuf_data, lo_ifp);
  return mbuf_data;
}

extern unsigned long ioctls[];
extern int num_ioctls;

__attribute__((visibility("default"))) bool initialize_network() {
  kernel_startup_bootstrap();
  kernel_startup_initialize_upto(STARTUP_SUB_EARLY_BOOT);
  extern void *socket_zone;
  assert(socket_zone != NULL);
  mcache_init();
  mbinit();
  eventhandler_init();
  dlil_init();
  socketinit();
  domaininit();
  loopattach();
  ether_family_init();
  tcp_cc_init();
  net_init_run();
  int res = necp_init();
  assert(!res);

  // Install the pending protocol input registrations. proto_register_input
  // only queues them for the DLIL input thread, which never runs here.
  drain_loopback_input();

  // Make DIOCSTART reachable; see the comment on this function.
  pf_enable_purge_thread();

  // Content filter (#183): set gate variables so cfil_sock_attach proceeds.
  // cfil_init() can't be called directly — it requires kctl infrastructure.
  // Setting cfil_active_count > 0 bypasses the "no active filters" gate.
  {
    extern uint32_t cfil_active_count;
    cfil_active_count = 1;
  }

  return true;
}

__attribute__((visibility("default"))) void ip_input_wrapper(void* m) {
  ip_input((mbuf_t)m);
}

__attribute__((visibility("default"))) void ip6_input_wrapper(void* m) {
  ip6_input((mbuf_t)m);
}
