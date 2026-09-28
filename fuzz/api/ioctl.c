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

#include "bsd/net/if.h"
#include "bsd/net/network_agent.h"
#include "bsd/net/pfvar.h"
#include "bsd/netinet6/in6_var.h"
#include "bsd/netinet6/nd6.h"
#include "bsd/sys/fcntl.h"
#include "bsd/sys/sockio.h"

#define SIOCGIFORDER _IOWR('i', 179, struct if_order)

__attribute__((visibility("default"))) unsigned long ioctls[281] = {
    SIOCSHIWAT,
    SIOCGHIWAT,
    SIOCSLOWAT,
    SIOCGLOWAT,
    SIOCATMARK,
    SIOCSPGRP,
    SIOCGPGRP,
    SIOCSIFADDR,
    OSIOCGIFADDR,
    SIOCSIFDSTADDR,
    OSIOCGIFDSTADDR,
    SIOCSIFFLAGS,
    SIOCGIFFLAGS,
    OSIOCGIFBRDADDR,
    SIOCSIFBRDADDR,
    OSIOCGIFCONF,
    OSIOCGIFCONF32,
    OSIOCGIFCONF64,
    OSIOCGIFNETMASK,
    SIOCSIFNETMASK,
    SIOCGIFMETRIC,
    SIOCSIFMETRIC,
    SIOCDIFADDR,
    SIOCAIFADDR,
    SIOCGIFADDR,
    SIOCGIFDSTADDR,
    SIOCGIFBRDADDR,
    SIOCGIFCONF,
    SIOCGIFCONF32,
    SIOCGIFCONF64,
    SIOCGIFNETMASK,
    SIOCADDMULTI,
    SIOCDELMULTI,
    SIOCGIFMTU,
    SIOCSIFMTU,
    SIOCGIFPHYS,
    SIOCSIFPHYS,
    SIOCSIFMEDIA,
    SIOCGIFMEDIA,
    SIOCGIFMEDIA32,
    SIOCGIFMEDIA64,
    SIOCSIFGENERIC,
    SIOCGIFGENERIC,
    SIOCSIFLLADDR,
    SIOCGIFSTATUS,
    SIOCSIFPHYADDR,
    SIOCGIFPSRCADDR,
    SIOCGIFPDSTADDR,
    SIOCDIFPHYADDR,
    SIOCGIFDEVMTU,
    SIOCSIFALTMTU,
    SIOCPROTOATTACH,
    SIOCPROTODETACH,
    SIOCIFCREATE,
    SIOCIFDESTROY,
    SIOCSIFVLAN,
    SIOCGIFVLAN,
    SIOCSETVLAN,
    SIOCGETVLAN,
    SIOCSIFDEVMTU,
    SIOCIFGCLONERS,
    SIOCIFGCLONERS32,
    SIOCIFGCLONERS64,
    SIOCGIFASYNCMAP,
    SIOCSIFASYNCMAP,
    SIOCSIFKPI,
    SIOCGIFKPI,
    SIOCGIFWAKEFLAGS,
    SIOCGIFGETRTREFCNT,
    SIOCGIFLINKQUALITYMETRIC,
    SIOCSETROUTERMODE,
    SIOCGIFEFLAGS,
    SIOCSIFDESC,
    SIOCGIFDESC,
    SIOCSIFLINKPARAMS,
    SIOCGIFLINKPARAMS,
    SIOCGIFQUEUESTATS,
    SIOCSIFTHROTTLE,
    SIOCGIFTHROTTLE,
    SIOCGASSOCIDS,
    SIOCGCONNIDS,
    SIOCGCONNINFO,
    SIOCGASSOCIDS32,
    SIOCGASSOCIDS64,
    SIOCGCONNIDS32,
    SIOCGCONNIDS64,
    SIOCGCONNINFO32,
    SIOCGCONNINFO64,
    SIOCSCONNORDER,
    SIOCGCONNORDER,
    SIOCSIFLOG,
    SIOCGIFLOG,
    SIOCGIFDELEGATE,
    SIOCGIFLLADDR,
    SIOCGIFTYPE,
    SIOCGIFEXPENSIVE,
    SIOCSIFEXPENSIVE,
    SIOCGIF2KCL,
    SIOCSIF2KCL,
    SIOCGSTARTDELAY,
    SIOCAIFAGENTID,
    SIOCDIFAGENTID,
    SIOCGIFAGENTIDS,
    SIOCGIFAGENTDATA,
    SIOCGIFAGENTIDS32,
    SIOCGIFAGENTIDS64,
    SIOCGIFAGENTDATA32,
    SIOCGIFAGENTDATA64,
    SIOCSIFINTERFACESTATE,
    SIOCGIFINTERFACESTATE,
    SIOCSIFPROBECONNECTIVITY,
    SIOCGIFPROBECONNECTIVITY,
    SIOCGIFFUNCTIONALTYPE,
    SIOCSIFNETSIGNATURE,
    SIOCGIFNETSIGNATURE,
    SIOCGECNMODE,
    SIOCSECNMODE,
    SIOCSIFORDER,
    SIOCGIFORDER,
    SIOCSQOSMARKINGMODE,
    SIOCSFASTLANECAPABLE,
    SIOCSQOSMARKINGENABLED,
    SIOCSFASTLEENABLED,
    SIOCGQOSMARKINGMODE,
    SIOCGQOSMARKINGENABLED,
    SIOCSIFTIMESTAMPENABLE,
    SIOCSIFTIMESTAMPDISABLE,
    SIOCGIFTIMESTAMPENABLED,
    SIOCSIFDISABLEOUTPUT,
    SIOCGIFAGENTLIST,
    SIOCGIFAGENTLIST32,
    SIOCGIFAGENTLIST64,
    SIOCSIFLOWINTERNET,
    SIOCGIFLOWINTERNET,
    SIOCGIFNAT64PREFIX,
    SIOCSIFNAT64PREFIX,
    SIOCGIFNEXUS,
    SIOCSIFADDR_IN6,
    SIOCGIFADDR_IN6,
    SIOCSIFDSTADDR_IN6,
    SIOCSIFNETMASK_IN6,
    SIOCGIFDSTADDR_IN6,
    SIOCGIFNETMASK_IN6,
    SIOCDIFADDR_IN6,
    SIOCAIFADDR_IN6,
    SIOCAIFADDR_IN6_32,
    SIOCAIFADDR_IN6_64,
    SIOCSIFPHYADDR_IN6,
    SIOCSIFPHYADDR_IN6_32,
    SIOCSIFPHYADDR_IN6_64,
    SIOCGIFPSRCADDR_IN6,
    SIOCGIFPDSTADDR_IN6,
    SIOCGIFAFLAG_IN6,
    SIOCGDRLST_IN6,
    SIOCGDRLST_IN6_32,
    SIOCGDRLST_IN6_64,
    SIOCGPRLST_IN6,
    SIOCGPRLST_IN6_32,
    SIOCGPRLST_IN6_64,
    OSIOCGIFINFO_IN6,
    SIOCGIFINFO_IN6,
    SIOCSNDFLUSH_IN6,
    SIOCGNBRINFO_IN6,
    SIOCGNBRINFO_IN6_32,
    SIOCGNBRINFO_IN6_64,
    SIOCSPFXFLUSH_IN6,
    SIOCSRTRFLUSH_IN6,
    SIOCGIFALIFETIME_IN6,
    SIOCSIFALIFETIME_IN6,
    SIOCGIFSTAT_IN6,
    SIOCGIFSTAT_ICMP6,
    SIOCSDEFIFACE_IN6,
    SIOCGDEFIFACE_IN6,
    SIOCSDEFIFACE_IN6_32,
    SIOCSDEFIFACE_IN6_64,
    SIOCGDEFIFACE_IN6_32,
    SIOCGDEFIFACE_IN6_64,
    SIOCSIFINFO_FLAGS,
    SIOCSSCOPE6,
    SIOCGSCOPE6,
    SIOCGSCOPE6DEF,
    SIOCSIFPREFIX_IN6,
    SIOCGIFPREFIX_IN6,
    SIOCDIFPREFIX_IN6,
    SIOCAIFPREFIX_IN6,
    SIOCCIFPREFIX_IN6,
    SIOCSGIFPREFIX_IN6,
    SIOCAADDRCTL_POLICY,
    SIOCDADDRCTL_POLICY,
    SIOCPROTOATTACH_IN6,
    SIOCPROTOATTACH_IN6_32,
    SIOCPROTOATTACH_IN6_64,
    SIOCPROTODETACH_IN6,
    SIOCLL_START,
    SIOCLL_START_32,
    SIOCLL_START_64,
    SIOCLL_STOP,
    SIOCAUTOCONF_START,
    SIOCAUTOCONF_STOP,
    SIOCDRADD_IN6,
    SIOCDRADD_IN6_32,
    SIOCDRADD_IN6_64,
    SIOCDRDEL_IN6,
    SIOCDRDEL_IN6_32,
    SIOCDRDEL_IN6_64,
    SIOCSETROUTERMODE_IN6,
    SIOCLL_CGASTART,
    SIOCLL_CGASTART_32,
    SIOCLL_CGASTART_64,
    SIOCGIFCGAPREP_IN6,
    SIOCSIFCGAPREP_IN6,
    DIOCSTART,
    DIOCSTOP,
    DIOCADDRULE,
    DIOCGETSTARTERS,
    DIOCGETRULES,
    DIOCGETRULE,
    DIOCSTARTREF,
    DIOCSTOPREF,
    DIOCCLRSTATES,
    DIOCGETSTATE,
    DIOCSETSTATUSIF,
    DIOCGETSTATUS,
    DIOCCLRSTATUS,
    DIOCNATLOOK,
    DIOCSETDEBUG,
    DIOCGETSTATES,
    DIOCCHANGERULE,
    DIOCINSERTRULE,
    DIOCDELETERULE,
    DIOCSETTIMEOUT,
    DIOCGETTIMEOUT,
    DIOCADDSTATE,
    DIOCCLRRULECTRS,
    DIOCGETLIMIT,
    DIOCSETLIMIT,
    DIOCKILLSTATES,
    DIOCSTARTALTQ,
    DIOCSTOPALTQ,
    DIOCADDALTQ,
    DIOCGETALTQS,
    DIOCGETALTQ,
    DIOCCHANGEALTQ,
    DIOCGETQSTATS,
    DIOCBEGINADDRS,
    DIOCADDADDR,
    DIOCGETADDRS,
    DIOCGETADDR,
    DIOCCHANGEADDR,
    DIOCGETRULESETS,
    DIOCGETRULESET,
    DIOCRCLRTABLES,
    DIOCRADDTABLES,
    DIOCRDELTABLES,
    DIOCRGETTABLES,
    DIOCRGETTSTATS,
    DIOCRCLRTSTATS,
    DIOCRCLRADDRS,
    DIOCRADDADDRS,
    DIOCRDELADDRS,
    DIOCRSETADDRS,
    DIOCRGETADDRS,
    DIOCRGETASTATS,
    DIOCRCLRASTATS,
    DIOCRTSTADDRS,
    DIOCRSETTFLAGS,
    DIOCRINADEFINE,
    DIOCOSFPFLUSH,
    DIOCOSFPADD,
    DIOCOSFPGET,
    DIOCXBEGIN,
    DIOCXCOMMIT,
    DIOCXROLLBACK,
    DIOCGETSRCNODES,
    DIOCCLRSRCNODES,
    DIOCSETHOSTID,
    DIOCIGETIFACES,
    DIOCSETIFFLAG,
    DIOCCLRIFFLAG,
    DIOCKILLSRCNODES,
    DIOCGIFSPEED,
};

__attribute__((visibility("default"))) const int num_ioctls =
    sizeof(ioctls) / sizeof(unsigned long);

// Export these enums so they are accessible outside libxnu.
__attribute__((visibility("default"))) const unsigned long siocaifaddr_in6_64 =
    SIOCAIFADDR_IN6_64;
__attribute__((visibility("default"))) const unsigned long siocsifflags =
    SIOCSIFFLAGS;
__attribute__((visibility("default"))) const unsigned long siocsifmtu_val =
    SIOCSIFMTU;
__attribute__((visibility("default"))) const unsigned long siocaddmulti_val =
    SIOCADDMULTI;
__attribute__((visibility("default"))) const unsigned long siocdelmulti_val =
    SIOCDELMULTI;
__attribute__((visibility("default"))) const unsigned long siocprotoattach_val =
    SIOCPROTOATTACH;
__attribute__((visibility("default"))) const unsigned long siocprotodetach_val =
    SIOCPROTODETACH;
__attribute__((visibility("default"))) const unsigned long siocsifaddr_val =
    SIOCSIFADDR;
__attribute__((visibility("default"))) const unsigned long diocstart_val =
    DIOCSTART;
__attribute__((visibility("default"))) const unsigned long diocstop_val =
    DIOCSTOP;
__attribute__((visibility("default"))) const unsigned long siocsetroutermode_val =
    SIOCSETROUTERMODE;
__attribute__((visibility("default"))) const unsigned long siocsifvlan_val =
    SIOCSIFVLAN;
__attribute__((visibility("default"))) const unsigned long diocaddrule_val =
    DIOCADDRULE;
__attribute__((visibility("default"))) const unsigned long diocchangerule_val =
    DIOCCHANGERULE;
__attribute__((visibility("default"))) const unsigned long diockillstates_val =
    DIOCKILLSTATES;

// --- Item 10: PF ioctl bridge ---
//
// PF is normally reached through ioctls on /dev/pf. This harness has no
// device layer and no /dev, so PF ioctls sent through an ordinary socket fd
// were handed to soioctl, rejected, and never reached PF at all. That is why
// the rule fields in the grammar had no effect and a sentinel pointer was
// good enough. These entry points call pfioctl directly, which is exactly
// what the character device switch would do. A device ioctl is handed a
// pointer the syscall layer has already copied into the kernel, so the
// structures are built here, in the one translation unit that can see
// pfvar.h, and passed through as they are.

extern struct proc* kernproc;
int pfioctl(dev_t dev, u_long cmd, caddr_t addr, int flags, struct proc* p);

// Flat description of a PF rule, so that net_fuzzer.cc can express one
// without including pfvar.h. Keep in sync with fuzz/api/pf_bridge_types.h
// users, that is, only backend.h declares these.
struct fuzz_pf_rule_spec {
  char ifname[16];
  uint32_t ioc_action;  /* pfioc_rule.action, the PF_CHANGE_* selector */
  uint32_t ticket;
  uint32_t pool_ticket;
  uint32_t nr;
  uint32_t rule_action; /* pf_rule.action, PF_PASS / PF_DROP / ... */
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

static void fuzz_pf_fill_addr(struct pf_addr_wrap* wrap,
                              union pf_rule_xport* xport,
                              const uint8_t addr[16], uint16_t port) {
  wrap->type = PF_ADDR_ADDRMASK;
  memcpy(&wrap->v.a.addr, addr, sizeof(wrap->v.a.addr));
  memset(&wrap->v.a.mask, 0xff, sizeof(wrap->v.a.mask));
  if (port != 0) {
    xport->range.port[0] = htons(port);
    xport->range.port[1] = htons(port);
    xport->range.op = PF_OP_EQ;
  }
}

__attribute__((visibility("default"))) int pf_ioctl_rule(
    unsigned long cmd, const struct fuzz_pf_rule_spec* spec) {
  struct pfioc_rule pr;

  memset(&pr, 0, sizeof(pr));
  pr.action = spec->ioc_action;
  pr.ticket = spec->ticket;
  pr.pool_ticket = spec->pool_ticket;
  pr.nr = spec->nr;
  /* Empty anchor means the main ruleset. */

  pr.rule.action = (u_int8_t)spec->rule_action;
  pr.rule.direction = (u_int8_t)spec->direction;
  pr.rule.af = (sa_family_t)spec->af;
  pr.rule.proto = (u_int8_t)spec->proto;
  pr.rule.rule_flag = spec->rule_flag;
  pr.rule.keep_state = spec->keep_state;
  pr.rule.quick = spec->quick;
  strlcpy(pr.rule.ifname, spec->ifname, sizeof(pr.rule.ifname));
  fuzz_pf_fill_addr(&pr.rule.src.addr, &pr.rule.src.xport, spec->src_addr,
                    spec->src_port);
  fuzz_pf_fill_addr(&pr.rule.dst.addr, &pr.rule.dst.xport, spec->dst_addr,
                    spec->dst_port);

  return pfioctl(0, cmd, (caddr_t)&pr, FREAD | FWRITE, kernproc);
}

__attribute__((visibility("default"))) int pf_ioctl_kill_states(
    unsigned long cmd, const struct fuzz_pf_kill_spec* spec) {
  struct pfioc_state_kill psk;

  memset(&psk, 0, sizeof(psk));
  psk.psk_af = (sa_family_t)spec->af;
  psk.psk_proto = (u_int8_t)spec->proto;
  strlcpy(psk.psk_ifname, spec->ifname, sizeof(psk.psk_ifname));
  fuzz_pf_fill_addr(&psk.psk_src.addr, &psk.psk_src.xport, spec->src_addr,
                    spec->src_port);
  fuzz_pf_fill_addr(&psk.psk_dst.addr, &psk.psk_dst.xport, spec->dst_addr,
                    spec->dst_port);

  return pfioctl(0, cmd, (caddr_t)&psk, FREAD | FWRITE, kernproc);
}

// PF refuses to start unless its purge thread exists, and this harness starts
// no kernel threads at all (kernel_thread_start is a stub), so DIOCSTART could
// only ever return ENOMEM and the whole PF data path stayed unreachable. The
// pointer is compared against NULL in three places and never dereferenced, so
// a sentinel is enough. States still get cleared explicitly in pf_flush_all,
// which is what the purge thread would otherwise do over time.
__attribute__((visibility("default"))) void pf_enable_purge_thread(void) {
  if (pf_purge_thread == NULL) {
    pf_purge_thread = (struct thread*)(void*)&pf_purge_thread;
  }
}

// DIOCSTART and DIOCSTOP take no payload.
__attribute__((visibility("default"))) int pf_ioctl_no_payload(
    unsigned long cmd) {
  return pfioctl(0, cmd, NULL, FREAD | FWRITE, kernproc);
}

// Drop every PF state and turn PF off again. Called during teardown so that
// one iteration cannot leave rules or states behind for the next one.
__attribute__((visibility("default"))) void pf_flush_all(void) {
  struct fuzz_pf_kill_spec clear;

  memset(&clear, 0, sizeof(clear));
  pf_ioctl_kill_states(DIOCCLRSTATES, &clear);
  pf_ioctl_no_payload(DIOCSTOP);
}
