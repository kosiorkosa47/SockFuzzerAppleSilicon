# Copyright 2021 Google LLC
#
# @APPLE_OSREFERENCE_LICENSE_HEADER_START@
#
# This file contains Original Code and/or Modifications of Original Code
# as defined in and that are subject to the Apple Public Source License
# Version 2.0 (the 'License'). You may not use this file except in
# compliance with the License. The rights granted to you under the License
# may not be used to create, or enable the creation or redistribution of,
# unlawful or unlicensed copies of an Apple operating system, or to
# circumvent, violate, or enable the circumvention or violation of, any
# terms of an Apple operating system software license agreement.
#
# Please obtain a copy of the License at
# http://www.opensource.apple.com/apsl/ and read it before using this file.
#
# The Original Code and all software distributed under the License are
# distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
# EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
# INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
# Please see the License for the specific language governing rights and
# limitations under the License.
#
# @APPLE_OSREFERENCE_LICENSE_HEADER_END@

cmake_minimum_required(VERSION 3.16)
project(sockfuzzer LANGUAGES C CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Force colorful output (Clang-specific)
if(CMAKE_C_COMPILER_ID MATCHES "Clang")
  add_compile_options(-fcolor-diagnostics)
endif()

# --------------------------------------------------------------------------
# XNU kernel defines — these are the same as what Apple's kernel build uses
# but adapted for userspace fuzzing.
# --------------------------------------------------------------------------

# Keep x86-originated defines even on arm64: the XNU source we compile
# was prepared with x86 stubs and the BUILD/obj tree is DEBUG_X86_64.
# The LIBXNU_BUILD=1 flag lets the stub layer handle architecture
# differences.  We keep PAL_I386 / X86_64 / __X86_64__ because the
# header tree (meta_features.h, config headers) was generated for that
# configuration and removing them causes cascading include failures.
set(XNU_DEFINES
    -DAH_ALL_CRYPTO
    -DAPPLE
    -DBINDFS
    -DCONFIG_32BIT_TELEMETRY
    -DCONFIG_AIO_MAX=90
    -DCONFIG_AIO_PROCESS_MAX=16
    -DCONFIG_AIO_THREAD_COUNT=4
    -DCONFIG_APPLEDOUBLE
    -DCONFIG_ARCADE
    -DCONFIG_ATM
    -DCONFIG_BACKGROUND_QUEUE
    -DCONFIG_BASESYSTEMROOT
    -DCONFIG_BLOCKS
    -DCONFIG_COALITIONS
    -DCONFIG_CODE_DECRYPTION
    -DCONFIG_COREDUMP
    -DCONFIG_CSR
    -DCONFIG_DATALESS_FILES
    -DCONFIG_DELAY_IDLE_SLEEP
    -DCONFIG_DEV_KMEM
    -DCONFIG_DIRTYSTATUS_TRACKING
    -DCONFIG_DYNAMIC_CODE_SIGNING
    -DCONFIG_EXT_RESOLVER
    -DCONFIG_FIRMLINKS
    -DCONFIG_GZALLOC
    -DCONFIG_ICMP_BANDLIM=250
    -DCONFIG_IMAGEBOOT_CHUNKLIST
    -DCONFIG_IMG4
    -DCONFIG_IMGSRC_ACCESS
    -DCONFIG_IOSCHED
    -DCONFIG_IPC_TABLE_ENTRIES_STEPS=256
    -DCONFIG_KAS_INFO
    -DCONFIG_KDP_INTERACTIVE_DEBUGGING
    -DCONFIG_KEC_FIPS
    -DCONFIG_KEXT_BASEMENT
    -DCONFIG_KEYPAGE_WP
    -DCONFIG_KN_HASHSIZE=64
    -DCONFIG_LEDGER_INTERVAL_MAX
    -DCONFIG_LTABLE_DEBUG
    -DCONFIG_LTABLE_STATS
    -DCONFIG_MACF_LAZY_VNODE_LABELS
    -DCONFIG_MACH_APPROXIMATE_TIME
    -DCONFIG_MACH_BRIDGE_SEND_TIME
    -DCONFIG_MAXVIFS=32
    -DCONFIG_MAX_CLUSTERS=8
    -DCONFIG_MAX_THREADS=500
    -DCONFIG_MBUF_JUMBO
    -DCONFIG_MCA
    -DCONFIG_MEMORYSTATUS
    -DCONFIG_MFCTBLSIZ=256
    -DCONFIG_MIN_NBUF=256
    -DCONFIG_MIN_NIOBUF=128
    -DCONFIG_MNT_ROOTSNAP
    -DCONFIG_MNT_SUID
    -DCONFIG_MOUNT_PREBOOTRECOVERY
    -DCONFIG_MOUNT_VM
    -DCONFIG_MSG_BSIZE=CONFIG_MSG_BSIZE_DEV
    -DCONFIG_MSG_BSIZE_DEV=131072
    -DCONFIG_MSG_BSIZE_REL=16384
    -DCONFIG_MTRR
    -DCONFIG_NC_HASH=4096
    -DCONFIG_NETBOOT
    -DCONFIG_NFS_GSS
    -DCONFIG_NMBCLUSTERS=512
    -DCONFIG_PERSONAS
    -DCONFIG_PHYS_WRITE_ACCT
    -DCONFIG_PROC_UDATA_STORAGE
    -DCONFIG_PROC_UUID_POLICY
    -DCONFIG_PROTECT
    -DCONFIG_REQUIRES_U32_MUNGING
    -DCONFIG_ROSV_STARTUP
    -DCONFIG_SCHED_GRRR
    -DCONFIG_SCHED_GRRR_CORE
    -DCONFIG_SCHED_MULTIQ
    -DCONFIG_SCHED_PROTO
    -DCONFIG_SCHED_SFI
    -DCONFIG_SCHED_TIMESHARE_CORE
    -DCONFIG_SCHED_TRADITIONAL
    -DCONFIG_SEARCHFS
    -DCONFIG_SETUID
    -DCONFIG_SLEEP
    -DCONFIG_SYSDIAGNOSE
    -DCONFIG_TASKWATCH
    -DCONFIG_TASK_MAX=1024
    -DCONFIG_TASK_ZONE_INFO
    -DCONFIG_TCBHASHSIZE=4096
    -DCONFIG_TELEMETRY
    -DCONFIG_THREAD_MAX=2560
    -DCONFIG_VFS_NAMES=4096
    -DCONFIG_VMX
    -DCONFIG_VNGUARD
    -DCONFIG_VNODES=263168
    -DCONFIG_VOLFS
    -DCONFIG_VSPRINTF
    -DCONFIG_WAITQ_DEBUG
    -DCONFIG_WAITQ_STATS
    -DCONFIG_WORKLOOP_DEBUG
    -DCONFIG_WORKQUEUE
    -DCONFIG_THREAD_GROUPS=0
    -DCONFIG_XNUPOST
    -DCONFIG_ZALLOC_SEQUESTER
    -DCONFIG_ZCACHE
    -DCONFIG_ZLEAKS
    -DCONFIG_ZLEAK_ALLOCATION_MAP_NUM=16384
    -DCONFIG_ZLEAK_TRACE_MAP_NUM=8192
    -DCONFIG_ZONE_MAP_MIN=120586240
    -DCONTENT_FILTER
    -DCOPYOUT_SHIM
    -DCRYPTO_SHA2
    -DFLOW_DIVERT
    -DHYPERVISOR
    -DICMP_BANDLIM
    -DIFNET_INPUT_SANITY_CHK
    -DIMPORTANCE_TRACE
    -DIOKIT
    -DIOKITCPP
    -DIOKITSTATS
    -DIOTRACKING
    -DIPSEC
    -DIPSEC_ESP
    -DKERNEL
    -DKERNEL_PRIVATE
    -DKPC
    -DKPERF
    -DLIBKERNCPP
    -DLOCK_STATS
    -DLP64
    -DMACH
    -DMACH_BSD
    -DMACH_KERNEL
    -DMULTICAST
    -DMULTIPATH
    -DNAMEDSTREAMS
    -DNECP
    -DNO_DIRECT_RPC
    -DNULLFS
    -DOLD_SEMWAIT_SIGNAL
    -DPACKET_MANGLER
    -DPAGE_SIZE_FIXED
    -DPAL_I386
    -DPGO
    -DPLATFORM_MacOSX
    -DPRIVATE
    -DPSYNCH
    -DSERIAL_CONSOLE
    -DTRAFFIC_MGT
    -DVIDEO_CONSOLE
    -DVM_PRESSURE_EVENTS
    -DX86_64
    -DXNU_KERNEL_PRIVATE
    -DXNU_KERN_EVENT_DATA_IS_VLA
    # SAFETY NOTE: _FORTIFY_SOURCE is disabled because the XNU code declares
    # its own copyin/copyout functions which conflict with the fortified
    # variants (copyin_chk/copyout_chk) that glibc/libssp would generate.
    # Since AddressSanitizer is always enabled and provides strictly stronger
    # buffer overflow detection, the practical impact is minimal.  Enabling
    # FORTIFY_SOURCE requires implementing the _chk variants in the stubs.
    -D_FORTIFY_SOURCE=0
    # section_keywords.h is overridden in fuzz/include/libkern/ to make
    # SECURITY_READ_ONLY_LATE variables writable (needed for zone init).
    -D__MACHO__=1
    -D__X86_64__
    -D__x86_64__
    -Dvolatile=__volatile
    -Dx86_64
    # On arm64 macOS, undefine the arm architecture macros so that the
    # machine/ dispatch headers (boolean.h, atomic.h, etc.) resolve
    # to the i386/x86_64 variants that exist in the BUILD tree.
    -U__arm64__
    -U__arm__
    -U__aarch64__
    -U__ARM_ARCH
    -URC_ENABLE_XNU_PRODUCT_INFO_FILTER
    # Force-include meta_features.h into every translation unit.  This header
    # is generated by the XNU build system and provides feature-flag #defines
    # (CONFIG_*, MACH_*, etc.) that nearly every XNU source file depends on.
    # Using -include avoids patching every XNU .c file to add an explicit
    # #include -- the same approach Apple's own build uses.
    -include
    meta_features.h
)

set(BSD_DEFINES
    -DBSD_BUILD
    -DBSD_KERNEL_PRIVATE
    -DCONFIG_SERIAL_KDP
    -DDEBUG
    -DDRIVER_PRIVATE
    -DENCRYPTED_SWAP
    -DHIBERNATION
    -DKERNEL_BUILD
    -DLP64_DEBUG=0
    -DMACH_KDP
    -DMACH_MP_DEBUG
    -DTARGET_OS_IPHONE=0
    -DTARGET_OS_OSX=1
    -DXNU_TARGET_OS_OSX=1
    -D_KERNEL_BUILD
    -D__APPLE__
)

set(OSFMK_DEFINES
    -DBOND
    -DCONFIG_AUDIT
    -DCONFIG_FSE
    -DCONFIG_IMAGEBOOT
    -DCONFIG_MACF
    -DCONFIG_MACF_SOCKET_SUBSET
    -DCONFIG_NFS4
    -DCONFIG_TRIGGERS
    -DDEVFS
    -DDUMMYNET
    -DFDESC
    -DFIFO
    -DFS_COMPRESSION
    -DIF_BRIDGE
    -DIF_FAKE
    -DIF_HEADLESS
    -DINET
    -DKERNEL_BASE_OFFSET=0x100000
    -DMACH_COMPAT
    -DMACH_FASTLINK
    -DMACH_KERNEL_PRIVATE
    -DMPTCP
    -DNETWORKING
    -DNFSCLIENT
    -DNFSSERVER
    -DPF
    -DPFLOG
    -DQUOTA
    -DSENDFILE
    -DSIXLOWPAN
    -DSOCKETS
    -DSYSV_MSG
    -DSYSV_SEM
    -DSYSV_SHM
    -DVLAN
    -DXNU_TARGET_OS_OSX
    -DZLIB
)

set(SAN_DEFINES -DKASAN_OFFSET=0 -DKASAN_SCALE=0)

set(XNU_WARNING_FLAGS
    -Wno-address-of-packed-member -Wno-unguarded-availability-new
    -Wno-pointer-to-int-cast -Wno-format -Wunused-result
    # Downgrade -Werror to warnings-only for the port — there are many
    # benign warnings (int-conversion, implicit-function-declaration, etc.)
    # that the original x86-Linux build did not trigger.
    -Wno-error
)

set(XNU_C_FLAGS
    -nostdinc
    -fno-builtin
    -fno-common
    -fsigned-bitfields
    -g
    -fblocks
    -O1
    -ftrivial-auto-var-init=pattern
    # Suppress warnings that are pervasive in XNU source when compiled
    # on arm64-darwin with a modern Clang (16+).
    -Wno-int-conversion
    -Wno-incompatible-pointer-types
    -Wno-implicit-function-declaration
    -Wno-implicit-int
    -Wno-unused-function
    -Wno-unused-variable
    -Wno-unused-but-set-variable
    -Wno-compare-distinct-pointer-types
    -Wno-enum-conversion
    -Wno-sometimes-uninitialized
    -Wno-tautological-constant-out-of-range-compare
    -Wno-pointer-sign
    -Wno-missing-declarations
    -Wno-strict-prototypes
    -Wno-deprecated-non-prototype
    -Wno-incompatible-function-pointer-types
    -Wno-incompatible-library-redeclaration
    -Wno-knr-promoted-parameter
    # Use gnu11 to avoid C23 strict errors on implicit decls
    -std=gnu11
    ${XNU_WARNING_FLAGS}
    ${XNU_DEFINES}
)

set(BSD_SOURCES
    third_party/xnu/bsd/conf/param.c
    third_party/xnu/bsd/kern/kern_asl.c
    third_party/xnu/bsd/kern/kern_control.c
    third_party/xnu/bsd/kern/kern_descrip.c
    third_party/xnu/bsd/kern/kern_event.c
    third_party/xnu/bsd/kern/kern_newsysctl.c
    third_party/xnu/bsd/kern/kern_sig.c
    third_party/xnu/bsd/kern/kern_subr.c
    third_party/xnu/bsd/kern/kpi_mbuf.c
    third_party/xnu/bsd/kern/kpi_socket.c
    third_party/xnu/bsd/kern/kpi_socketfilter.c
    third_party/xnu/bsd/kern/subr_eventhandler.c
    third_party/xnu/bsd/kern/sys_domain.c
    third_party/xnu/bsd/kern/sys_generic.c
    third_party/xnu/bsd/kern/sys_pipe.c
    third_party/xnu/bsd/kern/sys_reason.c
    third_party/xnu/bsd/kern/sys_socket.c
    third_party/xnu/bsd/kern/uipc_domain.c
    third_party/xnu/bsd/kern/uipc_mbuf.c
    third_party/xnu/bsd/kern/uipc_mbuf2.c
    third_party/xnu/bsd/kern/uipc_proto.c
    third_party/xnu/bsd/kern/uipc_socket.c
    third_party/xnu/bsd/kern/uipc_socket2.c
    third_party/xnu/bsd/kern/uipc_syscalls.c
    third_party/xnu/bsd/kern/uipc_usrreq.c
    third_party/xnu/bsd/kern/vsock_domain.c
    third_party/xnu/bsd/net/bpf.c
    third_party/xnu/bsd/net/bpf_filter.c
    third_party/xnu/bsd/net/classq/classq.c
    third_party/xnu/bsd/net/classq/classq_fq_codel.c
    third_party/xnu/bsd/net/classq/classq_sfb.c
    third_party/xnu/bsd/net/classq/classq_subr.c
    third_party/xnu/bsd/net/content_filter.c
    third_party/xnu/bsd/net/devtimer.c
    third_party/xnu/bsd/net/dlil.c
    third_party/xnu/bsd/net/ether_inet6_pr_module.c
    third_party/xnu/bsd/net/ether_if_module.c
    third_party/xnu/bsd/net/ether_inet_pr_module.c
    third_party/xnu/bsd/net/flowadv.c
    third_party/xnu/bsd/net/frame802154.c
    third_party/xnu/bsd/net/if.c
    third_party/xnu/bsd/net/if_6lowpan.c
    third_party/xnu/bsd/net/if_bridge.c
    third_party/xnu/bsd/net/if_bond.c
    third_party/xnu/bsd/net/if_fake.c
    third_party/xnu/bsd/net/if_llatbl.c
    third_party/xnu/bsd/net/if_llreach.c
    third_party/xnu/bsd/net/if_loop.c
    third_party/xnu/bsd/net/if_low_power_mode.c
    third_party/xnu/bsd/net/if_headless.c
    third_party/xnu/bsd/net/if_ipsec.c
    third_party/xnu/bsd/net/if_ports_used.c
    third_party/xnu/bsd/net/if_stf.c
    third_party/xnu/bsd/net/if_vlan.c
    third_party/xnu/bsd/net/init.c
    third_party/xnu/bsd/net/kpi_interface.c
    third_party/xnu/bsd/net/kpi_interfacefilter.c
    third_party/xnu/bsd/net/kpi_protocol.c
    third_party/xnu/bsd/net/linkaddr.c
    third_party/xnu/bsd/net/multicast_list.c
    third_party/xnu/bsd/net/ndrv.c
    third_party/xnu/bsd/net/net_str_id.c
    third_party/xnu/bsd/net/pf.c
    third_party/xnu/bsd/net/pf_if.c
    third_party/xnu/bsd/net/pf_ioctl.c
    third_party/xnu/bsd/net/pf_norm.c
    third_party/xnu/bsd/net/pf_osfp.c
    third_party/xnu/bsd/net/pf_pbuf.c
    third_party/xnu/bsd/net/pf_ruleset.c
    third_party/xnu/bsd/net/pf_table.c
    third_party/xnu/bsd/net/sixxlowpan.c
    third_party/xnu/bsd/net/necp.c
    third_party/xnu/bsd/net/necp_client.c
    third_party/xnu/bsd/net/net_perf.c
    third_party/xnu/bsd/net/network_agent.c
    third_party/xnu/bsd/net/ntstat.c
    third_party/xnu/bsd/net/pktap.c
    third_party/xnu/bsd/net/pktsched/pktsched.c
    third_party/xnu/bsd/net/pktsched/pktsched_fq_codel.c
    third_party/xnu/bsd/net/pktsched/pktsched_netem.c
    third_party/xnu/bsd/net/raw_cb.c
    third_party/xnu/bsd/net/raw_usrreq.c
    third_party/xnu/bsd/net/radix.c
    third_party/xnu/bsd/net/route.c
    third_party/xnu/bsd/net/rtsock.c
    third_party/xnu/bsd/netinet/flow_divert.c
    third_party/xnu/bsd/netinet/in.c
    third_party/xnu/bsd/netinet/igmp.c
    third_party/xnu/bsd/netinet/in_arp.c
    third_party/xnu/bsd/netinet/in_cksum.c
    third_party/xnu/bsd/netinet/in_mcast.c
    third_party/xnu/bsd/netinet/in_pcb.c
    third_party/xnu/bsd/netinet/in_pcblist.c
    third_party/xnu/bsd/netinet/in_proto.c
    third_party/xnu/bsd/netinet/in_rmx.c
    third_party/xnu/bsd/netinet/in_tclass.c
    third_party/xnu/bsd/netinet/ip_dummynet.c
    third_party/xnu/bsd/netinet/ip_ecn.c
    third_party/xnu/bsd/netinet/ip_encap.c
    third_party/xnu/bsd/netinet/ip_icmp.c
    third_party/xnu/bsd/netinet/ip_id.c
    third_party/xnu/bsd/netinet/ip_input.c
    third_party/xnu/bsd/netinet/ip_output.c
    third_party/xnu/bsd/netinet/kpi_ipfilter.c
    third_party/xnu/bsd/netinet/mp_pcb.c
    third_party/xnu/bsd/netinet/mp_proto.c
    third_party/xnu/bsd/netinet/mptcp.c
    third_party/xnu/bsd/netinet/mptcp_opt.c
    third_party/xnu/bsd/netinet/mptcp_subr.c
    third_party/xnu/bsd/netinet/mptcp_timer.c
    third_party/xnu/bsd/netinet/mptcp_usrreq.c
    third_party/xnu/bsd/netinet/raw_ip.c
    third_party/xnu/bsd/netinet/tcp_cache.c
    third_party/xnu/bsd/netinet/tcp_cc.c
    third_party/xnu/bsd/netinet/tcp_cubic.c
    third_party/xnu/bsd/netinet/tcp_input.c
    third_party/xnu/bsd/netinet/tcp_ledbat.c
    third_party/xnu/bsd/netinet/tcp_log.c
    third_party/xnu/bsd/netinet/tcp_newreno.c
    third_party/xnu/bsd/netinet/tcp_output.c
    third_party/xnu/bsd/netinet/tcp_sack.c
    third_party/xnu/bsd/netinet/tcp_subr.c
    third_party/xnu/bsd/netinet/tcp_timer.c
    third_party/xnu/bsd/netinet/tcp_usrreq.c
    third_party/xnu/bsd/netinet/udp_usrreq.c
    third_party/xnu/bsd/netinet6/ah_core.c
    third_party/xnu/bsd/netinet6/ah_input.c
    third_party/xnu/bsd/netinet6/ah_output.c
    third_party/xnu/bsd/netinet6/dest6.c
    third_party/xnu/bsd/netinet6/esp_chachapoly.c
    third_party/xnu/bsd/netinet6/esp_core.c
    third_party/xnu/bsd/netinet6/esp_input.c
    third_party/xnu/bsd/netinet6/esp_output.c
    third_party/xnu/bsd/netinet6/esp_rijndael.c
    third_party/xnu/bsd/netinet6/frag6.c
    third_party/xnu/bsd/netinet6/icmp6.c
    third_party/xnu/bsd/netinet6/in6.c
    third_party/xnu/bsd/netinet6/in6_cga.c
    third_party/xnu/bsd/netinet6/in6_cksum.c
    third_party/xnu/bsd/netinet6/in6_ifattach.c
    third_party/xnu/bsd/netinet6/in6_mcast.c
    third_party/xnu/bsd/netinet6/in6_pcb.c
    third_party/xnu/bsd/netinet6/in6_proto.c
    third_party/xnu/bsd/netinet6/in6_rmx.c
    third_party/xnu/bsd/netinet6/in6_src.c
    third_party/xnu/bsd/netinet6/ipsec.c
    third_party/xnu/bsd/netinet6/ip6_forward.c
    third_party/xnu/bsd/netinet6/ip6_input.c
    third_party/xnu/bsd/netinet6/ip6_id.c
    third_party/xnu/bsd/netinet6/ip6_output.c
    third_party/xnu/bsd/netinet6/mld6.c
    third_party/xnu/bsd/netinet6/nd6.c
    third_party/xnu/bsd/netinet6/nd6_nbr.c
    third_party/xnu/bsd/netinet6/nd6_prproxy.c
    third_party/xnu/bsd/netinet6/nd6_rti.c
    third_party/xnu/bsd/netinet6/nd6_rtr.c
    third_party/xnu/bsd/netinet6/nd6_send.c
    third_party/xnu/bsd/netinet6/raw_ip6.c
    third_party/xnu/bsd/netinet6/route6.c
    third_party/xnu/bsd/netinet6/scope6.c
    third_party/xnu/bsd/netinet6/udp6_output.c
    third_party/xnu/bsd/netinet6/udp6_usrreq.c
    third_party/xnu/bsd/netkey/key.c
    third_party/xnu/bsd/netkey/keydb.c
    third_party/xnu/bsd/netkey/keysock.c
    third_party/xnu/libkern/crypto/corecrypto_chacha20poly1305.c
    third_party/xnu/libkern/crypto/corecrypto_des.c
    third_party/xnu/libkern/crypto/corecrypto_sha2.c
    third_party/xnu/libkern/gen/OSAtomicOperations.c
    third_party/xnu/libkern/os/refcnt.c
    third_party/xnu/security/mac_system.c
    fuzz/api/syscall_wrappers.c
    fuzz/api/ioctl.c
    fuzz/api/backend.c
    fuzz/fakes/stubs.c
    fuzz/fakes/thread.c
    fuzz/fakes/fake_impls.c
    fuzz/fakes/mbuf.c
)

set(XNU_INCLUDES
    .
    # Our stub headers must come BEFORE EXPORT_HDRS so that e.g.
    # i386/proc_reg.h resolves to the arm64-safe stub instead of the
    # real x86-asm version.
    fuzz/include
    third_party/xnu
    third_party/xnu/BUILD/obj/EXPORT_HDRS/bsd
    third_party/xnu/BUILD/obj/EXPORT_HDRS/osfmk
    third_party/xnu/BUILD/obj/EXPORT_HDRS/libkern
    third_party/xnu/BUILD/obj/EXPORT_HDRS/iokit
    third_party/xnu/BUILD/obj/EXPORT_HDRS/pexpert
    third_party/xnu/BUILD/obj/EXPORT_HDRS/libsa
    third_party/xnu/BUILD/obj/EXPORT_HDRS/security
    third_party/xnu/BUILD/obj/EXPORT_HDRS/san
    third_party/xnu/EXTERNAL_HEADERS
)

# --------------------------------------------------------------------------
# Sanitizer / fuzzer flags
# --------------------------------------------------------------------------
if(DEFINED ENV{SANITIZER})
  if($ENV{SANITIZER} MATCHES "address")
    set(FUZZER_SOURCES fuzz/fakes/san.c
                       third_party/xnu/san/kasan-memintrinsics.c
    )
    set(FUZZER_DEFINES -DKASAN=1)
  endif()
else()
  set(FUZZER_CXX_FLAGS -fsanitize=address,fuzzer-no-link -mllvm -asan-globals=0)
  set(FUZZER_LD_FLAGS -fsanitize=address,fuzzer)
  set(ENV{LIB_FUZZING_ENGINE} -fsanitize=fuzzer)
  set(FUZZER_SOURCES fuzz/fakes/san.c third_party/xnu/san/kasan-memintrinsics.c)
  set(FUZZER_DEFINES -DKASAN=1)
endif()

# These must be built separately due to header incompatibilities
# NOTE: startup.c is excluded on Apple because it pulls in deeply nested
# i386 headers (cpu_data.h, pmap.h, thread.h) that contain x86 inline
# assembly. The startup code is the kernel bootstrap path and is never
# executed by the fuzzer anyway — all needed symbols from startup.c are
# stubbed in osfmk_stubs.c.
if(APPLE)
  set(OSFMK_SOURCES
    fuzz/fakes/zalloc.c
    fuzz/fakes/osfmk_stubs.c 
  )
else()
  set(OSFMK_SOURCES
    fuzz/fakes/zalloc.c
    fuzz/fakes/osfmk_stubs.c 
    third_party/xnu/osfmk/kern/startup.c
  )
endif()

set(BSD_INCLUDES
    ${XNU_INCLUDES} third_party/xnu/BUILD/obj/DEBUG_X86_64/bsd/DEBUG
    third_party/xnu/bsd third_party/xnu/san
)

set(OSFMK_INCLUDES
    ${XNU_INCLUDES} third_party/xnu/BUILD/obj/DEBUG_X86_64/osfmk/DEBUG
    third_party/xnu/osfmk third_party/xnu/osfmk/libsa
)

# --------------------------------------------------------------------------
# XNU object libraries (BSD + OSFMK)
# --------------------------------------------------------------------------

# We use an object library so we can include the osfmk objects which require
# different build flags into the libxnu library
add_library(osfmk OBJECT ${OSFMK_SOURCES})
target_include_directories(osfmk PRIVATE ${OSFMK_INCLUDES})
set_property(TARGET osfmk PROPERTY C_VISIBILITY_PRESET hidden)
set_property(TARGET osfmk PROPERTY POSITION_INDEPENDENT_CODE ON)
target_compile_options(
  osfmk PRIVATE ${XNU_C_FLAGS} ${OSFMK_DEFINES} ${FUZZER_DEFINES}
                ${FUZZER_CXX_FLAGS} -DLIBXNU_BUILD=1
)

add_library(bsd OBJECT ${BSD_SOURCES} ${FUZZER_SOURCES})
set_property(TARGET bsd PROPERTY C_VISIBILITY_PRESET hidden)
set_property(TARGET bsd PROPERTY POSITION_INDEPENDENT_CODE ON)

target_include_directories(bsd PRIVATE ${BSD_INCLUDES})
target_compile_options(
  bsd PRIVATE ${XNU_C_FLAGS} ${BSD_DEFINES} ${SAN_DEFINES} -DLIBXNU_BUILD=1
              ${FUZZER_DEFINES} ${FUZZER_CXX_FLAGS}
)

# --------------------------------------------------------------------------
# On macOS we build a static archive instead of using ld.lld -r + objcopy.
# On Linux we keep the original relocatable object approach.
# --------------------------------------------------------------------------
if(APPLE)
  # On macOS, combine all XNU objects into a single relocatable .o file,
  # then localize (hide) all symbols except the ones explicitly exported
  # by the fuzzing API. This prevents XNU kernel implementations of
  # sigaction, printf, read, write, ioctl, etc. from overriding the libc
  # versions that libFuzzer and protobuf depend on.
  #
  # Step 1: ld -r to merge all objects
  # Step 2: nmedit -s (keep globals listed in file, localize rest)
  find_program(NMEDIT nmedit REQUIRED)

  # Copy the exported symbols list into the build directory.
  configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/xnu_exported_symbols.txt
    ${CMAKE_CURRENT_BINARY_DIR}/xnu_exported_symbols.txt
    COPYONLY
  )

  add_custom_command(
    OUTPUT libxnu_relocatable.o
    COMMAND ld -r -arch ${CMAKE_SYSTEM_PROCESSOR} $<TARGET_OBJECTS:bsd> $<TARGET_OBJECTS:osfmk> -o libxnu_relocatable_raw.o
    COMMAND nmedit -s ${CMAKE_CURRENT_BINARY_DIR}/xnu_exported_symbols.txt -p libxnu_relocatable_raw.o -o libxnu_relocatable.o
    DEPENDS $<TARGET_OBJECTS:bsd> $<TARGET_OBJECTS:osfmk> ${CMAKE_CURRENT_BINARY_DIR}/xnu_exported_symbols.txt
    COMMAND_EXPAND_LISTS
    VERBATIM
    COMMENT "Creating relocatable XNU object with localized symbols"
  )
  add_custom_target(xnu_obj DEPENDS libxnu_relocatable.o)
else()
  find_program(LLD ld.lld REQUIRED)
  find_program(OBJCOPY objcopy REQUIRED)

  add_custom_command(
    OUTPUT libxnu_relocatable.o
    COMMAND ${LLD} -r $<TARGET_OBJECTS:bsd> $<TARGET_OBJECTS:osfmk> -o libxnu_relocatable.o && ${OBJCOPY} --localize-hidden libxnu_relocatable.o
    DEPENDS $<TARGET_OBJECTS:bsd> $<TARGET_OBJECTS:osfmk>
    COMMAND_EXPAND_LISTS
    VERBATIM
  )
endif()

# --------------------------------------------------------------------------
# Protobuf — find system-installed protobuf v34
# --------------------------------------------------------------------------
find_package(Protobuf REQUIRED)
# Protobuf and generated header directories are scoped to targets that need
# them (protobuf-mutator, net_fuzzer) rather than polluting all targets.

# --------------------------------------------------------------------------
# libprotobuf-mutator — updated to work with protobuf v34
# --------------------------------------------------------------------------
add_library(
  protobuf-mutator STATIC
  third_party/libprotobuf-mutator/src/binary_format.cc
  third_party/libprotobuf-mutator/src/mutator.cc
  third_party/libprotobuf-mutator/src/text_format.cc
  third_party/libprotobuf-mutator/src/utf8_fix.cc
  third_party/libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.cc
  third_party/libprotobuf-mutator/src/libfuzzer/libfuzzer_mutator.cc
)

target_include_directories(
  protobuf-mutator PRIVATE
  third_party/libprotobuf-mutator
  ${Protobuf_INCLUDE_DIRS}
  ${CMAKE_CURRENT_BINARY_DIR}
)

# Protobuf v34 / abseil requires at least C++17 for absl headers; the old
# -std=c++11 breaks immediately on absl/strings/string_view.h.
target_compile_options(protobuf-mutator PRIVATE -std=c++17
  -Wno-deprecated-declarations -Wno-error)

target_link_libraries(protobuf-mutator ${Protobuf_LIBRARIES})

# --------------------------------------------------------------------------
# libbsd (strlcat/strlcpy) — only needed on Linux, macOS has them natively
# --------------------------------------------------------------------------
if(NOT APPLE)
  add_library(libbsd STATIC
    third_party/libbsd/src/strlcat.c
    third_party/libbsd/src/strlcpy.c)
endif()

# --------------------------------------------------------------------------
# Generate protobuf sources from the .proto file
# --------------------------------------------------------------------------
protobuf_generate_cpp(NET_PROTO_SRCS NET_PROTO_HDRS fuzz/net_fuzzer.proto)

# --------------------------------------------------------------------------
# net_fuzzer executable
# --------------------------------------------------------------------------
if(APPLE)
  # startup_trampoline.c is compiled without -nostdinc so it can use
  # macOS system headers for Mach-O section introspection.
  add_library(startup_trampoline OBJECT fuzz/fakes/startup_trampoline.c)
  target_compile_options(startup_trampoline PRIVATE -g ${FUZZER_CXX_FLAGS})

  add_executable(
    net_fuzzer fuzz/net_fuzzer.cc ${NET_PROTO_SRCS} ${NET_PROTO_HDRS}
    ${CMAKE_CURRENT_BINARY_DIR}/libxnu_relocatable.o
    $<TARGET_OBJECTS:startup_trampoline>
  )
  add_dependencies(net_fuzzer bsd osfmk xnu_obj)
  target_link_libraries(
    net_fuzzer
    ${FUZZER_LD_FLAGS}
    $ENV{LIB_FUZZING_ENGINE}
    protobuf-mutator
    ${Protobuf_LIBRARIES}
    # SAFETY NOTE: -undefined dynamic_lookup allows unresolved symbols at
    # link time, which is dangerous in general because a missing stub could
    # silently bind to a system function at runtime.  This is mitigated here
    # by the preceding nmedit step, which localizes ALL XNU symbols except
    # the explicit export list (cmake/xnu_exported_symbols.txt).  Only the
    # fuzzer API callbacks (get_fuzzed_bytes, get_fuzzed_bool, etc.) remain
    # unresolved — these are provided by the C++ fuzzer harness and are
    # guaranteed to be present in the final executable.
    "-Wl,-undefined,dynamic_lookup"
  )
else()
  add_executable(
    net_fuzzer fuzz/net_fuzzer.cc ${NET_PROTO_SRCS} ${NET_PROTO_HDRS} libxnu_relocatable.o
  )
  add_dependencies(net_fuzzer bsd)
  target_link_libraries(
    net_fuzzer
    ${FUZZER_LD_FLAGS}
    $ENV{LIB_FUZZING_ENGINE}
    protobuf-mutator
    ${Protobuf_LIBRARIES}
    pthread
    libbsd
  )
endif()

target_include_directories(net_fuzzer PRIVATE
  third_party/libprotobuf-mutator
  ${Protobuf_INCLUDE_DIRS}
  ${CMAKE_CURRENT_BINARY_DIR}
)
# Fuzzer harness gets stricter warnings than XNU source.
target_compile_options(
  net_fuzzer PRIVATE -g -std=c++17 -Wall -Wextra
                     -Wno-unused-parameter -Wno-sign-compare
                     -Wno-address-of-packed-member
                     -Wno-deprecated-declarations
                     -Wno-missing-field-initializers
                     ${FUZZER_CXX_FLAGS}
)

# --------------------------------------------------------------------------
# Unit tests
# --------------------------------------------------------------------------
if(NOT DEFINED ENV{SANITIZER})
  enable_testing()
  add_executable(fake_impls_test fuzz/fakes/fake_impls_test.cc)
  target_compile_options(fake_impls_test PRIVATE -std=c++17 -g)
  target_include_directories(fake_impls_test PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
  if(APPLE)
    target_link_libraries(fake_impls_test
      ${CMAKE_CURRENT_BINARY_DIR}/libxnu_relocatable.o
      $<TARGET_OBJECTS:startup_trampoline>
      protobuf-mutator ${Protobuf_LIBRARIES}
      "-Wl,-undefined,dynamic_lookup"
    )
    add_dependencies(fake_impls_test xnu_obj)
  else()
    target_link_libraries(fake_impls_test
      libxnu_relocatable.o protobuf-mutator ${Protobuf_LIBRARIES} libbsd pthread
    )
  endif()
  add_test(NAME fake_impls_test COMMAND fake_impls_test)
endif()

# --------------------------------------------------------------------------
# Coverage builds — Linux and macOS
# --------------------------------------------------------------------------
if(NOT DEFINED ENV{SANITIZER} AND APPLE)
  # macOS coverage build using Homebrew LLVM
  add_library(osfmk_cov OBJECT ${OSFMK_SOURCES})
  target_include_directories(osfmk_cov PRIVATE ${OSFMK_INCLUDES})
  set_property(TARGET osfmk_cov PROPERTY C_VISIBILITY_PRESET hidden)
  set_property(TARGET osfmk_cov PROPERTY POSITION_INDEPENDENT_CODE ON)
  target_compile_options(
    osfmk_cov PRIVATE ${XNU_C_FLAGS} ${OSFMK_DEFINES} -DLIBXNU_BUILD=1
                      -fprofile-instr-generate -fcoverage-mapping
  )

  add_library(bsd_cov OBJECT ${BSD_SOURCES} ${FUZZER_SOURCES})
  set_property(TARGET bsd_cov PROPERTY C_VISIBILITY_PRESET hidden)
  set_property(TARGET bsd_cov PROPERTY POSITION_INDEPENDENT_CODE ON)
  target_include_directories(bsd_cov PRIVATE ${BSD_INCLUDES})
  target_compile_options(
    bsd_cov PRIVATE ${XNU_C_FLAGS} ${BSD_DEFINES} ${SAN_DEFINES} -DLIBXNU_BUILD=1
                    ${FUZZER_DEFINES} -fprofile-instr-generate -fcoverage-mapping
  )

  configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/xnu_exported_symbols.txt
    ${CMAKE_CURRENT_BINARY_DIR}/xnu_cov_exported_symbols.txt COPYONLY
  )

  add_custom_command(
    OUTPUT libxnu_cov_relocatable.o
    COMMAND ld -r -arch ${CMAKE_SYSTEM_PROCESSOR} $<TARGET_OBJECTS:bsd_cov> $<TARGET_OBJECTS:osfmk_cov> -o libxnu_cov_relocatable_raw.o
    COMMAND nmedit -s ${CMAKE_CURRENT_BINARY_DIR}/xnu_cov_exported_symbols.txt -p libxnu_cov_relocatable_raw.o -o libxnu_cov_relocatable.o
    DEPENDS $<TARGET_OBJECTS:bsd_cov> $<TARGET_OBJECTS:osfmk_cov>
    COMMAND_EXPAND_LISTS VERBATIM
    COMMENT "Creating coverage-instrumented XNU object"
  )
  add_custom_target(xnu_cov_obj DEPENDS libxnu_cov_relocatable.o)

  add_library(startup_trampoline_cov OBJECT fuzz/fakes/startup_trampoline.c)
  target_compile_options(startup_trampoline_cov PRIVATE -g
    -fprofile-instr-generate -fcoverage-mapping)

  add_executable(
    net_cov fuzz/net_fuzzer.cc ${NET_PROTO_SRCS} ${NET_PROTO_HDRS}
    ${CMAKE_CURRENT_BINARY_DIR}/libxnu_cov_relocatable.o
    $<TARGET_OBJECTS:startup_trampoline_cov>
  )
  add_dependencies(net_cov bsd_cov osfmk_cov xnu_cov_obj)
  target_include_directories(net_cov PRIVATE
    third_party/libprotobuf-mutator ${Protobuf_INCLUDE_DIRS}
    ${CMAKE_CURRENT_BINARY_DIR}
  )
  target_compile_options(
    net_cov PRIVATE -g -std=c++17 -Wno-error -Wno-address-of-packed-member
                    -Wno-deprecated-declarations
                    -fprofile-instr-generate -fcoverage-mapping
  )
  target_link_libraries(
    net_cov
    -fsanitize=fuzzer
    -fprofile-instr-generate -fcoverage-mapping
    protobuf-mutator ${Protobuf_LIBRARIES}
    "-Wl,-undefined,dynamic_lookup"
  )
endif()

if(NOT DEFINED ENV{SANITIZER} AND NOT APPLE)
  add_library(osfmk_cov OBJECT ${OSFMK_SOURCES})
  target_include_directories(osfmk_cov PRIVATE ${OSFMK_INCLUDES})
  set_target_properties(osfmk_cov PROPERTIES C_VISIBILITY_PRESET hidden)
  set_property(TARGET osfmk_cov PROPERTY POSITION_INDEPENDENT_CODE ON)
  target_compile_options(
    osfmk_cov PRIVATE ${XNU_C_FLAGS} ${OSFMK_DEFINES} -DLIBXNU_BUILD=1
                      -fprofile-instr-generate -fcoverage-mapping
  )

  add_library(bsd_cov STATIC ${BSD_SOURCES} $<TARGET_OBJECTS:osfmk_cov>)
  target_include_directories(bsd_cov PRIVATE ${BSD_INCLUDES})
  set_target_properties(bsd_cov PROPERTIES C_VISIBILITY_PRESET hidden)
  target_compile_options(
    bsd_cov
    PRIVATE ${XNU_C_FLAGS} ${BSD_DEFINES} ${SAN_DEFINES} -DLIBXNU_BUILD=1
            -fprofile-instr-generate -fcoverage-mapping
  )

  add_custom_command(
    OUTPUT libxnu_cov_relocatable.o
    COMMAND ${LLD} -r $<TARGET_OBJECTS:bsd_cov> $<TARGET_OBJECTS:osfmk_cov> -o libxnu_cov_relocatable.o && ${OBJCOPY} --localize-hidden libxnu_cov_relocatable.o
    DEPENDS $<TARGET_OBJECTS:bsd_cov> $<TARGET_OBJECTS:osfmk_cov>
    COMMAND_EXPAND_LISTS
  )

  add_executable(
    net_cov fuzz/net_fuzzer.cc ${NET_PROTO_SRCS} ${NET_PROTO_HDRS} libxnu_cov_relocatable.o
  )
  add_dependencies(net_cov bsd_cov osfmk_cov)
  target_include_directories(net_cov PRIVATE
    third_party/libprotobuf-mutator
    ${Protobuf_INCLUDE_DIRS}
    ${CMAKE_CURRENT_BINARY_DIR}
  )
  target_compile_options(
    net_cov PRIVATE -g -std=c++17 -Wno-error -Wno-address-of-packed-member
                    -fprofile-instr-generate -fcoverage-mapping
  )
  target_link_libraries(
    net_cov
    -fsanitize=fuzzer
    -fprofile-instr-generate
    -fcoverage-mapping
    protobuf-mutator
    ${Protobuf_LIBRARIES}
    libbsd
    pthread
    -Wl,--exclude-libs,ALL
  )
endif()
