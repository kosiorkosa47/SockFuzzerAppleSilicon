#ifndef FUZZ_INCLUDE_NETINET_IN_PCB_H_
#define FUZZ_INCLUDE_NETINET_IN_PCB_H_

#include_next <netinet/in_pcb.h>

#if SOCKFUZZER_PCB_LOOKUP_HOOK
#include <stdbool.h>

bool fuzz_pcb_lookup_should_skip(struct inpcb* inp);
#define get_fuzzed_bool() fuzz_pcb_lookup_should_skip(inp)
#endif

#endif
