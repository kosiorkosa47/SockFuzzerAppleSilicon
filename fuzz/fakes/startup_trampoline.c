/*
 * Copyright 2024 Google LLC
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the "License"). You may not use this file except in
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
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#include <kern/assert.h>
#include <kern/startup.h>
#include <stdbool.h>
#include <stddef.h>

#define FUZZ_MAX_STARTUP_ENTRIES 4096

struct fuzz_startup_entry {
  startup_subsystem_id_t subsystem;
  startup_rank_t rank;
  void (*function)(const void *);
  const void *argument;
  uint32_t registration_order;
};

static struct fuzz_startup_entry
    fuzz_startup_entries[FUZZ_MAX_STARTUP_ENTRIES];
static uint32_t fuzz_startup_entry_count;
static uint32_t fuzz_startup_next_entry;
static bool fuzz_startup_entries_sorted;
static bool fuzz_startup_overflow;

startup_subsystem_id_t startup_phase = STARTUP_SUB_NONE;

void
fuzz_startup_register(startup_subsystem_id_t subsystem, startup_rank_t rank,
                      void (*function)(const void *), const void *argument)
{
  if (fuzz_startup_entry_count == FUZZ_MAX_STARTUP_ENTRIES) {
    fuzz_startup_overflow = true;
    return;
  }

  struct fuzz_startup_entry *entry =
      &fuzz_startup_entries[fuzz_startup_entry_count];
  entry->subsystem = subsystem;
  entry->rank = rank;
  entry->function = function;
  entry->argument = argument;
  entry->registration_order = fuzz_startup_entry_count;
  ++fuzz_startup_entry_count;
}

static bool
fuzz_startup_entry_precedes(const struct fuzz_startup_entry *left,
                            const struct fuzz_startup_entry *right)
{
  if (left->subsystem != right->subsystem) {
    return left->subsystem < right->subsystem;
  }
  if (left->rank != right->rank) {
    return left->rank < right->rank;
  }
  return left->registration_order < right->registration_order;
}

static void
fuzz_startup_sort_entries(void)
{
  for (uint32_t index = 1; index < fuzz_startup_entry_count; ++index) {
    struct fuzz_startup_entry entry = fuzz_startup_entries[index];
    uint32_t destination = index;
    while (destination > 0 &&
           fuzz_startup_entry_precedes(
               &entry, &fuzz_startup_entries[destination - 1])) {
      fuzz_startup_entries[destination] =
          fuzz_startup_entries[destination - 1];
      --destination;
    }
    fuzz_startup_entries[destination] = entry;
  }
  fuzz_startup_entries_sorted = true;
}

void
kernel_startup_initialize_upto(startup_subsystem_id_t subsystem)
{
  assert(!fuzz_startup_overflow);
  if (subsystem <= startup_phase) {
    return;
  }
  if (!fuzz_startup_entries_sorted) {
    fuzz_startup_sort_entries();
  }

  while (fuzz_startup_next_entry < fuzz_startup_entry_count) {
    struct fuzz_startup_entry *entry =
        &fuzz_startup_entries[fuzz_startup_next_entry];
    if (entry->subsystem > subsystem) {
      break;
    }
    startup_phase = entry->subsystem - 1;
    if (entry->function != NULL) {
      entry->function(entry->argument);
    }
    ++fuzz_startup_next_entry;
  }

  startup_phase = subsystem;
}
