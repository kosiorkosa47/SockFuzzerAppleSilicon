/*
 * Copyright 2026 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// A deterministic single-threaded clock and timer queue for the XNU fakes.

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <kern/clock.h>
#include <kern/thread_call.h>
#include <sys/time.h>

#define FAKE_THREAD_CALL_LIMIT 4096
#define FAKE_FUNCTION_CALL_LIMIT 1024
#define FAKE_TIMEOUT_LIMIT 1024
#define FAKE_CALLBACKS_PER_ADVANCE 256
#define FAKE_COMMAND_INTERVAL_NS 10000000ULL
#define FAKE_CALENDAR_EPOCH_SECONDS 1700000000ULL

struct thread_call {
  thread_call_func_t function;
  thread_call_param_t parameter0;
  thread_call_param_t parameter1;
  uint64_t deadline;
  uint64_t sequence;
  bool allocated;
  bool pending;
  bool running;
  bool free_after_run;
};

struct fake_function_call {
  thread_call_func_t function;
  thread_call_param_t parameter;
  uint64_t deadline;
  uint64_t sequence;
  bool pending;
  bool running;
};

struct fake_timeout {
  void (*function)(void *);
  void *argument;
  uint64_t deadline;
  uint64_t sequence;
  bool pending;
  bool running;
};

static struct thread_call g_thread_calls[FAKE_THREAD_CALL_LIMIT];
static struct fake_function_call g_function_calls[FAKE_FUNCTION_CALL_LIMIT];
static struct fake_timeout g_timeouts[FAKE_TIMEOUT_LIMIT];
static uint64_t g_timer_sequence;
static bool g_dispatching;

uint64_t g_fake_time_counter = 1000000ULL;

extern int hz;

static uint64_t
fake_add_saturating(uint64_t left, uint64_t right)
{
  if (UINT64_MAX - left < right) {
    return UINT64_MAX;
  }
  return left + right;
}

static uint64_t
fake_multiply_saturating(uint64_t left, uint64_t right)
{
  if (left != 0 && right > UINT64_MAX / left) {
    return UINT64_MAX;
  }
  return left * right;
}

static uint64_t
fake_next_sequence(void)
{
  if (++g_timer_sequence == 0) {
    ++g_timer_sequence;
  }
  return g_timer_sequence;
}

static bool
fake_thread_call_valid(thread_call_t call)
{
  uintptr_t address = (uintptr_t)call;
  uintptr_t first = (uintptr_t)&g_thread_calls[0];
  uintptr_t last = (uintptr_t)&g_thread_calls[FAKE_THREAD_CALL_LIMIT];

  if (address < first || address >= last ||
      (address - first) % sizeof(g_thread_calls[0]) != 0) {
    return false;
  }
  return call->allocated;
}

static thread_call_t
fake_thread_call_allocate(thread_call_func_t function,
                          thread_call_param_t parameter0)
{
  for (size_t index = 0; index < FAKE_THREAD_CALL_LIMIT; ++index) {
    thread_call_t call = &g_thread_calls[index];
    if (!call->allocated) {
      memset(call, 0, sizeof(*call));
      call->function = function;
      call->parameter0 = parameter0;
      call->allocated = true;
      return call;
    }
  }
  return NULL;
}

static boolean_t
fake_thread_call_schedule(thread_call_t call, thread_call_param_t parameter1,
                          uint64_t deadline)
{
  if (!fake_thread_call_valid(call)) {
    return FALSE;
  }

  boolean_t was_pending = call->pending ? TRUE : FALSE;
  call->parameter1 = parameter1;
  call->deadline = deadline;
  call->sequence = fake_next_sequence();
  call->pending = true;
  return was_pending;
}

thread_call_t
thread_call_allocate(thread_call_func_t function,
                     thread_call_param_t parameter0)
{
  return fake_thread_call_allocate(function, parameter0);
}

thread_call_t
thread_call_allocate_with_priority(thread_call_func_t function,
                                   thread_call_param_t parameter0,
                                   thread_call_priority_t priority)
{
  (void)priority;
  return fake_thread_call_allocate(function, parameter0);
}

thread_call_t
thread_call_allocate_with_options(thread_call_func_t function,
                                  thread_call_param_t parameter0,
                                  thread_call_priority_t priority,
                                  thread_call_options_t options)
{
  (void)priority;
  (void)options;
  return fake_thread_call_allocate(function, parameter0);
}

boolean_t
thread_call_enter(thread_call_t call)
{
  return fake_thread_call_schedule(call, NULL, g_fake_time_counter);
}

boolean_t
thread_call_enter1(thread_call_t call, thread_call_param_t parameter1)
{
  return fake_thread_call_schedule(call, parameter1, g_fake_time_counter);
}

boolean_t
thread_call_enter_delayed(thread_call_t call, uint64_t deadline)
{
  return fake_thread_call_schedule(call, NULL, deadline);
}

boolean_t
thread_call_enter1_delayed(thread_call_t call,
                           thread_call_param_t parameter1,
                           uint64_t deadline)
{
  return fake_thread_call_schedule(call, parameter1, deadline);
}

boolean_t
thread_call_enter_delayed_with_leeway(thread_call_t call,
                                      thread_call_param_t parameter1,
                                      uint64_t deadline, uint64_t leeway,
                                      uint32_t flags)
{
  (void)leeway;
  (void)flags;
  return fake_thread_call_schedule(call, parameter1, deadline);
}

boolean_t
thread_call_cancel(thread_call_t call)
{
  if (!fake_thread_call_valid(call) || !call->pending) {
    return FALSE;
  }
  call->pending = false;
  return TRUE;
}

boolean_t
thread_call_cancel_wait(thread_call_t call)
{
  return thread_call_cancel(call);
}

boolean_t
thread_call_free(thread_call_t call)
{
  if (!fake_thread_call_valid(call) || call->pending) {
    return FALSE;
  }
  if (call->running) {
    call->free_after_run = true;
  } else {
    memset(call, 0, sizeof(*call));
  }
  return TRUE;
}

boolean_t
thread_call_isactive(thread_call_t call)
{
  if (!fake_thread_call_valid(call)) {
    return FALSE;
  }
  return call->pending || call->running ? TRUE : FALSE;
}

void
thread_call_func_delayed(thread_call_func_t function,
                         thread_call_param_t parameter, uint64_t deadline)
{
  for (size_t index = 0; index < FAKE_FUNCTION_CALL_LIMIT; ++index) {
    struct fake_function_call *call = &g_function_calls[index];
    if (!call->pending && !call->running) {
      call->function = function;
      call->parameter = parameter;
      call->deadline = deadline;
      call->sequence = fake_next_sequence();
      call->pending = true;
      return;
    }
  }
}

void
thread_call_func_delayed_with_leeway(thread_call_func_t function,
                                     thread_call_param_t parameter,
                                     uint64_t deadline, uint64_t leeway,
                                     uint32_t flags)
{
  (void)leeway;
  (void)flags;
  thread_call_func_delayed(function, parameter, deadline);
}

boolean_t
thread_call_func_cancel(thread_call_func_t function,
                        thread_call_param_t parameter, boolean_t cancel_all)
{
  boolean_t cancelled = FALSE;

  for (size_t index = 0; index < FAKE_FUNCTION_CALL_LIMIT; ++index) {
    struct fake_function_call *call = &g_function_calls[index];
    if (call->pending && call->function == function &&
        call->parameter == parameter) {
      call->pending = false;
      cancelled = TRUE;
      if (!cancel_all) {
        break;
      }
    }
  }
  return cancelled;
}

static void
fake_timeout_schedule(void (*function)(void *), void *argument, int ticks)
{
  uint64_t nanoseconds_per_tick =
      hz > 0 ? 1000000000ULL / (uint64_t)hz : 10000000ULL;
  uint64_t tick_count = ticks > 0 ? (uint64_t)ticks : 1ULL;
  uint64_t delay = fake_multiply_saturating(tick_count,
                                             nanoseconds_per_tick);

  for (size_t index = 0; index < FAKE_TIMEOUT_LIMIT; ++index) {
    struct fake_timeout *timeout_entry = &g_timeouts[index];
    if (!timeout_entry->pending && !timeout_entry->running) {
      timeout_entry->function = function;
      timeout_entry->argument = argument;
      timeout_entry->deadline = fake_add_saturating(g_fake_time_counter,
                                                     delay);
      timeout_entry->sequence = fake_next_sequence();
      timeout_entry->pending = true;
      return;
    }
  }
}

void
timeout(void (*function)(void *), void *argument, int ticks)
{
  fake_timeout_schedule(function, argument, ticks);
}

void
timeout_with_leeway(void (*function)(void *), void *argument, int ticks,
                    int leeway_ticks)
{
  (void)leeway_ticks;
  fake_timeout_schedule(function, argument, ticks);
}

void
untimeout(void (*function)(void *), void *argument)
{
  for (size_t index = 0; index < FAKE_TIMEOUT_LIMIT; ++index) {
    struct fake_timeout *timeout_entry = &g_timeouts[index];
    if (timeout_entry->pending && timeout_entry->function == function &&
        timeout_entry->argument == argument) {
      timeout_entry->pending = false;
      return;
    }
  }
}

enum fake_timer_kind {
  FAKE_TIMER_NONE,
  FAKE_TIMER_THREAD_CALL,
  FAKE_TIMER_FUNCTION_CALL,
  FAKE_TIMER_TIMEOUT,
};

static enum fake_timer_kind
fake_find_next_due(void **result)
{
  enum fake_timer_kind kind = FAKE_TIMER_NONE;
  uint64_t earliest_deadline = UINT64_MAX;
  uint64_t earliest_sequence = UINT64_MAX;
  *result = NULL;

#define CONSIDER_TIMER(entry, entry_kind)                                      \
  do {                                                                         \
    if ((entry)->pending && (entry)->deadline <= g_fake_time_counter &&         \
        ((entry)->deadline < earliest_deadline ||                               \
         ((entry)->deadline == earliest_deadline &&                             \
          (entry)->sequence < earliest_sequence))) {                            \
      earliest_deadline = (entry)->deadline;                                    \
      earliest_sequence = (entry)->sequence;                                    \
      kind = (entry_kind);                                                      \
      *result = (entry);                                                        \
    }                                                                           \
  } while (0)

  for (size_t index = 0; index < FAKE_THREAD_CALL_LIMIT; ++index) {
    CONSIDER_TIMER(&g_thread_calls[index], FAKE_TIMER_THREAD_CALL);
  }
  for (size_t index = 0; index < FAKE_FUNCTION_CALL_LIMIT; ++index) {
    CONSIDER_TIMER(&g_function_calls[index], FAKE_TIMER_FUNCTION_CALL);
  }
  for (size_t index = 0; index < FAKE_TIMEOUT_LIMIT; ++index) {
    CONSIDER_TIMER(&g_timeouts[index], FAKE_TIMER_TIMEOUT);
  }

#undef CONSIDER_TIMER
  return kind;
}

static void
fake_dispatch_due_timers(void)
{
  if (g_dispatching) {
    return;
  }
  g_dispatching = true;

  for (unsigned int count = 0; count < FAKE_CALLBACKS_PER_ADVANCE; ++count) {
    void *entry = NULL;
    enum fake_timer_kind kind = fake_find_next_due(&entry);
    if (kind == FAKE_TIMER_NONE) {
      break;
    }

    if (kind == FAKE_TIMER_THREAD_CALL) {
      thread_call_t call = entry;
      thread_call_func_t function = call->function;
      thread_call_param_t parameter0 = call->parameter0;
      thread_call_param_t parameter1 = call->parameter1;
      call->pending = false;
      call->running = true;
      if (function != NULL) {
        function(parameter0, parameter1);
      }
      if (call->free_after_run) {
        memset(call, 0, sizeof(*call));
      } else {
        call->running = false;
      }
      continue;
    }

    if (kind == FAKE_TIMER_FUNCTION_CALL) {
      struct fake_function_call *call = entry;
      thread_call_func_t function = call->function;
      thread_call_param_t parameter = call->parameter;
      call->pending = false;
      call->running = true;
      if (function != NULL) {
        function(parameter, NULL);
      }
      call->running = false;
      continue;
    }

    struct fake_timeout *timeout_entry = entry;
    void (*function)(void *) = timeout_entry->function;
    void *argument = timeout_entry->argument;
    timeout_entry->pending = false;
    timeout_entry->running = true;
    if (function != NULL) {
      function(argument);
    }
    timeout_entry->running = false;
  }

  g_dispatching = false;
}

__attribute__((visibility("default")))
void
fake_time_advance(void)
{
  g_fake_time_counter = fake_add_saturating(g_fake_time_counter,
                                             FAKE_COMMAND_INTERVAL_NS);
  fake_dispatch_due_timers();
}

__attribute__((visibility("default")))
void
fake_time_reset(void)
{
  for (size_t index = 0; index < FAKE_THREAD_CALL_LIMIT; ++index) {
    g_thread_calls[index].pending = false;
  }
  for (size_t index = 0; index < FAKE_FUNCTION_CALL_LIMIT; ++index) {
    g_function_calls[index].pending = false;
  }
  for (size_t index = 0; index < FAKE_TIMEOUT_LIMIT; ++index) {
    g_timeouts[index].pending = false;
  }

  // Keep time monotonic between fuzzing iterations.
  g_fake_time_counter = fake_add_saturating(g_fake_time_counter, 1ULL);
}

uint64_t
mach_absolute_time(void)
{
  return g_fake_time_counter;
}

uint64_t
mach_continuous_time(void)
{
  return g_fake_time_counter;
}

void
clock_get_uptime(uint64_t *result)
{
  *result = g_fake_time_counter;
}

static uint64_t
fake_calendar_time(void)
{
  return fake_add_saturating(
      fake_multiply_saturating(FAKE_CALENDAR_EPOCH_SECONDS, 1000000000ULL),
      g_fake_time_counter);
}

static void
fake_time_to_microtime(uint64_t nanoseconds, uint32_t *seconds,
                       uint32_t *microseconds)
{
  *seconds = (uint32_t)(nanoseconds / 1000000000ULL);
  *microseconds = (uint32_t)((nanoseconds / 1000ULL) % 1000000ULL);
}

static void
fake_time_to_nanotime(uint64_t nanoseconds, uint32_t *seconds,
                      uint32_t *subseconds)
{
  *seconds = (uint32_t)(nanoseconds / 1000000000ULL);
  *subseconds = (uint32_t)(nanoseconds % 1000000000ULL);
}

void
clock_get_calendar_microtime(clock_sec_t *seconds, clock_usec_t *microseconds)
{
  fake_time_to_microtime(fake_calendar_time(), seconds, microseconds);
}

void
clock_get_calendar_absolute_and_microtime(clock_sec_t *seconds,
                                          clock_usec_t *microseconds,
                                          uint64_t *absolute_time)
{
  clock_get_calendar_microtime(seconds, microseconds);
  if (absolute_time != NULL) {
    *absolute_time = g_fake_time_counter;
  }
}

void
clock_get_calendar_nanotime(clock_sec_t *seconds, clock_nsec_t *nanoseconds)
{
  fake_time_to_nanotime(fake_calendar_time(), seconds, nanoseconds);
}

void
clock_get_system_microtime(clock_sec_t *seconds, clock_usec_t *microseconds)
{
  fake_time_to_microtime(g_fake_time_counter, seconds, microseconds);
}

void
clock_get_system_nanotime(clock_sec_t *seconds, clock_nsec_t *nanoseconds)
{
  fake_time_to_nanotime(g_fake_time_counter, seconds, nanoseconds);
}

void
clock_get_boottime_nanotime(clock_sec_t *seconds, clock_nsec_t *nanoseconds)
{
  *seconds = (clock_sec_t)FAKE_CALENDAR_EPOCH_SECONDS;
  *nanoseconds = 0;
}

time_t
boottime_sec(void)
{
  return (time_t)FAKE_CALENDAR_EPOCH_SECONDS;
}

void
microtime(struct timeval *time_value)
{
  uint64_t current_time = fake_calendar_time();
  time_value->tv_sec = (time_t)(current_time / 1000000000ULL);
  time_value->tv_usec = (suseconds_t)((current_time / 1000ULL) % 1000000ULL);
}

void
microuptime(struct timeval *time_value)
{
  time_value->tv_sec = (time_t)(g_fake_time_counter / 1000000000ULL);
  time_value->tv_usec =
      (suseconds_t)((g_fake_time_counter / 1000ULL) % 1000000ULL);
}

void
nanotime(struct timespec *time_value)
{
  uint64_t current_time = fake_calendar_time();
  time_value->tv_sec = (time_t)(current_time / 1000000000ULL);
  time_value->tv_nsec = (long)(current_time % 1000000000ULL);
}

void
nanouptime(struct timespec *time_value)
{
  time_value->tv_sec = (time_t)(g_fake_time_counter / 1000000000ULL);
  time_value->tv_nsec = (long)(g_fake_time_counter % 1000000000ULL);
}

void
clock_interval_to_deadline(uint32_t interval, uint32_t scale_factor,
                           uint64_t *result)
{
  uint64_t duration = fake_multiply_saturating(interval, scale_factor);
  *result = fake_add_saturating(g_fake_time_counter, duration);
}

void
clock_interval_to_absolutetime_interval(uint32_t interval,
                                        uint32_t scale_factor,
                                        uint64_t *result)
{
  *result = fake_multiply_saturating(interval, scale_factor);
}

void
clock_absolutetime_interval_to_deadline(uint64_t interval,
                                        uint64_t *deadline)
{
  *deadline = fake_add_saturating(g_fake_time_counter, interval);
}

void
clock_continuoustime_interval_to_deadline(uint64_t interval,
                                          uint64_t *deadline)
{
  *deadline = fake_add_saturating(g_fake_time_counter, interval);
}

void
clock_deadline_for_periodic_event(uint64_t interval, uint64_t absolute_time,
                                  uint64_t *deadline)
{
  *deadline = fake_add_saturating(*deadline, interval);
  if (*deadline <= absolute_time) {
    *deadline = fake_add_saturating(absolute_time, interval);
  }
  if (*deadline <= g_fake_time_counter) {
    *deadline = fake_add_saturating(g_fake_time_counter, interval);
  }
}

void
nanoseconds_to_absolutetime(uint64_t nanoseconds, uint64_t *result)
{
  *result = nanoseconds;
}

void
absolutetime_to_nanoseconds(uint64_t absolute_time, uint64_t *result)
{
  *result = absolute_time;
}

void
absolutetime_to_microtime(uint64_t absolute_time, clock_sec_t *seconds,
                          clock_usec_t *microseconds)
{
  fake_time_to_microtime(absolute_time, seconds, microseconds);
}
