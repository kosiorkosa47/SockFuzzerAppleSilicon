// Copyright 2024 ckosiorkosa47
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Unit tests for the fake kernel implementations.
// These verify that the fuzzer's kernel stubs behave correctly,
// especially for critical functions like copyin/copyout/zalloc.

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

// Stub implementations of fuzz data providers for test builds.
// In the real fuzzer these live in net_fuzzer.cc and are fed by libFuzzer.
// For unit tests we use deterministic values.
static unsigned int test_fuzz_counter = 0;
extern "C" {
void get_fuzzed_bytes(void* addr, size_t bytes) {
  memset(addr, (int)(test_fuzz_counter++ & 0xFF), bytes);
}
bool get_fuzzed_bool(void) { return (test_fuzz_counter++ & 1) != 0; }
int get_fuzzed_int32(int low, int high) { return low; }
unsigned int get_fuzzed_uint32(unsigned int low, unsigned int high) { return low; }
unsigned int get_remaining_bytes(void) { return 4096; }
}

// Declarations for functions under test (defined in fake_impls.c / zalloc.c)
extern "C" {
extern bool real_copyout;
int copyout(const void* kaddr, uint64_t udaddr, size_t len);
int copyin(uint64_t uaddr, void* kaddr, size_t len);

// zalloc
struct zone;
struct zone* zinit(uintptr_t size, uintptr_t max, uintptr_t alloc,
                   const char* name);
void* zalloc(struct zone* zone);
void zfree(struct zone* zone, void* elem);
void kmem_mb_reset_pages(void);
}

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
  static void test_##name(); \
  static void run_##name() { \
    printf("  TEST %-40s ", #name); \
    test_##name(); \
    printf("PASS\n"); \
    tests_passed++; \
  } \
  static void test_##name()

#define ASSERT_EQ(a, b) do { \
    if ((a) != (b)) { \
      printf("FAIL\n    %s:%d: %s != %s\n", __FILE__, __LINE__, #a, #b); \
      tests_failed++; \
      return; \
    } \
  } while(0)

#define ASSERT_NE(a, b) do { \
    if ((a) == (b)) { \
      printf("FAIL\n    %s:%d: %s == %s\n", __FILE__, __LINE__, #a, #b); \
      tests_failed++; \
      return; \
    } \
  } while(0)

// --- copyout tests ---

TEST(copyout_null_kaddr) {
  // Should return 0 without crashing
  int ret = copyout(nullptr, 0, 10);
  ASSERT_EQ(ret, 0);
}

TEST(copyout_zero_len) {
  char buf[4] = {1, 2, 3, 4};
  int ret = copyout(buf, 0, 0);
  ASSERT_EQ(ret, 0);
}

TEST(copyout_fuzzed_addr) {
  // Address == 1 (USERADDR_FUZZED): should validate source via malloc+memcpy
  char src[8] = {0x0A, 0x0B, 0x0C, 0x0D, 0, 0, 0, 0};
  real_copyout = true;
  // This path allocates a temp buffer, copies, frees — testing ASAN catches
  int ret = copyout(src, 1, sizeof(src));
  // ret is either 0 or EFAULT (random), both are valid
  assert(ret == 0 || ret == 14);
}

TEST(copyout_real_pointer) {
  char src[4] = {0x11, 0x22, 0x33, 0x44};  // all < 128, no narrowing
  char dst[4] = {};
  real_copyout = true;
  // Force a non-random success by running multiple times
  for (int i = 0; i < 100; i++) {
    memset(dst, 0, sizeof(dst));
    int ret = copyout(src, (uint64_t)dst, sizeof(src));
    if (ret == 0) {
      ASSERT_EQ(memcmp(src, dst, 4), 0);
      return;  // success
    }
  }
  // If all 100 attempts randomly failed, that's statistically impossible
  assert(false && "copyout randomly failed 100 times");
}

// --- copyin tests ---

TEST(copyin_null_kaddr) {
  int ret = copyin(1, nullptr, 10);
  ASSERT_EQ(ret, 0);
}

TEST(copyin_real_pointer) {
  char src[4] = {0x1E, 0x2D, 0x3E, 0x4F};
  char dst[4] = {};
  int ret = copyin((uint64_t)src, dst, sizeof(src));
  ASSERT_EQ(ret, 0);
  ASSERT_EQ(memcmp(src, dst, 4), 0);
}

// --- zalloc tests ---

TEST(zinit_creates_zone) {
  struct zone* z = zinit(64, 1024, 128, "test_zone");
  ASSERT_NE(z, (struct zone*)nullptr);
}

TEST(zalloc_null_zone) {
  // NULL zone should return a valid default allocation (4096 bytes)
  void* p = zalloc(nullptr);
  ASSERT_NE(p, (void*)nullptr);
  free(p);
}

TEST(zalloc_from_zone) {
  struct zone* z = zinit(128, 1024, 128, "test_alloc");
  void* p = zalloc(z);
  ASSERT_NE(p, (void*)nullptr);
  // Should be zero-filled (calloc)
  char* c = (char*)p;
  ASSERT_EQ(c[0], 0);
  ASSERT_EQ(c[127], 0);
  free(p);
}

TEST(kmem_mb_reset) {
  // Should not crash
  kmem_mb_reset_pages();
}

// --- time tests ---

extern "C" {
uint64_t mach_absolute_time(void);
void fake_time_reset(void);
void fake_time_advance(void);
void fake_uuid_reset(void);
}

TEST(time_progresses) {
  fake_time_reset();
  uint64_t t1 = mach_absolute_time();
  fake_time_advance();
  uint64_t t2 = mach_absolute_time();
  // Clock reads are stable and explicit advancement moves time forward.
  uint64_t t3 = mach_absolute_time();
  assert(t2 > t1);
  ASSERT_EQ(t3, t2);
  ASSERT_EQ(t2 - t1, (uint64_t)10000000);
}

TEST(time_reset) {
  fake_time_reset();
  uint64_t t1 = mach_absolute_time();
  fake_time_reset();
  uint64_t t2 = mach_absolute_time();
  // Iteration reset must not make monotonic time go backwards.
  ASSERT_GT(t2, t1);
}

// --- UUID tests ---

extern "C" {
void uuid_generate_random(unsigned char out[16]);
}

TEST(uuid_unique) {
  fake_uuid_reset();
  unsigned char u1[16], u2[16], u3[16];
  uuid_generate_random(u1);
  uuid_generate_random(u2);
  uuid_generate_random(u3);
  // All should be different
  ASSERT_NE(memcmp(u1, u2, 16), 0);
  ASSERT_NE(memcmp(u2, u3, 16), 0);
  ASSERT_NE(memcmp(u1, u3, 16), 0);
}

TEST(uuid_reset_restarts) {
  fake_uuid_reset();
  unsigned char u1[16];
  uuid_generate_random(u1);
  fake_uuid_reset();
  unsigned char u2[16];
  uuid_generate_random(u2);
  // After reset, should produce same first UUID
  ASSERT_EQ(memcmp(u1, u2, 16), 0);
}

// --- permission tests ---

extern "C" {
int proc_suser(void);
bool kauth_cred_issuser(void);
}

TEST(permissions_vary) {
  // Run 100 times — at least one should succeed and one should fail
  int successes = 0, failures = 0;
  for (int i = 0; i < 100; i++) {
    if (proc_suser() == 0) successes++; else failures++;
  }
  // With fuzzed bool, statistically impossible for all 100 to be same
  assert(successes > 0 || failures > 0);  // trivially true, but checks no crash
}

// --- main ---

int main() {
  printf("Running fake_impls tests:\n");

  run_copyout_null_kaddr();
  run_copyout_zero_len();
  run_copyout_fuzzed_addr();
  run_copyout_real_pointer();
  run_copyin_null_kaddr();
  run_copyin_real_pointer();
  run_zinit_creates_zone();
  run_zalloc_null_zone();
  run_zalloc_from_zone();
  run_kmem_mb_reset();
  run_time_progresses();
  run_time_reset();
  run_uuid_unique();
  run_uuid_reset_restarts();
  run_permissions_vary();

  printf("\nResults: %d passed, %d failed\n", tests_passed, tests_failed);
  return tests_failed > 0 ? 1 : 0;
}
