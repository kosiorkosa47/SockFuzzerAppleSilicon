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
#include <cstring>

// Declarations for functions under test (defined in fake_impls.c / zalloc.c)
extern "C" {
extern bool real_copyout;
int copyout(const void* kaddr, uint64_t udaddr, size_t len);
int copyin(uint64_t uaddr, void* kaddr, size_t len);
void get_fuzzed_bytes(void* addr, size_t bytes);
bool get_fuzzed_bool(void);

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

TEST(kmem_mb_reset) {
  // Should not crash
  kmem_mb_reset_pages();
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
  run_kmem_mb_reset();

  printf("\nResults: %d passed, %d failed\n", tests_passed, tests_failed);
  return tests_failed > 0 ? 1 : 0;
}
