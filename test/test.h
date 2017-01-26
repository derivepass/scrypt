#ifndef TEST_TEST_H_
#define TEST_TEST_H_

#include <stdlib.h>  /* NULL */
#include <stdint.h>  /* uint8_t */

typedef struct scrypt_test_s scrypt_test_t;
typedef void (*scrypt_test_fn)(scrypt_test_t* test);

struct scrypt_test_s {
  const char* name;
  scrypt_test_fn fn;

  scrypt_test_t* next;
};

void scrypt_add_test(scrypt_test_t* test);

int scrypt_compare_hex(const uint8_t* actual, const char* expected);

#if defined(_MSC_VER)
# pragma section(".CRT$XCU", read)
# define SCRYPT_C_CTOR(fn)                                                    \
    static void __cdecl fn(void);                                             \
    __declspec(dllexport, allocate(".CRT$XCU"))                               \
        void (__cdecl*fn ## _)(void) = fn;                                    \
    static void __cdecl fn(void)
#else
# define SCRYPT_C_CTOR(fn)                                                    \
    static void fn(void) __attribute__((constructor));                        \
    static void fn(void)
#endif

#define SCRYPT_TEST(NAME)                                                     \
    static void scrypt_test_impl_##NAME(scrypt_test_t* test);                 \
    SCRYPT_C_CTOR(scrypt_test_decl_##NAME) {                                  \
      static scrypt_test_t test = {                                           \
        .name = #NAME,                                                        \
        .fn = scrypt_test_impl_##NAME,                                        \
        .next = NULL                                                          \
      };                                                                      \
      scrypt_add_test(&test);                                                 \
    }                                                                         \
    void scrypt_test_impl_##NAME(scrypt_test_t* test)

#endif  /* TEST_TEST_H_ */
