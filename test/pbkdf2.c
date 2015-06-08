#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "test/test.h"
#include "src/common.h"
#include "src/pbkdf2.h"

typedef struct pbkdf2_test_vector_s pbkdf2_test_vector_t;

struct pbkdf2_test_vector_s {
  const char* password;
  const char* salt;
  unsigned int c;
  size_t dkLen;
  const char* expected;
};

SCRYPT_TEST(pbkdf2_test_vectors) {
  size_t i;

  /* See: https://tools.ietf.org/html/draft-josefsson-scrypt-kdf-03#page-10 */
  pbkdf2_test_vector_t tests[] = {
    {
      .password = "passwd",
      .salt = "salt",
      .c = 1,
      .dkLen = 64,
      .expected = "55ac046e56e3089fec1691c22544b605"
                  "f94185216dde0465e68b9d57c20dacbc"
                  "49ca9cccf179b645991664b39d77ef31"
                  "7c71b845b1e30bd509112041d3a19783"
    },
    {
      .password = "Password",
      .salt = "NaCl",
      .c = 80000,
      .dkLen = 64,
      .expected = "4ddcd8f60b98be21830cee5ef22701f9"
                  "641a4418d04c0414aeff08876b34ab56"
                  "a1d425a1225833549adb841b51c9b317"
                  "6a272bdebba1d078478f62b397f33c8d"
    }
  };

  for (i = 0; i < ARRAY_SIZE(tests); i++) {
    pbkdf2_test_vector_t* v;
    uint8_t out[1024];

    v = &tests[i];
    ASSERT(v->dkLen <= sizeof(out), "Not enough space for dkLen");

    scrypt_pbkdf2_sha256((const uint8_t*) v->password,
                         strlen(v->password),
                         (const uint8_t*) v->salt,
                         strlen(v->salt),
                         v->c,
                         out,
                         v->dkLen);

    ASSERT(scrypt_compare_hex(out, v->expected) == 0, "DK mismatch");
  }
}
