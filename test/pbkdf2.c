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
    int j;

    v = &tests[i];
    ASSERT(v->dkLen <= sizeof(out), "Not enough space for dkLen");

    scrypt_pbkdf2_sha256((const uint8_t*) v->password,
                         strlen(v->password),
                         (const uint8_t*) v->salt,
                         strlen(v->salt),
                         v->c,
                         out,
                         v->dkLen);

    for (j = 0; v->expected[j] != '\0'; j += 2) {
      char hi;
      char lo;
      uint8_t ch;

      hi = v->expected[j];
      lo = v->expected[j + 1];
      if ('0' <= hi && hi <= '9')
        ch = hi - '0';
      else
        ch = (hi - 'a') + 0xa;
      ch <<= 4;
      if ('0' <= lo && lo <= '9')
        ch |= lo - '0';
      else
        ch |= (lo - 'a') + 0xa;

      if (out[j / 2] != ch) {
        fprintf(stderr,
                "DK mismatch: 0x%02x instead of 0x%02x at %d (vec: %d)\n",
                out[j / 2],
                ch,
                j,
                (int) i);
        ASSERT(0, "DK mismatch");
      }
    }
  }
}
