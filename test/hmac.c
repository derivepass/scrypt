#include <stdio.h>
#include <string.h>

#include "test/test.h"
#include "src/common.h"
#include "src/hmac.h"

typedef struct scrypt_hmac_test_s scrypt_hmac_test_t;

struct scrypt_hmac_test_s {
  const char* key;
  const char* inputs[16];
  uint8_t expected[32];
};

SCRYPT_TEST(hmac) {
  size_t i;

  /* See https://tools.ietf.org/html/rfc4231 */
  scrypt_hmac_test_t tests[] = {
    {
      .key = "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
             "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
      .inputs = { "Hi There", NULL },
      .expected = {
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
        0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
        0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
        0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7
      }
    },
    {
      .key = "Jefe",
      .inputs = { "what do ya want ", "for nothing?", NULL },
      .expected = {
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
        0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
        0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
        0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43
      }
    },
    {
      .key = "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa",
      .inputs = {
        "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd",
        "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd",
        "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd",
        "\xdd\xdd",
        NULL
      },
      .expected = {
        0x77, 0x3e, 0xa9, 0x1e, 0x36, 0x80, 0x0e, 0x46,
        0x85, 0x4d, 0xb8, 0xeb, 0xd0, 0x91, 0x81, 0xa7,
        0x29, 0x59, 0x09, 0x8b, 0x3e, 0xf8, 0xc1, 0x22,
        0xd9, 0x63, 0x55, 0x14, 0xce, 0xd5, 0x65, 0xfe
      }
    },
    {
      .key = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
             "\x11\x12\x13\x14\x15\x16\x17\x18\x19",
      .inputs = {
        "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd",
        "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd",
        "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd",
        "\xcd\xcd",
        NULL
      },
      .expected = {
        0x82, 0x55, 0x8a, 0x38, 0x9a, 0x44, 0x3c, 0x0e,
        0xa4, 0xcc, 0x81, 0x98, 0x99, 0xf2, 0x08, 0x3a,
        0x85, 0xf0, 0xfa, 0xa3, 0xe5, 0x78, 0xf8, 0x07,
        0x7a, 0x2e, 0x3f, 0xf4, 0x67, 0x29, 0x66, 0x5b
      }
    },
    {
      .key = "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa",
      .inputs = {
        "Test Using Large",
        "r Than Block-Siz",
        "e Key - Hash Key",
        " First",
        NULL
      },
      .expected = {
        0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f,
        0x0d, 0x8a, 0x26, 0xaa, 0xcb, 0xf5, 0xb7, 0x7f,
        0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14,
        0x05, 0x46, 0x04, 0x0f, 0x0e, 0xe3, 0x7f, 0x54
      }
    },
    {
      .key = "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
             "\xaa\xaa\xaa",
      .inputs = {
        "This is a test u",
        "sing a larger th",
        "an block-size ke",
        "y and a larger t",
        "han block-size d",
        "ata. The key nee",
        "ds to be hashed ",
        "before being use",
        "d by the HMAC al",
        "gorithm.",
        NULL
      },
      .expected = {
        0x9b, 0x09, 0xff, 0xa7, 0x1b, 0x94, 0x2f, 0xcb,
        0x27, 0x63, 0x5f, 0xbc, 0xd5, 0xb0, 0xe9, 0x44,
        0xbf, 0xdc, 0x63, 0x64, 0x4f, 0x07, 0x13, 0x93,
        0x8a, 0x7f, 0x51, 0x53, 0x5c, 0x3a, 0x35, 0xe2
      }
    }
  };

  for (i = 0; i < ARRAY_SIZE(tests); i++) {
    scrypt_hmac_test_t* v;
    uint8_t out[sizeof(v->expected)];
    size_t j;
    scrypt_hmac_t hmac;
    const char** chunk;

    v = &tests[i];

    scrypt_hmac_init(&hmac, (uint8_t*) v->key, strlen(v->key));
    for (chunk = v->inputs; *chunk != NULL; chunk++)
      scrypt_hmac_update(&hmac, (uint8_t*) *chunk, strlen(*chunk));
    scrypt_hmac_digest(&hmac, out);

    for (j = 0; j < ARRAY_SIZE(out); j++) {
      if (out[j] == v->expected[j])
        continue;

      fprintf(stderr,
              "0x%02x != 0x%02x at %d (test vector: %d)\n",
              out[j],
              v->expected[j],
              (int) j,
              (int) i);
      ASSERT(0, "sha256 hmac failure");
    }
  }
}
