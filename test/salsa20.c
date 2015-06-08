#include <stdio.h>
#include <string.h>

#include "test/test.h"
#include "src/common.h"
#include "src/salsa20.h"

typedef struct salsa20_quarter_test_vector_s salsa20_quarter_test_vector_t;
typedef struct salsa20_row_test_vector_s salsa20_row_test_vector_t;
typedef struct salsa20_test_vector_s salsa20_test_vector_t;

struct salsa20_quarter_test_vector_s {
  uint32_t input[4];
  uint32_t expected[4];
};

struct salsa20_row_test_vector_s {
  uint32_t input[16];
  uint32_t expected[16];
};

struct salsa20_test_vector_s {
  int rounds;
  uint8_t input[64];
  uint8_t expected[64];
};

SCRYPT_TEST(salsa20_quarterround) {
  size_t i;

  /* http://cr.yp.to/snuffle/spec.pdf */
  salsa20_quarter_test_vector_t tests[] = {
    {
      .input = { 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
      .expected = { 0x00000000, 0x00000000, 0x00000000, 0x00000000 }
    },
    {
      .input = { 0x00000001, 0x00000000, 0x00000000, 0x00000000 },
      .expected = { 0x08008145, 0x00000080, 0x00010200, 0x20500000 }
    },
    {
      .input = { 0x00000000, 0x00000001, 0x00000000, 0x00000000 },
      .expected = { 0x88000100, 0x00000001, 0x00000200, 0x00402000 }
    },
    {
      .input = { 0x00000000, 0x00000000, 0x00000001, 0x00000000 },
      .expected = { 0x80040000, 0x00000000, 0x00000001, 0x00002000 }
    },
    {
      .input = { 0x00000000, 0x00000000, 0x00000000, 0x00000001 },
      .expected = { 0x00048044, 0x00000080, 0x00010000, 0x20100001 }
    },
    {
      .input = { 0xe7e8c006, 0xc4f9417d, 0x6479b4b2, 0x68c67137 },
      .expected = { 0xe876d72b, 0x9361dfd5, 0xf1460244, 0x948541a3 }
    },
    {
      .input = { 0xd3917c5b, 0x55f1c407, 0x52a58a7a, 0x8f887a3b },
      .expected = { 0x3e2f308c, 0xd90a8f36, 0x6ab2a923, 0x2883524c }
    }
  };

  for (i = 0; i < ARRAY_SIZE(tests); i++) {
    salsa20_quarter_test_vector_t* v;
    uint32_t out[ARRAY_SIZE(v->input)];
    size_t j;

    v = &tests[i];

    scrypt_salsa20_quarterround(v->input, out);
    for (j = 0; j < ARRAY_SIZE(out); j++) {
      if (out[j] == v->expected[j])
        continue;

      fprintf(stderr,
              "0x%08x != 0x%08x at %d\n",
              out[j],
              v->expected[j],
              (int) j);
      ASSERT(0, "Quarterround failure");
    }
  }
}


SCRYPT_TEST(salsa20_columnround) {
  size_t i;

  /* http://cr.yp.to/snuffle/spec.pdf */
  salsa20_row_test_vector_t tests[] = {
    {
      .input = {
        0x00000001, 0x00000000, 0x00000000, 0x00000000,
        0x00000001, 0x00000000, 0x00000000, 0x00000000,
        0x00000001, 0x00000000, 0x00000000, 0x00000000,
        0x00000001, 0x00000000, 0x00000000, 0x00000000
      },
      .expected = {
        0x10090288, 0x00000000, 0x00000000, 0x00000000,
        0x00000101, 0x00000000, 0x00000000, 0x00000000,
        0x00020401, 0x00000000, 0x00000000, 0x00000000,
        0x40a04001, 0x00000000, 0x00000000, 0x00000000
      }
    },
    {
      .input = {
        0x08521bd6, 0x1fe88837, 0xbb2aa576, 0x3aa26365,
        0xc54c6a5b, 0x2fc74c2f, 0x6dd39cc3, 0xda0a64f6,
        0x90a2f23d, 0x067f95a6, 0x06b35f61, 0x41e4732e,
        0xe859c100, 0xea4d84b7, 0x0f619bff, 0xbc6e965a
      },
      .expected = {
        0x8c9d190a, 0xce8e4c90, 0x1ef8e9d3, 0x1326a71a,
        0x90a20123, 0xead3c4f3, 0x63a091a0, 0xf0708d69,
        0x789b010c, 0xd195a681, 0xeb7d5504, 0xa774135c,
        0x481c2027, 0x53a8e4b5, 0x4c1f89c5, 0x3f78c9c8
      }
    }
  };

  for (i = 0; i < ARRAY_SIZE(tests); i++) {
    salsa20_row_test_vector_t* v;
    uint32_t out[ARRAY_SIZE(v->input)];
    size_t j;

    v = &tests[i];

    scrypt_salsa20_columnround(v->input, out);
    for (j = 0; j < ARRAY_SIZE(out); j++) {
      if (out[j] == v->expected[j])
        continue;

      fprintf(stderr,
              "0x%08x != 0x%08x at %d\n",
              out[j],
              v->expected[j],
              (int) j);
      ASSERT(0, "Columnround failure");
    }
  }
}


SCRYPT_TEST(salsa20_doubleround) {
  size_t i;

  /* http://cr.yp.to/snuffle/spec.pdf */
  salsa20_row_test_vector_t tests[] = {
    {
      .input = {
        0x00000001, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000000
      },
      .expected = {
        0x8186a22d, 0x0040a284, 0x82479210, 0x06929051,
        0x08000090, 0x02402200, 0x00004000, 0x00800000,
        0x00010200, 0x20400000, 0x08008104, 0x00000000,
        0x20500000, 0xa0000040, 0x0008180a, 0x612a8020
      }
    },
    {
      .input = {
        0xde501066, 0x6f9eb8f7, 0xe4fbbd9b, 0x454e3f57,
        0xb75540d3, 0x43e93a4c, 0x3a6f2aa0, 0x726d6b36,
        0x9243f484, 0x9145d1e8, 0x4fa9d247, 0xdc8dee11,
        0x054bf545, 0x254dd653, 0xd9421b6d, 0x67b276c1
      },
      .expected = {
        0xccaaf672, 0x23d960f7, 0x9153e63a, 0xcd9a60d0,
        0x50440492, 0xf07cad19, 0xae344aa0, 0xdf4cfdfc,
        0xca531c29, 0x8e7943db, 0xac1680cd, 0xd503ca00,
        0xa74b2ad6, 0xbc331c5c, 0x1dda24c7, 0xee928277
      }
    }
  };

  for (i = 0; i < ARRAY_SIZE(tests); i++) {
    salsa20_row_test_vector_t* v;
    uint32_t out[ARRAY_SIZE(v->input)];
    size_t j;

    v = &tests[i];

    scrypt_salsa20_doubleround(v->input, out);
    for (j = 0; j < ARRAY_SIZE(out); j++) {
      if (out[j] == v->expected[j])
        continue;

      fprintf(stderr,
              "0x%08x != 0x%08x at %d\n",
              out[j],
              v->expected[j],
              (int) j);
      ASSERT(0, "Doubleround failure");
    }
  }
}


SCRYPT_TEST(salsa20_rowround) {
  size_t i;

  /* http://cr.yp.to/snuffle/spec.pdf */
  salsa20_row_test_vector_t tests[] = {
    {
      .input = {
        0x00000001, 0x00000000, 0x00000000, 0x00000000,
        0x00000001, 0x00000000, 0x00000000, 0x00000000,
        0x00000001, 0x00000000, 0x00000000, 0x00000000,
        0x00000001, 0x00000000, 0x00000000, 0x00000000
      },
      .expected = {
        0x08008145, 0x00000080, 0x00010200, 0x20500000,
        0x20100001, 0x00048044, 0x00000080, 0x00010000,
        0x00000001, 0x00002000, 0x80040000, 0x00000000,
        0x00000001, 0x00000200, 0x00402000, 0x88000100
      }
    },
    {
      .input = {
        0x08521bd6, 0x1fe88837, 0xbb2aa576, 0x3aa26365,
        0xc54c6a5b, 0x2fc74c2f, 0x6dd39cc3, 0xda0a64f6,
        0x90a2f23d, 0x067f95a6, 0x06b35f61, 0x41e4732e,
        0xe859c100, 0xea4d84b7, 0x0f619bff, 0xbc6e965a
      },
      .expected = {
        0xa890d39d, 0x65d71596, 0xe9487daa, 0xc8ca6a86,
        0x949d2192, 0x764b7754, 0xe408d9b9, 0x7a41b4d1,
        0x3402e183, 0x3c3af432, 0x50669f96, 0xd89ef0a8,
        0x0040ede5, 0xb545fbce, 0xd257ed4f, 0x1818882d
      }
    }
  };

  for (i = 0; i < ARRAY_SIZE(tests); i++) {
    salsa20_row_test_vector_t* v;
    uint32_t out[ARRAY_SIZE(v->input)];
    size_t j;

    v = &tests[i];

    scrypt_salsa20_rowround(v->input, out);
    for (j = 0; j < ARRAY_SIZE(out); j++) {
      if (out[j] == v->expected[j])
        continue;

      fprintf(stderr,
              "0x%08x != 0x%08x at %d\n",
              out[j],
              v->expected[j],
              (int) j);
      ASSERT(0, "Rowround failure");
    }
  }
}

SCRYPT_TEST(salsa20_test_vectors) {
  size_t i;

  salsa20_test_vector_t tests[] = {
    {
      .rounds = 10,
      .input = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
      },
      .expected = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
      }
    },
    {
      .rounds = 10,
      .input = {
        211,159, 13,115, 76, 55, 82,183, 3,117,222, 37,191,187,234,136,
         49,237,179, 48, 1,106,178,219,175,199,166, 48, 86, 16,179,207,
         31,240, 32, 63, 15, 83, 93,161,116,147, 48,113,238, 55,204, 36,
         79,201,235, 79, 3, 81,156, 47,203, 26,244,243, 88,118,104, 54
      },
      .expected = {
        109, 42,178,168,156,240,248,238,168,196,190,203, 26,110,170,154,
         29, 29,150, 26,150, 30,235,249,190,163,251, 48, 69,144, 51, 57,
        118, 40,152,157,180, 57, 27, 94,107, 42,236, 35, 27,111,114,114,
        219,236,232,135,111,155,110, 18, 24,232, 95,158,179, 19, 48,202
      }
    },
    {
      .rounds = 10,
      .input = {
         88,118,104, 54, 79,201,235, 79, 3, 81,156, 47,203, 26,244,243,
        191,187,234,136,211,159, 13,115, 76, 55, 82,183, 3,117,222, 37,
         86, 16,179,207, 49,237,179, 48, 1,106,178,219,175,199,166, 48,
        238, 55,204, 36, 31,240, 32, 63, 15, 83, 93,161,116,147, 48,113
      },
      .expected = {
        179, 19, 48,202,219,236,232,135,111,155,110, 18, 24,232, 95,158,
         26,110,170,154,109, 42,178,168,156,240,248,238,168,196,190,203,
         69,144, 51, 57, 29, 29,150, 26,150, 30,235,249,190,163,251, 48,
         27,111,114,114,118, 40,152,157,180, 57, 27, 94,107, 42,236, 35
      }
    },

    /* https://tools.ietf.org/html/draft-josefsson-scrypt-kdf-03#page-8 */
    {
      .rounds = 4,
      .input = {
        0x7e, 0x87, 0x9a, 0x21, 0x4f, 0x3e, 0xc9, 0x86,
        0x7c, 0xa9, 0x40, 0xe6, 0x41, 0x71, 0x8f, 0x26,
        0xba, 0xee, 0x55, 0x5b, 0x8c, 0x61, 0xc1, 0xb5,
        0x0d, 0xf8, 0x46, 0x11, 0x6d, 0xcd, 0x3b, 0x1d,
        0xee, 0x24, 0xf3, 0x19, 0xdf, 0x9b, 0x3d, 0x85,
        0x14, 0x12, 0x1e, 0x4b, 0x5a, 0xc5, 0xaa, 0x32,
        0x76, 0x02, 0x1d, 0x29, 0x09, 0xc7, 0x48, 0x29,
        0xed, 0xeb, 0xc6, 0x8d, 0xb8, 0xb8, 0xc2, 0x5e
      },
      .expected = {
        0xa4, 0x1f, 0x85, 0x9c, 0x66, 0x08, 0xcc, 0x99,
        0x3b, 0x81, 0xca, 0xcb, 0x02, 0x0c, 0xef, 0x05,
        0x04, 0x4b, 0x21, 0x81, 0xa2, 0xfd, 0x33, 0x7d,
        0xfd, 0x7b, 0x1c, 0x63, 0x96, 0x68, 0x2f, 0x29,
        0xb4, 0x39, 0x31, 0x68, 0xe3, 0xc9, 0xe6, 0xbc,
        0xfe, 0x6b, 0xc5, 0xb7, 0xa0, 0x6d, 0x96, 0xba,
        0xe4, 0x24, 0xcc, 0x10, 0x2c, 0x91, 0x74, 0x5c,
        0x24, 0xad, 0x67, 0x3d, 0xc7, 0x61, 0x8f, 0x81,
      }
    },
  };

  for (i = 0; i < ARRAY_SIZE(tests); i++) {
    salsa20_test_vector_t* v;
    uint8_t out[kSalsa20BlockSize];
    size_t j;

    v = &tests[i];

    scrypt_salsa20(v->input, v->rounds, out);
    for (j = 0; j < ARRAY_SIZE(out); j++) {
      if (out[j] == v->expected[j])
        continue;

      fprintf(stderr,
              "0x%02x != 0x%02x at %d (test vector: %d)\n",
              out[j],
              v->expected[j],
              (int) j,
              (int) i);
      ASSERT(0, "salsa20 failure");
    }
  }
}
