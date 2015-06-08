#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test/test.h"

static scrypt_test_t* tests;


void scrypt_add_test(scrypt_test_t* test) {
  test->next = tests;
  tests = test;
}


int scrypt_compare_hex(const uint8_t* actual, const char* expected) {
  int i;
  for (i = 0; expected[i] != '\0'; i += 2) {
    char hi;
    char lo;
    uint8_t ch;

    hi = expected[i];
    lo = expected[i + 1];
    if ('0' <= hi && hi <= '9')
      ch = hi - '0';
    else
      ch = (hi - 'a') + 0xa;
    ch <<= 4;
    if ('0' <= lo && lo <= '9')
      ch |= lo - '0';
    else
      ch |= (lo - 'a') + 0xa;

    if (actual[i / 2] != ch) {
      fprintf(stderr,
              "HEX mismatch: 0x%02x instead of 0x%02x at %d\n",
              actual[i / 2],
              ch,
              i);
      return -1;
    }
  }

  return 0;
}


int main(int argc, char** argv) {
  scrypt_test_t* cur;

  for (cur = tests; cur != NULL; cur = cur->next) {
    if (argc == 2 && strcmp(cur->name, argv[1]) != 0)
      continue;

    fprintf(stderr, "===== [%s] =====\n", cur->name);
    cur->fn(cur);
  }

  return 0;
}
