#include <stdio.h>
#include <stdlib.h>

#include "test/test.h"

static scrypt_test_t* tests;


void scrypt_add_test(scrypt_test_t* test) {
  test->next = tests;
  tests = test;
}


int main() {
  scrypt_test_t* cur;

  for (cur = tests; cur != NULL; cur = cur->next) {
    fprintf(stderr, "===== [%s] =====\n", cur->name);
    cur->fn(cur);
  }

  return 0;
}
