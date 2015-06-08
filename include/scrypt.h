#ifndef INCLUDE_SCRYPT_H_
#define INCLUDE_SCRYPT_H_

#include <stdint.h>  /* uint8_t */
#include <stdlib.h>  /* size_t */

typedef struct scrypt_state_s scrypt_state_t;

struct scrypt_state_s {
  unsigned int r;
  unsigned int n;
  unsigned int p;

  size_t block_size;

  /* ro_mix params */
  uint8_t* x;
  uint8_t* v;
  uint8_t* t;
};

int scrypt_state_init(scrypt_state_t* state,
                      unsigned int r,
                      unsigned int n,
                      unsigned int p);
void scrypt_state_free(scrypt_state_t* state);

#endif  /* INCLUDE_SCRYPT_H_ */
