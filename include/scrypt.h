#ifndef INCLUDE_SCRYPT_H_
#define INCLUDE_SCRYPT_H_

#include <stdint.h>  /* uint8_t */
#include <stdlib.h>  /* size_t */

/* Auxiliary functions */

void scrypt_pbkdf2_sha256(const uint8_t* password,
                          size_t password_len,
                          const uint8_t* salt,
                          size_t salt_len,
                          unsigned int c,
                          uint8_t* out,
                          size_t out_len);

#endif  /* INCLUDE_SCRYPT_H_ */
