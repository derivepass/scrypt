#ifndef SRC_BACKEND_H_
#define SRC_BACKEND_H_

#include <stdint.h>  /* uint8_t */
#include <stdlib.h>  /* size_t */

static const int kSha256DigestSize = 32;

void scrypt_hmac_sha256(const uint8_t* key,
                        size_t key_len,
                        const uint8_t* data,
                        size_t data_len,
                        uint8_t* out);
void scrypt_hmac_sha256_vec(const uint8_t* key,
                            size_t key_len,
                            const uint8_t** data,
                            size_t* data_len,
                            size_t data_count,
                            uint8_t* out);

#endif  /* SRC_BACKEND_H_ */
