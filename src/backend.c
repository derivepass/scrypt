#include "src/backend.h"

void scrypt_hmac_sha256(const uint8_t* key,
                        size_t key_len,
                        const uint8_t* data,
                        size_t data_len,
                        uint8_t* out) {
  scrypt_hmac_sha256_vec(key, key_len, &data, &data_len, 1, out);
}
