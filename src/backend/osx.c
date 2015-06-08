#include <CommonCrypto/CommonHMAC.h>

#include "src/backend.h"

void scrypt_hmac_sha256_vec(const uint8_t* key,
                            size_t key_len,
                            const uint8_t** data,
                            size_t* data_len,
                            size_t data_count,
                            uint8_t* out) {
  CCHmacContext ctx;
  size_t i;

  CCHmacInit(&ctx, kCCHmacAlgSHA256, key, key_len);
  for (i = 0; i < data_count; i++)
    CCHmacUpdate(&ctx, data[i], data_len[i]);
  CCHmacFinal(&ctx, out);
}
