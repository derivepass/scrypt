#include <stdlib.h>
#include <string.h>

#include "src/scrypt.h"
#include "include/scrypt.h"
#include "src/salsa20.h"


static int kScryptSalsaRounds = 4;
static int kScryptBlockMultiplier = 128;

static void scrypt_xor(const uint8_t* a,
                       const uint8_t* b,
                       size_t size,
                       uint8_t* out) {
  size_t i;

  for (i = 0; i < size; i++)
    out[i] = a[i] ^ b[i];
}

void scrypt_block_mix(const uint8_t* b, unsigned int r, uint8_t* output) {
  /*
   * Algorithm scryptBlockMix
   *
   * Parameters:
   *          r       Block size parameter.
   *
   * Input:
   *          B[0], ..., B[2 * r - 1]
   *                 Input vector of 2 * r 64-octet blocks.
   *
   * Output:
   *          B'[0], ..., B'[2 * r - 1]
   *                  Output vector of 2 * r 64-octet blocks.
   *
   * Steps:
   *
   *   1. X = B[2 * r - 1]
   *
   *   2. for i = 0 to 2 * r - 1 do
   *        T = X xor B[i]
   *        X = Salsa (T)
   *        Y[i] = X
   *      end for
   *
   *   3. B' = (Y[0], Y[2], ..., Y[2 * r - 2],
   *            Y[1], Y[3], ..., Y[2 * r - 1])
   */

  uint8_t x[kSalsa20BlockSize];
  unsigned int i;

  /* Step 1 */
  memcpy(x, &b[(2 * r - 1) * kSalsa20BlockSize], sizeof(x));

  /* Step 2 */
  for (i = 0; i < 2 * r; i++) {
    uint8_t t[sizeof(x)];

    scrypt_xor(x, &b[i * kSalsa20BlockSize], kSalsa20BlockSize, t);
    scrypt_salsa20(t, kScryptSalsaRounds, x);

    /* Step 3 */
    memcpy(&output[i * kSalsa20BlockSize], x, sizeof(x));
  }
}


static uint64_t scrypt_integerify(const uint8_t* x, scrypt_state_t* state) {
  const uint8_t* p;
  uint64_t res;

  p = &x[state->block_size - kScryptBlockMultiplier / 2];
  res = (uint64_t) p[0] + ((uint64_t) p[1] << 8) +
        ((uint64_t) p[2] << 16) + ((uint64_t) p[3] << 24) +
        ((uint64_t) p[4] << 32) + ((uint64_t) p[5] << 40) +
        ((uint64_t) p[6] << 48) + ((uint64_t) p[7] << 56);

  return res;
}


void scrypt_ro_mix(const uint8_t* b, scrypt_state_t* state, uint8_t* output) {
  /*
   * Algorithm scryptROMix
   *
   *   Input:
   *            r       Block size parameter.
   *            B       Input octet vector of length 128 * r octets.
   *            N       CPU/Memory cost parameter, must be larger than 1,
   *                    a power of 2 and less than 2^(128 * r / 8).
   *
   *   Output:
   *            B'      Output octet vector of length 128 * r octets.
   *
   *   Steps:
   *
   *     1. X = B
   *
   *     2. for i = 0 to N - 1 do
   *          V[i] = X
   *          X = scryptBlockMix (X)
   *        end for
   *
   *     3. for i = 0 to N - 1 do
   *          j = Integerify (X) mod N
   *                 where Integerify (B[0] ... B[2 * r - 1]) is defined
   *                 as the result of interpreting B[2 * r - 1] as a
   *                 little-endian integer.
   *          T = X xor V[j]
   *          X = scryptBlockMix (T)
   *        end for
   *
   *     4. B' = X
   */

  uint8_t* x;
  uint8_t* v;
  uint8_t* t;
  unsigned int i;

  x = state->x;
  v = state->v;
  t = state->t;

  /* Step 1 */
  memcpy(x, b, state->block_size);

  /* Step 2 */
  for (i = 0; i < state->n; i++) {
    memcpy(&v[state->block_size * i], x, state->block_size);
    scrypt_block_mix(x, state->r, x);
  }

  /* Step 3 */
  for (i = 0; i < state->n; i++) {
    int j;

    j = scrypt_integerify(x, state) % state->n;
    scrypt_xor(x, &v[j * state->block_size], state->block_size, t);
    scrypt_block_mix(t, state->r, x);
  }

  memcpy(output, x, state->block_size);
}


int scrypt_state_init(scrypt_state_t* state,
                      unsigned int r,
                      unsigned int n,
                      unsigned int p) {
  state->r = r;
  state->n = n;
  state->p = p;

  state->block_size = kScryptBlockMultiplier * r;

  state->x = malloc(state->block_size);
  if (state->x == NULL)
    goto failed_alloc_x;

  state->v = malloc(state->block_size * n);
  if (state->v == NULL)
    goto failed_alloc_v;

  state->t = malloc(state->block_size);
  if (state->t == NULL)
    goto failed_alloc_t;

  return 0;

failed_alloc_t:
  free(state->v);
  state->v = NULL;

failed_alloc_v:
  free(state->x);
  state->x = NULL;

failed_alloc_x:
  return -1;
}


void scrypt_state_free(scrypt_state_t* state) {
  free(state->v);
  free(state->x);
  free(state->t);
  memset(state, 0, sizeof(*state));
}
