#ifndef LKP1_KEYS_H
#define LKP1_KEYS_H
#include "lkp1/crypto.h"
#include <stdint.h>

struct lkp1_handshake_keys {
    uint8_t prk[32];
    uint8_t c_hs_key[16], c_hs_iv[12];
    uint8_t s_hs_key[16], s_hs_iv[12];
    uint8_t c_fin_key[32], s_fin_key[32];
};
struct lkp1_app_keys {
    uint8_t c2s_key[16], c2s_iv[12];
    uint8_t s2c_key[16], s2c_iv[12];
    uint8_t session_id[4];
};

int lkp1_derive_handshake_keys(const struct lkp1_crypto *crypto,
    const uint8_t shared[32], const uint8_t c_nonce[32],
    const uint8_t s_nonce[32], const uint8_t th_hello[32],
    struct lkp1_handshake_keys *out);
int lkp1_derive_app_keys(const struct lkp1_crypto *crypto,
    const uint8_t prk[32], const uint8_t th_app[32],
    struct lkp1_app_keys *out);
void lkp1_nonce(const uint8_t iv[12], uint64_t counter, uint8_t nonce[12]);
#endif
