#include "lkp1/keys.h"
#include <string.h>

static int expand(const struct lkp1_crypto *crypto, const uint8_t prk[32],
                  const char *label, const uint8_t *context,
                  size_t context_len, uint8_t *out, size_t out_len)
{
    uint8_t info[64];
    size_t label_len = strlen(label);
    if (label_len + context_len + 6 > sizeof(info)) {
        return -1;
    }
    memcpy(info, "LKP1 ", 5);
    memcpy(info + 5, label, label_len);
    info[5 + label_len] = 0;
    if (context_len != 0) {
        memcpy(info + 6 + label_len, context, context_len);
    }
    return crypto->hkdf_expand(prk, info, 6 + label_len + context_len,
                               out, out_len);
}

int lkp1_derive_handshake_keys(const struct lkp1_crypto *crypto,
    const uint8_t shared[32], const uint8_t c_nonce[32],
    const uint8_t s_nonce[32], const uint8_t th_hello[32],
    struct lkp1_handshake_keys *out)
{
    uint8_t salt[64];
    if (crypto == NULL || crypto->hmac == NULL ||
        crypto->hkdf_expand == NULL || out == NULL) {
        return -1;
    }
    memcpy(salt, c_nonce, 32);
    memcpy(salt + 32, s_nonce, 32);
    if (crypto->hmac(salt, sizeof(salt), shared, 32, out->prk) != 0) {
        lkp1_secure_zero(salt, sizeof(salt));
        return -1;
    }
    lkp1_secure_zero(salt, sizeof(salt));
#define DERIVE(field, label) \
    if (expand(crypto, out->prk, label, th_hello, 32, out->field, \
               sizeof(out->field)) != 0) goto fail
    DERIVE(c_hs_key, "c hs key");
    DERIVE(c_hs_iv, "c hs iv");
    DERIVE(s_hs_key, "s hs key");
    DERIVE(s_hs_iv, "s hs iv");
    DERIVE(c_fin_key, "c finished");
    DERIVE(s_fin_key, "s finished");
#undef DERIVE
    return 0;
fail:
    lkp1_secure_zero(out, sizeof(*out));
    return -1;
}

int lkp1_derive_app_keys(const struct lkp1_crypto *crypto,
    const uint8_t prk[32], const uint8_t th_app[32],
    struct lkp1_app_keys *out)
{
    uint8_t master[32];
    if (crypto == NULL || crypto->hkdf_expand == NULL || out == NULL ||
        expand(crypto, prk, "master", th_app, 32,
               master, sizeof(master)) != 0) {
        return -1;
    }
#define DERIVE(field, label) \
    if (expand(crypto, master, label, NULL, 0, out->field, \
               sizeof(out->field)) != 0) goto fail
    DERIVE(c2s_key, "c2s key");
    DERIVE(c2s_iv, "c2s iv");
    DERIVE(s2c_key, "s2c key");
    DERIVE(s2c_iv, "s2c iv");
    DERIVE(session_id, "session id");
#undef DERIVE
    lkp1_secure_zero(master, sizeof(master));
    return 0;
fail:
    lkp1_secure_zero(master, sizeof(master));
    lkp1_secure_zero(out, sizeof(*out));
    return -1;
}

void lkp1_nonce(const uint8_t iv[12], uint64_t counter, uint8_t nonce[12])
{
    memcpy(nonce, iv, 12);
    for (size_t i = 0; i < 8; i++) {
        nonce[11 - i] ^= (uint8_t)(counter >> (8 * i));
    }
}
