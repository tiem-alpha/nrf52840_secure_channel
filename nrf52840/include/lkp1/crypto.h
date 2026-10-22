#ifndef LKP1_CRYPTO_H
#define LKP1_CRYPTO_H
#include <stddef.h>
#include <stdint.h>

/* The protocol core depends only on these operations. Implementations must
 * use a maintained cryptographic library and return 0 only on success. */
struct lkp1_crypto {
    int (*random)(uint8_t *out, size_t len);
    int (*sha256)(const uint8_t *in, size_t len, uint8_t out[32]);
    int (*hmac)(const uint8_t *key, size_t key_len, const uint8_t *in,
                size_t len, uint8_t out[32]);
    int (*hkdf_expand)(const uint8_t prk[32], const uint8_t *info,
                       size_t info_len, uint8_t *out, size_t out_len);
    int (*x25519_public)(const uint8_t private_key[32], uint8_t out[32]);
    int (*x25519_shared)(const uint8_t private_key[32],
                         const uint8_t peer_public[32], uint8_t out[32]);
    int (*p256_sign)(const uint8_t private_key[32], const uint8_t *in,
                     size_t len, uint8_t signature[64]);
    int (*p256_verify)(const uint8_t public_key[64], const uint8_t *in,
                       size_t len, const uint8_t signature[64]);
    int (*p256_valid)(const uint8_t public_key[64]);
    int (*gcm_encrypt)(const uint8_t key[16], const uint8_t nonce[12],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *plain, size_t plain_len,
                       uint8_t *cipher_and_tag);
    int (*gcm_decrypt)(const uint8_t key[16], const uint8_t nonce[12],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *cipher_and_tag, size_t input_len,
                       uint8_t *plain);
};

void lkp1_secure_zero(void *ptr, size_t len);
int lkp1_constant_time_equal(const uint8_t *a, const uint8_t *b, size_t len);
/* All-zero X25519 result is forbidden by the protocol. */
int lkp1_x25519_checked(const struct lkp1_crypto *crypto,
                        const uint8_t private_key[32],
                        const uint8_t peer_public[32], uint8_t shared[32]);
#endif
