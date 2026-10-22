#ifndef LKP1_CERTIFICATE_H
#define LKP1_CERTIFICATE_H
#include <stddef.h>
#include <stdint.h>

#define LKP1_CERT_LEN 164u
#define LKP1_CERT_TBS_LEN 100u
#define LKP1_CERT_LOCK 1u
#define LKP1_CERT_PHONE 2u
#define LKP1_CERT_CA 0x10u
#define LKP1_USAGE_HANDSHAKE 1u
#define LKP1_USAGE_CA_SIGN 2u

/* Exactly 64-byte P-256 X||Y keys. Key IDs are SHA256(key)[0..7]. */
struct lkp1_root {
    uint8_t public_key[64];
    uint8_t key_id[8];
};

/* PSA/OpenSSL adapters must reject off-curve points and invalid ECDSA r,s. */
struct lkp1_cert_crypto {
    int (*sha256)(const uint8_t *input, size_t len, uint8_t digest[32]);
    int (*verify)(const uint8_t public_key[64], const uint8_t *message,
                  size_t len, const uint8_t signature[64]);
    int (*valid_public_key)(const uint8_t public_key[64]);
};

/* Input is Certificate message BODY, leaf first, with 1 or 2 certs.
 * Lock has no trusted clock; time checks are left to the phone. On success
 * leaf_key and subject_id are copied to caller-owned buffers. */
int lkp1_verify_certificate_chain(const uint8_t *body, size_t body_len,
    uint8_t expected_leaf_type, const struct lkp1_root *roots,
    size_t root_count, const struct lkp1_cert_crypto *crypto,
    uint8_t leaf_key[64], uint8_t subject_id[16]);
#endif
