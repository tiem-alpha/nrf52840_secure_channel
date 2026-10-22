#include "lkp1/certificate.h"
#include <string.h>

static uint16_t be16(const uint8_t *p)
{
    return ((uint16_t)p[0] << 8) | p[1];
}

static int key_id_matches(const uint8_t key[64], const uint8_t id[8],
                          const struct lkp1_cert_crypto *crypto)
{
    uint8_t hash[32];
    if (crypto->sha256(key, 64, hash) != 0) {
        return 0;
    }
    int equal = 0;
    for (size_t i = 0; i < 8; i++) {
        equal |= hash[i] ^ id[i];
    }
    memset(hash, 0, sizeof(hash));
    return equal == 0;
}

static int issuer_is_root(const uint8_t cert[LKP1_CERT_LEN],
                          const struct lkp1_root *roots, size_t count,
                          const struct lkp1_cert_crypto *crypto)
{
    for (size_t i = 0; i < count; i++) {
        if (memcmp(cert + 18, roots[i].key_id, 8) == 0 &&
            key_id_matches(roots[i].public_key, roots[i].key_id, crypto) &&
            crypto->valid_public_key(roots[i].public_key) == 0 &&
            crypto->verify(roots[i].public_key, cert, LKP1_CERT_TBS_LEN,
                           cert + LKP1_CERT_TBS_LEN) == 0) {
            return 1;
        }
    }
    return 0;
}

int lkp1_verify_certificate_chain(const uint8_t *body, size_t body_len,
    uint8_t expected_leaf_type, const struct lkp1_root *roots,
    size_t root_count, const struct lkp1_cert_crypto *crypto,
    uint8_t leaf_key[64], uint8_t subject_id[16])
{
    const uint8_t *cert[2];
    size_t offset = 1;
    if (body == NULL || roots == NULL || leaf_key == NULL ||
        subject_id == NULL || crypto == NULL || crypto->sha256 == NULL ||
        crypto->verify == NULL || crypto->valid_public_key == NULL ||
        root_count == 0 || root_count > 2 || body_len < 1 ||
        (body[0] != 1 && body[0] != 2) ||
        (expected_leaf_type != LKP1_CERT_LOCK &&
         expected_leaf_type != LKP1_CERT_PHONE)) {
        return -1;
    }
    for (size_t i = 0; i < body[0]; i++) {
        if (body_len - offset < 2) {
            return -1;
        }
        uint16_t len = be16(body + offset);
        offset += 2;
        if (len != LKP1_CERT_LEN || body_len - offset < len) {
            return -1;
        }
        cert[i] = body + offset;
        offset += len;
    }
    if (offset != body_len) {
        return -1;
    }
    const uint8_t *leaf = cert[0];
    if (leaf[0] != 1 || leaf[1] != expected_leaf_type ||
        (be16(leaf + 34) & LKP1_USAGE_HANDSHAKE) == 0 ||
        crypto->valid_public_key(leaf + 36) != 0) {
        return -1;
    }
    if (body[0] == 1) {
        if (!issuer_is_root(leaf, roots, root_count, crypto)) {
            return -1;
        }
    } else {
        const uint8_t *ca = cert[1];
        if (ca[0] != 1 || ca[1] != LKP1_CERT_CA ||
            (be16(ca + 34) & LKP1_USAGE_CA_SIGN) == 0 ||
            crypto->valid_public_key(ca + 36) != 0 ||
            !issuer_is_root(ca, roots, root_count, crypto) ||
            !key_id_matches(ca + 36, leaf + 18, crypto) ||
            crypto->verify(ca + 36, leaf, LKP1_CERT_TBS_LEN,
                           leaf + LKP1_CERT_TBS_LEN) != 0) {
            return -1;
        }
    }
    memcpy(leaf_key, leaf + 36, 64);
    memcpy(subject_id, leaf + 2, 16);
    return 0;
}
