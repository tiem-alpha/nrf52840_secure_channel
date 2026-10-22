#include "lkp1/crypto_psa.h"
#include <psa/crypto.h>
#include <string.h>

static int random_bytes(uint8_t *out, size_t len)
{
    return psa_generate_random(out, len) == PSA_SUCCESS ? 0 : -1;
}

static int sha256(const uint8_t *in, size_t len, uint8_t out[32])
{
    size_t actual = 0;
    return psa_hash_compute(PSA_ALG_SHA_256, in, len, out, 32,
                            &actual) == PSA_SUCCESS && actual == 32 ? 0 : -1;
}

static int import_key(psa_key_type_t type, psa_key_usage_t usage,
                      psa_algorithm_t algorithm, const uint8_t *data,
                      size_t length, psa_key_id_t *id)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, type);
    psa_set_key_usage_flags(&attr, usage);
    psa_set_key_algorithm(&attr, algorithm);
    psa_status_t result = psa_import_key(&attr, data, length, id);
    psa_reset_key_attributes(&attr);
    return result == PSA_SUCCESS ? 0 : -1;
}

static int hmac_sha256(const uint8_t *key, size_t key_len,
                       const uint8_t *in, size_t len, uint8_t out[32])
{
    psa_key_id_t id = 0;
    size_t actual = 0;
    if (import_key(PSA_KEY_TYPE_HMAC, PSA_KEY_USAGE_SIGN_MESSAGE,
                   PSA_ALG_HMAC(PSA_ALG_SHA_256), key, key_len, &id) != 0) {
        return -1;
    }
    psa_status_t result = psa_mac_compute(id, PSA_ALG_HMAC(PSA_ALG_SHA_256),
                                          in, len, out, 32, &actual);
    (void)psa_destroy_key(id);
    return result == PSA_SUCCESS && actual == 32 ? 0 : -1;
}

static int hkdf_expand(const uint8_t prk[32], const uint8_t *info,
                       size_t info_len, uint8_t *out, size_t out_len)
{
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_status_t result = psa_key_derivation_setup(
        &op, PSA_ALG_HKDF_EXPAND(PSA_ALG_SHA_256));
    if (result == PSA_SUCCESS) {
        result = psa_key_derivation_input_bytes(
            &op, PSA_KEY_DERIVATION_INPUT_SECRET, prk, 32);
    }
    if (result == PSA_SUCCESS) {
        result = psa_key_derivation_input_bytes(
            &op, PSA_KEY_DERIVATION_INPUT_INFO, info, info_len);
    }
    if (result == PSA_SUCCESS) {
        result = psa_key_derivation_output_bytes(&op, out, out_len);
    }
    (void)psa_key_derivation_abort(&op);
    return result == PSA_SUCCESS ? 0 : -1;
}

static int x25519_public(const uint8_t private_key[32], uint8_t out[32])
{
    psa_key_id_t id = 0;
    size_t actual = 0;
    if (import_key(PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY),
                   PSA_KEY_USAGE_EXPORT, PSA_ALG_ECDH,
                   private_key, 32, &id) != 0) {
        return -1;
    }
    psa_status_t result = psa_export_public_key(id, out, 32, &actual);
    (void)psa_destroy_key(id);
    return result == PSA_SUCCESS && actual == 32 ? 0 : -1;
}

static int x25519_shared(const uint8_t private_key[32],
                         const uint8_t peer_public[32], uint8_t out[32])
{
    psa_key_id_t id = 0;
    size_t actual = 0;
    if (import_key(PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY),
                   PSA_KEY_USAGE_DERIVE, PSA_ALG_ECDH,
                   private_key, 32, &id) != 0) {
        return -1;
    }
    psa_status_t result = psa_raw_key_agreement(PSA_ALG_ECDH, id,
        peer_public, 32, out, 32, &actual);
    (void)psa_destroy_key(id);
    return result == PSA_SUCCESS && actual == 32 ? 0 : -1;
}

static int p256_sign(const uint8_t private_key[32], const uint8_t *in,
                     size_t len, uint8_t signature[64])
{
    psa_key_id_t id = 0;
    size_t actual = 0;
    if (import_key(PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1),
                   PSA_KEY_USAGE_SIGN_MESSAGE,
                   PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                   private_key, 32, &id) != 0) {
        return -1;
    }
    psa_status_t result = psa_sign_message(id,
        PSA_ALG_ECDSA(PSA_ALG_SHA_256), in, len, signature, 64, &actual);
    (void)psa_destroy_key(id);
    return result == PSA_SUCCESS && actual == 64 ? 0 : -1;
}

static int p256_public_import(const uint8_t key[64], psa_key_usage_t usage,
                              psa_key_id_t *id)
{
    uint8_t sec1[65] = { 4 };
    memcpy(sec1 + 1, key, 64);
    return import_key(PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1),
        usage, PSA_ALG_ECDSA(PSA_ALG_SHA_256), sec1, sizeof(sec1), id);
}

static int p256_valid(const uint8_t key[64])
{
    psa_key_id_t id = 0;
    if (p256_public_import(key, PSA_KEY_USAGE_VERIFY_MESSAGE, &id) != 0) {
        return -1;
    }
    (void)psa_destroy_key(id);
    return 0;
}

static int p256_verify(const uint8_t key[64], const uint8_t *in,
                       size_t len, const uint8_t signature[64])
{
    psa_key_id_t id = 0;
    if (p256_public_import(key, PSA_KEY_USAGE_VERIFY_MESSAGE, &id) != 0) {
        return -1;
    }
    psa_status_t result = psa_verify_message(id,
        PSA_ALG_ECDSA(PSA_ALG_SHA_256), in, len, signature, 64);
    (void)psa_destroy_key(id);
    return result == PSA_SUCCESS ? 0 : -1;
}

static int gcm(const uint8_t key[16], const uint8_t nonce[12],
               const uint8_t *aad, size_t aad_len, const uint8_t *input,
               size_t input_len, uint8_t *output, int decrypt)
{
    psa_key_id_t id = 0;
    size_t actual = 0;
    psa_key_usage_t usage = decrypt ? PSA_KEY_USAGE_DECRYPT :
                                      PSA_KEY_USAGE_ENCRYPT;
    if (import_key(PSA_KEY_TYPE_AES, usage, PSA_ALG_GCM, key, 16,
                   &id) != 0) {
        return -1;
    }
    psa_status_t result;
    if (decrypt) {
        if (input_len < 16) {
            (void)psa_destroy_key(id);
            return -1;
        }
        result = psa_aead_decrypt(id, PSA_ALG_GCM, nonce, 12, aad, aad_len,
            input, input_len, output, input_len - 16, &actual);
    } else {
        result = psa_aead_encrypt(id, PSA_ALG_GCM, nonce, 12, aad, aad_len,
            input, input_len, output, input_len + 16, &actual);
    }
    (void)psa_destroy_key(id);
    return result == PSA_SUCCESS &&
           actual == (decrypt ? input_len - 16 : input_len + 16) ? 0 : -1;
}

static int encrypt(const uint8_t key[16], const uint8_t nonce[12],
                   const uint8_t *aad, size_t aad_len, const uint8_t *plain,
                   size_t len, uint8_t *cipher_and_tag)
{
    return gcm(key, nonce, aad, aad_len, plain, len, cipher_and_tag, 0);
}

static int decrypt(const uint8_t key[16], const uint8_t nonce[12],
                   const uint8_t *aad, size_t aad_len, const uint8_t *input,
                   size_t len, uint8_t *plain)
{
    return gcm(key, nonce, aad, aad_len, input, len, plain, 1);
}

const struct lkp1_crypto lkp1_psa_crypto = {
    .random = random_bytes,
    .sha256 = sha256,
    .hmac = hmac_sha256,
    .hkdf_expand = hkdf_expand,
    .x25519_public = x25519_public,
    .x25519_shared = x25519_shared,
    .p256_sign = p256_sign,
    .p256_verify = p256_verify,
    .p256_valid = p256_valid,
    .gcm_encrypt = encrypt,
    .gcm_decrypt = decrypt,
};
