#include "lkp1/server.h"
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "vectors.h"

static int random_calls;
static int test_random(uint8_t *out, size_t len)
{
    if (len != 32 || random_calls >= 2) return -1;
    memcpy(out, random_calls++ == 0 ? v_server_ephemeral_private : v_server_nonce, len);
    return 0;
}
static int hash(const uint8_t *in, size_t n, uint8_t out[32])
{ return SHA256(in, n, out) ? 0 : -1; }
static int mac(const uint8_t *key, size_t kn, const uint8_t *in, size_t n, uint8_t out[32])
{
    unsigned int len = 0;
    return HMAC(EVP_sha256(), key, (int)kn, in, n, out, &len) && len == 32 ? 0 : -1;
}
/* HKDF-Expand (RFC 5869), with PRK supplied by the protocol core. */
static int expand(const uint8_t prk[32], const uint8_t *info, size_t info_len,
                  uint8_t *out, size_t out_len)
{
    uint8_t block[32], data[32 + 64 + 1];
    size_t used = 0, previous = 0;
    unsigned int counter = 1;
    if (info_len > 64 || out_len > 255 * 32) return -1;
    while (used < out_len) {
        memcpy(data, block, previous);
        memcpy(data + previous, info, info_len);
        data[previous + info_len] = (uint8_t)counter++;
        if (mac(prk, 32, data, previous + info_len + 1, block)) return -1;
        size_t take = out_len - used < 32 ? out_len - used : 32;
        memcpy(out + used, block, take);
        used += take;
        previous = 32;
    }
    OPENSSL_cleanse(block, sizeof(block));
    return 0;
}
static int x_public(const uint8_t priv[32], uint8_t out[32])
{
    int ok = -1; size_t n = 32;
    EVP_PKEY *p = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, 32);
    if (p && EVP_PKEY_get_raw_public_key(p, out, &n) == 1 && n == 32) ok = 0;
    EVP_PKEY_free(p); return ok;
}
static int x_shared(const uint8_t priv[32], const uint8_t pub[32], uint8_t out[32])
{
    int ok = -1; size_t n = 32;
    EVP_PKEY *a = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, 32);
    EVP_PKEY *b = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, pub, 32);
    EVP_PKEY_CTX *ctx = a ? EVP_PKEY_CTX_new(a, NULL) : NULL;
    if (ctx && b && EVP_PKEY_derive_init(ctx) == 1 &&
        EVP_PKEY_derive_set_peer(ctx, b) == 1 &&
        EVP_PKEY_derive(ctx, out, &n) == 1 && n == 32) ok = 0;
    EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(a); EVP_PKEY_free(b); return ok;
}
static EC_KEY *public_key(const uint8_t raw[64])
{
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    uint8_t point[65] = {4};
    memcpy(point + 1, raw, 64);
    if (!key || EC_KEY_oct2key(key, point, sizeof(point), NULL) != 1 ||
        EC_KEY_check_key(key) != 1) { EC_KEY_free(key); return NULL; }
    return key;
}
static int valid(const uint8_t raw[64])
{ EC_KEY *key = public_key(raw); EC_KEY_free(key); return key ? 0 : -1; }
static int verify(const uint8_t pub[64], const uint8_t *in, size_t n, const uint8_t sig[64])
{
    uint8_t digest[32];
    EC_KEY *key = public_key(pub);
    ECDSA_SIG *s = ECDSA_SIG_new();
    BIGNUM *r = BN_bin2bn(sig, 32, NULL), *t = BN_bin2bn(sig + 32, 32, NULL);
    int ok = -1;
    if (key && s && r && t && ECDSA_SIG_set0(s, r, t) == 1) {
        r = t = NULL;
        if (hash(in, n, digest) == 0 && ECDSA_do_verify(digest, 32, s, key) == 1) ok = 0;
    }
    BN_free(r); BN_free(t); ECDSA_SIG_free(s); EC_KEY_free(key); return ok;
}
/* The fixture freezes its randomized ECDSA signature. This callback only
 * reproduces F2 byte-for-byte; peer verification still uses OpenSSL. */
static int fixture_sign(const uint8_t priv[32], const uint8_t *in, size_t n, uint8_t sig[64])
{
    (void)in; (void)n;
    if (memcmp(priv, v_server_private, 32)) return -1;
    memcpy(sig, v_M4 + 3, 64);
    return 0;
}
static int gcm(int enc, const uint8_t key[16], const uint8_t nonce[12],
               const uint8_t *aad, size_t aad_len, const uint8_t *input,
               size_t input_len, uint8_t *out)
{
    int n = 0, done = 0, ok = -1;
    if (!enc && input_len < 16) return -1;
    size_t text_len = enc ? input_len : input_len - 16;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    if (EVP_CipherInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL, enc) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1 ||
        EVP_CipherInit_ex(ctx, NULL, NULL, key, nonce, enc) != 1 ||
        EVP_CipherUpdate(ctx, NULL, &n, aad, (int)aad_len) != 1 ||
        EVP_CipherUpdate(ctx, out, &n, input, (int)text_len) != 1) goto end;
    done = n;
    if (!enc && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                                      (void *)(input + text_len)) != 1) goto end;
    if (EVP_CipherFinal_ex(ctx, out + done, &n) != 1) goto end;
    if (enc && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16,
                                    out + text_len) != 1) goto end;
    ok = 0;
end:
    EVP_CIPHER_CTX_free(ctx); return ok;
}
static int encrypt(const uint8_t k[16], const uint8_t iv[12], const uint8_t *aad,
                   size_t an, const uint8_t *p, size_t pn, uint8_t *out)
{ return gcm(1, k, iv, aad, an, p, pn, out); }
static int decrypt(const uint8_t k[16], const uint8_t iv[12], const uint8_t *aad,
                   size_t an, const uint8_t *p, size_t pn, uint8_t *out)
{ return gcm(0, k, iv, aad, an, p, pn, out); }
static const struct lkp1_crypto crypto = {
    test_random, hash, mac, expand, x_public, x_shared, fixture_sign,
    verify, valid, encrypt, decrypt
};

int main(void)
{
    struct lkp1_server server = {0};
    struct lkp1_root root = {0};
    uint8_t f2a[128], f2b[512], plain[512];
    size_t f2a_len = 0, f2b_len = 0, plain_len = 0;
    memcpy(root.public_key, v_roots, 64);
    uint8_t digest[32];
    assert(hash(v_roots, 64, digest) == 0);
    memcpy(root.key_id, digest, 8);
    uint8_t cert_body[1 + 2 + sizeof(v_server_chain)] = {1, 0, sizeof(v_server_chain)};
    memcpy(cert_body + 3, v_server_chain, sizeof(v_server_chain));
    struct lkp1_server_identity identity = {
        cert_body, sizeof(cert_body), v_server_private, &root, 1
    };
    uint8_t bad_m1[sizeof(v_M1)];
    memcpy(bad_m1, v_M1, sizeof(bad_m1));
    bad_m1[4] = 2; /* suite downgrade */
    assert(lkp1_server_f1(&server, &identity, &crypto, bad_m1,
        sizeof(bad_m1), 999, f2a, &f2a_len, f2b, &f2b_len) != 0);
    memcpy(bad_m1, v_M1, sizeof(bad_m1));
    memset(bad_m1 + 5, 0, 32); /* low-order X25519 point */
    assert(lkp1_server_f1(&server, &identity, &crypto, bad_m1,
        sizeof(bad_m1), 999, f2a, &f2a_len, f2b, &f2b_len) != 0);
    random_calls = 0;
    assert(lkp1_server_f1(&server, &identity, &crypto, v_M1, sizeof(v_M1),
                          1000, f2a, &f2a_len, f2b, &f2b_len) == 0);
    assert(f2a_len == sizeof(v_F2a) && memcmp(f2a, v_F2a, f2a_len) == 0);
    assert(f2b_len == sizeof(v_F2b) && memcmp(f2b, v_F2b, f2b_len) == 0);
    assert(memcmp(server.hs.c_hs_key, v_c_hs_key, 16) == 0);
    assert(memcmp(server.hs.s_hs_key, v_s_hs_key, 16) == 0);
    uint8_t bad_f3[sizeof(v_F3)];
    memcpy(bad_f3, v_F3, sizeof(bad_f3));
    bad_f3[sizeof(bad_f3) - 1] ^= 1;
    struct lkp1_server invalid = server;
    assert(lkp1_server_f3(&invalid, &identity, &crypto, bad_f3 + 4,
        sizeof(bad_f3) - 4, 2000) != 0);
    assert(invalid.state == LKP1_IDLE);
    assert(lkp1_server_f3(&server, &identity, &crypto, v_F3 + 4,
                          sizeof(v_F3) - 4, 2000) == 0);
    assert(server.state == LKP1_OPEN);
    assert(memcmp(server.client_id, v_client_id, 16) == 0);
    assert(memcmp(server.app.c2s_key, v_c2s_key, 16) == 0);
    assert(memcmp(server.app.c2s_iv, v_c2s_iv, 12) == 0);
    assert(memcmp(server.app.s2c_key, v_s2c_key, 16) == 0);
    assert(memcmp(server.app.s2c_iv, v_s2c_iv, 12) == 0);
    assert(memcmp(server.app.session_id, v_session_id, 4) == 0);
    uint8_t bad_app[sizeof(v_app0)];
    memcpy(bad_app, v_app0, sizeof(bad_app));
    bad_app[sizeof(bad_app) - 1] ^= 1;
    assert(lkp1_server_open_data(&server, &crypto, bad_app + 4,
        sizeof(bad_app) - 4, 2001, plain, &plain_len) != 0);
    memcpy(bad_app, v_app0, sizeof(bad_app));
    bad_app[11] = 1; /* skip sequence zero */
    assert(lkp1_server_open_data(&server, &crypto, bad_app + 4,
        sizeof(bad_app) - 4, 2001, plain, &plain_len) != 0);
    assert(lkp1_server_open_data(&server, &crypto, v_app0 + 4,
        sizeof(v_app0) - 4, 2001, plain, &plain_len) == 0);
    assert(plain_len == sizeof(v_app0_plaintext));
    assert(memcmp(plain, v_app0_plaintext, plain_len) == 0);
    assert(lkp1_server_open_data(&server, &crypto, v_app0 + 4,
        sizeof(v_app0) - 4, 2002, plain, &plain_len) != 0);
    puts("LKP1 server fixture: OK");
    return 0;
}
