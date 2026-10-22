#include "lkp1/server.h"
#include <string.h>

/* All message and record lengths are checked before copying or decrypting. */
static void be16(uint8_t *p, size_t n)
{
    p[0] = (uint8_t)(n >> 8);
    p[1] = (uint8_t)n;
}
static uint16_t read16(const uint8_t *p)
{
    return ((uint16_t)p[0] << 8) | p[1];
}
static uint32_t read32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}
static void write32(uint8_t *p, uint32_t n)
{
    p[0] = (uint8_t)(n >> 24);
    p[1] = (uint8_t)(n >> 16);
    p[2] = (uint8_t)(n >> 8);
    p[3] = (uint8_t)n;
}
static int append(struct lkp1_server *s, const uint8_t *p, size_t n)
{
    if (n > sizeof(s->transcript) - s->transcript_len) {
        return -1;
    }
    memcpy(s->transcript + s->transcript_len, p, n);
    s->transcript_len += n;
    return 0;
}
static int digest(const struct lkp1_server *s,
                  const struct lkp1_crypto *crypto, uint8_t out[32])
{
    return crypto->sha256(s->transcript, s->transcript_len, out);
}
static size_t message(uint8_t *out, uint8_t type, const uint8_t *body,
                      size_t body_len)
{
    out[0] = type;
    be16(out + 1, body_len);
    memcpy(out + 3, body, body_len);
    return body_len + 3;
}
static void record_header(uint8_t out[4], uint8_t type, size_t body_len)
{
    out[0] = 1;
    out[1] = type;
    be16(out + 2, body_len);
}
static int next_message(const uint8_t *p, size_t total, size_t *offset,
                        uint8_t expected_type, const uint8_t **body,
                        size_t *body_len, size_t *whole_len)
{
    if (*offset > total || total - *offset < 3 ||
        p[*offset] != expected_type) {
        return -1;
    }
    *body_len = read16(p + *offset + 1);
    *whole_len = *body_len + 3;
    if (*whole_len > total - *offset) {
        return -1;
    }
    *body = p + *offset + 3;
    *offset += *whole_len;
    return 0;
}
static int signature_input(const char *label, const uint8_t hash[32],
                           uint8_t *out, size_t *len)
{
    size_t label_len = strlen(label);
    if (label_len + 33 > 64) {
        return -1;
    }
    memcpy(out, label, label_len);
    out[label_len] = 0;
    memcpy(out + label_len + 1, hash, 32);
    *len = label_len + 33;
    return 0;
}
static int input_ok(const struct lkp1_crypto *c)
{
    return c && c->random && c->sha256 && c->hmac && c->hkdf_expand &&
           c->x25519_public && c->x25519_shared && c->p256_sign &&
           c->p256_verify && c->p256_valid && c->gcm_encrypt &&
           c->gcm_decrypt;
}

void lkp1_server_reset(struct lkp1_server *server)
{
    if (server != NULL) {
        lkp1_secure_zero(server, sizeof(*server));
    }
}

int lkp1_server_f1(struct lkp1_server *s,
    const struct lkp1_server_identity *identity,
    const struct lkp1_crypto *c, const uint8_t *body, size_t body_len,
    int64_t now_ms, uint8_t *f2a, size_t *f2a_len,
    uint8_t *f2b, size_t *f2b_len)
{
    uint8_t m2[69], m3[336], m4[67], m5[35], hash[32], shared[32];
    uint8_t sign_input[64], signature[64], finished[32], nonce[12];
    uint8_t plaintext[438];
    size_t sign_len, m3_len, offset = 0;
    int result = -1;
    if (s == NULL || s->state != LKP1_IDLE || !input_ok(c) ||
        identity == NULL || identity->private_key == NULL ||
        identity->cert_body == NULL || identity->cert_body_len < 1 ||
        identity->cert_body_len > sizeof(m3) - 3 || body == NULL ||
        body_len != 69 || body[0] != 1 || read16(body + 1) != 66 ||
        read16(body + 3) != 1 || f2a == NULL || f2b == NULL ||
        f2a_len == NULL || f2b_len == NULL) {
        return -1;
    }
    s->started_ms = now_ms;
    memcpy(s->client_public, body + 5, 32);
    memcpy(s->client_nonce, body + 37, 32);
    if (append(s, body, body_len) != 0 ||
        c->random(s->ephemeral_private, 32) != 0 ||
        c->random(s->server_nonce, 32) != 0) {
        goto fail;
    }
    uint8_t hello[66] = {0, 1};
    if (c->x25519_public(s->ephemeral_private, hello + 2) != 0) {
        goto fail;
    }
    memcpy(hello + 34, s->server_nonce, 32);
    message(m2, 2, hello, sizeof(hello));
    if (append(s, m2, sizeof(m2)) != 0 || digest(s, c, hash) != 0 ||
        lkp1_x25519_checked(c, s->ephemeral_private,
                             s->client_public, shared) != 0 ||
        lkp1_derive_handshake_keys(c, shared, s->client_nonce,
            s->server_nonce, hash, &s->hs) != 0) {
        goto fail;
    }
    lkp1_secure_zero(shared, sizeof(shared));
    m3_len = message(m3, 0x0b, identity->cert_body,
                     identity->cert_body_len);
    if (append(s, m3, m3_len) != 0 || digest(s, c, hash) != 0 ||
        signature_input("LKP1-SIG-SERVER", hash, sign_input,
                        &sign_len) != 0 ||
        c->p256_sign(identity->private_key, sign_input,
                     sign_len, signature) != 0) {
        goto fail;
    }
    message(m4, 0x0f, signature, sizeof(signature));
    if (append(s, m4, sizeof(m4)) != 0 || digest(s, c, hash) != 0 ||
        c->hmac(s->hs.s_fin_key, 32, hash, 32, finished) != 0) {
        goto fail;
    }
    message(m5, 0x14, finished, sizeof(finished));
    if (append(s, m5, sizeof(m5)) != 0) {
        goto fail;
    }
    memcpy(plaintext + offset, m3, m3_len); offset += m3_len;
    memcpy(plaintext + offset, m4, sizeof(m4)); offset += sizeof(m4);
    memcpy(plaintext + offset, m5, sizeof(m5)); offset += sizeof(m5);
    if (offset > 1008) {
        goto fail;
    }
    record_header(f2a, 1, sizeof(m2));
    memcpy(f2a + 4, m2, sizeof(m2));
    *f2a_len = sizeof(m2) + 4;
    record_header(f2b, 2, offset + 16);
    lkp1_nonce(s->hs.s_hs_iv, 0, nonce);
    if (c->gcm_encrypt(s->hs.s_hs_key, nonce, f2b, 4,
                       plaintext, offset, f2b + 4) != 0) {
        goto fail;
    }
    *f2b_len = offset + 20;
    s->state = LKP1_WAIT_F3;
    result = 0;
fail:
    lkp1_secure_zero(shared, sizeof(shared));
    lkp1_secure_zero(signature, sizeof(signature));
    lkp1_secure_zero(sign_input, sizeof(sign_input));
    lkp1_secure_zero(plaintext, sizeof(plaintext));
    if (result != 0) {
        lkp1_server_reset(s);
    }
    return result;
}

int lkp1_server_f3(struct lkp1_server *s,
    const struct lkp1_server_identity *identity,
    const struct lkp1_crypto *c, const uint8_t *body, size_t body_len,
    int64_t now_ms)
{
    uint8_t plaintext[1008], nonce[12], header[4], hash[32], input[64];
    uint8_t leaf_key[64], subject_id[16], finished[32];
    const uint8_t *cert, *sig, *fin;
    size_t cert_len, sig_len, fin_len, whole, offset = 0, input_len;
    struct lkp1_cert_crypto cert_crypto;
    int result = -1;
    if (s == NULL || s->state != LKP1_WAIT_F3 || identity == NULL ||
        identity->roots == NULL || !input_ok(c) || body == NULL ||
        body_len < 16 || body_len > sizeof(plaintext) + 16 ||
        now_ms - s->started_ms > 10000) {
        return -1;
    }
    record_header(header, 2, body_len);
    lkp1_nonce(s->hs.c_hs_iv, 0, nonce);
    if (c->gcm_decrypt(s->hs.c_hs_key, nonce, header, 4, body,
                       body_len, plaintext) != 0) {
        goto fail;
    }
    size_t plain_len = body_len - 16;
    if (next_message(plaintext, plain_len, &offset, 0x0b,
                     &cert, &cert_len, &whole) != 0 ||
        append(s, plaintext, whole) != 0) {
        goto fail;
    }
    cert_crypto.sha256 = c->sha256;
    cert_crypto.verify = c->p256_verify;
    cert_crypto.valid_public_key = c->p256_valid;
    if (lkp1_verify_certificate_chain(cert, cert_len, LKP1_CERT_PHONE,
        identity->roots, identity->root_count, &cert_crypto,
        leaf_key, subject_id) != 0) {
        goto fail;
    }
    size_t sig_start = offset;
    if (next_message(plaintext, plain_len, &offset, 0x0f,
                     &sig, &sig_len, &whole) != 0 || sig_len != 64 ||
        digest(s, c, hash) != 0 ||
        signature_input("LKP1-SIG-CLIENT", hash, input,
                        &input_len) != 0 ||
        c->p256_verify(leaf_key, input, input_len, sig) != 0 ||
        append(s, plaintext + sig_start, whole) != 0) {
        goto fail;
    }
    size_t fin_start = offset;
    if (next_message(plaintext, plain_len, &offset, 0x14,
                     &fin, &fin_len, &whole) != 0 || fin_len != 32 ||
        offset != plain_len || digest(s, c, hash) != 0 ||
        c->hmac(s->hs.c_fin_key, 32, hash, 32, finished) != 0 ||
        !lkp1_constant_time_equal(fin, finished, 32) ||
        append(s, plaintext + fin_start, whole) != 0 ||
        digest(s, c, hash) != 0 ||
        lkp1_derive_app_keys(c, s->hs.prk, hash, &s->app) != 0) {
        goto fail;
    }
    memcpy(s->client_id, subject_id, 16);
    lkp1_secure_zero(&s->hs, sizeof(s->hs));
    lkp1_secure_zero(s->ephemeral_private, 32);
    lkp1_secure_zero(s->transcript, sizeof(s->transcript));
    s->transcript_len = 0;
    s->opened_ms = now_ms;
    s->state = LKP1_OPEN;
    result = 0;
fail:
    lkp1_secure_zero(plaintext, sizeof(plaintext));
    lkp1_secure_zero(input, sizeof(input));
    lkp1_secure_zero(leaf_key, sizeof(leaf_key));
    lkp1_secure_zero(finished, sizeof(finished));
    if (result != 0) {
        lkp1_server_reset(s);
    }
    return result;
}

static int app_state_ok(const struct lkp1_server *s, int64_t now_ms)
{
    return s != NULL && s->state == LKP1_OPEN &&
           now_ms >= s->opened_ms &&
           now_ms - s->opened_ms <= 24LL * 60 * 60 * 1000;
}

int lkp1_server_open_data(struct lkp1_server *s,
    const struct lkp1_crypto *c, const uint8_t *body, size_t body_len,
    int64_t now_ms, uint8_t *plain, size_t *plain_len)
{
    uint8_t header[4], aad[12], nonce[12];
    if (!app_state_ok(s, now_ms) || c == NULL || c->gcm_decrypt == NULL ||
        body == NULL || plain == NULL || plain_len == NULL ||
        body_len < 24 || body_len > LKP1_MAX_APP_PLAINTEXT + 24 ||
        !lkp1_constant_time_equal(body, s->app.session_id, 4) ||
        s->rx_seq == UINT32_MAX || read32(body + 4) != s->rx_seq) {
        return -1;
    }
    record_header(header, 3, body_len);
    memcpy(aad, header, 4);
    memcpy(aad + 4, body, 8);
    lkp1_nonce(s->app.c2s_iv, s->rx_seq, nonce);
    if (c->gcm_decrypt(s->app.c2s_key, nonce, aad, sizeof(aad),
                       body + 8, body_len - 8, plain) != 0) {
        return -1;
    }
    *plain_len = body_len - 24;
    s->rx_seq++;
    return 0;
}

int lkp1_server_seal_data(struct lkp1_server *s,
    const struct lkp1_crypto *c, const uint8_t *plain, size_t plain_len,
    int64_t now_ms, uint8_t *record, size_t *record_len)
{
    uint8_t nonce[12];
    if (!app_state_ok(s, now_ms) || c == NULL || c->gcm_encrypt == NULL ||
        plain == NULL || record == NULL || record_len == NULL ||
        plain_len > LKP1_MAX_APP_PLAINTEXT || s->tx_seq == UINT32_MAX) {
        return -1;
    }
    record_header(record, 3, plain_len + 24);
    memcpy(record + 4, s->app.session_id, 4);
    write32(record + 8, s->tx_seq);
    lkp1_nonce(s->app.s2c_iv, s->tx_seq, nonce);
    if (c->gcm_encrypt(s->app.s2c_key, nonce, record, 12,
                       plain, plain_len, record + 12) != 0) {
        return -1;
    }
    *record_len = plain_len + 28;
    s->tx_seq++;
    return 0;
}
