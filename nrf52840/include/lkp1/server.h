#ifndef LKP1_SERVER_H
#define LKP1_SERVER_H
#include "lkp1/certificate.h"
#include "lkp1/crypto.h"
#include "lkp1/keys.h"
#include <stddef.h>
#include <stdint.h>

#define LKP1_MAX_TRANSCRIPT 1200u
#define LKP1_MAX_APP_PLAINTEXT 512u

enum lkp1_server_state { LKP1_IDLE, LKP1_WAIT_F3, LKP1_OPEN };

/* cert_body is the complete Certificate message BODY, including count and
 * big-endian lengths. Its leaf must correspond to private_key. */
struct lkp1_server_identity {
    const uint8_t *cert_body;
    size_t cert_body_len;
    const uint8_t *private_key;
    const struct lkp1_root *roots;
    size_t root_count;
};

struct lkp1_server {
    enum lkp1_server_state state;
    uint8_t transcript[LKP1_MAX_TRANSCRIPT];
    size_t transcript_len;
    uint8_t ephemeral_private[32];
    uint8_t client_nonce[32], server_nonce[32];
    uint8_t client_public[32];
    uint8_t client_id[16];
    struct lkp1_handshake_keys hs;
    struct lkp1_app_keys app;
    uint32_t rx_seq, tx_seq;
    int64_t started_ms, opened_ms;
};

/* Output consists of two complete records: plaintext M2 and encrypted
 * M3||M4||M5. Caller sends them in order. */
int lkp1_server_f1(struct lkp1_server *server,
    const struct lkp1_server_identity *identity,
    const struct lkp1_crypto *crypto, const uint8_t *body, size_t body_len,
    int64_t now_ms, uint8_t *f2a, size_t *f2a_len,
    uint8_t *f2b, size_t *f2b_len);
int lkp1_server_f3(struct lkp1_server *server,
    const struct lkp1_server_identity *identity,
    const struct lkp1_crypto *crypto, const uint8_t *body, size_t body_len,
    int64_t now_ms);
int lkp1_server_open_data(struct lkp1_server *server,
    const struct lkp1_crypto *crypto, const uint8_t *body, size_t body_len,
    int64_t now_ms, uint8_t *plain, size_t *plain_len);
int lkp1_server_seal_data(struct lkp1_server *server,
    const struct lkp1_crypto *crypto, const uint8_t *plain, size_t plain_len,
    int64_t now_ms, uint8_t *record, size_t *record_len);
void lkp1_server_reset(struct lkp1_server *server);
#endif
