#ifndef LKP1_FRAMING_H
#define LKP1_FRAMING_H
#include <stddef.h>
#include <stdint.h>

#define LKP1_VERSION 1u
#define LKP1_MAX_BODY_LEN 1024u
#define LKP1_FRAGMENT_TIMEOUT_MS 5000
#define LKP1_RECORD_HANDSHAKE 1u
#define LKP1_RECORD_HANDSHAKE_ENC 2u
#define LKP1_RECORD_APP_DATA 3u
#define LKP1_RECORD_ALERT 4u
#define LKP1_ERR_PROTOCOL (-1)
#define LKP1_ERR_AUTH (-2)

/* One bounded decoder belongs to one BLE connection. Callback body pointers
 * are valid only during the callback. */
struct lkp1_decoder {
    uint8_t header[4];
    uint8_t body[LKP1_MAX_BODY_LEN];
    uint16_t received;
    uint16_t expected;
    uint8_t header_received;
    int64_t last_fragment_ms;
};
typedef int (*lkp1_record_callback)(void *context, uint8_t type,
                                    const uint8_t *body, uint16_t body_len);
void lkp1_decoder_reset(struct lkp1_decoder *decoder);
int lkp1_decoder_feed(struct lkp1_decoder *decoder, const uint8_t *input,
                      size_t input_len, int64_t now_ms,
                      lkp1_record_callback callback, void *context);
#endif
