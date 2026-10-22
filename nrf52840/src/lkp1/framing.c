#include "lkp1/framing.h"
#include <string.h>

void lkp1_decoder_reset(struct lkp1_decoder *decoder)
{
    if (decoder != NULL) {
        memset(decoder, 0, sizeof(*decoder));
    }
}

int lkp1_decoder_feed(struct lkp1_decoder *decoder, const uint8_t *input,
                      size_t input_len, int64_t now_ms,
                      lkp1_record_callback callback, void *context)
{
    size_t offset = 0;
    if (decoder == NULL || callback == NULL ||
        (input_len != 0 && input == NULL)) {
        return LKP1_ERR_PROTOCOL;
    }
    if (decoder->header_received != 0 &&
        now_ms - decoder->last_fragment_ms > LKP1_FRAGMENT_TIMEOUT_MS) {
        lkp1_decoder_reset(decoder);
        return LKP1_ERR_PROTOCOL;
    }
    while (offset < input_len) {
        if (decoder->header_received < sizeof(decoder->header)) {
            decoder->header[decoder->header_received++] = input[offset++];
            decoder->last_fragment_ms = now_ms;
            if (decoder->header_received != sizeof(decoder->header)) {
                continue;
            }
            decoder->expected = ((uint16_t)decoder->header[2] << 8) |
                                decoder->header[3];
            if (decoder->header[0] != LKP1_VERSION ||
                decoder->header[1] < LKP1_RECORD_HANDSHAKE ||
                decoder->header[1] > LKP1_RECORD_ALERT ||
                decoder->expected == 0 ||
                decoder->expected > LKP1_MAX_BODY_LEN ||
                (decoder->header[1] == LKP1_RECORD_ALERT &&
                 decoder->expected != 1)) {
                lkp1_decoder_reset(decoder);
                return LKP1_ERR_PROTOCOL;
            }
        }
        size_t remaining = decoder->expected - decoder->received;
        size_t available = input_len - offset;
        size_t count = remaining < available ? remaining : available;
        if (count != 0) {
            memcpy(decoder->body + decoder->received, input + offset, count);
            decoder->received += (uint16_t)count;
            offset += count;
            decoder->last_fragment_ms = now_ms;
        }
        if (decoder->received == decoder->expected) {
            int rc = callback(context, decoder->header[1], decoder->body,
                              decoder->expected);
            lkp1_decoder_reset(decoder);
            if (rc != 0) {
                return rc;
            }
        }
    }
    return 0;
}
