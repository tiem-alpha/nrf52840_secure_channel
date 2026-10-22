#include "lkp1/framing.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static unsigned int records;
static int record(void *context, uint8_t type, const uint8_t *body,
                  uint16_t len)
{
    (void)context;
    assert(type == LKP1_RECORD_HANDSHAKE);
    assert(len == 3);
    assert(memcmp(body, "abc", 3) == 0);
    records++;
    return 0;
}

int main(void)
{
    struct lkp1_decoder decoder;
    const uint8_t valid[] = {1, 1, 0, 3, 'a', 'b', 'c'};
    const uint8_t oversized[] = {1, 1, 4, 1};
    const uint8_t empty[] = {1, 1, 0, 0};
    const uint8_t wrong_version[] = {2, 1, 0, 1, 0};
    lkp1_decoder_reset(&decoder);
    assert(lkp1_decoder_feed(&decoder, valid, 2, 100, record, NULL) == 0);
    assert(lkp1_decoder_feed(&decoder, valid + 2, 5, 101, record, NULL) == 0);
    assert(records == 1);
    assert(lkp1_decoder_feed(&decoder, valid, sizeof(valid), 102,
                              record, NULL) == 0);
    assert(records == 2);
    assert(lkp1_decoder_feed(&decoder, oversized, sizeof(oversized), 103,
                              record, NULL) == LKP1_ERR_PROTOCOL);
    assert(lkp1_decoder_feed(&decoder, empty, sizeof(empty), 103,
                              record, NULL) == LKP1_ERR_PROTOCOL);
    assert(lkp1_decoder_feed(&decoder, wrong_version, sizeof(wrong_version),
                              103, record, NULL) == LKP1_ERR_PROTOCOL);
    assert(lkp1_decoder_feed(&decoder, valid, 2, 104, record, NULL) == 0);
    assert(lkp1_decoder_feed(&decoder, valid + 2, 5, 5105,
                              record, NULL) == LKP1_ERR_PROTOCOL);
    puts("framing tests passed");
    return 0;
}
