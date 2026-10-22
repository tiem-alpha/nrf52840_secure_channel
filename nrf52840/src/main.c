/* BLE/NUS adapter. All protocol decisions belong to lkp1/server.c. */
#include <zephyr/kernel.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/sys/util.h>
#include <bluetooth/services/nus.h>
#include <psa/crypto.h>
#include <zephyr/dfu/mcuboot.h>
#include <string.h>
#include "lkp1/framing.h"
#include "lkp1/server.h"
#include "lkp1/crypto_psa.h"
#include "lkp1/acl.h"

/* A generated prototype credential header is optional at compile time. When
 * absent, this firmware advertises but rejects every LKP1 handshake. */
#if __has_include("factory_credentials.h")
#include "factory_credentials.h"
#endif

static struct bt_conn *active_conn;
static bool link_ready;
static bool closing;
static int64_t closing_started_ms;
static unsigned int notifications_pending;
static struct lkp1_decoder decoder;
static struct lkp1_server server;
static uint8_t tx_buffer[1028];
static size_t tx_size, tx_offset;
#if defined(LKP1_FACTORY_PROVISIONED)
static uint8_t f2a[73], f2b[458];
#endif
static uint8_t app_plain[LKP1_MAX_APP_PLAINTEXT];
static unsigned int failures;
static int64_t backoff_until_ms;

static void disconnect_with_alert(uint8_t code)
{
    if (active_conn != NULL) {
        uint8_t alert[5] = { 1, LKP1_RECORD_ALERT, 0, 1, code };
        closing = true;
        closing_started_ms = k_uptime_get();
        if (!link_ready || bt_nus_send(active_conn, alert,
                                        sizeof(alert)) != 0) {
            (void)bt_conn_disconnect(active_conn,
                                     BT_HCI_ERR_REMOTE_USER_TERM_CONN);
        } else {
            notifications_pending++;
        }
    }
}

static void failed(uint8_t code)
{
    lkp1_server_reset(&server);
    lkp1_decoder_reset(&decoder);
    tx_size = tx_offset = 0;
    failures++;
    if (failures >= 3) {
        unsigned int shift = MIN(failures - 3, 6u);
        int64_t delay = MIN(1u << shift, 60u);
        backoff_until_ms = k_uptime_get() + delay * 1000;
    }
    disconnect_with_alert(code);
}

static void send_next(void)
{
    if (active_conn == NULL || !link_ready || closing ||
        tx_offset == tx_size) {
        return;
    }
    uint16_t mtu = bt_gatt_get_mtu(active_conn);
    size_t limit = mtu > 3 ? mtu - 3 : 0;
    size_t remaining = tx_size - tx_offset;
    size_t count = MIN(remaining, limit);
    if (count == 0 || bt_nus_send(active_conn, tx_buffer + tx_offset,
                                   count) != 0) {
        failed(1);
        return;
    }
    tx_offset += count;
    notifications_pending++;
}

static void sent(struct bt_conn *conn)
{
    if (conn == active_conn) {
        if (notifications_pending != 0) {
            notifications_pending--;
        }
        if (closing) {
            if (notifications_pending == 0) {
                (void)bt_conn_disconnect(conn,
                                         BT_HCI_ERR_REMOTE_USER_TERM_CONN);
            }
        } else {
            send_next();
        }
    }
}

static int on_record(void *context, uint8_t type, const uint8_t *body,
                     uint16_t body_len)
{
    ARG_UNUSED(context);
#if defined(LKP1_FACTORY_PROVISIONED)
    if (type == LKP1_RECORD_HANDSHAKE && server.state == LKP1_IDLE) {
        size_t a_len = 0, b_len = 0;
        if (tx_size != tx_offset || lkp1_server_f1(&server,
            &lkp1_factory_identity, &lkp1_psa_crypto, body, body_len,
            k_uptime_get(), f2a, &a_len, f2b, &b_len) != 0) {
            return -1;
        }
        memcpy(tx_buffer, f2a, a_len);
        memcpy(tx_buffer + a_len, f2b, b_len);
        tx_size = a_len + b_len;
        tx_offset = 0;
        send_next();
        return 0;
    }
    if (type == LKP1_RECORD_HANDSHAKE_ENC &&
        server.state == LKP1_WAIT_F3) {
        if (tx_size != tx_offset ||
            lkp1_server_f3(&server, &lkp1_factory_identity,
            &lkp1_psa_crypto, body, body_len, k_uptime_get()) != 0) {
            return LKP1_ERR_AUTH;
        }
        failures = 0;
        return 0;
    }
    if (type == LKP1_RECORD_APP_DATA && server.state == LKP1_OPEN) {
        size_t plain_len = 0;
        if (lkp1_server_open_data(&server, &lkp1_psa_crypto, body,
            body_len, k_uptime_get(), app_plain, &plain_len) != 0) {
            return LKP1_ERR_AUTH;
        }
        if (!lkp1_acl_contains(server.client_id,
            lkp1_factory_allowed_ids, lkp1_factory_allowed_count)) {
            lkp1_secure_zero(app_plain, plain_len);
            return LKP1_ERR_AUTH;
        }
        /* Command 1 is a read-only demo status. No unlock actuator is wired
         * into this transport. Unknown commands are protocol errors. */
        if (plain_len == 0 || app_plain[0] != 1 || tx_size != tx_offset) {
            lkp1_secure_zero(app_plain, plain_len);
            return -1;
        }
        static const uint8_t response[] = { 0x81, 'r', 'e', 'a', 'd', 'y' };
        if (lkp1_server_seal_data(&server, &lkp1_psa_crypto, response,
            sizeof(response), k_uptime_get(), tx_buffer, &tx_size) != 0) {
            lkp1_secure_zero(app_plain, plain_len);
            return -1;
        }
        tx_offset = 0;
        send_next();
        lkp1_secure_zero(app_plain, plain_len);
        return 0;
    }
#else
    ARG_UNUSED(type);
    ARG_UNUSED(body);
    ARG_UNUSED(body_len);
#endif
    return -1;
}

static void receive(struct bt_conn *conn, const uint8_t *data, uint16_t len)
{
    if (conn != active_conn || closing || data == NULL || len == 0) {
        return;
    }
    if (!link_ready) {
        failed(1);
        return;
    }
    int rc = lkp1_decoder_feed(&decoder, data, len, k_uptime_get(),
                                on_record, NULL);
    if (rc != 0) {
        failed(rc == LKP1_ERR_AUTH ? 2 : 1);
    }
}

static struct bt_nus_cb nus_callbacks = {
    .received = receive,
    .sent = sent,
};

static void connected(struct bt_conn *conn, uint8_t err)
{
    if (err != 0 || conn == NULL) {
        return;
    }
    if (active_conn != NULL || k_uptime_get() < backoff_until_ms) {
        (void)bt_conn_disconnect(conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
        return;
    }
    active_conn = bt_conn_ref(conn);
    link_ready = bt_conn_get_security(conn) >= BT_SECURITY_L2;
    closing = false;
    notifications_pending = 0;
    lkp1_decoder_reset(&decoder);
    lkp1_server_reset(&server);
    tx_size = tx_offset = 0;
    /* Just Works is only transport encryption; LKP1 authenticates peers. */
    if (!link_ready && bt_conn_set_security(conn, BT_SECURITY_L2) != 0) {
        (void)bt_conn_disconnect(conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
    }
}

static void security_changed(struct bt_conn *conn, bt_security_t level,
                             enum bt_security_err err)
{
    if (conn != active_conn) {
        return;
    }
    link_ready = err == BT_SECURITY_ERR_SUCCESS && level >= BT_SECURITY_L2;
    if (!link_ready) {
        (void)bt_conn_disconnect(conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
    }
}

static void disconnected(struct bt_conn *conn, uint8_t reason)
{
    ARG_UNUSED(reason);
    if (conn == active_conn) {
        lkp1_decoder_reset(&decoder);
        lkp1_server_reset(&server);
        lkp1_secure_zero(tx_buffer, sizeof(tx_buffer));
        lkp1_secure_zero(app_plain, sizeof(app_plain));
        tx_size = tx_offset = 0;
        link_ready = false;
        closing = false;
        notifications_pending = 0;
        bt_conn_unref(active_conn);
        active_conn = NULL;
    }
}

static struct bt_conn_cb conn_callbacks = {
    .connected = connected,
    .disconnected = disconnected,
    .security_changed = security_changed,
};

static void timeout_check(struct k_work *work);
K_WORK_DELAYABLE_DEFINE(timeout_work, timeout_check);

static void timeout_check(struct k_work *work)
{
    ARG_UNUSED(work);
    int64_t now = k_uptime_get();
    if (active_conn != NULL && closing &&
        now - closing_started_ms > 1000) {
        (void)bt_conn_disconnect(active_conn,
                                 BT_HCI_ERR_REMOTE_USER_TERM_CONN);
    } else if (active_conn != NULL && !closing &&
        ((decoder.header_received != 0 &&
          now - decoder.last_fragment_ms > LKP1_FRAGMENT_TIMEOUT_MS) ||
         (server.state == LKP1_WAIT_F3 &&
          now - server.started_ms > 10000) ||
         (server.state == LKP1_OPEN &&
          now - server.opened_ms > 24LL * 60 * 60 * 1000))) {
        failed(1);
    }
    (void)k_work_reschedule(&timeout_work, K_SECONDS(1));
}

int main(void)
{
    static const uint8_t flags = BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR;
    static const uint8_t nus_uuid[] = { BT_UUID_NUS_VAL };
    static const struct bt_data advertising[] = {
        BT_DATA(BT_DATA_FLAGS, &flags, sizeof(flags)),
        BT_DATA(BT_DATA_NAME_COMPLETE, CONFIG_BT_DEVICE_NAME,
                sizeof(CONFIG_BT_DEVICE_NAME) - 1),
    };
    static const struct bt_data scan_response[] = {
        BT_DATA(BT_DATA_UUID128_ALL, nus_uuid, sizeof(nus_uuid)),
    };
    if (psa_crypto_init() != PSA_SUCCESS) {
        return 1;
    }
    lkp1_decoder_reset(&decoder);
    lkp1_server_reset(&server);
    bt_conn_cb_register(&conn_callbacks);
    if (bt_enable(NULL) != 0 || bt_nus_init(&nus_callbacks) != 0) {
        return 1;
    }
    if (bt_le_adv_start(BT_LE_ADV_CONN_FAST_1, advertising,
                        ARRAY_SIZE(advertising), scan_response,
                        ARRAY_SIZE(scan_response)) != 0) {
        return 1;
    }
    /* Confirm an update only after PSA, BLE, NUS and advertising initialized.
     * Product firmware should add device-specific self tests before this. */
    if (!boot_is_img_confirmed() && boot_write_img_confirmed() != 0) {
        return 1;
    }
    (void)k_work_reschedule(&timeout_work, K_SECONDS(1));
    for (;;) {
        k_sleep(K_SECONDS(1));
    }
}
