// cell_radio.c — ESP-NOW transport for cell-mesh frames.

#include "cell_radio.h"

#include <string.h>

#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_now.h"
#include "nvs_flash.h"

static const char *TAG = "cell_radio";

static const uint8_t BROADCAST_MAC[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

static cm_radio_recv_fn s_recv_cb       = NULL;
static void            *s_recv_userdata = NULL;
static bool             s_initialized   = false;
static esp_netif_t     *s_sta_netif     = NULL;

static void radio_recv_trampoline(const esp_now_recv_info_t *info,
                                  const uint8_t *data, int data_len) {
    if (!s_recv_cb || !info || data_len <= 0) return;
    s_recv_cb(info->src_addr, data, (size_t)data_len, s_recv_userdata);
}

static esp_err_t ensure_nvs_initialized(void) {
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    return err;
}

esp_err_t cm_radio_init(void) {
    if (s_initialized) return ESP_OK;

    ESP_ERROR_CHECK(ensure_nvs_initialized());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    s_sta_netif = esp_netif_create_default_wifi_sta();

    wifi_init_config_t wcfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&wcfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_set_channel(CM_RADIO_CHANNEL, WIFI_SECOND_CHAN_NONE));

    ESP_ERROR_CHECK(esp_now_init());
    ESP_ERROR_CHECK(esp_now_register_recv_cb(radio_recv_trampoline));

    // Register the broadcast peer so esp_now_send accepts BROADCAST_MAC.
    esp_now_peer_info_t peer = {0};
    memcpy(peer.peer_addr, BROADCAST_MAC, 6);
    peer.channel = CM_RADIO_CHANNEL;
    peer.ifidx   = WIFI_IF_STA;
    peer.encrypt = false;
    esp_err_t err = esp_now_add_peer(&peer);
    if (err != ESP_OK && err != ESP_ERR_ESPNOW_EXIST) return err;

    s_initialized = true;
    ESP_LOGI(TAG, "ESP-NOW up on channel %u", (unsigned)CM_RADIO_CHANNEL);
    return ESP_OK;
}

void cm_radio_register_recv(cm_radio_recv_fn cb, void *userdata) {
    s_recv_cb       = cb;
    s_recv_userdata = userdata;
}

esp_err_t cm_radio_send_cell(const uint8_t cell[CM_CELL_SIZE],
                              const uint8_t sig[CM_FRAME_SIG_SIZE],
                              uint32_t cell_id) {
    if (!s_initialized) {
        esp_err_t err = cm_radio_init();
        if (err != ESP_OK) return err;
    }
    if (!cell || !sig) return ESP_ERR_INVALID_ARG;

    cm_frame_t frames[CM_FRAMES_PER_CELL];
    size_t n = cm_frame_split(cell, sig, cell_id, frames);
    if (n != CM_FRAMES_PER_CELL) return ESP_FAIL;

    for (size_t i = 0; i < n; i++) {
        esp_err_t err = esp_now_send(BROADCAST_MAC, frames[i].bytes, frames[i].len);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "esp_now_send frame %u: %s", (unsigned)i, esp_err_to_name(err));
            return err;
        }
    }
    return ESP_OK;
}

esp_err_t cm_radio_send_cell_to(const uint8_t peer_mac[6],
                                 const uint8_t cell[CM_CELL_SIZE],
                                 const uint8_t sig[CM_FRAME_SIG_SIZE],
                                 uint32_t cell_id) {
    if (!s_initialized) {
        esp_err_t err = cm_radio_init();
        if (err != ESP_OK) return err;
    }
    if (!peer_mac || !cell || !sig) return ESP_ERR_INVALID_ARG;

    // ESP-NOW refuses a send to an unregistered peer, and the peer table is
    // small (CONFIG_ESP_NOW_MAX_TOTAL_PEER_NUM). Add on demand and tolerate
    // "already exists" — a relay path revisits the same next hop constantly.
    if (!esp_now_is_peer_exist(peer_mac)) {
        esp_now_peer_info_t peer = {0};
        memcpy(peer.peer_addr, peer_mac, 6);
        peer.channel = CM_RADIO_CHANNEL;
        peer.ifidx   = WIFI_IF_STA;
        peer.encrypt = false;
        esp_err_t err = esp_now_add_peer(&peer);
        if (err != ESP_OK && err != ESP_ERR_ESPNOW_EXIST) {
            ESP_LOGW(TAG, "esp_now_add_peer %02x:%02x:%02x:%02x:%02x:%02x: %s",
                     peer_mac[0], peer_mac[1], peer_mac[2],
                     peer_mac[3], peer_mac[4], peer_mac[5], esp_err_to_name(err));
            return err;
        }
    }

    cm_frame_t frames[CM_FRAMES_PER_CELL];
    size_t n = cm_frame_split(cell, sig, cell_id, frames);
    if (n != CM_FRAMES_PER_CELL) return ESP_FAIL;

    for (size_t i = 0; i < n; i++) {
        esp_err_t err = esp_now_send(peer_mac, frames[i].bytes, frames[i].len);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "esp_now_send unicast frame %u: %s", (unsigned)i, esp_err_to_name(err));
            return err;
        }
    }
    return ESP_OK;
}

esp_err_t cm_radio_get_mac(uint8_t out_mac[6]) {
    if (!out_mac) return ESP_ERR_INVALID_ARG;
    return esp_wifi_get_mac(WIFI_IF_STA, out_mac);
}

esp_netif_t *cm_radio_get_sta_netif(void) {
    return s_sta_netif;
}
