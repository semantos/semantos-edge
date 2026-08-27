// cell_radio.h — ESP-NOW transport for cell-mesh frames.
//
// ESP-NOW = Espressif's WiFi-layer broadcast — no AP, no IP stack needed.
// Each peer on the same channel hears each other's frames directly. ~250
// byte frame cap matches our cm_frame_t layout.
//
// Topology: open broadcast (FF:FF:FF:FF:FF:FF). Every node hears every
// frame; reassembly + sig verify discriminate by sender MAC. The radio
// layer itself does no filtering — just pushes raw frames at the
// reassembler.
//
// Threading: ESP-NOW's recv callback fires in the WiFi task context.
// `cell_radio` invokes the user callback directly from that context, so
// the callback MUST be fast (no malloc, no logging in tight paths). For
// the demo this is fine — we just push into the reassembler and (on
// COMPLETE) enqueue to a FreeRTOS queue for the main task.
//
// IDF-only. Depends on esp_now / esp_wifi.

#pragma once

#include "cell_wire.h"
#include "cell_frame.h"
#include "esp_err.h"
#include "esp_netif.h"

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Default channel for the mesh. All XIAOs in a swarm must agree.
#ifndef CM_RADIO_CHANNEL
#define CM_RADIO_CHANNEL 6u
#endif

// Receive callback signature. `sender_mac` is the MAC of the broadcaster.
// `frame_bytes` / `frame_len` is the raw ESP-NOW payload (one of our
// `cm_frame_t` byte arrays). Invoked from the WiFi task context — keep
// it short.
typedef void (*cm_radio_recv_fn)(const uint8_t sender_mac[6],
                                  const uint8_t *frame_bytes,
                                  size_t frame_len,
                                  void *userdata);

// Initialize WiFi (STA mode, fixed channel) + ESP-NOW + the broadcast
// peer. Idempotent. Returns ESP_OK on success.
esp_err_t cm_radio_init(void);

// Register the receive callback. Set `cb=NULL` to clear.
void cm_radio_register_recv(cm_radio_recv_fn cb, void *userdata);

// Send a cell (1024 bytes) + its 64-byte signature as 5 ESP-NOW broadcast
// frames. `cell_id` is the per-cell reassembly tag (caller picks unique
// values within a TTL window — a monotonic counter is fine).
esp_err_t cm_radio_send_cell(const uint8_t cell[CM_CELL_SIZE],
                              const uint8_t sig[CM_FRAME_SIG_SIZE],
                              uint32_t cell_id);

/**
 * Send a cell to ONE peer instead of broadcasting.
 *
 * This is what lets a relayed cell stay byte-identical. Broadcast routing has
 * to carry a cursor inside the cell — which hop are we at, who is next — and
 * mutating that cursor changes the bytes the origin signed, so the signature
 * cannot survive a hop. Addressing at the radio layer instead means the cell
 * is signed once and relayed unchanged: the cell IS the wire format.
 *
 * The peer is registered on demand; "already exists" is not an error.
 */
esp_err_t cm_radio_send_cell_to(const uint8_t peer_mac[6],
                                 const uint8_t cell[CM_CELL_SIZE],
                                 const uint8_t sig[CM_FRAME_SIG_SIZE],
                                 uint32_t cell_id);

// Read this node's WiFi STA MAC into `out_mac[6]`. Useful for stamping
// cells with an owner_id derived from MAC at provisioning time.
esp_err_t cm_radio_get_mac(uint8_t out_mac[6]);

// Return the shared WiFi STA netif created during radio init. This lets
// applications layer ordinary WLAN/IP behavior on top of the same STA
// without attaching a second netif after WiFi has already started.
esp_netif_t *cm_radio_get_sta_netif(void);

#ifdef __cplusplus
}
#endif
