// mesh_demo — end-to-end cell-mesh radio test with rules + effects.
//
// Each XIAO ESP32-C6:
//   * Broadcasts a pre-signed heartbeat cell every 5 seconds.
//   * Broadcasts a pre-signed tap cell every ~8 seconds.
//   * Receives every other device's broadcasts via ESP-NOW,
//     reassembles + ECDSA-secp256k1 verifies + evaluates rules.
//   * Tap rule: fire a 500 ms blink on the onboard LED (GPIO15).
//
// **No private key on the device.** A host-side wallet
// (tools/sign-cell-deck.ts) pre-signs every cell at
// provisioning time and bakes the signed deck into firmware via
// EMBED_FILES. Devices pop cells from the embedded deck and
// broadcast — they verify other devices' cells against the wallet's
// pubkey, but never themselves hold a signing key.
//
// This matches the project rule that IoT devices verify and act while
// wallets sign. The runtime rule-driven EMIT path (confirmed_tap) still
// requires a key for now; see the confirmed_tap notes below.

#include <stdio.h>
#include <string.h>
#include <math.h>
#include <pthread.h>
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/gpio.h"
#include "driver/usb_serial_jtag.h"
#include "mbedtls/sha256.h"

#include "cell_wire.h"
#include "cell_frame.h"
#include "cell_ring.h"
#include "cell_sig.h"
#include "cell_radio.h"
#include "cell_rules.h"
#include "cell_forward.h"
#include "cell_forward_v1.h"
#include "cell_forward_v2.h"
#include "cell_channel.h"
#include "cell_capability.h"
#include "cell_domains.h"
#include "cell_meter.h"
#include "cell_mnca.h"
#include "semantos.h"
#include "wasm_export.h"   // wasm_runtime_init_thread_env
#include "esp_heap_caps.h"
#include "esp_now.h"          // ESP_ERR_ESPNOW_NO_MEM for relay retry

static const char *TAG = "mesh_demo";

// ── Hardware pins (XIAO ESP32-C6) ────────────────────────────────────
#define LED_GPIO          GPIO_NUM_15   // onboard yellow LED, active LOW

// Tap auto-emit cadence. Slightly slower than heartbeat (5s) so the
// LED-blink event is visually distinguishable in serial logs. Each
// boot picks a random offset so two devices don't sync up.
#define TAP_PERIOD_MS     8000u
#define TAP_JITTER_MS     2000u

// ── Wallet pubkey (compressed, 33 bytes) ─────────────────────────────
// Off-device wallet — the only key in the system. Devices verify
// against this pubkey; the matching private key lives in the host
// signing tool (tools/sign-cell-deck.ts), never on the C6.
//
// To rotate: change WALLET_PRIVKEY_HEX in sign-cell-deck.ts, re-run,
// update the hex below with the printed pubkey, rebuild.
// Set to 1 to trust a Plexus-derived FLEET operator root instead of the
// standalone sign-cell-deck demo key. Regenerate the array with
// `bun run fleet:anchor` (tools/fleet/anchor.ts) — it prints exactly this
// block for whatever FLEET_ROOT_EMAIL / FLEET_ROOT_SALT you derive under.
#define USE_FLEET_ANCHOR 1

// The domain this device is provisioned into — `fleet.device` from
// tools/fleet-zig/src/domains.zig, client-sovereign band.
//
// With this set, the device refuses a capability cert issued in any OTHER
// domain even when the operator signature on it is perfectly valid: an
// org.member cert (0x00f10002) is real authority, just not authority over a
// device. Set it to CM_CAP_DOMAIN_ANY to install certs from every domain and
// rely on the per-cert binding alone, which is what this firmware did before
// the domain flag was written at all.
//
// Must stay below 0x80000000. The engine reads the expected flag as a BSV
// script number, so bit 31 is a SIGN bit — see the encoding note in
// components/cell-mesh/test/vectors/domainflag_vectors.h.
//
// CM_DOMAIN_FLEET_DEVICE is generated from tools/fleet-zig/src/domains.zig, so
// the firmware, the Zig control plane and the TypeScript bridge cannot drift
// apart on this value. It is also CM_DOMAIN_MESH_RELAY — the same flag, because
// a capability cert grants a device the right to relay, and that IS what a
// fleet device's identity is for. Two provisioning paths, one namespace;
// different issuers are separated by the signature anchor, not the domain.
#define DEVICE_DOMAIN_FLAG CM_DOMAIN_FLEET_DEVICE

#if USE_FLEET_ANCHOR
// Fleet operator trust anchor, derived not invented.
//   universe: operator@fleet.example  (DEMO root — salt is in the repo)
//   pubkey  : 0245ad80f7eb6d2222ad6741fe6aa6a9b51d5571c6945a43813cf4b71b5441e6d6
static const uint8_t s_wallet_pubkey[CM_SIG_PUBKEY_COMPRESSED] = {
    0x02, 0x45, 0xad, 0x80, 0xf7, 0xeb, 0x6d, 0x22,
    0x22, 0xad, 0x67, 0x41, 0xfe, 0x6a, 0xa6, 0xa9,
    0xb5, 0x1d, 0x55, 0x71, 0xc6, 0x94, 0x5a, 0x43,
    0x81, 0x3c, 0xf4, 0xb7, 0x1b, 0x54, 0x41, 0xe6,
    0xd6,
};
#else
// Original sign-cell-deck demo key (WALLET_PRIVKEY_HEX = ...0042).
static const uint8_t s_wallet_pubkey[CM_SIG_PUBKEY_COMPRESSED] = {
    0x03, 0x07, 0x92, 0x64, 0xc4, 0xb4, 0xbf, 0xcd,
    0x7f, 0xe3, 0xa7, 0xb7, 0xb9, 0x2b, 0x6c, 0x43,
    0x9f, 0x3a, 0x5b, 0x3a, 0xbc, 0xd2, 0x91, 0x89,
    0xbf, 0x7b, 0x54, 0xd7, 0x81, 0xff, 0x03, 0xd7,
    0x22,
};
#endif

// ── Cell types — type_hash = SHA-256 of the type name ────────────────
static const char HEARTBEAT_TYPE_NAME[]     = "cellmesh.heartbeat.v0";
static const char TAP_TYPE_NAME[]           = "cellmesh.tap.v0";
static const char CONFIRMED_TAP_TYPE_NAME[] = "cellmesh.confirmed_tap.v0";
static const char RULE_TYPE_NAME[]          = "cellmesh.rule.v0";
static const char FORWARD_TYPE_NAME[]            = "cellmesh.forward.v0";
static const char FORWARD_V1_TYPE_NAME[]         = "cellmesh.forward.v1";
static const char FORWARD_V2_TYPE_NAME[]         = "cellmesh.forward.v2";
static const char ROUTING_CONT_V0_TYPE_NAME[]    = "cellmesh.routing.cont.v0";
static const char CHANNEL_OPEN_TYPE_NAME[]       = "cellmesh.channel_open.v0";
static const char CHANNEL_COMMITMENT_TYPE_NAME[] = "cellmesh.channel_commitment.v0";
static const char CHANNEL_CLOSE_TYPE_NAME[]      = "cellmesh.channel_close.v0";
static const char CHANNEL_SETTLE_TYPE_NAME[]     = "cellmesh.channel_settle.v0";
static const char SCRIPTED_TYPE_NAME[]           = "cellmesh.scripted.v0";
static const char ACTUATOR_OFFER_TYPE_NAME[]     = "cellmesh.actuator_offer.v0";
static const char ACTUATOR_ACTIVATE_TYPE_NAME[]  = "cellmesh.actuator_activate.v0";
// Speeder telemetry — unsigned, high-cadence pose cells. The hot path: at
// ~270ms/verify the C6 can't sign per frame, so telemetry rides unsigned and
// only race results (heartbeats/anchors) get signed. See the mesh-observer
// harness for the wire format the log lines below conform to.
static const char TELEM_TYPE_NAME[]               = "cellmesh.telem.v0";
static const char CAPABILITY_V0_TYPE_NAME[]       = "cellmesh.capability.v0";
// MNCA incentives — tile.v0 is the on-device compute cell; channel_settle.v0
// is the economic signal when k-of-n devices agree on the same tile hash.
static const char MNCA_TILE_V0_TYPE_NAME[]        = "mnca.tile.v0";
static const char MNCA_CHANNEL_SETTLE_TYPE_NAME[] = "mnca.channel_settle.v0";
static uint8_t    s_heartbeat_type_hash[32];
static uint8_t    s_tap_type_hash[32];
static uint8_t    s_confirmed_tap_type_hash[32];
static uint8_t    s_rule_type_hash[32];
static uint8_t    s_forward_type_hash[32];
static uint8_t    s_forward_v1_type_hash[32];
static uint8_t    s_forward_v2_type_hash[32];
static uint8_t    s_routing_cont_type_hash[32];
static uint8_t    s_channel_open_type_hash[32];
static uint8_t    s_channel_commitment_type_hash[32];
static uint8_t    s_channel_close_type_hash[32];
static uint8_t    s_channel_settle_type_hash[32];
static uint8_t    s_scripted_type_hash[32];
static uint8_t    s_actuator_offer_type_hash[32];
static uint8_t    s_actuator_activate_type_hash[32];
static uint8_t    s_telem_type_hash[32];
static uint8_t    s_capability_v0_type_hash[32];
static uint8_t    s_mnca_tile_v0_type_hash[32];
static uint8_t    s_mnca_channel_settle_type_hash[32];

// ── MNCA tile state ───────────────────────────────────────────────────
// Each device owns one 8×8 tile. Tile coordinates are role-derived at
// boot: A=(0,0), B=(1,0), C=(2,0). Every MNCA_PERIOD_MS the device
// advances the tile one generation and broadcasts an mnca.tile.v0 cell.
// The quorum table fires a channel_settle.v0 when ≥2 devices agree on
// the same tile hash (same x, y, generation, SHA-256(state)).
#define MNCA_PERIOD_MS     3000u
#define MNCA_JITTER_MS      500u
static cm_mnca_tile_t   s_mnca_tile;
static cm_mnca_quorum_t s_mnca_quorum;

// ── Cell-engine (BSV-script, Zig kernel → WASM, hosted by WAMR) ──────
//
// Each RX'd `cellmesh.scripted.v0` cell carries a lock script + unlock
// script in its payload. We load them into the kernel and call execute;
// if the kernel accepts (stack top non-zero on exit), we fire the
// SCRIPTED_BLINK_MS visual + emit a "*** SCRIPT ACCEPTED ***" log line.
//
// This is the layer-collapse moment: the SAME BSV-script interpreter
// that validates transactions on a server is sitting on a $4 chip,
// gating IoT behavior.
static semantos_t *s_engine = NULL;
#define SCRIPTED_BLINK_MS 5000u

// ── Demo choreography ───────────────────────────────────────────────
// DEMO_SCRIPT_ONLY=1 turns mesh_demo into a clean single-purpose stage for
// the cell-engine demo: every background broadcaster (heartbeat, telemetry,
// tap, mnca, forward, channel, actuator) is silenced so the boards sit dark
// until a script is injected. The board that receives a serial inject pulses
// its LED 3× ("got it from the laptop"), waits DEMO_BROADCAST_DELAY_MS, then
// broadcasts; the receiving board runs the script through the cell-engine and
// holds its LED solid for SCRIPTED_BLINK_MS on ACCEPT. The deliberate gaps
// make the laptop → A → (air) → B causal chain watchable.
// Set to 0 to restore the full mesh demo (telemetry / forwarding / channels).
#define DEMO_SCRIPT_ONLY        1
#define DEMO_BROADCAST_DELAY_MS 1800u   // gap between A's ack-blink and its broadcast

// ── Capability cert table ────────────────────────────────────────────
// Stores up to CM_CAP_TABLE_MAX=4 per-channel relay-key grants.
// Populated by incoming cellmesh.capability.v0 cells signed by the
// master wallet pubkey.  forward.v1 cells are sig-verified against
// the matching edge key (or wallet pubkey if no cert installed).
static cm_cap_table_t s_cap_table;

// ── Engine-at-boot gate ──────────────────────────────────────────────
// Whether to bring up the cell-engine at boot.
//
// History (2026-05-21):
//   - First attempt with cell-engine-embedded.wasm at initial_memory=128KB:
//     engine + WiFi together exceeded the C6's 329 KB SRAM and WiFi
//     starved on its RX buffers. Gated OFF.
//   - Re-carved the WASM (core/cell-engine: stack 32→16 KB, ARENA 8→2 KB,
//     AUX_STACK 4→2, snapshot_buffer ~20 KB → 12 B on embedded). Now
//     initial_memory=64KB (one page). Engine + WiFi coexist; this gate
//     flips ON.
#define MESH_DEMO_ENGINE_AT_BOOT 1

// Pending-script mailbox. The WiFi RX callback runs in WiFi task ctx,
// which is NOT registered with WAMR's pthread shim — calling the engine
// from there triggers `pthread_self: Failed to find current thread ID`.
// Receive callback queues the payload here; main loop drains and runs.
//
// Mailbox is sized for one in-flight script. Since scripted cells fire
// every 12 s (originator cadence) and dispatch runs in ~ms, we'd never
// overflow even with a much faster cadence.
// P2PKH scripted cells (with embedded tx context) run ~350 B; bump
// past 512 to leave room for richer scripts. The mbox is a single
// static buffer copied from the WiFi RX task into the main pthread.
#define SCRIPTED_MBOX_BYTES 768u
static volatile bool      s_pending_script              = false;
static          char      s_pending_script_mac_str[18];
static          uint8_t   s_pending_script_payload[SCRIPTED_MBOX_BYTES];
static          uint32_t  s_pending_script_len          = 0;
static volatile uint32_t  s_pending_script_overruns     = 0;

// Second mailbox for actuator_activate.v0 cells — same WiFi-task →
// main-pthread routing as scripted, but discriminated so the drainer
// extends the LED-active window on accept (not just blinks).
static volatile bool      s_pending_actuator            = false;
static          char      s_pending_actuator_mac_str[18];
static          uint8_t   s_pending_actuator_payload[SCRIPTED_MBOX_BYTES];
static          uint32_t  s_pending_actuator_len        = 0;
static volatile uint32_t  s_pending_actuator_overruns   = 0;

// ── Multi-hop forward visual: A → B → C ──────────────────────────────
// The three XIAOs on the bench, hardcoded by MAC. A is the originator
// (mints + broadcasts forward cells); B is a relay hop; C is the
// destination. Each device matches its own MAC against these constants
// at boot and assumes the corresponding role.
//
// v0 shortcut: forward cells are NOT signed end-to-end, because the
// `segments` and `hop_index` fields mutate at each hop — verifying
// cm_sig_hash_cell (which hashes the whole 1 KB cell) would fail
// downstream. A future cm_sig_forward_hash should hash only the
// {flow_id, total_hops, inner_payload} subset so the source signature
// survives mutation; tracked in the cell_forward header doc.
static const uint8_t MAC_A[6] = {0x58, 0xe6, 0xc5, 0x1a, 0x8b, 0x28};
static const uint8_t MAC_B[6] = {0x58, 0xe6, 0xc5, 0x1a, 0x8c, 0x54};
static const uint8_t MAC_C[6] = {0x58, 0xe6, 0xc5, 0x1a, 0x8c, 0xf8};

// Originator cadence — A mints a new forward cell roughly every 10s
// with a small jitter so its rhythm is visually distinct from the
// 8s tap cadence + 5s heartbeat.
#define FORWARD_PERIOD_MS   10000u
#define FORWARD_JITTER_MS    2000u

// Forward-delivered blink (visually distinct from 100/500/1200 ms).
#define FORWARD_DELIVERED_BLINK_MS  800u

static bool s_is_originator = false;
static bool s_is_relay      = false;
static bool s_is_destination = false;

// ── Hot-swap timing ──────────────────────────────────────────────────
// Each device broadcasts one rule.v0 cell at this delay after boot.
// The carried rule is: BLINK 100 ms on heartbeat — once installed,
// every heartbeat (received from peers) also briefly flashes the LED,
// visually distinct from the per-tap 500 ms blink and the quorum 1.2 s
// blink. Demonstrates "reprogram the swarm from the wire."
#define HOT_SWAP_BROADCAST_DELAY_US  (15ULL * 1000ULL * 1000ULL)

// ── Pre-signed cell deck (embedded in flash via EMBED_FILES) ─────────
//
// Binary layout (matches tools/sign-cell-deck.ts):
//   HEADER (16 bytes, LE):
//     u32 magic = 0xDECDCDCD
//     u32 version = 1
//     u32 entry_count
//     u32 reserved = 0
//   ENTRIES (entry_count × 1096 bytes):
//     u8  device_mac[6]                — which device transmits this
//     u8  kind                         — DECK_KIND_*
//     u8  reserved
//     u8  cell[CM_CELL_SIZE = 1024]    — owner_id = wallet, NOT device
//     u8  sig[CM_FRAME_SIG_SIZE = 64]  — r||s, 32+32 BE
extern const uint8_t cell_deck_bin_start[] asm("_binary_cell_deck_bin_start");
extern const uint8_t cell_deck_bin_end[]   asm("_binary_cell_deck_bin_end");

#define DECK_MAGIC         0xDECDCDCDu
#define DECK_VERSION       1u
#define DECK_HEADER_SIZE   16u
#define DECK_ENTRY_PREFIX  8u
#define DECK_ENTRY_SIZE    (DECK_ENTRY_PREFIX + CM_CELL_SIZE + CM_FRAME_SIG_SIZE)

typedef enum {
    DECK_KIND_HEARTBEAT          = 1,
    DECK_KIND_TAP                = 2,
    DECK_KIND_HOT_SWAP_RULE      = 3,
    DECK_KIND_CONFIRMED_TAP      = 4,
    DECK_KIND_CHANNEL_OPEN       = 5,
    DECK_KIND_CHANNEL_COMMITMENT = 6,
    DECK_KIND_CHANNEL_CLOSE      = 7,
    DECK_KIND_SCRIPTED           = 8,
    DECK_KIND_ACTUATOR_OFFER     = 9,
    DECK_KIND_ACTUATOR_ACTIVATE  = 10,
} deck_kind_t;

// Per-kind sub-queue of entries for THIS device. At boot we walk the
// deck once and bucket pointers (into flash) by kind. Pop is O(1).
typedef struct {
    const uint8_t *entries[32];  // pointers to entry start (in flash)
    size_t         count;
    size_t         cursor;
    bool           exhausted_logged;
} deck_queue_t;

static deck_queue_t s_q_heartbeat;
static deck_queue_t s_q_tap;
static deck_queue_t s_q_hot_swap;
static deck_queue_t s_q_confirmed_tap;
static deck_queue_t s_q_channel_open;
static deck_queue_t s_q_channel_commitment;
static deck_queue_t s_q_channel_close;
static deck_queue_t s_q_scripted;
static deck_queue_t s_q_actuator_offer;
static deck_queue_t s_q_actuator_activate;

// ── State ────────────────────────────────────────────────────────────
static cm_reasm_t s_reasm;
static cm_ring_t  s_ring;   // Sliding window of received cells; quorum-aware.
static cm_rules_t s_rules;
static uint8_t    s_my_mac[6];
static char       s_my_mac_str[18];
static uint32_t   s_tx_heartbeat_counter = 0;
static uint32_t   s_tx_tap_counter       = 0;
static uint32_t   s_rx_counter           = 0;

// LED blink schedule — set by the receive callback (in WiFi task ctx),
// polled by the main task. Single-writer-from-main-after-init is fine;
// the receive callback writes only on rule-fire. Word writes are
// atomic on RISC-V — no mutex needed at this scale.
static volatile uint64_t s_blink_until_us = 0;
#if DEMO_SCRIPT_ONLY
// Demo choreography state (see DEMO_SCRIPT_ONLY above).
static volatile uint64_t s_inject_ack_start_us  = 0;     // A's 3-pulse ack in progress (0 = idle)
static volatile bool     s_demo_pending         = false; // a cell staged for delayed broadcast
static          uint64_t s_demo_broadcast_at_us = 0;
static          uint8_t  s_demo_cell[CM_CELL_SIZE];
static          uint8_t  s_demo_sig[CM_FRAME_SIG_SIZE];
#endif

// Pending-emit signal — when a rule's CM_EFFECT_EMIT fires (for the
// confirmed_tap type), the receive callback raises this; the main loop
// pops a pre-signed confirmed_tap cell from the deck and broadcasts.
// The cell payload is fixed at provisioning, so we don't need to carry
// the effect details — only "an emit happened, pop one." Single
// producer / single consumer.
static volatile bool     s_pending_emit       = false;
static volatile uint32_t s_emit_overruns      = 0;
static          uint32_t s_tx_emit_counter    = 0;

// Pending-forward mailbox — same shape as emit. The receive callback
// runs in WiFi task context and shouldn't itself broadcast (build +
// fragment a 1 KB cell on a small stack). When a forward cell needs to
// be re-emitted (relay hop), the decoded + stepped forward is queued
// here and the main loop broadcasts it.
//
// Single producer (receive callback), single consumer (main loop).
static volatile bool      s_pending_forward       = false;
static          cm_forward_t s_pending_forward_f;

// The domain flag of the cell currently queued for relay.
//
// A relay is the SAME authority being exercised one hop further on, so the
// relayed cell must carry the domain the original signer declared. Minting it
// with cm_cell_init alone leaves header bytes 24-27 at zero, and the next hop's
// cm_cap_lookup — which keys on the domain — then misses and drops the cell
// with "no cert for channel", naming the capability table for what is actually
// a lost header field. Observed on real silicon at hop 1.
//
// It must NOT be this device's own domain: stamping our own would let a device
// in one domain launder a cell out of another.
static uint32_t s_pending_forward_domain    = 0;
static uint32_t s_pending_forward_v1_domain = 0;
static uint32_t s_pending_fwdv2_domain      = 0;
static volatile uint32_t  s_forward_overruns      = 0;
static          uint32_t  s_tx_forward_counter    = 0;
static          uint32_t  s_rx_forward_counter    = 0;

// ── forward.v1 mailbox (channel-gated forwarding) ────────────────────
// Same single-producer/single-consumer pattern as forward.v0.
// The receive callback checks the channel commitment for THIS hop; if
// accepted, it queues the (already-stepped) forward cell here and the
// main loop broadcasts it. Channel state lives in s_fwd_channel.
static volatile bool       s_pending_forward_v1   = false;
static          cm_forward_v1_t s_pending_forward_v1_f;
static volatile uint32_t   s_forward_v1_overruns  = 0;
static          uint32_t   s_rx_forward_v1_counter = 0;

// Upstream payment channel for forward.v1: one channel per relay/destination.
// Pre-opened at boot with the demo wallet key as peer.  The source (control
// plane) pre-signs commitments that debit this channel at each forwarding hop.
// channel_id = all-zeros (demo); any commitment with a matching channel_id
// and strictly increasing seq passes. Channel starts in CM_CHAN_OPEN state
// so the first valid commitment transitions it to ACTIVE.
//
// In production: established via cellmesh.channel_open.v0 handshake; the
// UTXO funding check is deferred (see cell_channel.h "What this module does
// NOT do").
static cm_channel_t s_fwd_channel;
#define FWD_V1_DEMO_CAPACITY     1000000u  // 1M sats — plenty for the demo
#define FWD_V1_HOP_COST_SATS        10u   // sats credited per relay hop

// ── hop_verb INSTALL_RULE mailbox ────────────────────────────────────
// CM_HOP_VERB_INSTALL_RULE fires at every relay hop and at the destination.
// The receive callback (WiFi task) queues the encoded rule bytes here; the
// main loop decodes + installs them into s_rules. Same single-producer /
// single-consumer pattern as s_pending_forward.
static volatile bool s_pending_fwd_rule          = false;
static uint8_t       s_pending_fwd_rule_bytes[CM_RULE_ENCODED_SIZE];

// ── forward.v2 burst buffer ───────────────────────────────────────────
// forward.v2 uses a 2-cell burst: Cell A (cellmesh.forward.v2) carries
// the application payload; Cell B (cellmesh.routing.cont.v0) carries the
// routing + payment header.  Cells are correlated by flow_id.
//
// Receive flow: Cell A arrives → stored in s_fwdv2_burst_a.  Cell B
// arrives with matching flow_id → pair processed together, then the
// advanced burst is queued in s_pending_forward_v2 for re-emission.
//
// If Cell A arrives before Cell B the burst slot is overwritten (we
// assume the bridge sends them back-to-back and they arrive in order).
// A mismatched flow_id discards the buffered Cell A and buffers the new one.
typedef struct {
    cm_forward_v2_t  primary;
    uint8_t          primary_cell[CM_CELL_SIZE];          // original signed cell bytes
    uint8_t          primary_sig[CM_FRAME_SIG_SIZE];      // Cell A sig (needed for cap check at Cell B)
    bool             valid;                                // true if a Cell A is buffered
} cm_fwdv2_burst_slot_t;

static cm_fwdv2_burst_slot_t s_fwdv2_burst;

// Queued (already-stepped) forward.v2 burst for the main-loop broadcaster
static volatile bool         s_pending_forward_v2 = false;
static bool                  s_pending_fwdv2_cell_a_sent = false; // Cell A' sent once per relay — skip on retries
static uint8_t               s_pending_fwdv2_retry_skip  = 0;     // ticks to skip before retry
static uint8_t               s_fwdv2_cell_b_sends_left   = 0;     // redundant Cell B sends remaining
static cm_forward_v2_t       s_pending_fwdv2_a;
static cm_routing_cont_t     s_pending_fwdv2_b;
static volatile uint32_t     s_forward_v2_overruns = 0;
static          uint32_t     s_rx_forward_v2_counter = 0;

// ── Synthetic tap cell for hop_verb EVAL_RULES ───────────────────────
// A static 1024-byte cell with only the tap type_hash set. Used as the
// "trigger source" for cm_rules_evaluate when a hop_verb fires: rules
// that blink on tap will blink at each relay and at the destination.
// Initialized in app_main after s_tap_type_hash is computed.
static uint8_t s_synthetic_tap_cell[CM_CELL_SIZE];

// ── Speeder telemetry state ──────────────────────────────────────────
static          uint32_t  s_tx_telem_counter      = 0;
static          uint32_t  s_rx_telem_counter      = 0;
static          int32_t   s_telem_spd             = 0;   // this device's speeder id
// Figure-8 (lemniscate of Gerono) so the path is closed + obviously moving.
// Pose units match the harness wire format: x/y mm, hdg milliradians, v mm/s.
#define TELEM_PERIOD_US   (200ULL * 1000ULL)  // 5 Hz — reduced from 20 Hz so ESP-NOW TX buffer doesn't fill before forward-cell frame 3
#define TELEM_FIG8_MM     6000.0
#define TELEM_LAP_SEC     8.0
#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

// ── Lightbulb-channel state (device C aka MAC_C is the lightbulb) ────
//
// Device C runs the channel state machine. When state == CM_CHAN_ACTIVE,
// the LED is steady-on (the "lightbulb is paid for"). When the wallet
// stops broadcasting commitments, the device's periodic tick_expiry
// transitions ACTIVE → EXPIRED → LED off. The wallet's channel_close
// cell eventually transitions EXPIRED → CLOSED.
//
// Device A runs a TX scheduler that paces the wallet's pre-signed
// channel cells onto the radio (channel_open, then N commitments at 1s
// intervals, then a channel_close after a deliberate "wallet stopped
// paying" gap). Device A doesn't track channel state — it's just the
// wallet's broadcaster.
static cm_channel_t s_channel;
static uint64_t     s_channel_base_ms = 0;     // device's clock at channel_open RX

// ── Draining meter (the MFP device-side value bound) ─────────────────
//
// While the channel is ACTIVE the device is delivering service (LED on),
// so it meters consumed value at a pro-rata rate. The actuator stays
// energized only while the consumer's paid `device_share` covers what's
// been consumed (cm_meter_authorized, within a small tolerance). When the
// wallet stops sending fresh commitments — its Tier-0 vault exhausted —
// consumption catches up to the last paid amount and the device cuts the
// LED off: the prepaid drain reaching empty, decided on-device. Mirrors
// the host MfpFlowAdapter exhausting at its cap.
//
// Rate is the device's deployment parameter (a 10 W bulb metered at
// ~1.2 sat/sec here; the deck pays device_share=seq = 1 sat/sec, so the
// channel stays lit while paid and drains to cut-off ~1.4 s into the
// "wallet stopped paying" gap — before any expiry).
#define CM_METER_RATE_MSAT_PER_SEC  1200u
#define CM_METER_TOLERANCE_SATS        1u
static cm_meter_t s_meter;
static bool       s_meter_cut = false;   // edge-detect authorized → cut-off

// Device A's TX scheduler.
//   step 0     = channel_open
//   step 1..N  = commitment seq=step
//   step N+1   = channel_close
//   step >N+1  = done
#define CHANNEL_TX_COMMITMENT_COUNT  8u
#define CHANNEL_TX_GAP_MS         1000u   // 1s between adjacent cells
#define CHANNEL_TX_STOP_GAP_MS    5000u   // 5s "wallet stopped paying" gap before close
// Defer the channel demo until after the existing hot-swap + early-quorum
// arcs have shown — 25s gives the existing demos breathing room.
#define CHANNEL_TX_START_DELAY_MS 25000u
static bool     s_channel_tx_started     = false;
static uint32_t s_channel_tx_step        = 0;
static uint64_t s_channel_tx_next_us     = 0;

// Device A also paces scripted cells onto the radio at SCRIPTED_TX_GAP_MS.
// Starts at boot+SCRIPTED_TX_START_DELAY_MS so the first SCRIPT ACCEPTED
// log fires while the existing demos are still warming up — the layer-
// collapse moment lands inside the same demo arc.
#define SCRIPTED_TX_START_DELAY_MS  12000u
#define SCRIPTED_TX_GAP_MS          12000u
static uint64_t s_scripted_tx_next_us   = 0;
static bool     s_scripted_tx_started   = false;
static bool     s_scripted_tx_done      = false;  // sticky terminal flag

// Rentable-device demo (x402-over-cells). See docs/x402-over-cells.md.
// Device C broadcasts offers periodically; device A broadcasts wallet-
// signed activations that the device C's cell-engine verifies and uses
// to extend the LED-on window.
#define ACTUATOR_OFFER_GAP_MS         5000u
#define ACTUATOR_OFFER_START_DELAY_MS 8000u
#define ACTUATOR_ACTIVATE_GAP_MS      3500u
#define ACTUATOR_ACTIVATE_START_DELAY_MS 90000u   // after the rest of the demo
// Must match ACTUATOR_DURATION_MS in tools/sign-cell-deck.ts — the
// deck's offer cells advertise this duration and the device debits it.
#define ACTUATOR_DURATION_MS          5000u
static uint64_t s_actuator_offer_next_us    = 0;
static uint64_t s_actuator_activate_next_us = 0;
static bool     s_actuator_offer_started    = false;
static bool     s_actuator_activate_started = false;
static bool     s_actuator_offer_done       = false;
static bool     s_actuator_activate_done    = false;

// Device C's LED-active window. Set by activated actuator cells.
// `led_active_until_us > now` → LED steady on (rentable mode).
static volatile uint64_t s_actuator_active_until_us = 0;
static volatile uint32_t s_actuator_activations    = 0;

static void format_mac(char buf[18], const uint8_t mac[6]) {
    snprintf(buf, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// ── LED ──────────────────────────────────────────────────────────────
static void led_init(void) {
    gpio_config_t cfg = {
        .pin_bit_mask = 1ULL << LED_GPIO,
        .mode         = GPIO_MODE_OUTPUT,
        .pull_up_en   = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    gpio_config(&cfg);
    gpio_set_level(LED_GPIO, 1); // OFF (active LOW)
}

static inline void led_off(void) { gpio_set_level(LED_GPIO, 1); }
static inline void led_on(void)  { gpio_set_level(LED_GPIO, 0); }

// ── Effect dispatch ───────────────────────────────────────────────────
//
// Called from the WiFi task context via the radio receive callback.
// MUST stay cheap — heavy lifting (broadcast) is deferred to the main
// loop via the s_pending_emit signal.
static void dispatch_effect(const cm_effect_t *e) {
    switch (e->kind) {
        case CM_EFFECT_BLINK: {
            uint64_t now = esp_timer_get_time();
            s_blink_until_us = now + (uint64_t)e->as.blink.duration_ms * 1000ULL;
            // Heuristic: any blink >= 1s == the quorum rule (per-tap is
            // 500ms, hot-swap is 100ms, quorum is 1200ms). Surfaces the
            // quorum trigger in serial logs when all 3 XIAOs are live.
            if (e->as.blink.duration_ms >= 1000) {
                ESP_LOGI(TAG, "*** QUORUM FIRED *** (BLINK %u ms)",
                         (unsigned)e->as.blink.duration_ms);
            }
            break;
        }
        case CM_EFFECT_EMIT:
            // Pre-signed confirmed_tap cells live in the deck. The main
            // loop pops one when this signal is set. Effect payload is
            // ignored — every confirmed_tap in the deck has the same
            // {'A','C','K',0x01,counter} payload, signed at provisioning.
            if (!s_pending_emit) {
                s_pending_emit = true;
            } else {
                s_emit_overruns++;
            }
            break;
        default:
            break;
    }
}

// ── Deck inspection ──────────────────────────────────────────────────
//
// Walk the embedded deck once at boot, bucketing entries for this device
// into per-kind queues. Cells live in flash (Const); we store pointers
// only — no copies into RAM.
static int deck_init(void) {
    const size_t deck_bytes = (size_t)(cell_deck_bin_end - cell_deck_bin_start);
    if (deck_bytes < DECK_HEADER_SIZE) {
        ESP_LOGE(TAG, "deck: too small (%u bytes)", (unsigned)deck_bytes);
        return -1;
    }
    uint32_t magic   = cm_read_u32(cell_deck_bin_start + 0);
    uint32_t version = cm_read_u32(cell_deck_bin_start + 4);
    uint32_t count   = cm_read_u32(cell_deck_bin_start + 8);
    if (magic != DECK_MAGIC || version != DECK_VERSION) {
        ESP_LOGE(TAG, "deck: bad magic/version (0x%08x v%u)",
                 (unsigned)magic, (unsigned)version);
        return -1;
    }
    if (DECK_HEADER_SIZE + (size_t)count * DECK_ENTRY_SIZE > deck_bytes) {
        ESP_LOGE(TAG, "deck: count %u overflows %u bytes",
                 (unsigned)count, (unsigned)deck_bytes);
        return -1;
    }

    memset(&s_q_heartbeat,          0, sizeof(s_q_heartbeat));
    memset(&s_q_tap,                0, sizeof(s_q_tap));
    memset(&s_q_hot_swap,            0, sizeof(s_q_hot_swap));
    memset(&s_q_confirmed_tap,      0, sizeof(s_q_confirmed_tap));
    memset(&s_q_channel_open,       0, sizeof(s_q_channel_open));
    memset(&s_q_channel_commitment, 0, sizeof(s_q_channel_commitment));
    memset(&s_q_channel_close,      0, sizeof(s_q_channel_close));
    memset(&s_q_scripted,           0, sizeof(s_q_scripted));
    memset(&s_q_actuator_offer,     0, sizeof(s_q_actuator_offer));
    memset(&s_q_actuator_activate,  0, sizeof(s_q_actuator_activate));

    for (uint32_t i = 0; i < count; i++) {
        const uint8_t *e = cell_deck_bin_start + DECK_HEADER_SIZE + (size_t)i * DECK_ENTRY_SIZE;
        if (memcmp(e, s_my_mac, 6) != 0) continue;
        uint8_t kind = e[6];
        deck_queue_t *q = NULL;
        switch (kind) {
            case DECK_KIND_HEARTBEAT:          q = &s_q_heartbeat;          break;
            case DECK_KIND_TAP:                q = &s_q_tap;                break;
            case DECK_KIND_HOT_SWAP_RULE:      q = &s_q_hot_swap;           break;
            case DECK_KIND_CONFIRMED_TAP:      q = &s_q_confirmed_tap;      break;
            case DECK_KIND_CHANNEL_OPEN:       q = &s_q_channel_open;       break;
            case DECK_KIND_CHANNEL_COMMITMENT: q = &s_q_channel_commitment; break;
            case DECK_KIND_CHANNEL_CLOSE:      q = &s_q_channel_close;      break;
            case DECK_KIND_SCRIPTED:           q = &s_q_scripted;           break;
            case DECK_KIND_ACTUATOR_OFFER:     q = &s_q_actuator_offer;     break;
            case DECK_KIND_ACTUATOR_ACTIVATE:  q = &s_q_actuator_activate;  break;
            default: continue;
        }
        if (q->count >= sizeof(q->entries) / sizeof(q->entries[0])) continue;
        q->entries[q->count++] = e;
    }
    ESP_LOGI(TAG, "deck: %u entries; for-me: hb=%u tap=%u rule=%u conf_tap=%u chan_open=%u chan_commit=%u chan_close=%u scripted=%u offer=%u activate=%u",
             (unsigned)count,
             (unsigned)s_q_heartbeat.count,
             (unsigned)s_q_tap.count,
             (unsigned)s_q_hot_swap.count,
             (unsigned)s_q_confirmed_tap.count,
             (unsigned)s_q_channel_open.count,
             (unsigned)s_q_channel_commitment.count,
             (unsigned)s_q_channel_close.count,
             (unsigned)s_q_scripted.count,
             (unsigned)s_q_actuator_offer.count,
             (unsigned)s_q_actuator_activate.count);
    return 0;
}

// Pop the next entry from the given queue. Returns NULL when exhausted
// (logs an exhausted message once). On success, *out_cell points into
// flash at the 1024-byte cell, *out_sig points at the 64-byte sig.
static bool deck_pop(deck_queue_t *q, const char *kind_name,
                     const uint8_t **out_cell, const uint8_t **out_sig) {
    if (q->cursor >= q->count) {
        if (!q->exhausted_logged) {
            ESP_LOGW(TAG, "deck: %s queue exhausted (%u cells used)",
                     kind_name, (unsigned)q->count);
            q->exhausted_logged = true;
        }
        return false;
    }
    const uint8_t *e = q->entries[q->cursor++];
    *out_cell = e + DECK_ENTRY_PREFIX;
    *out_sig  = e + DECK_ENTRY_PREFIX + CM_CELL_SIZE;
    return true;
}

// ── Scripted cells: dispatch through the cell-engine ─────────────────
//
// Payload format (cellmesh.scripted.v0):
//   u16 LE  lock_len
//   bytes   lock_script   (BSV script bytecode)
//   u16 LE  unlock_len
//   bytes   unlock_script
//
// Returns true iff the kernel accepted (executed cleanly AND final
// stack top is non-zero, matching Bitcoin-script success semantics).
static bool dispatch_scripted_cell(const char *mac_str,
                                    const uint8_t *payload, uint32_t ptot) {
    if (!s_engine) {
        ESP_LOGW(TAG, "scripted [%s]: dropping — cell-engine not initialized", mac_str);
        return false;
    }
    if (ptot < 4) {
        ESP_LOGW(TAG, "scripted [%s]: payload too short (%u)", mac_str, (unsigned)ptot);
        return false;
    }
    size_t off = 0;
    uint16_t lock_len   = cm_read_u16(payload + off);                       off += 2;
    if (off + lock_len + 2 > ptot) {
        ESP_LOGW(TAG, "scripted [%s]: lock_len=%u overflows payload", mac_str, lock_len);
        return false;
    }
    const uint8_t *lock = payload + off;                                    off += lock_len;
    uint16_t unlock_len = cm_read_u16(payload + off);                       off += 2;
    if (off + unlock_len + 2 > ptot) {
        ESP_LOGW(TAG, "scripted [%s]: unlock_len=%u overflows payload", mac_str, unlock_len);
        return false;
    }
    const uint8_t *unlock = payload + off;                                  off += unlock_len;
    uint16_t tx_len     = cm_read_u16(payload + off);                       off += 2;
    const uint8_t *tx_bytes = NULL;
    uint32_t       input_idx = 0;
    uint64_t       input_value = 0;
    if (tx_len > 0) {
        if (off + tx_len + 4 + 8 > ptot) {
            ESP_LOGW(TAG, "scripted [%s]: tx_len=%u overflows payload", mac_str, tx_len);
            return false;
        }
        tx_bytes    = payload + off;                                        off += tx_len;
        input_idx   = cm_read_u32(payload + off);                           off += 4;
        input_value = cm_read_u64(payload + off);                           off += 8;
    }

    semantos_kernel_reset(s_engine);
    int rc;
    if (tx_len > 0) {
        // Required by OP_CHECKSIG (BIP143 sighash). Must come BEFORE
        // load_script — kernel_reset clears any prior tx context.
        rc = semantos_kernel_load_tx_context(s_engine, tx_bytes, tx_len,
                                              input_idx, input_value);
        if (rc != SEMANTOS_OK) {
            ESP_LOGW(TAG, "scripted [%s]: load_tx_context rc=%d", mac_str, rc);
            return false;
        }
    }
    rc = semantos_kernel_load_script(s_engine, lock, lock_len);
    if (rc != SEMANTOS_OK) {
        ESP_LOGW(TAG, "scripted [%s]: load_script rc=%d", mac_str, rc);
        return false;
    }
    if (unlock_len > 0) {
        rc = semantos_kernel_load_unlock(s_engine, unlock, unlock_len);
        if (rc != SEMANTOS_OK) {
            ESP_LOGW(TAG, "scripted [%s]: load_unlock rc=%d", mac_str, rc);
            return false;
        }
    }
    rc = semantos_kernel_execute(s_engine);
    uint32_t err     = semantos_kernel_get_error(s_engine);
    uint32_t opcount = semantos_kernel_get_opcount(s_engine);
    uint32_t depth   = semantos_kernel_stack_depth(s_engine);
    uint32_t top     = depth > 0 ? semantos_kernel_stack_peek(s_engine, depth - 1) : 0;

    bool accepted = (rc == SEMANTOS_OK) && (err == 0) && (depth > 0) && (top != 0);
    if (accepted) {
        ESP_LOGI(TAG, "*** SCRIPT ACCEPTED *** from=[%s] opcount=%u depth=%u top=0x%08x",
                 mac_str, (unsigned)opcount, (unsigned)depth, (unsigned)top);
    } else {
        ESP_LOGW(TAG, "scripted [%s] REJECTED: rc=%d err=%u opcount=%u depth=%u top=0x%08x",
                 mac_str, rc, (unsigned)err, (unsigned)opcount, (unsigned)depth, (unsigned)top);
    }
    return accepted;
}

// ── OP_CHECKDOMAINFLAG self-test ─────────────────────────────────────────────
//
// The forward hot path gates on cm_domain_flag_matches, a u32 compare, because
// running the engine per cell is not affordable next to a ~270 ms signature
// verify. That is only legitimate if the compare IS the opcode. The host suite
// proves that against a vector generated from this exact WASM blob; this proves
// it again at boot, on the silicon, with the engine that is actually loaded.
//
// One-shot. Two executions. If it ever disagrees, the fast path is enforcing
// something other than OP_CHECKDOMAINFLAG and the log says so loudly.

/** Encode a u32 as a minimal BSV script number. Returns the byte count. */
static size_t domain_script_num(uint32_t v, uint8_t out[5]) {
    if (v == 0) return 0;                 // script-number zero is the empty push
    size_t n = 0;
    while (v > 0) { out[n++] = (uint8_t)(v & 0xffu); v >>= 8; }
    // Bit 7 of the top byte is the SIGN. Pad, or the engine reads a negative.
    if (out[n - 1] & 0x80u) out[n++] = 0x00u;
    return n;
}

// Static, not stack: a 1024-byte cell plus pushes overflows the task stack.
static uint8_t s_dft_script[CM_CELL_SIZE + 16];

/** Run <cell(actual)> <expected> OP_CHECKDOMAINFLAG. true = engine accepted. */
static bool domain_opcode_accepts(uint32_t actual, uint32_t expected, int *out_err) {
    uint8_t *sp = s_dft_script;
    uint8_t *cell = sp + 3;                       // after PUSHDATA2 + u16 len
    *sp++ = 0x4d;                                 // OP_PUSHDATA2
    *sp++ = (uint8_t)(CM_CELL_SIZE & 0xffu);
    *sp++ = (uint8_t)((CM_CELL_SIZE >> 8) & 0xffu);
    memset(cell, 0, CM_CELL_SIZE);
    cm_cell_init(cell);                           // magic + version
    cm_set_flags(cell, actual);                   // the field under test
    sp += CM_CELL_SIZE;

    uint8_t num[5];
    size_t nlen = domain_script_num(expected, num);
    *sp++ = (uint8_t)nlen;                        // direct push (nlen <= 5)
    for (size_t i = 0; i < nlen; i++) *sp++ = num[i];
    *sp++ = 0xC6;                                 // OP_CHECKDOMAINFLAG

    semantos_kernel_reset(s_engine);
    if (semantos_kernel_load_script(s_engine, s_dft_script,
                                    (uint32_t)(sp - s_dft_script)) != SEMANTOS_OK) {
        *out_err = -1;
        return false;
    }
    int rc = semantos_kernel_execute(s_engine);
    *out_err = rc;
    return rc == SEMANTOS_OK;
}

static void domain_flag_selftest(void) {
    if (!s_engine) {
        ESP_LOGW(TAG, "OP_CHECKDOMAINFLAG selftest SKIPPED — no engine; the "
                      "fast path is unverified on this boot");
        return;
    }
    // A matching pair and a mismatching one. The mismatch is the load-bearing
    // half: an opcode that accepted everything would pass the first alone.
    const uint32_t mine  = DEVICE_DOMAIN_FLAG;
    const uint32_t other = CM_DOMAIN_ORG_MEMBER;  // a real, different domain

    int err_match = 0, err_mismatch = 0;
    bool engine_match    = domain_opcode_accepts(mine, mine,  &err_match);
    bool engine_mismatch = domain_opcode_accepts(mine, other, &err_mismatch);

    bool native_match    = cm_domain_flag_matches(mine, mine);
    bool native_mismatch = cm_domain_flag_matches(mine, other);

    if (engine_match == native_match && engine_mismatch == native_mismatch &&
        engine_match && !engine_mismatch) {
        ESP_LOGI(TAG, "OP_CHECKDOMAINFLAG selftest OK — engine and fast path agree "
                      "(match=accept, mismatch=reject rc=%d)", err_mismatch);
    } else {
        ESP_LOGE(TAG, "OP_CHECKDOMAINFLAG selftest FAILED — engine(match=%d,mismatch=%d) "
                      "native(match=%d,mismatch=%d) rc=(%d,%d). The forward gate is "
                      "NOT enforcing the opcode's predicate.",
                 (int)engine_match, (int)engine_mismatch,
                 (int)native_match, (int)native_mismatch, err_match, err_mismatch);
    }
}

// Forward declaration — emit_mnca_settle is defined after broadcast_telem.
static void emit_mnca_settle(const cm_mnca_tile_t *t, const uint8_t tile_hash[32]);

// ── Radio receive callback (WiFi task context) ───────────────────────
static void on_radio_recv(const uint8_t sender_mac[6],
                          const uint8_t *frame_bytes, size_t frame_len,
                          void *userdata) {
    (void)userdata;
    if (memcmp(sender_mac, s_my_mac, 6) == 0) return;

    // Static to avoid 1088 B stack alloc in the ESP-NOW receive callback.
    // The callback runs in a single task context so static is safe.
    static uint8_t cell[CM_CELL_SIZE];
    static uint8_t sig[CM_FRAME_SIG_SIZE];
    uint64_t now_ms = (uint64_t)esp_log_timestamp();

    cm_reasm_result_t r = cm_reasm_push(&s_reasm,
                                         frame_bytes, frame_len,
                                         sender_mac, now_ms,
                                         cell, sig);
    if (r != CM_REASM_COMPLETE) return;

    char mac_str[18]; format_mac(mac_str, sender_mac);

    // Forward.v0 is signature-free for now (segments mutate per hop;
    // see build_forward_cell comments). Handle it BEFORE the sig verify
    // gate so the unsigned cell isn't rejected.
    const uint8_t *th = cm_type_hash(cell);
    if (memcmp(th, s_forward_type_hash, 32) == 0) {
        s_rx_forward_counter++;
        const uint8_t *payload = cm_payload(cell);
        uint32_t payload_total = cm_payload_total(cell);
        if (payload_total < CM_FORWARD_HEADER_BYTES) {
            ESP_LOGW(TAG, "RX [%s] forward: payload_total=%u — too short",
                     mac_str, (unsigned)payload_total);
            return;
        }
        cm_forward_t fwd;
        if (cm_forward_decode(payload, (size_t)payload_total, &fwd) != 0) {
            ESP_LOGW(TAG, "RX [%s] forward: decode failed", mac_str);
            return;
        }
        // Is segments[0] me? If not — drop silently (ESP-NOW is broadcast;
        // peers see every other peer's cells and just ignore ones not
        // addressed to them).
        if (fwd.segments_remaining > 0 &&
            memcmp(fwd.segments[0], s_my_mac, 6) != 0) {
            return;
        }
        uint8_t next_mac[6] = {0};
        cm_forward_step_rc_t rc = cm_forward_step(&fwd, next_mac);

        // ── Apply hop_verb side-effect (relay hops AND destination) ──────
        // hop_verb is safe to dispatch here (WiFi task context) because:
        //   EVAL_RULES: only sets s_blink_until_us (word-atomic on RISC-V).
        //   INSTALL_RULE: copies bytes to s_pending_fwd_rule_bytes, single writer.
        // Neither calls the WASM engine or any task-registered WAMR API.
        if (fwd.hop_verb == CM_HOP_VERB_EVAL_RULES) {
            // Fire all tap-type rules against our synthetic tap cell.
            // The tap rule installed by install_demo_rules() is: blink 500ms.
            cm_effect_t hop_effects[CM_RULES_MAX];
            size_t n_effects = cm_rules_evaluate(&s_rules, NULL,
                                                  s_synthetic_tap_cell,
                                                  (uint64_t)esp_log_timestamp(),
                                                  hop_effects);
            for (size_t i = 0; i < n_effects; i++) {
                if (hop_effects[i].kind == CM_EFFECT_BLINK) {
                    s_blink_until_us = esp_timer_get_time()
                                     + (uint64_t)hop_effects[i].as.blink.duration_ms * 1000ULL;
                    ESP_LOGI(TAG, "HOP_VERB EVAL_RULES: blink %ums (hop %u)",
                             (unsigned)hop_effects[i].as.blink.duration_ms,
                             (unsigned)fwd.hop_index);
                }
            }
        } else if (fwd.hop_verb == CM_HOP_VERB_INSTALL_RULE) {
            if (fwd.inner_payload_len >= CM_RULE_ENCODED_SIZE) {
                if (!s_pending_fwd_rule) {
                    memcpy(s_pending_fwd_rule_bytes, fwd.inner_payload, CM_RULE_ENCODED_SIZE);
                    s_pending_fwd_rule = true;
                    ESP_LOGI(TAG, "HOP_VERB INSTALL_RULE: queued (hop %u)", (unsigned)fwd.hop_index);
                } else {
                    ESP_LOGW(TAG, "HOP_VERB INSTALL_RULE: mailbox full, dropped");
                }
            } else {
                ESP_LOGW(TAG, "HOP_VERB INSTALL_RULE: inner_payload too short (%u < %u)",
                         (unsigned)fwd.inner_payload_len, (unsigned)CM_RULE_ENCODED_SIZE);
            }
        }

        if (rc == CM_FWD_DELIVERED) {
            // Truncate inner_payload to a printable bound for the log.
            char preview[33] = {0};
            size_t n = fwd.inner_payload_len < sizeof(preview) - 1
                       ? fwd.inner_payload_len : sizeof(preview) - 1;
            memcpy(preview, fwd.inner_payload, n);
            ESP_LOGI(TAG, "*** FORWARD DELIVERED *** from=[%s] hop_index=%u verb=%u inner='%s'",
                     mac_str, (unsigned)fwd.hop_index, (unsigned)fwd.hop_verb, preview);
            // Visual: 800ms blink (in addition to any verb-driven blink above).
            s_blink_until_us = esp_timer_get_time()
                             + (uint64_t)FORWARD_DELIVERED_BLINK_MS * 1000ULL;
        } else if (rc == CM_FWD_NEXT) {
            ESP_LOGI(TAG, "RX [%s] forward → relay; next=%02x:%02x:%02x:%02x:%02x:%02x remaining=%u verb=%u",
                     mac_str,
                     next_mac[0], next_mac[1], next_mac[2],
                     next_mac[3], next_mac[4], next_mac[5],
                     (unsigned)fwd.segments_remaining, (unsigned)fwd.hop_verb);
            if (!s_pending_forward) {
                s_pending_forward_f      = fwd;
                s_pending_forward_domain = cm_flags(cell);
                s_pending_forward   = true;
            } else {
                s_forward_overruns++;
            }
        } else {
            ESP_LOGW(TAG, "RX [%s] forward: step error", mac_str);
        }
        return;
    }

    // ── forward.v1: channel-gated SRv6 forwarding ───────────────────────
    // Same unsigned fast-path as forward.v0. After segments[0]-check and
    // BEFORE stepping, we verify this hop's pre-signed commitment against
    // the local payment channel.  If the channel check fails we drop the
    // cell silently (the relay refuses to forward without payment).
    if (memcmp(th, s_forward_v1_type_hash, 32) == 0) {
        s_rx_forward_v1_counter++;
        const uint8_t *payload     = cm_payload(cell);
        uint32_t       payload_tot = cm_payload_total(cell);
        if (payload_tot < CM_FORWARD_V1_HEADER_BYTES) {
            ESP_LOGW(TAG, "RX [%s] forward.v1: too short (%u)", mac_str, (unsigned)payload_tot);
            return;
        }
        cm_forward_v1_t fv1;
        if (cm_forward_v1_decode(payload, (size_t)payload_tot, &fv1) != 0) {
            ESP_LOGW(TAG, "RX [%s] forward.v1: decode failed", mac_str);
            return;
        }
        // Is segments[0] addressed to me?
        if (fv1.segments_remaining > 0 &&
            memcmp(fv1.segments[0], s_my_mac, 6) != 0) {
            return;  // not for me — drop silently
        }
        // ── Capability check: sig must come from a certified relay key ──
        // hop_index before step = which commitment slot to read channel_id from.
        uint8_t my_hop = fv1.hop_index;
        uint64_t now_cap = (uint64_t)esp_log_timestamp();
        {
            // ── F2: Capability check — strict, no fallback to master key ────────
            // BRC-115: cert must be installed before any forward.v1 is accepted.
            uint8_t fwd_hash[32];
            cm_sig_hash_cell(cell, fwd_hash);
            const uint8_t *chid = (my_hop < CM_FORWARD_MAX_HOPS)
                                   ? fv1.hop_commitments[my_hop].channel_id
                                   : NULL;
            // OP_CHECKDOMAINFLAG, in the fast path: the cell's declared domain
            // (header bytes 24-27) is part of the lookup key, so authority
            // issued for one domain cannot relay a cell from another. A
            // mismatch is a miss, and the no-cert DROP below handles it.
            const uint32_t cell_domain = cm_flags(cell);
            const uint8_t *edge_pk = chid
                ? cm_cap_lookup(&s_cap_table, chid, CM_CAP_ROUTE_FWD_V1, now_cap, cell_domain)
                : NULL;
            if (!edge_pk) {
                // No cert installed for this channel — DROP (BRC-115, no fallback).
                ESP_LOGW(TAG, "RX [%s] forward.v1: no cert for channel "
                         "%02x%02x%02x%02x domain=0x%08x — DROP",
                         mac_str,
                         chid ? chid[0] : 0, chid ? chid[1] : 0,
                         chid ? chid[2] : 0, chid ? chid[3] : 0,
                         (unsigned)cell_domain);
                return;
            }
            if (cm_sig_verify(edge_pk, fwd_hash, sig) != 0) {
                ESP_LOGW(TAG, "RX [%s] forward.v1: sig INVALID (edge key) — DROP",
                         mac_str);
                return;
            }
            ESP_LOGI(TAG, "RX [%s] forward.v1: CAP-verified hop=%u",
                     mac_str, (unsigned)my_hop);
        }
        // ── Channel check + cert_hash binding ────────────────────────────────
        if (my_hop < CM_FORWARD_MAX_HOPS) {
            // F5: BRC-108 cert_hash binding — commitment must reference the same
            // cert that authorised the relay key.  Prevents replay with a different
            // or expired cert.
            const uint8_t *chid = fv1.hop_commitments[my_hop].channel_id;
            const uint8_t *stored_hash =
                cm_cap_cert_hash(&s_cap_table, chid, CM_CAP_ROUTE_FWD_V1, now_cap, cm_flags(cell));
            if (stored_hash &&
                memcmp(stored_hash, fv1.hop_commitments[my_hop].cert_hash, 32) != 0) {
                ESP_LOGW(TAG, "RX [%s] forward.v1: cert_hash mismatch hop=%u — DROP",
                         mac_str, (unsigned)my_hop);
                return;
            }

            // F6: Auto-adopt real BSV channel_id on the relay's forward channel.
            // The relay's s_fwd_channel is pre-opened with all-zeros (demo sentinel).
            // When the first real-channel commitment arrives (non-zero channel_id) and
            // the capability check above has already passed, migrate the stored
            // channel_id so the state machine accepts the commitment without
            // returning CM_CHAN_ERR_BAD_ID.  Safe because cm_cap_lookup (F2) already
            // verified a valid cert exists for this exact channel_id.
            {
                static const uint8_t s_zero16[16] = {0};
                if (s_fwd_channel.state == CM_CHAN_OPEN &&
                    memcmp(s_fwd_channel.channel_id, s_zero16, 16) == 0 &&
                    memcmp(chid, s_zero16, 16) != 0) {
                    memcpy(s_fwd_channel.channel_id, chid, 16);
                    ESP_LOGI(TAG, "fwd_channel: real channel_id adopted %02x%02x%02x%02x...",
                             chid[0], chid[1], chid[2], chid[3]);
                }
            }

            cm_channel_rc_t crc = cm_channel_apply_commitment(
                &s_fwd_channel,
                &fv1.hop_commitments[my_hop],
                now_cap);
            if (crc != CM_CHAN_OK) {
                ESP_LOGW(TAG, "RX [%s] forward.v1: CHANNEL REJECT hop=%u rc=%d "
                         "(seq=%u ds=%u)", mac_str, (unsigned)my_hop, (int)crc,
                         (unsigned)fv1.hop_commitments[my_hop].seq,
                         (unsigned)fv1.hop_commitments[my_hop].device_share);
                return;
            }
            ESP_LOGI(TAG, "RX [%s] forward.v1: channel OK hop=%u seq=%u "
                     "device_share=%u cert_hash=%02x%02x%02x%02x",
                     mac_str, (unsigned)my_hop,
                     (unsigned)s_fwd_channel.current_seq,
                     (unsigned)s_fwd_channel.device_share,
                     fv1.hop_commitments[my_hop].cert_hash[0],
                     fv1.hop_commitments[my_hop].cert_hash[1],
                     fv1.hop_commitments[my_hop].cert_hash[2],
                     fv1.hop_commitments[my_hop].cert_hash[3]);
        }
        // ── Step + hop_verb (same as v0) ─────────────────────────────────
        uint8_t next_mac[6] = {0};
        cm_forward_step_rc_t rc = cm_forward_v1_step(&fv1, next_mac);
        // Reuse v0 hop_verb dispatch (EVAL_RULES / INSTALL_RULE identical).
        if (fv1.hop_verb == CM_HOP_VERB_EVAL_RULES) {
            cm_effect_t hop_effects[CM_RULES_MAX];
            size_t n_eff = cm_rules_evaluate(&s_rules, NULL, s_synthetic_tap_cell,
                                              (uint64_t)esp_log_timestamp(), hop_effects);
            for (size_t i = 0; i < n_eff; i++) {
                if (hop_effects[i].kind == CM_EFFECT_BLINK) {
                    s_blink_until_us = esp_timer_get_time()
                                     + (uint64_t)hop_effects[i].as.blink.duration_ms * 1000ULL;
                    ESP_LOGI(TAG, "forward.v1 EVAL_RULES: blink %ums (hop %u)",
                             (unsigned)hop_effects[i].as.blink.duration_ms,
                             (unsigned)fv1.hop_index);
                }
            }
        } else if (fv1.hop_verb == CM_HOP_VERB_INSTALL_RULE) {
            if (fv1.inner_payload_len >= CM_RULE_ENCODED_SIZE && !s_pending_fwd_rule) {
                memcpy(s_pending_fwd_rule_bytes, fv1.inner_payload, CM_RULE_ENCODED_SIZE);
                s_pending_fwd_rule = true;
                ESP_LOGI(TAG, "forward.v1 INSTALL_RULE: queued (hop %u)", (unsigned)fv1.hop_index);
            }
        }
        if (rc == CM_FWD_DELIVERED) {
            char preview[33] = {0};
            size_t n = fv1.inner_payload_len < sizeof(preview) - 1
                       ? fv1.inner_payload_len : sizeof(preview) - 1;
            memcpy(preview, fv1.inner_payload, n);
            ESP_LOGI(TAG, "*** FORWARD.V1 DELIVERED *** from=[%s] hop=%u verb=%u "
                     "ds=%u inner='%s'", mac_str, (unsigned)fv1.hop_index,
                     (unsigned)fv1.hop_verb,
                     (unsigned)s_fwd_channel.device_share, preview);
            s_blink_until_us = esp_timer_get_time()
                             + (uint64_t)FORWARD_DELIVERED_BLINK_MS * 1000ULL;
        } else if (rc == CM_FWD_NEXT) {
            ESP_LOGI(TAG, "RX [%s] forward.v1 → relay; next=%02x:%02x:%02x:%02x:%02x:%02x "
                     "remaining=%u verb=%u ds=%u",
                     mac_str, next_mac[0], next_mac[1], next_mac[2],
                     next_mac[3], next_mac[4], next_mac[5],
                     (unsigned)fv1.segments_remaining, (unsigned)fv1.hop_verb,
                     (unsigned)s_fwd_channel.device_share);
            if (!s_pending_forward_v1) {
                s_pending_forward_v1_f      = fv1;
                s_pending_forward_v1_domain = cm_flags(cell);
                s_pending_forward_v1   = true;
            } else {
                s_forward_v1_overruns++;
            }
        } else {
            ESP_LOGW(TAG, "RX [%s] forward.v1: step error", mac_str);
        }
        return;
    }

    // ── forward.v2: Cell A — buffer until routing continuation arrives ────
    // forward.v2 is a 2-cell burst: Cell A (application payload) + Cell B
    // (routing continuation, same flow_id).  Signature is on Cell A; Cell B
    // carries unsigned routing+payment data.
    //
    // Receive path: verify sig → decode → store in burst slot keyed by flow_id.
    // When the matching Cell B arrives (cellmesh.routing.cont.v0 handler below),
    // process both together and queue for re-emission or deliver locally.
    if (memcmp(th, s_forward_v2_type_hash, 32) == 0) {
        s_rx_forward_v2_counter++;
        const uint8_t *payload     = cm_payload(cell);
        uint32_t       payload_tot = cm_payload_total(cell);
        if (payload_tot < CM_FORWARD_V2_HEADER_BYTES) {
            ESP_LOGW(TAG, "RX [%s] forward.v2 Cell A: too short (%u)",
                     mac_str, (unsigned)payload_tot);
            return;
        }
        // Do NOT verify sig here — Cell A is signed with a BRC-42-derived relay
        // key, which is only known after Cell B arrives and we look up the cert
        // table.  The sig is verified in the Cell B handler via edge_pk.
        cm_forward_v2_t pa;
        if (cm_forward_v2_decode(payload, (size_t)payload_tot, &pa) != 0) {
            ESP_LOGW(TAG, "RX [%s] forward.v2 Cell A: decode failed", mac_str);
            return;
        }
        // Hop-monotonic override: discard stale re-broadcasts of earlier hops.
        // Once slot holds hop N, don't let a hop<N overwrite it — this prevents
        // device A's 2nd broadcast (hop=0) from downgrading a relay Cell A' (hop=1)
        // that arrived first.  Different flow_ids always replace (new burst).
        if (s_fwdv2_burst.valid &&
            memcmp(pa.flow_id, s_fwdv2_burst.primary.flow_id, 16) == 0 &&
            pa.hop_index < s_fwdv2_burst.primary.hop_index) {
            return;  // stale hop — discard without touching slot
        }
        // Buffer Cell A — overwrite any prior slot.
        s_fwdv2_burst.primary = pa;
        memcpy(s_fwdv2_burst.primary_cell, cell, CM_CELL_SIZE);
        memcpy(s_fwdv2_burst.primary_sig,  sig,  CM_FRAME_SIG_SIZE);
        s_fwdv2_burst.valid   = true;
        ESP_LOGI(TAG, "RX [%s] forward.v2 Cell A: buffered flow=%02x%02x%02x%02x"
                 " hop=%u hops=%u inner=%u",
                 mac_str, pa.flow_id[0], pa.flow_id[1], pa.flow_id[2], pa.flow_id[3],
                 (unsigned)pa.hop_index, (unsigned)pa.total_hops,
                 (unsigned)pa.inner_payload_len);
        return;
    }

    // ── forward.v2: Cell B — routing continuation, pair with buffered Cell A ─
    // Cell B is unsigned (routing state mutates at each hop; signing would
    // require on-device keys).  Flow_id must match the buffered Cell A.
    if (memcmp(th, s_routing_cont_type_hash, 32) == 0) {
        const uint8_t *payload     = cm_payload(cell);
        uint32_t       payload_tot = cm_payload_total(cell);
        if (payload_tot < CM_ROUTING_CONT_USED_BYTES) {
            ESP_LOGW(TAG, "RX [%s] routing.cont: too short (%u)",
                     mac_str, (unsigned)payload_tot);
            return;
        }
        cm_routing_cont_t pb;
        if (cm_routing_cont_decode(payload, (size_t)payload_tot, &pb) != 0) {
            ESP_LOGW(TAG, "RX [%s] routing.cont: decode failed", mac_str);
            return;
        }
        // Must have a buffered Cell A with matching flow_id.
        if (!s_fwdv2_burst.valid ||
            memcmp(s_fwdv2_burst.primary.flow_id, pb.flow_id, 16) != 0) {
            ESP_LOGW(TAG, "RX [%s] routing.cont: no matching Cell A (flow=%02x%02x) — DROP",
                     mac_str, pb.flow_id[0], pb.flow_id[1]);
            s_fwdv2_burst.valid = false;
            return;
        }
        cm_forward_v2_t pa = s_fwdv2_burst.primary;
        // NOTE: do NOT clear valid yet — the original Cell B (from the source)
        // and the relayed Cell B (from an intermediate relay) both carry the
        // same flow_id.  We must NOT consume the burst slot on the first Cell B
        // that passes the flow_id check if it is not destined for this device.
        // Only consume (valid=false) once we confirm this Cell B is for us.

        // Is this burst addressed to me at this hop?
        // If segments_remaining > 0, segments[0] must be my MAC.
        // If segments_remaining == 0, the previous hop addressed me (deliver).
        if (pb.segments_remaining > 0 &&
            memcmp(pb.segments[0], s_my_mac, 6) != 0) {
            return;  // not for me at this hop — preserve burst slot for relay
        }
        s_fwdv2_burst.valid = false;  // consume the slot now that we own this hop

        uint8_t my_hop = pa.hop_index;

        // ── Capability check using Cell A's signing key ────────────────────
        {
            uint8_t fwd_hash[32];
            cm_sig_hash_cell(s_fwdv2_burst.primary_cell, fwd_hash);
            const uint8_t *chid = (my_hop < CM_FORWARD_MAX_HOPS)
                                   ? pb.hop_commitments[my_hop].channel_id
                                   : NULL;
            uint64_t now_cap = (uint64_t)esp_log_timestamp();
            // OP_CHECKDOMAINFLAG, in the fast path: the cell's declared domain
            // (header bytes 24-27) is part of the lookup key, so authority
            // issued for one domain cannot relay a cell from another. A
            // mismatch is a miss, and the no-cert DROP below handles it.
            const uint32_t cell_domain = cm_flags(cell);
            const uint8_t *edge_pk = chid
                ? cm_cap_lookup(&s_cap_table, chid, CM_CAP_ROUTE_FWD_V1, now_cap, cell_domain)
                : NULL;
            if (!edge_pk) {
                // No capability cert — DROP (same rule as forward.v1).
                ESP_LOGW(TAG, "RX [%s] forward.v2: no cert for channel "
                         "%02x%02x%02x%02x — DROP",
                         mac_str,
                         chid ? chid[0] : 0, chid ? chid[1] : 0,
                         chid ? chid[2] : 0, chid ? chid[3] : 0);
                return;
            }
            // Verify Cell A's sig (stored at burst time) against the edge key.
            // NOTE: relay devices rebuild Cell A with a zero sig (routing fields
            // mutate per hop — the payload changes with hop_index so the original
            // sig is intentionally cleared by design).  When primary_sig is all-
            // zeros the route is trusted on the strength of the cap cert alone.
            static const uint8_t ZERO_SIG[CM_FRAME_SIG_SIZE] = {0};
            if (memcmp(s_fwdv2_burst.primary_sig, ZERO_SIG, CM_FRAME_SIG_SIZE) != 0) {
                if (cm_sig_verify(edge_pk, fwd_hash, s_fwdv2_burst.primary_sig) != 0) {
                    ESP_LOGW(TAG, "RX [%s] forward.v2: sig INVALID (edge key) — DROP",
                             mac_str);
                    return;
                }
            }
            ESP_LOGI(TAG, "RX [%s] forward.v2: CAP-verified hop=%u", mac_str, (unsigned)my_hop);
        }

        // ── Channel check ──────────────────────────────────────────────────
        if (my_hop < CM_FORWARD_MAX_HOPS) {
            uint64_t now_ms = (uint64_t)esp_log_timestamp();
            const uint8_t *chid = pb.hop_commitments[my_hop].channel_id;
            const uint8_t *stored_hash =
                cm_cap_cert_hash(&s_cap_table, chid, CM_CAP_ROUTE_FWD_V1, now_ms, cm_flags(cell));
            if (stored_hash &&
                memcmp(stored_hash, pb.hop_commitments[my_hop].cert_hash, 32) != 0) {
                ESP_LOGW(TAG, "RX [%s] forward.v2: cert_hash mismatch hop=%u — DROP",
                         mac_str, (unsigned)my_hop);
                return;
            }
            // F6: same auto-adopt as forward.v1 — see comment above.
            {
                static const uint8_t s_zero16_v2[16] = {0};
                if (s_fwd_channel.state == CM_CHAN_OPEN &&
                    memcmp(s_fwd_channel.channel_id, s_zero16_v2, 16) == 0 &&
                    memcmp(chid, s_zero16_v2, 16) != 0) {
                    memcpy(s_fwd_channel.channel_id, chid, 16);
                    ESP_LOGI(TAG, "fwd_channel(v2): real channel_id adopted %02x%02x%02x%02x...",
                             chid[0], chid[1], chid[2], chid[3]);
                }
            }

            cm_channel_rc_t crc = cm_channel_apply_commitment(
                &s_fwd_channel,
                &pb.hop_commitments[my_hop],
                now_ms);
            if (crc != CM_CHAN_OK) {
                ESP_LOGW(TAG, "RX [%s] forward.v2: CHANNEL REJECT hop=%u rc=%d",
                         mac_str, (unsigned)my_hop, (int)crc);
                return;
            }
            ESP_LOGI(TAG, "RX [%s] forward.v2: channel OK hop=%u seq=%u device_share=%u",
                     mac_str, (unsigned)my_hop,
                     (unsigned)s_fwd_channel.current_seq,
                     (unsigned)s_fwd_channel.device_share);
        }

        // ── Step ──────────────────────────────────────────────────────────
        uint8_t next_mac[6] = {0};
        cm_forward_step_rc_t rc = cm_forward_v2_step(&pa, &pb, next_mac);

        if (rc == CM_FWD_DELIVERED) {
            char preview[33] = {0};
            size_t n = pa.inner_payload_len < sizeof(preview) - 1
                       ? pa.inner_payload_len : sizeof(preview) - 1;
            memcpy(preview, pa.inner_payload, n);
            ESP_LOGI(TAG, "*** FORWARD.V2 DELIVERED *** from=[%s] hop=%u verb=%u "
                     "ds=%u inner='%s'",
                     mac_str, (unsigned)pa.hop_index,
                     (unsigned)pa.hop_verb,
                     (unsigned)s_fwd_channel.device_share, preview);
            s_blink_until_us = esp_timer_get_time()
                             + (uint64_t)FORWARD_DELIVERED_BLINK_MS * 1000ULL;
        } else if (rc == CM_FWD_NEXT) {
            ESP_LOGI(TAG, "RX [%s] forward.v2 → relay; next=%02x:%02x:%02x:%02x:%02x:%02x "
                     "remaining=%u ds=%u",
                     mac_str, next_mac[0], next_mac[1], next_mac[2],
                     next_mac[3], next_mac[4], next_mac[5],
                     (unsigned)pb.segments_remaining,
                     (unsigned)s_fwd_channel.device_share);
            if (!s_pending_forward_v2) {
                s_pending_fwdv2_a           = pa;
                s_pending_fwdv2_b           = pb;
                s_pending_fwdv2_domain      = cm_flags(cell);
                s_pending_fwdv2_cell_a_sent = false;  // Cell A' not yet sent
                s_pending_fwdv2_retry_skip  = 0;
                s_fwdv2_cell_b_sends_left   = 3;      // redundant Cell B sends
                s_pending_forward_v2        = true;
            } else {
                s_forward_v2_overruns++;
            }
        } else {
            ESP_LOGW(TAG, "RX [%s] forward.v2: step error", mac_str);
        }
        return;
    }

    // mnca.tile.v0 and cellmesh.channel_settle.v0 — unsigned, handled before
    // the sig-verify gate. Tile cells are high-cadence gossip (one per 3s per
    // device) and carry no ECDSA sig; quorum provides integrity.  Settle cells
    // are also unsigned (emitted by the quorum trigger, not the wallet).
    if (memcmp(th, s_mnca_tile_v0_type_hash, 32) == 0) {
        const uint8_t *payload = cm_payload(cell);
        uint32_t       ptot    = cm_payload_total(cell);
        cm_mnca_tile_t decoded;
        if (cm_mnca_tile_decode(payload, (size_t)ptot, &decoded) == 0) {
            uint8_t tile_hash[32];
            cm_mnca_tile_hash(&decoded, tile_hash);
            uint64_t now_ms2 = (uint64_t)esp_log_timestamp();
            cm_mnca_quorum_rc_t qrc = cm_mnca_quorum_update(
                &s_mnca_quorum, decoded.x, decoded.y, decoded.generation,
                tile_hash, sender_mac, now_ms2);
            ESP_LOGI(TAG, "RX [%s] mnca.tile.v0 x=%u y=%u gen=%u "
                     "hash=%02x%02x%02x%02x quorum=%s",
                     mac_str,
                     (unsigned)decoded.x, (unsigned)decoded.y,
                     (unsigned)decoded.generation,
                     tile_hash[0], tile_hash[1], tile_hash[2], tile_hash[3],
                     qrc == CM_MNCA_QUORUM_HIT ? "HIT" : "PENDING");
            if (qrc == CM_MNCA_QUORUM_HIT) {
                emit_mnca_settle(&decoded, tile_hash);
            }
        } else {
            ESP_LOGW(TAG, "RX [%s] mnca.tile.v0 decode failed (ptot=%u)",
                     mac_str, (unsigned)ptot);
        }
        return;
    }

    if (memcmp(th, s_mnca_channel_settle_type_hash, 32) == 0) {
        const uint8_t *payload = cm_payload(cell);
        uint32_t       ptot    = cm_payload_total(cell);
        if (ptot >= 40) {
            uint16_t sx  = (uint16_t)(payload[0] | (payload[1] << 8));
            uint16_t sy  = (uint16_t)(payload[2] | (payload[3] << 8));
            uint32_t gen = (uint32_t)(payload[4] | (payload[5] << 8) |
                                      (payload[6] << 16) | (payload[7] << 24));
            ESP_LOGI(TAG, "RX [%s] mnca.channel_settle.v0 x=%u y=%u gen=%u "
                     "hash=%02x%02x%02x%02x...",
                     mac_str, (unsigned)sx, (unsigned)sy, (unsigned)gen,
                     payload[8], payload[9], payload[10], payload[11]);
        }
        return;
    }

    // Telemetry.v0 — unsigned hot-path. Handled before the sig-verify gate
    // (like forward.v0): per-frame verify at ~270ms would cap us at ~3
    // cells/sec, so pose cells carry no signature. Just decode + log; the
    // mesh-observer parses these into latency/jitter/Hz metrics.
    if (memcmp(th, s_telem_type_hash, 32) == 0) {
        const uint8_t *p = cm_payload(cell);
        if (cm_payload_total(cell) < 28) return;
        uint32_t seq   = cm_read_u32(p + 0);
        int32_t  spd   = (int32_t)cm_read_u32(p + 4);
        int32_t  x     = (int32_t)cm_read_u32(p + 8);
        int32_t  y     = (int32_t)cm_read_u32(p + 12);
        int32_t  hdg   = (int32_t)cm_read_u32(p + 16);
        int32_t  v     = (int32_t)cm_read_u32(p + 20);
        uint32_t tx_us = cm_read_u32(p + 24);
        s_rx_telem_counter++;
        ESP_LOGI(TAG, "RX [%s] telem #%u spd=%d x=%d y=%d hdg=%d v=%d tx_t=%u (rx_total=%u)",
                 mac_str, (unsigned)seq, (int)spd, (int)x, (int)y, (int)hdg, (int)v,
                 (unsigned)tx_us, (unsigned)s_rx_telem_counter);
        return;
    }

    // Verify signature for all non-forward cells, against the wallet
    // pubkey (compiled-in s_wallet_pubkey).
    uint8_t hash[32];
    cm_sig_hash_cell(cell, hash);
    if (cm_sig_verify(s_wallet_pubkey, hash, sig) != 0) {
        ESP_LOGW(TAG, "RX [%s] signature INVALID (wallet pubkey)", mac_str);
        return;
    }

    s_rx_counter++;

    // Determine cell type for the log line.
    const char *kind = "unknown";
    bool is_rule = false;
    bool is_channel_open       = false;
    bool is_channel_commitment = false;
    bool is_channel_close      = false;
    bool is_scripted           = false;
    bool is_actuator_offer     = false;
    bool is_actuator_activate  = false;
    bool is_capability_v0      = false;
    bool is_channel_settle     = false;
    if      (memcmp(th, s_heartbeat_type_hash,          32) == 0) kind = "heartbeat";
    else if (memcmp(th, s_tap_type_hash,                32) == 0) kind = "TAP";
    else if (memcmp(th, s_confirmed_tap_type_hash,      32) == 0) kind = "confirmed_tap";
    else if (memcmp(th, s_rule_type_hash,               32) == 0) { kind = "RULE";              is_rule = true; }
    else if (memcmp(th, s_channel_open_type_hash,       32) == 0) { kind = "channel_open";      is_channel_open = true; }
    else if (memcmp(th, s_channel_commitment_type_hash, 32) == 0) { kind = "channel_commit";    is_channel_commitment = true; }
    else if (memcmp(th, s_channel_close_type_hash,      32) == 0) { kind = "channel_close";     is_channel_close = true; }
    else if (memcmp(th, s_channel_settle_type_hash,     32) == 0) { kind = "channel_settle";    is_channel_settle = true; }
    else if (memcmp(th, s_scripted_type_hash,           32) == 0) { kind = "scripted";          is_scripted = true; }
    else if (memcmp(th, s_actuator_offer_type_hash,     32) == 0) { kind = "actuator_offer";    is_actuator_offer = true; }
    else if (memcmp(th, s_actuator_activate_type_hash,  32) == 0) { kind = "actuator_activate"; is_actuator_activate = true; }
    else if (memcmp(th, s_capability_v0_type_hash,      32) == 0) { kind = "CAP cert";          is_capability_v0 = true; }

    ESP_LOGI(TAG, "RX [%s] %s verified (rx_total=%u)", mac_str, kind, (unsigned)s_rx_counter);

    // channel_settle: the bridge has closed the channel on-chain.  Log the
    // settlement evidence: channel_id[16] + final_seq u32 + device_share u32
    // + settle_txid[32].  No local state change needed — the channel state
    // machine is driven by the bridge; devices are read-only verifiers here.
    if (memcmp(th, s_channel_settle_type_hash, 32) == 0) {
        const uint8_t *p  = cm_payload(cell);
        uint32_t       pt = cm_payload_total(cell);
        if (pt >= 16 + 4 + 4 + 32) {
            // channel_id as hex prefix (8 bytes = 16 hex chars)
            uint32_t final_seq    = (uint32_t)p[16] | ((uint32_t)p[17] << 8)
                                  | ((uint32_t)p[18] << 16) | ((uint32_t)p[19] << 24);
            uint32_t device_share = (uint32_t)p[20] | ((uint32_t)p[21] << 8)
                                  | ((uint32_t)p[22] << 16) | ((uint32_t)p[23] << 24);
            // settle_txid: bytes 24..55 (hex first 8 bytes = 16 chars)
            ESP_LOGI(TAG,
                "CHANNEL SETTLE: seq=%u device_share=%u sats "
                "txid=%02x%02x%02x%02x%02x%02x%02x%02x...",
                (unsigned)final_seq, (unsigned)device_share,
                p[24], p[25], p[26], p[27], p[28], p[29], p[30], p[31]);
        } else {
            ESP_LOGW(TAG, "channel_settle payload too short (%u bytes)", (unsigned)pt);
        }
    }

    // Scripted cells: enqueue the payload for the main loop to dispatch.
    // We can't run the cell-engine from the WiFi RX task — WAMR's
    // pthread shim only knows about the main task (registered at boot
    // via wasm_runtime_init_thread_env), and calling from anywhere else
    // trips an assertion in pthread.c. Skip the rules engine entirely.
    if (is_scripted) {
        const uint8_t *payload = cm_payload(cell);
        uint32_t       ptot    = cm_payload_total(cell);
        if (s_pending_script) {
            s_pending_script_overruns++;
        } else if (ptot <= SCRIPTED_MBOX_BYTES) {
            memcpy(s_pending_script_payload, payload, ptot);
            s_pending_script_len = ptot;
            memcpy(s_pending_script_mac_str, mac_str, sizeof(s_pending_script_mac_str));
            s_pending_script = true;
        } else {
            ESP_LOGW(TAG, "scripted [%s]: payload %u > mbox %u — dropping",
                     mac_str, (unsigned)ptot, (unsigned)SCRIPTED_MBOX_BYTES);
        }
        return;
    }

    // actuator_offer.v0 — informational. Devices that want to pay
    // would parse cost/duration/lock here. For our demo, device A's
    // deck already encodes the matching activate cells; nothing to do.
    if (is_actuator_offer) {
        return;
    }

    // actuator_activate.v0 — only the rentable device (C) processes.
    // Same dispatch pattern as scripted: enqueue payload, drain runs
    // engine on main pthread, on accept extend the LED-active window.
    if (is_actuator_activate) {
        if (!DEMO_SCRIPT_ONLY && !s_is_destination) return; // demo: any board is the rentable actuator
        const uint8_t *payload = cm_payload(cell);
        uint32_t       ptot    = cm_payload_total(cell);
        if (s_pending_actuator) {
            s_pending_actuator_overruns++;
        } else if (ptot <= SCRIPTED_MBOX_BYTES) {
            memcpy(s_pending_actuator_payload, payload, ptot);
            s_pending_actuator_len = ptot;
            memcpy(s_pending_actuator_mac_str, mac_str, sizeof(s_pending_actuator_mac_str));
            s_pending_actuator = true;
        } else {
            ESP_LOGW(TAG, "actuator [%s]: payload %u > mbox %u — dropping",
                     mac_str, (unsigned)ptot, (unsigned)SCRIPTED_MBOX_BYTES);
        }
        return;
    }

    // ── Capability cert handler ─────────────────────────────────────────
    // Install the relay key grant from the cert payload.  Any device
    // installs certs (not just the destination) so that all relays can
    // accept forward.v1 from the certified relay key.
    if (is_capability_v0) {
        const uint8_t *p  = cm_payload(cell);
        uint32_t       pt = cm_payload_total(cell);
        // The domain is taken from the cert CELL's header, not the payload —
        // the 66-byte payload has no spare room, and the cell header is
        // covered by the operator signature verified above, so the recorded
        // domain is authenticated rather than merely asserted.
        const uint32_t cert_domain = cm_flags(cell);
        cm_cap_rc_t crc = cm_cap_install(&s_cap_table, p, (size_t)pt,
                                          (uint64_t)esp_log_timestamp(),
                                          cert_domain);
        if (crc == CM_CAP_OK) {
            // Payload layout: edge_pubkey[33] | channel_id[16] | expiry[8] | route[1]
            ESP_LOGI(TAG,
                "CAP cert installed: ch=%02x%02x%02x%02x... edge=%02x%02x%02x%02x... domain=0x%08x",
                p[CM_CAP_OFF_CHANNEL_ID],   p[CM_CAP_OFF_CHANNEL_ID+1],
                p[CM_CAP_OFF_CHANNEL_ID+2], p[CM_CAP_OFF_CHANNEL_ID+3],
                p[CM_CAP_OFF_EDGE_PUBKEY],  p[CM_CAP_OFF_EDGE_PUBKEY+1],
                p[CM_CAP_OFF_EDGE_PUBKEY+2],p[CM_CAP_OFF_EDGE_PUBKEY+3],
                (unsigned)cert_domain);
        } else if (crc == CM_CAP_ERR_WRONG_DOMAIN) {
            // A cert the operator really did sign, for a domain this device is
            // not in. Signature valid, authority valid, namespace wrong.
            ESP_LOGW(TAG, "CAP cert REFUSED: wrong domain 0x%08x, this device is 0x%08x",
                     (unsigned)cert_domain, (unsigned)cm_cap_get_domain(&s_cap_table));
        } else {
            ESP_LOGW(TAG, "CAP cert install FAILED: rc=%d", (int)crc);
        }
        return;
    }

    // ── Channel settle handler ──────────────────────────────────────────
    // Log the BSV settlement event: seq, device_share, and settle txid.
    if (is_channel_settle) {
        const uint8_t *p  = cm_payload(cell);
        uint32_t       pt = cm_payload_total(cell);
        if (pt >= 16 + 4 + 4 + 32) {
            uint32_t final_seq    = (uint32_t)p[16] | ((uint32_t)p[17] << 8)
                                  | ((uint32_t)p[18] << 16) | ((uint32_t)p[19] << 24);
            uint32_t device_share = (uint32_t)p[20] | ((uint32_t)p[21] << 8)
                                  | ((uint32_t)p[22] << 16) | ((uint32_t)p[23] << 24);
            ESP_LOGI(TAG,
                "CHANNEL SETTLE: seq=%u device_share=%u sats "
                "txid=%02x%02x%02x%02x%02x%02x%02x%02x...",
                (unsigned)final_seq, (unsigned)device_share,
                p[24], p[25], p[26], p[27], p[28], p[29], p[30], p[31]);
        }
        return;
    }

    // ── Channel cells ────────────────────────────────────────────────
    // Only the lightbulb (device C) runs the channel state machine.
    // Other devices verify the sig + log, then drop. The lightbulb
    // decodes the payload, runs the matching apply_*, and the main loop
    // turns the LED steady-on when state == CM_CHAN_ACTIVE.
    //
    // Channel cells DO NOT enter the rules engine — return early to
    // skip the ring push + rules eval (keeps quorum counters clean).
    if (is_channel_open || is_channel_commitment || is_channel_close) {
        if (!DEMO_SCRIPT_ONLY && !s_is_destination) return; // demo: any board runs the metered channel
        const uint8_t *payload = cm_payload(cell);
        uint32_t       ptot    = cm_payload_total(cell);

        if (is_channel_open) {
            if (ptot < CM_CHANNEL_OPEN_PAYLOAD_BYTES) {
                ESP_LOGW(TAG, "RX channel_open: ptot=%u too short", (unsigned)ptot);
                return;
            }
            cm_channel_open_t op;
            if (cm_channel_open_decode(payload, &op) != 0) {
                ESP_LOGW(TAG, "RX channel_open: decode failed"); return;
            }
            cm_channel_rc_t rc = cm_channel_apply_open(&s_channel, &op);
            if (rc != CM_CHAN_OK) {
                ESP_LOGW(TAG, "RX channel_open: apply_open rc=%d", (int)rc);
                return;
            }
            s_channel_base_ms = now_ms;
            cm_meter_init(&s_meter, CM_METER_RATE_MSAT_PER_SEC); // fresh meter per channel (don't carry consumed across sessions)
            s_meter_cut = false;
            ESP_LOGI(TAG, "*** CHANNEL OPEN *** capacity=%u locktime=%llu ms (state=OPEN)",
                     (unsigned)op.total_capacity,
                     (unsigned long long)op.initial_locktime_ms);
        } else if (is_channel_commitment) {
            if (ptot < CM_CHANNEL_COMMITMENT_PAYLOAD_BYTES) {
                ESP_LOGW(TAG, "RX channel_commit: ptot=%u too short", (unsigned)ptot);
                return;
            }
            cm_channel_commitment_t cm;
            if (cm_channel_commitment_decode(payload, &cm) != 0) {
                ESP_LOGW(TAG, "RX channel_commit: decode failed"); return;
            }
            // Translate wallet's "relative-to-open" expiry into the
            // device's now_ms domain by passing relative_now.
            uint64_t relative_now = now_ms - s_channel_base_ms;
            cm_channel_rc_t rc = cm_channel_apply_commitment(&s_channel, &cm, relative_now);
            if (rc != CM_CHAN_OK) {
                ESP_LOGW(TAG, "RX channel_commit seq=%u: apply rc=%d (rel_now=%llu expiry=%llu)",
                         (unsigned)cm.seq, (int)rc,
                         (unsigned long long)relative_now,
                         (unsigned long long)cm.expiry_ms);
                return;
            }
            // Service is being delivered → start metering on the first
            // commitment (idempotent once running). The actuator gate then
            // tracks consumed-vs-paid every loop.
            cm_meter_start(&s_meter, now_ms);
            ESP_LOGI(TAG, "*** CHANNEL COMMIT seq=%u *** device_share=%u consumed=%u sats expiry=%llu (rel_now=%llu, state=ACTIVE)",
                     (unsigned)cm.seq, (unsigned)cm.device_share,
                     (unsigned)cm_meter_consumed_sats(&s_meter),
                     (unsigned long long)cm.expiry_ms,
                     (unsigned long long)relative_now);
        } else /* is_channel_close */ {
            if (ptot < CM_CHANNEL_CLOSE_PAYLOAD_BYTES) {
                ESP_LOGW(TAG, "RX channel_close: ptot=%u too short", (unsigned)ptot);
                return;
            }
            cm_channel_close_t cl;
            if (cm_channel_close_decode(payload, &cl) != 0) {
                ESP_LOGW(TAG, "RX channel_close: decode failed"); return;
            }
            cm_channel_rc_t rc = cm_channel_apply_close(&s_channel, &cl);
            if (rc != CM_CHAN_OK) {
                ESP_LOGW(TAG, "RX channel_close: apply rc=%d", (int)rc);
                return;
            }
            cm_meter_stop(&s_meter, now_ms);
            ESP_LOGI(TAG, "*** CHANNEL CLOSED *** final_seq=%u final_device_share=%u consumed=%u sats",
                     (unsigned)cl.final_seq, (unsigned)cl.final_device_share,
                     (unsigned)cm_meter_consumed_sats(&s_meter));
        }
        return;
    }

    // Rule-as-cell hot-swap: a verified `cellmesh.rule.v0` cell carries
    // a serialized rule in its payload. Parse + install into the rules
    // table at runtime. Dedup against already-installed rules so two
    // devices broadcasting the same rule don't double-install.
    if (is_rule) {
        const uint8_t *payload = cm_payload(cell);
        uint32_t      payload_total = cm_payload_total(cell);
        if (payload_total < CM_RULE_ENCODED_SIZE) {
            ESP_LOGW(TAG, "RX rule: payload_total=%u < %u — too short, dropping",
                     (unsigned)payload_total, (unsigned)CM_RULE_ENCODED_SIZE);
        } else {
            cm_rule_t parsed;
            if (cm_rule_decode(payload, &parsed) != 0) {
                ESP_LOGW(TAG, "RX rule: decode failed");
            } else {
                // Dedup: if any installed rule is structurally identical, skip.
                bool dup = false;
                for (size_t i = 0; i < CM_RULES_MAX; i++) {
                    if (!s_rules.entries[i].occupied) continue;
                    if (cm_rule_equals(&s_rules.entries[i], &parsed)) { dup = true; break; }
                }
                if (dup) {
                    ESP_LOGI(TAG, "RX rule: already installed — skipping (dedup)");
                } else {
                    int slot = cm_rules_install(&s_rules, &parsed);
                    if (slot < 0) {
                        ESP_LOGW(TAG, "RX rule: install failed (table full?)");
                    } else {
                        ESP_LOGI(TAG, "RX rule: *** HOT-SWAP INSTALLED at slot %d ***", slot);
                    }
                }
            }
        }
        // Rule cells don't themselves trigger downstream rules — return.
        // (Pushing them into the ring would clutter quorum counters.)
        return;
    }

    // Push the just-arrived cell into the ring BEFORE evaluating rules,
    // so quorum triggers can count it. The ring's window/dedup is what
    // cm_rules_evaluate consults for CM_TRIGGER_QUORUM matches.
    cm_ring_push(&s_ring, cell, sender_mac, now_ms);

    // Evaluate rules + dispatch effects.
    cm_effect_t effects[CM_RULES_MAX];
    size_t n_effects = cm_rules_evaluate(&s_rules, &s_ring, cell, now_ms, effects);
    for (size_t i = 0; i < n_effects; i++) {
        dispatch_effect(&effects[i]);
    }
}

// ── Broadcast helpers (deck-driven; no on-device signing) ────────────
//
// Each helper pops the next pre-signed cell from its queue and sends.
// Cells live in flash; we copy into a local RAM buffer because
// cm_radio_send_cell fragments + may write into the buffer (and flash
// reads should be linear in any case for predictable latency).
static void broadcast_heartbeat(void) {
    if (DEMO_SCRIPT_ONLY) return;        // demo: dark stage, no background radio
    const uint8_t *cell_flash, *sig_flash;
    if (!deck_pop(&s_q_heartbeat, "heartbeat", &cell_flash, &sig_flash)) return;

    uint8_t cell[CM_CELL_SIZE], sig[CM_FRAME_SIG_SIZE];
    memcpy(cell, cell_flash, CM_CELL_SIZE);
    memcpy(sig,  sig_flash,  CM_FRAME_SIG_SIZE);

    uint32_t cell_id = (uint32_t)esp_random();
    if (cm_radio_send_cell(cell, sig, cell_id) == 0) {
        s_tx_heartbeat_counter++;
        ESP_LOGI(TAG, "TX heartbeat #%u (deck)", (unsigned)s_tx_heartbeat_counter);
    }
}

// Hot-swap rule: the pre-signed rule cell carries a serialized BLINK-on-
// heartbeat rule. Each device installs it locally first (so it self-
// reacts) AND broadcasts so peers install it too. Pre-signing means
// the rule definition is locked at provisioning time; to swap a
// different rule, regenerate the deck.
static void broadcast_hot_swap_rule(void) {
    if (DEMO_SCRIPT_ONLY) return;        // demo: dark stage, no background radio
    const uint8_t *cell_flash, *sig_flash;
    if (!deck_pop(&s_q_hot_swap, "hot_swap", &cell_flash, &sig_flash)) return;

    // Install locally first. Decode the rule from the cell payload and
    // install it dedup-aware, matching the broadcast-side behavior.
    const uint8_t *payload = cm_payload(cell_flash);
    cm_rule_t parsed;
    if (cm_rule_decode(payload, &parsed) == 0) {
        bool dup = false;
        for (size_t i = 0; i < CM_RULES_MAX; i++) {
            if (s_rules.entries[i].occupied && cm_rule_equals(&s_rules.entries[i], &parsed)) {
                dup = true; break;
            }
        }
        if (!dup) {
            int slot = cm_rules_install(&s_rules, &parsed);
            if (slot >= 0) {
                ESP_LOGI(TAG, "TX hot-swap rule: installing locally at slot %d", slot);
            }
        }
    } else {
        ESP_LOGW(TAG, "TX hot-swap rule: local decode failed (still broadcasting)");
    }

    uint8_t cell[CM_CELL_SIZE], sig[CM_FRAME_SIG_SIZE];
    memcpy(cell, cell_flash, CM_CELL_SIZE);
    memcpy(sig,  sig_flash,  CM_FRAME_SIG_SIZE);

    uint32_t cell_id = (uint32_t)esp_random();
    if (cm_radio_send_cell(cell, sig, cell_id) == 0) {
        ESP_LOGI(TAG, "TX *** HOT-SWAP RULE *** (BLINK 100ms on heartbeat, deck) cell_id=0x%08x",
                 (unsigned)cell_id);
    }
}

static void broadcast_tap(void) {
    if (DEMO_SCRIPT_ONLY) return;        // demo: dark stage, no background radio
    const uint8_t *cell_flash, *sig_flash;
    if (!deck_pop(&s_q_tap, "tap", &cell_flash, &sig_flash)) return;

    uint8_t cell[CM_CELL_SIZE], sig[CM_FRAME_SIG_SIZE];
    memcpy(cell, cell_flash, CM_CELL_SIZE);
    memcpy(sig,  sig_flash,  CM_FRAME_SIG_SIZE);

    uint32_t cell_id = (uint32_t)esp_random();
    if (cm_radio_send_cell(cell, sig, cell_id) == 0) {
        s_tx_tap_counter++;
        ESP_LOGI(TAG, "TX *** TAP #%u *** (deck, broadcasting)", (unsigned)s_tx_tap_counter);
        // Local feedback — blink our own LED too.
        s_blink_until_us = esp_timer_get_time() + 500ULL * 1000ULL;
    }
}

// ── Multi-hop forward: build + broadcast a forward cell ──────────────
//
// Builds a forward cell. `fwd` already has segments + inner_payload
// populated by the caller. The cell is NOT signed (see v0 shortcut
// note above); the type_hash + payload_root still anchor the wire
// shape so a future signed variant slots in without changing layout.
static int build_forward_cell(uint32_t domain_flag, const cm_forward_t *fwd,
                              uint8_t out_cell[CM_CELL_SIZE],
                              uint8_t out_sig[CM_FRAME_SIG_SIZE]) {
    cm_cell_init(out_cell);
    cm_set_flags(out_cell, domain_flag);   // carry the relayed cell's domain
    cm_set_linearity(out_cell, CM_LINEARITY_AFFINE);
    memcpy(cm_type_hash_mut(out_cell), s_forward_type_hash, 32);
    memcpy(cm_owner_id_mut(out_cell), s_my_mac, 6);
    memset(cm_owner_id_mut(out_cell) + 6, 0, 10);
    cm_set_timestamp_ms(out_cell, (uint64_t)esp_log_timestamp());

    uint8_t  payload[CM_PAYLOAD_SIZE];
    size_t   used = 0;
    if (cm_forward_encode(fwd, payload, &used) != 0) return -1;
    if (used < CM_PAYLOAD_SIZE) memset(payload + used, 0, CM_PAYLOAD_SIZE - used);

    memcpy(cm_payload_mut(out_cell), payload, CM_PAYLOAD_SIZE);
    cm_set_payload_total(out_cell, (uint32_t)used);

    uint8_t pr[32];
    mbedtls_sha256(cm_payload(out_cell), CM_PAYLOAD_SIZE, pr, 0);
    memcpy(cm_domain_payload_root_mut(out_cell), pr, 32);

    // v0 shortcut: leave sig zeroed (segments mutate per hop; full-cell
    // signature would not survive). Future cm_sig_forward_hash will hash
    // only flow_id + inner_payload so a real signature can pass through.
    memset(out_sig, 0, CM_FRAME_SIG_SIZE);
    return 0;
}

// Originator role only. Mints a fresh forward cell with segments=[B,C]
// and broadcasts it. The cell carries a short inner payload tagged
// with the current flow counter so the destination's log line is
// distinguishable across multiple test runs.
static void broadcast_forward_route(void) {
    if (DEMO_SCRIPT_ONLY) return;        // demo: dark stage, no background radio
    cm_forward_t fwd = {0};
    // flow_id: timestamp-derived + tx counter — enough for visual debug.
    uint64_t ts = (uint64_t)esp_log_timestamp();
    memcpy(fwd.flow_id + 0, &ts, sizeof(ts));
    cm_write_u32(fwd.flow_id + 8, s_tx_forward_counter);
    memset(fwd.flow_id + 12, 0, 4);

    fwd.hop_index           = 0;
    fwd.total_hops          = 2;
    fwd.segments_remaining  = 2;
    fwd.hop_verb            = CM_HOP_VERB_EVAL_RULES;  // blink wave: tap rules fire at B then C
    memcpy(fwd.segments[0], MAC_B, 6);
    memcpy(fwd.segments[1], MAC_C, 6);

    static const char inner[] = "forward-test";
    memcpy(fwd.inner_payload, inner, sizeof(inner) - 1);
    fwd.inner_payload_len = sizeof(inner) - 1;

    uint8_t cell[CM_CELL_SIZE], sig[CM_FRAME_SIG_SIZE];
    if (build_forward_cell(s_pending_forward_domain, &fwd, cell, sig) != 0) {
        ESP_LOGE(TAG, "forward: build_forward_cell failed");
        return;
    }
    uint32_t cell_id = (uint32_t)esp_random();
    if (cm_radio_send_cell(cell, sig, cell_id) == 0) {
        s_tx_forward_counter++;
        ESP_LOGI(TAG, "TX *** FORWARD ORIGINATED #%u *** segments=[B,C] cell_id=0x%08x",
                 (unsigned)s_tx_forward_counter, (unsigned)cell_id);
    }
}

// ── Speeder telemetry: synthetic figure-8 + unsigned broadcast ───────
//
// The pose source uses float trig for clarity — it's a synthetic stand-in
// for a real flight-controller feed. The cell PAYLOAD and any downstream
// transform-on-hop compute stay integer/fixed-point (MNCA discipline); only
// this generator touches floats, and at 20 Hz the soft-float cost is noise.
static void telem_pose(uint64_t now_us, int32_t *x, int32_t *y,
                       int32_t *hdg, int32_t *v) {
    double t  = (double)now_us / 1e6;
    double w  = 2.0 * M_PI / TELEM_LAP_SEC;
    double ph = (double)(s_telem_spd > 0 ? s_telem_spd - 1 : 0) * (M_PI / 3.0);
    double a  = w * t + ph;
    double sx = sin(a), cx = cos(a);
    double px = TELEM_FIG8_MM * sx;
    double py = TELEM_FIG8_MM * sx * cx;
    double dx = TELEM_FIG8_MM * cx * w;
    double dy = TELEM_FIG8_MM * (cx * cx - sx * sx) * w;
    double speed = sqrt(dx * dx + dy * dy);
    double h = atan2(dy, dx);
    if (h < 0) h += 2.0 * M_PI;
    *x   = (int32_t)lround(px);
    *y   = (int32_t)lround(py);
    *hdg = (int32_t)lround(h * 1000.0);
    *v   = (int32_t)lround(speed);
}

// Builds + broadcasts one unsigned pose cell. Payload layout (little-endian,
// 28 bytes): seq u32, spd u32, x i32, y i32, hdg i32, v i32, tx_us u32.
static void broadcast_telem(uint64_t now_us) {
    if (DEMO_SCRIPT_ONLY) return;        // demo: dark stage, no background radio
    int32_t x, y, hdg, v;
    telem_pose(now_us, &x, &y, &hdg, &v);
    uint32_t tx_us = (uint32_t)now_us;   // wraps ~71 min; consumers use deltas

    uint8_t cell[CM_CELL_SIZE], sig[CM_FRAME_SIG_SIZE];
    cm_cell_init(cell);
    cm_set_flags(cell, CM_DOMAIN_MESH_TELEMETRY);  // unsigned: a namespace label, not a claim
    cm_set_linearity(cell, CM_LINEARITY_AFFINE);
    memcpy(cm_type_hash_mut(cell), s_telem_type_hash, 32);
    memcpy(cm_owner_id_mut(cell), s_my_mac, 6);
    memset(cm_owner_id_mut(cell) + 6, 0, 10);
    cm_set_timestamp_ms(cell, (uint64_t)esp_log_timestamp());

    uint8_t payload[CM_PAYLOAD_SIZE];
    memset(payload, 0, sizeof(payload));
    size_t off = 0;
    cm_write_u32(payload + off, s_tx_telem_counter); off += 4;
    cm_write_u32(payload + off, (uint32_t)s_telem_spd); off += 4;
    cm_write_u32(payload + off, (uint32_t)x);   off += 4;
    cm_write_u32(payload + off, (uint32_t)y);   off += 4;
    cm_write_u32(payload + off, (uint32_t)hdg); off += 4;
    cm_write_u32(payload + off, (uint32_t)v);   off += 4;
    cm_write_u32(payload + off, tx_us);         off += 4;
    memcpy(cm_payload_mut(cell), payload, CM_PAYLOAD_SIZE);
    cm_set_payload_total(cell, (uint32_t)off);

    uint8_t pr[32];
    mbedtls_sha256(cm_payload(cell), CM_PAYLOAD_SIZE, pr, 0);
    memcpy(cm_domain_payload_root_mut(cell), pr, 32);

    memset(sig, 0, CM_FRAME_SIG_SIZE);   // unsigned hot-path (no per-frame verify)

    uint32_t cell_id = (uint32_t)esp_random();
    if (cm_radio_send_cell(cell, sig, cell_id) == 0) {
        ESP_LOGI(TAG, "TX *** TELEM #%u *** spd=%d x=%d y=%d hdg=%d v=%d t=%u",
                 (unsigned)s_tx_telem_counter, (int)s_telem_spd,
                 (int)x, (int)y, (int)hdg, (int)v, (unsigned)tx_us);
        s_tx_telem_counter++;
    }
}

// ── MNCA tile step + broadcast ────────────────────────────────────────
//
// Advances the local tile one generation and broadcasts an unsigned
// mnca.tile.v0 cell.  Unsigned like telem — no on-device key needed;
// the quorum check provides consensus integrity.
//
// Channel_settle.v0 settle payload (40 bytes LE):
//   0  u16  x
//   2  u16  y
//   4  u32  generation
//   8  u8[32] tile_hash  SHA-256(state_bytes)
static void emit_mnca_settle(const cm_mnca_tile_t *t, const uint8_t tile_hash[32]) {
    // Use static buffers — cell+sig+payload = ~1856 B would overflow the
    // ESP-NOW receive callback stack.  This function is called only from a
    // single FreeRTOS task context so static storage is safe.
    static uint8_t cell[CM_CELL_SIZE], sig[CM_FRAME_SIG_SIZE];
    static uint8_t payload[CM_PAYLOAD_SIZE];
    cm_cell_init(cell);
    cm_set_flags(cell, CM_DOMAIN_MESH_TELEMETRY);  // unsigned observation of a settlement
    cm_set_linearity(cell, CM_LINEARITY_AFFINE);
    memcpy(cm_type_hash_mut(cell), s_mnca_channel_settle_type_hash, 32);
    memcpy(cm_owner_id_mut(cell), s_my_mac, 6);
    memset(cm_owner_id_mut(cell) + 6, 0, 10);
    cm_set_timestamp_ms(cell, (uint64_t)esp_log_timestamp());

    memset(payload, 0, CM_PAYLOAD_SIZE);
    cm_write_u16(payload + 0, t->x);
    cm_write_u16(payload + 2, t->y);
    cm_write_u32(payload + 4, t->generation);
    memcpy(payload + 8, tile_hash, 32);
    size_t used = 40;
    memcpy(cm_payload_mut(cell), payload, CM_PAYLOAD_SIZE);
    cm_set_payload_total(cell, (uint32_t)used);

    uint8_t pr[32];
    mbedtls_sha256(cm_payload(cell), CM_PAYLOAD_SIZE, pr, 0);
    memcpy(cm_domain_payload_root_mut(cell), pr, 32);
    memset(sig, 0, CM_FRAME_SIG_SIZE);

    uint32_t cell_id = (uint32_t)esp_random();
    // Log unconditionally — the economic signal is the consensus, not just the TX.
    ESP_LOGI(TAG, "*** MNCA QUORUM SETTLE *** x=%u y=%u gen=%u "
             "hash=%02x%02x%02x%02x%02x%02x%02x%02x cell_id=0x%08x",
             (unsigned)t->x, (unsigned)t->y, (unsigned)t->generation,
             tile_hash[0], tile_hash[1], tile_hash[2], tile_hash[3],
             tile_hash[4], tile_hash[5], tile_hash[6], tile_hash[7],
             (unsigned)cell_id);
    int tx_rc = cm_radio_send_cell(cell, sig, cell_id);
    if (tx_rc != 0) {
        ESP_LOGW(TAG, "SETTLE: radio send failed rc=%d (cell queued for retry)", tx_rc);
    }
}

static void broadcast_mnca_tile(void) {
    if (DEMO_SCRIPT_ONLY) return;        // demo: dark stage, no background radio
    // Advance one generation (double-buffered: cur → next).
    cm_mnca_tile_t next;
    cm_mnca_step(&s_mnca_tile, &next, &CM_MNCA_DEFAULT_RULE);
    s_mnca_tile = next;

    // Build unsigned mnca.tile.v0 cell.  Use static buffers to avoid
    // a 1088-byte stack alloc in the tight broadcast path.
    static uint8_t cell[CM_CELL_SIZE], sig[CM_FRAME_SIG_SIZE];
    cm_cell_init(cell);
    cm_set_flags(cell, CM_DOMAIN_MESH_TELEMETRY);  // unsigned device observation
    cm_set_linearity(cell, CM_LINEARITY_AFFINE);
    memcpy(cm_type_hash_mut(cell), s_mnca_tile_v0_type_hash, 32);
    memcpy(cm_owner_id_mut(cell), s_my_mac, 6);
    memset(cm_owner_id_mut(cell) + 6, 0, 10);
    cm_set_timestamp_ms(cell, (uint64_t)esp_log_timestamp());

    uint8_t payload[CM_PAYLOAD_SIZE];
    size_t used = cm_mnca_tile_encode(&s_mnca_tile, &CM_MNCA_DEFAULT_RULE, payload);
    memcpy(cm_payload_mut(cell), payload, CM_PAYLOAD_SIZE);
    cm_set_payload_total(cell, (uint32_t)used);

    uint8_t pr[32];
    mbedtls_sha256(cm_payload(cell), CM_PAYLOAD_SIZE, pr, 0);
    memcpy(cm_domain_payload_root_mut(cell), pr, 32);
    memset(sig, 0, CM_FRAME_SIG_SIZE);

    // Also feed our own tile into the quorum table.
    uint8_t tile_hash[32];
    cm_mnca_tile_hash(&s_mnca_tile, tile_hash);
    uint64_t now_ms = (uint64_t)esp_log_timestamp();
    cm_mnca_quorum_rc_t qrc = cm_mnca_quorum_update(
        &s_mnca_quorum, s_mnca_tile.x, s_mnca_tile.y, s_mnca_tile.generation,
        tile_hash, s_my_mac, now_ms);

    uint32_t cell_id = (uint32_t)esp_random();
    int tile_tx_rc = cm_radio_send_cell(cell, sig, cell_id);
    ESP_LOGI(TAG, "TX *** MNCA TILE *** x=%u y=%u gen=%u "
             "hash=%02x%02x%02x%02x quorum=%s cell_id=0x%08x%s",
             (unsigned)s_mnca_tile.x, (unsigned)s_mnca_tile.y,
             (unsigned)s_mnca_tile.generation,
             tile_hash[0], tile_hash[1], tile_hash[2], tile_hash[3],
             qrc == CM_MNCA_QUORUM_HIT ? "HIT" : "PENDING",
             (unsigned)cell_id,
             tile_tx_rc != 0 ? " [NO_MEM]" : "");
    if (qrc == CM_MNCA_QUORUM_HIT) {
        emit_mnca_settle(&s_mnca_tile, tile_hash);
    }
}

// ── Channel-broadcast scheduler (device A = wallet's voice) ──────────
//
// Paces pre-signed channel cells onto the radio. Cells live in the deck
// (wallet pre-signed at provisioning); this just paces TX timing.
//
//   step 0           channel_open
//   step 1..N        commitment seq=step (1s apart)
//   step N+1         channel_close (5s after last commitment)
//   step >N+1        done — leave channel closed, do not re-trigger
//
// Returns true if a cell was sent this tick (caller can skip other TX
// to avoid bunching).
static bool channel_tx_tick(uint64_t now_us) {
    if (DEMO_SCRIPT_ONLY) return false;  // demo: dark stage, no background radio
    if (!s_channel_tx_started) return false;
    if (now_us < s_channel_tx_next_us) return false;
    if (s_channel_tx_step > CHANNEL_TX_COMMITMENT_COUNT + 1) return false;

    deck_queue_t *q = NULL;
    const char   *what = NULL;
    uint64_t      gap_ms = CHANNEL_TX_GAP_MS;

    if (s_channel_tx_step == 0) {
        q = &s_q_channel_open;            what = "channel_open";
    } else if (s_channel_tx_step <= CHANNEL_TX_COMMITMENT_COUNT) {
        q = &s_q_channel_commitment;      what = "channel_commit";
        // The "wallet stopped paying" gap happens AFTER the last
        // commitment — schedule the next step (close) at a longer
        // delay so the device gets time to expire its current state.
        if (s_channel_tx_step == CHANNEL_TX_COMMITMENT_COUNT) {
            gap_ms = CHANNEL_TX_STOP_GAP_MS;
        }
    } else {
        q = &s_q_channel_close;           what = "channel_close";
    }

    const uint8_t *cell_flash, *sig_flash;
    if (!deck_pop(q, what, &cell_flash, &sig_flash)) {
        // Out of cells for this kind — skip step, advance.
        s_channel_tx_step++;
        s_channel_tx_next_us = now_us + (uint64_t)gap_ms * 1000ULL;
        return false;
    }

    uint8_t cell[CM_CELL_SIZE], sig[CM_FRAME_SIG_SIZE];
    memcpy(cell, cell_flash, CM_CELL_SIZE);
    memcpy(sig,  sig_flash,  CM_FRAME_SIG_SIZE);
    uint32_t cell_id = (uint32_t)esp_random();
    if (cm_radio_send_cell(cell, sig, cell_id) == 0) {
        ESP_LOGI(TAG, "TX *** %s *** (step=%u, cell_id=0x%08x)",
                 what, (unsigned)s_channel_tx_step, (unsigned)cell_id);
    }
    s_channel_tx_step++;
    s_channel_tx_next_us = now_us + (uint64_t)gap_ms * 1000ULL;
    return true;
}

// ── Scripted-cell drainer (main task only — WAMR-registered) ─────────
static void drain_pending_actuator(void) {
    if (!s_pending_actuator) return;
    if (dispatch_scripted_cell(s_pending_actuator_mac_str,
                                s_pending_actuator_payload,
                                s_pending_actuator_len)) {
        // ACCEPT: extend the LED-active window. The duration is the
        // device's own ACTUATOR_DURATION_MS — device C knows what it's
        // renting for. Multiple activations accumulate.
        uint64_t now_us = esp_timer_get_time();
        uint64_t base   = (s_actuator_active_until_us > now_us)
                          ? s_actuator_active_until_us : now_us;
        s_actuator_active_until_us = base
            + (uint64_t)ACTUATOR_DURATION_MS * 1000ULL;
        s_actuator_activations++;
        uint64_t remaining_ms = (s_actuator_active_until_us - now_us) / 1000ULL;
        ESP_LOGI(TAG, "*** ACTUATOR ACTIVATED *** from=[%s] activations=%u ms_remaining=%llu",
                 s_pending_actuator_mac_str,
                 (unsigned)s_actuator_activations,
                 (unsigned long long)remaining_ms);
    }
    s_pending_actuator = false;
}

static void drain_pending_script(void) {
    if (!s_pending_script) return;
    if (dispatch_scripted_cell(s_pending_script_mac_str,
                                s_pending_script_payload,
                                s_pending_script_len)) {
        s_blink_until_us = esp_timer_get_time()
                         + (uint64_t)SCRIPTED_BLINK_MS * 1000ULL;
    }
    s_pending_script = false;
}

// ── Scripted-broadcast scheduler (device A) ──────────────────────────
//
// Paces pre-signed scripted cells onto the radio. Each cell carries
// BSV-script bytecode in its payload — devices receiving it run it
// through the cell-engine and blink on accept.
static bool scripted_tx_tick(uint64_t now_us) {
    if (DEMO_SCRIPT_ONLY) return false;  // demo: dark stage, no background radio
    if (!s_scripted_tx_started || s_scripted_tx_done) return false;
    if (now_us < s_scripted_tx_next_us) return false;

    const uint8_t *cell_flash, *sig_flash;
    if (!deck_pop(&s_q_scripted, "scripted", &cell_flash, &sig_flash)) {
        // exhausted — terminal; keep s_scripted_tx_started true so the
        // outer gate doesn't re-arm + retrigger the deck-pop loop.
        s_scripted_tx_done = true;
        return false;
    }

    uint8_t cell[CM_CELL_SIZE], sig[CM_FRAME_SIG_SIZE];
    memcpy(cell, cell_flash, CM_CELL_SIZE);
    memcpy(sig,  sig_flash,  CM_FRAME_SIG_SIZE);
    uint32_t cell_id = (uint32_t)esp_random();
    if (cm_radio_send_cell(cell, sig, cell_id) == 0) {
        ESP_LOGI(TAG, "TX *** SCRIPTED *** (deck, cell_id=0x%08x)", (unsigned)cell_id);
    }
    s_scripted_tx_next_us = now_us + (uint64_t)SCRIPTED_TX_GAP_MS * 1000ULL;
    return true;
}

// ── Rentable-device broadcasters (x402-over-cells) ───────────────────
//
// Two halves of the x402 handshake on cell-mesh:
//   - actuator_offer_tx_tick:    device C broadcasts "I rent for N
//                                 sats / D ms; here's the lock script"
//   - actuator_activate_tx_tick: device A (wallet) broadcasts
//                                 BIP-143-signed activations
static bool actuator_offer_tx_tick(uint64_t now_us) {
    if (DEMO_SCRIPT_ONLY) return false;  // demo: dark stage, no background radio
    if (!s_actuator_offer_started || s_actuator_offer_done) return false;
    if (now_us < s_actuator_offer_next_us) return false;
    const uint8_t *cell_flash, *sig_flash;
    if (!deck_pop(&s_q_actuator_offer, "actuator_offer", &cell_flash, &sig_flash)) {
        s_actuator_offer_done = true;
        return false;
    }
    uint8_t cell[CM_CELL_SIZE], sig[CM_FRAME_SIG_SIZE];
    memcpy(cell, cell_flash, CM_CELL_SIZE);
    memcpy(sig,  sig_flash,  CM_FRAME_SIG_SIZE);
    uint32_t cell_id = (uint32_t)esp_random();
    if (cm_radio_send_cell(cell, sig, cell_id) == 0) {
        ESP_LOGI(TAG, "TX *** ACTUATOR OFFER *** (deck, cell_id=0x%08x)", (unsigned)cell_id);
    }
    s_actuator_offer_next_us = now_us + (uint64_t)ACTUATOR_OFFER_GAP_MS * 1000ULL;
    return true;
}

static bool actuator_activate_tx_tick(uint64_t now_us) {
    if (DEMO_SCRIPT_ONLY) return false;  // demo: dark stage, no background radio
    if (!s_actuator_activate_started || s_actuator_activate_done) return false;
    if (now_us < s_actuator_activate_next_us) return false;
    const uint8_t *cell_flash, *sig_flash;
    if (!deck_pop(&s_q_actuator_activate, "actuator_activate", &cell_flash, &sig_flash)) {
        s_actuator_activate_done = true;
        return false;
    }
    uint8_t cell[CM_CELL_SIZE], sig[CM_FRAME_SIG_SIZE];
    memcpy(cell, cell_flash, CM_CELL_SIZE);
    memcpy(sig,  sig_flash,  CM_FRAME_SIG_SIZE);
    uint32_t cell_id = (uint32_t)esp_random();
    if (cm_radio_send_cell(cell, sig, cell_id) == 0) {
        ESP_LOGI(TAG, "TX *** ACTUATOR ACTIVATE *** (deck, wallet-signed, cell_id=0x%08x)",
                 (unsigned)cell_id);
    }
    s_actuator_activate_next_us = now_us + (uint64_t)ACTUATOR_ACTIVATE_GAP_MS * 1000ULL;
    return true;
}

// ── Pending-forward drainer (main-loop side) ─────────────────────────
//
// A relay hop's receive callback queued a stepped forward here. Rebuild
// the cell from the (mutated) cm_forward_t and broadcast.
static void drain_pending_forward(void) {
    if (!s_pending_forward) return;
    cm_forward_t fwd = s_pending_forward_f;
    s_pending_forward = false;

    uint8_t cell[CM_CELL_SIZE], sig[CM_FRAME_SIG_SIZE];
    if (build_forward_cell(s_pending_forward_domain, &fwd, cell, sig) != 0) {
        ESP_LOGW(TAG, "forward relay: build_forward_cell failed");
        return;
    }
    uint32_t cell_id = (uint32_t)esp_random();
    if (cm_radio_send_cell(cell, sig, cell_id) == 0) {
        ESP_LOGI(TAG, "TX *** FORWARD RELAY *** hop_index=%u remaining=%u cell_id=0x%08x",
                 (unsigned)fwd.hop_index, (unsigned)fwd.segments_remaining,
                 (unsigned)cell_id);
    }
}

// ── forward.v1 relay builder + drain ────────────────────────────────
static int build_forward_v1_cell(const cm_forward_v1_t *fv1,
                                  uint8_t out_cell[CM_CELL_SIZE],
                                  uint8_t out_sig[CM_FRAME_SIG_SIZE],
                                  uint32_t domain_flag) {
    cm_cell_init(out_cell);
    cm_set_flags(out_cell, domain_flag);   // carry the relayed cell's domain
    cm_set_linearity(out_cell, CM_LINEARITY_AFFINE);
    memcpy(cm_type_hash_mut(out_cell), s_forward_v1_type_hash, 32);
    memcpy(cm_owner_id_mut(out_cell), s_my_mac, 6);
    memset(cm_owner_id_mut(out_cell) + 6, 0, 10);
    cm_set_timestamp_ms(out_cell, (uint64_t)esp_log_timestamp());

    uint8_t payload[CM_PAYLOAD_SIZE];
    size_t  used = 0;
    if (cm_forward_v1_encode(fv1, payload, &used) != 0) return -1;
    if (used < CM_PAYLOAD_SIZE) memset(payload + used, 0, CM_PAYLOAD_SIZE - used);

    memcpy(cm_payload_mut(out_cell), payload, CM_PAYLOAD_SIZE);
    cm_set_payload_total(out_cell, (uint32_t)used);

    uint8_t pr[32];
    mbedtls_sha256(cm_payload(out_cell), CM_PAYLOAD_SIZE, pr, 0);
    memcpy(cm_domain_payload_root_mut(out_cell), pr, 32);

    memset(out_sig, 0, CM_FRAME_SIG_SIZE);  // unsigned (segments mutate per hop)
    return 0;
}

static void drain_pending_forward_v1(void) {
    if (!s_pending_forward_v1) return;
    cm_forward_v1_t fv1 = s_pending_forward_v1_f;
    s_pending_forward_v1 = false;

    uint8_t cell[CM_CELL_SIZE], sig[CM_FRAME_SIG_SIZE];
    if (build_forward_v1_cell(&fv1, cell, sig, s_pending_forward_v1_domain) != 0) {
        ESP_LOGW(TAG, "forward.v1 relay: build failed");
        return;
    }
    uint32_t cell_id = (uint32_t)esp_random();
    if (cm_radio_send_cell(cell, sig, cell_id) == 0) {
        ESP_LOGI(TAG, "TX *** FORWARD.V1 RELAY *** hop_index=%u remaining=%u "
                 "cell_id=0x%08x ds=%u",
                 (unsigned)fv1.hop_index, (unsigned)fv1.segments_remaining,
                 (unsigned)cell_id, (unsigned)s_fwd_channel.device_share);
    }
}

// ── forward.v2 burst builder + drainer (main-loop side) ─────────────
//
// Builds Cell A (cellmesh.forward.v2) and Cell B (cellmesh.routing.cont.v0)
// from the decoded structs queued by the WiFi-task receive handler, then
// broadcasts both cells back-to-back.  Called on the main pthread only so
// cm_radio_send_cell serialisation matches the rest of the drainers.
static int build_forward_v2_cell_a(uint32_t domain_flag, const cm_forward_v2_t *pa,
                                    uint8_t out_cell[CM_CELL_SIZE],
                                    uint8_t out_sig[CM_FRAME_SIG_SIZE]) {
    cm_cell_init(out_cell);
    cm_set_flags(out_cell, domain_flag);   // carry the relayed cell's domain
    cm_set_linearity(out_cell, CM_LINEARITY_AFFINE);
    memcpy(cm_type_hash_mut(out_cell), s_forward_v2_type_hash, 32);

    uint8_t payload[CM_PAYLOAD_SIZE];
    size_t  used = 0;
    if (cm_forward_v2_encode(pa, payload, &used) != 0) return -1;
    memcpy(cm_payload_mut(out_cell), payload, used);
    cm_set_payload_total(out_cell, (uint32_t)used);

    memset(out_sig, 0, CM_FRAME_SIG_SIZE);   // routing fields mutate per hop — unsigned
    return 0;
}

static int build_forward_v2_cell_b(uint32_t domain_flag, const cm_routing_cont_t *pb,
                                    uint8_t out_cell[CM_CELL_SIZE],
                                    uint8_t out_sig[CM_FRAME_SIG_SIZE]) {
    cm_cell_init(out_cell);
    cm_set_flags(out_cell, domain_flag);   // carry the relayed cell's domain
    cm_set_linearity(out_cell, CM_LINEARITY_AFFINE);
    memcpy(cm_type_hash_mut(out_cell), s_routing_cont_type_hash, 32);

    uint8_t payload[CM_PAYLOAD_SIZE];
    size_t  used = 0;
    if (cm_routing_cont_encode(pb, payload, &used) != 0) return -1;
    memcpy(cm_payload_mut(out_cell), payload, used);
    cm_set_payload_total(out_cell, (uint32_t)used);

    memset(out_sig, 0, CM_FRAME_SIG_SIZE);   // routing continuation — unsigned
    return 0;
}

static void drain_pending_forward_v2(void) {
    if (!s_pending_forward_v2) return;

    // Backoff: skip N ticks to let the ESP-NOW queue drain.
    if (s_pending_fwdv2_retry_skip > 0) {
        s_pending_fwdv2_retry_skip--;
        return;
    }

    cm_forward_v2_t   pa = s_pending_fwdv2_a;
    cm_routing_cont_t pb = s_pending_fwdv2_b;
    s_pending_forward_v2 = false;

    // Static to avoid 2×1088 B stack alloc in the main-loop path.
    static uint8_t cell_a[CM_CELL_SIZE], sig_a[CM_FRAME_SIG_SIZE];
    static uint8_t cell_b[CM_CELL_SIZE], sig_b[CM_FRAME_SIG_SIZE];

    // Two-phase relay to guarantee Cell A' reaches the destination before Cell B'.
    //
    // Phase 1 (Cell A' not yet sent): send Cell A' and re-queue with a 150 ms
    // inter-frame gap.  This gives the destination time to buffer Cell A' (hop=1)
    // before Cell B' arrives — preventing the hop_index mismatch step error.
    //
    // Phase 2 (Cell A' already sent and propagated): send Cell B'.  Repeat up to
    // s_fwdv2_cell_b_sends_left times for redundancy.
    if (!s_pending_fwdv2_cell_a_sent) {
        // ── Phase 1: send Cell A' ────────────────────────────────────────────
        if (build_forward_v2_cell_a(s_pending_fwdv2_domain, &pa, cell_a, sig_a) != 0) {
            ESP_LOGW(TAG, "forward.v2 relay: build cell_a failed");
            return;
        }
        uint32_t id_a = (uint32_t)esp_random();
        int rc_a = cm_radio_send_cell(cell_a, sig_a, id_a);
        if (rc_a == 0) {
            // Cell A' queued — wait 150 ms before sending Cell B'.
            s_pending_fwdv2_cell_a_sent = true;
            s_pending_fwdv2_a          = pa;
            s_pending_fwdv2_b          = pb;
            s_pending_forward_v2       = true;
            s_pending_fwdv2_retry_skip = 3;   // ~150 ms for Cell A' to propagate
            ESP_LOGI(TAG, "forward.v2 relay Phase1: Cell A' sent id_a=0x%08x hop=%u — waiting 150ms",
                     (unsigned)id_a, (unsigned)pa.hop_index);
        } else {
            // NO_MEM on Cell A' — retry with backoff.
            s_pending_fwdv2_a          = pa;
            s_pending_fwdv2_b          = pb;
            s_pending_forward_v2       = true;
            s_pending_fwdv2_retry_skip = 10;  // ~500 ms
            ESP_LOGW(TAG, "forward.v2 relay Phase1: Cell A' NO_MEM rc=%d — retry in ~500ms", rc_a);
        }
        return;  // always return after Phase 1 — Cell B' waits for next tick
    }

    // ── Phase 2: Cell A' already sent and propagated — send Cell B' ─────────
    if (build_forward_v2_cell_b(s_pending_fwdv2_domain, &pb, cell_b, sig_b) != 0) {
        ESP_LOGW(TAG, "forward.v2 relay: build cell_b failed");
        return;
    }
    uint32_t id_b = (uint32_t)esp_random();
    int rc_b = cm_radio_send_cell(cell_b, sig_b, id_b);

    if (rc_b == 0) {
        if (s_fwdv2_cell_b_sends_left > 0) {
            s_fwdv2_cell_b_sends_left--;
            ESP_LOGI(TAG, "TX *** FORWARD.V2 RELAY *** hop=%u segs_rem=%u "
                     "id_b=0x%08x inner=%u (redundant_left=%u)",
                     (unsigned)pa.hop_index,
                     (unsigned)pb.segments_remaining,
                     (unsigned)id_b,
                     (unsigned)pa.inner_payload_len,
                     (unsigned)s_fwdv2_cell_b_sends_left);
            if (s_fwdv2_cell_b_sends_left > 0) {
                // Queue another redundant Cell B send (150 ms apart).
                s_pending_fwdv2_a          = pa;
                s_pending_fwdv2_b          = pb;
                s_pending_forward_v2       = true;
                s_pending_fwdv2_retry_skip = 3;   // ~150 ms between redundant sends
            } else {
                // All redundant sends done — relay complete.
                s_pending_fwdv2_cell_a_sent = false;
            }
        }
    } else {
        ESP_LOGW(TAG, "forward.v2 relay Phase2: Cell B' rc=%d", rc_b);
        if (rc_b == ESP_ERR_ESPNOW_NO_MEM) {
            s_pending_fwdv2_a          = pa;
            s_pending_fwdv2_b          = pb;
            s_pending_forward_v2       = true;
            s_pending_fwdv2_retry_skip = 10;  // ~500 ms to drain the ESP-NOW queue
            ESP_LOGW(TAG, "forward.v2 relay Phase2: NO_MEM — retry in ~500ms");
        }
    }
}

// ── Pending-fwd-rule drainer (main-loop side) ────────────────────────
//
// CM_HOP_VERB_INSTALL_RULE: the WiFi-task receive callback queued an
// encoded rule payload here. The main loop decodes it and installs it
// into s_rules (same as the rule-as-cell hot-swap path). Called in the
// main pthread so s_rules modifications are serialised with app_main.
static void drain_pending_fwd_rule(void) {
    if (!s_pending_fwd_rule) return;
    s_pending_fwd_rule = false;

    cm_rule_t rule;
    if (cm_rule_decode(s_pending_fwd_rule_bytes, &rule) != 0) {
        ESP_LOGW(TAG, "HOP_VERB INSTALL_RULE: rule_decode failed — bad payload");
        return;
    }
    int slot = cm_rules_install(&s_rules, &rule);
    if (slot >= 0) {
        ESP_LOGI(TAG, "*** HOP_VERB INSTALL_RULE: installed at slot %d ***", slot);
    } else {
        ESP_LOGW(TAG, "HOP_VERB INSTALL_RULE: table full, rule dropped");
    }
}

// ── Pending-emit drainer (main-loop side) ────────────────────────────
//
// Rule-driven confirmed_tap. Pops a pre-signed confirmed_tap cell from
// the deck (no on-device signing). The cell payload is fixed at
// provisioning ('A','C','K',0x01,counter) — every confirmed_tap is
// distinct (per-cell counter) so the ring dedup doesn't collapse them.
static void drain_pending_emit(void) {
    if (!s_pending_emit) return;
    s_pending_emit = false;

    const uint8_t *cell_flash, *sig_flash;
    if (!deck_pop(&s_q_confirmed_tap, "confirmed_tap", &cell_flash, &sig_flash)) return;

    uint8_t cell[CM_CELL_SIZE], sig[CM_FRAME_SIG_SIZE];
    memcpy(cell, cell_flash, CM_CELL_SIZE);
    memcpy(sig,  sig_flash,  CM_FRAME_SIG_SIZE);

    uint32_t cell_id = (uint32_t)esp_random();
    if (cm_radio_send_cell(cell, sig, cell_id) == 0) {
        s_tx_emit_counter++;
        ESP_LOGI(TAG, "TX *** EMIT #%u *** (deck confirmed_tap, cell_id=0x%08x)",
                 (unsigned)s_tx_emit_counter, (unsigned)cell_id);
    }
}

// ── Setup ────────────────────────────────────────────────────────────
static void install_demo_rules(void) {
    // Rule 1: BLINK 500 ms on every TAP — single-cell visual cue.
    cm_rule_t blink_on_tap = {0};
    blink_on_tap.trigger_kind = CM_TRIGGER_ON_TYPE;
    memcpy(blink_on_tap.trigger_type_hash, s_tap_type_hash, 32);
    blink_on_tap.effect.kind = CM_EFFECT_BLINK;
    blink_on_tap.effect.as.blink.duration_ms = 500;
    int s1 = cm_rules_install(&s_rules, &blink_on_tap);

    // Rule 2: EMIT a `confirmed_tap` cell on TAP — proves the rule
    // engine can chain effects back into the substrate (not just GPIO).
    // The confirmed_tap cell has no rule installed against it, so the
    // chain terminates (no infinite emit loop).
    cm_rule_t emit_on_tap = {0};
    emit_on_tap.trigger_kind = CM_TRIGGER_ON_TYPE;
    memcpy(emit_on_tap.trigger_type_hash, s_tap_type_hash, 32);
    emit_on_tap.effect.kind = CM_EFFECT_EMIT;
    memcpy(emit_on_tap.effect.as.emit.type_hash, s_confirmed_tap_type_hash, 32);
    emit_on_tap.effect.as.emit.payload[0] = 'A';
    emit_on_tap.effect.as.emit.payload[1] = 'C';
    emit_on_tap.effect.as.emit.payload[2] = 'K';
    emit_on_tap.effect.as.emit.payload[3] = 0x01;
    emit_on_tap.effect.as.emit.payload_len = 4;
    int s2 = cm_rules_install(&s_rules, &emit_on_tap);

    // Rule 3: QUORUM — when 2 distinct peers send TAP within 500 ms, fire
    // a long (1.2 s) blink. With only two XIAOs on the table this rule
    // never fires (each node only ever sees one distinct external peer).
    // With three or more XIAOs, the long blink visually distinguishes
    // quorum-triggered blinks from the per-tap short blink.
    cm_rule_t quorum_blink_on_tap = {0};
    quorum_blink_on_tap.trigger_kind          = CM_TRIGGER_QUORUM;
    memcpy(quorum_blink_on_tap.trigger_type_hash, s_tap_type_hash, 32);
    quorum_blink_on_tap.quorum_n              = 2;
    quorum_blink_on_tap.quorum_window_ms      = 500;
    quorum_blink_on_tap.quorum_distinct_peers = true;
    quorum_blink_on_tap.effect.kind = CM_EFFECT_BLINK;
    quorum_blink_on_tap.effect.as.blink.duration_ms = 1200;
    int s3 = cm_rules_install(&s_rules, &quorum_blink_on_tap);

    ESP_LOGI(TAG, "rules: BLINK@%d, EMIT(confirmed_tap)@%d, QUORUM(2-of-3 distinct, 500ms)@%d",
             s1, s2, s3);
}

// ── Serial cell-injection (x402 bridge mesh transport) ──────────────
//
// A host process (tools/x402-bridge) frames a wallet-signed
// cell over USB-Serial-JTAG; this task reads it and broadcasts it on the
// mesh via cm_radio_send_cell — turning the bridge's mesh leg from
// dry-run into a real agent→bridge→device path. The device that receives
// the broadcast (the rentable actuator) verifies + acts exactly as it
// does for a deck cell; nothing about trust changes, the bridge just
// relays a cell the wallet already signed.
//
// Frame: an ASCII line, newline-terminated, integrity-checked end-to-end:
//
//   "IJ" <hex(cell[1024] || sig[64])> <hex(crc32le[4])> "\n"
//
// Why a hex line + CRC rather than raw binary framing: the console already
// owns the USB-Serial-JTAG driver, so the app can't size the RX ring, and
// a raw binary burst overflows the small ring and silently drops bytes —
// corrupting the cell so its wallet signature fails on the receiver. A
// newline-delimited hex line lets the reader resync cleanly, and the CRC32
// over (cell||sig) means any dropped/garbled byte is detected and the frame
// is rejected (never broadcast) rather than corrupting a cell. The host
// also paces the send so a fast burst can't outrun the ring. Bulk reads
// drain the ring quickly.

static uint8_t s_inject_cell[CM_CELL_SIZE];
static uint8_t s_inject_sig[CM_FRAME_SIG_SIZE];

// Standard CRC-32 (zlib/PNG: poly 0xEDB88320, init+final 0xFFFFFFFF).
static uint32_t inject_crc32(const uint8_t *d, size_t n) {
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) {
        c ^= d[i];
        for (int k = 0; k < 8; k++) c = (c >> 1) ^ (0xEDB88320u & (uint32_t)(-(int32_t)(c & 1u)));
    }
    return c ^ 0xFFFFFFFFu;
}

static int inject_hexval(int ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

// payload = cell || sig || crc32le  → hex chars, plus the "IJ" prefix.
#define INJECT_PAYLOAD_BYTES (CM_CELL_SIZE + CM_FRAME_SIG_SIZE + 4u)
#define INJECT_LINE_MAX      (2u + 2u * INJECT_PAYLOAD_BYTES)

static char    s_inject_line[INJECT_LINE_MAX + 4];
static uint8_t s_inject_decoded[INJECT_PAYLOAD_BYTES];

// Decode + verify one accumulated line; broadcast on success.
static void inject_process_line(const char *line, size_t len) {
    if (len < 2 || line[0] != 'I' || line[1] != 'J') return;        // not an inject line (e.g. log echo)
    size_t hexlen = len - 2;
    if (hexlen != 2u * INJECT_PAYLOAD_BYTES) {
        ESP_LOGW(TAG, "inject: line len %u (want %u) — drop", (unsigned)hexlen, (unsigned)(2u * INJECT_PAYLOAD_BYTES));
        return;
    }
    for (size_t i = 0; i < INJECT_PAYLOAD_BYTES; i++) {
        int hi = inject_hexval((unsigned char)line[2 + 2 * i]);
        int lo = inject_hexval((unsigned char)line[2 + 2 * i + 1]);
        if (hi < 0 || lo < 0) { ESP_LOGW(TAG, "inject: bad hex — drop"); return; }
        s_inject_decoded[i] = (uint8_t)((hi << 4) | lo);
    }
    uint32_t want = (uint32_t)s_inject_decoded[INJECT_PAYLOAD_BYTES - 4]
                  | ((uint32_t)s_inject_decoded[INJECT_PAYLOAD_BYTES - 3] << 8)
                  | ((uint32_t)s_inject_decoded[INJECT_PAYLOAD_BYTES - 2] << 16)
                  | ((uint32_t)s_inject_decoded[INJECT_PAYLOAD_BYTES - 1] << 24);
    uint32_t got = inject_crc32(s_inject_decoded, CM_CELL_SIZE + CM_FRAME_SIG_SIZE);
    if (got != want) {
        ESP_LOGW(TAG, "inject: CRC mismatch got=0x%08x want=0x%08x — drop (corrupt frame)",
                 (unsigned)got, (unsigned)want);
        return;
    }
    memcpy(s_inject_cell, s_inject_decoded, CM_CELL_SIZE);
    memcpy(s_inject_sig,  s_inject_decoded + CM_CELL_SIZE, CM_FRAME_SIG_SIZE);
#if DEMO_SCRIPT_ONLY
    // Demo: don't broadcast straight away. Acknowledge "received from the
    // laptop" with a 3-pulse LED blink, stage the cell, and let the main
    // loop broadcast it after DEMO_BROADCAST_DELAY_MS — so the laptop → A →
    // (air) → B chain plays out as a watchable sequence rather than instantly.
    memcpy(s_demo_cell, s_inject_cell, CM_CELL_SIZE);
    memcpy(s_demo_sig,  s_inject_sig,  CM_FRAME_SIG_SIZE);
    s_inject_ack_start_us  = esp_timer_get_time();
    s_demo_broadcast_at_us = s_inject_ack_start_us + (uint64_t)DEMO_BROADCAST_DELAY_MS * 1000ULL;
    s_demo_pending = true;
    ESP_LOGI(TAG, "*** CELL INJECTED *** (demo: ack-blink x3, broadcast in %ums) crc=0x%08x",
             (unsigned)DEMO_BROADCAST_DELAY_MS, (unsigned)got);
#else
    uint32_t cell_id = (uint32_t)esp_random();
    esp_err_t e = cm_radio_send_cell(s_inject_cell, s_inject_sig, cell_id);
    ESP_LOGI(TAG, "*** CELL INJECTED *** broadcast cell_id=0x%08x rc=%d crc=0x%08x (from x402 bridge)",
             (unsigned)cell_id, (int)e, (unsigned)got);
#endif
}

static void serial_inject_task(void *arg) {
    (void)arg;
    static uint8_t rx[512];
    size_t pos = 0;
    ESP_LOGI(TAG, "serial cell-injection ready (line: IJ<hex cell+sig><hex crc32le>\\n)");
    for (;;) {
        int n = usb_serial_jtag_read_bytes(rx, sizeof(rx), pdMS_TO_TICKS(1000));
        for (int i = 0; i < n; i++) {
            uint8_t ch = rx[i];
            if (ch == '\n' || ch == '\r') {
                if (pos > 0) { inject_process_line(s_inject_line, pos); pos = 0; }
            } else if (pos < INJECT_LINE_MAX) {
                s_inject_line[pos++] = (char)ch;
            } else {
                pos = 0; // overrun — drop, resync at next newline
            }
        }
    }
}

// Install the USB-Serial-JTAG driver (idempotent w.r.t. the console) and
// spawn the injection reader. Logging keeps using the console output path.
static void serial_inject_start(void) {
    usb_serial_jtag_driver_config_t cfg = USB_SERIAL_JTAG_DRIVER_CONFIG_DEFAULT();
    cfg.rx_buffer_size = 4096; // applied only if the console hasn't already
                               // installed the driver; harmless otherwise.
    esp_err_t e = usb_serial_jtag_driver_install(&cfg);
    if (e != ESP_OK && e != ESP_ERR_INVALID_STATE) {
        ESP_LOGW(TAG, "usb_serial_jtag_driver_install rc=%d — cell-injection disabled", (int)e);
        return;
    }
    xTaskCreate(serial_inject_task, "cell_inject", 4096, NULL, 5, NULL);
}

// ── Entry point ───────────────────────────────────────────────────────
//
// Everything runs on a pthread (not the default FreeRTOS main_task), so
// WAMR's pthread shim — used by the cell-engine internally — can
// resolve `pthread_self()`. ESP-IDF's pthread layer maintains a thread
// table keyed by FreeRTOS task handle; tasks not created via
// pthread_create aren't in that table, and calls into pthread_self from
// such tasks trip an assertion. (Same pattern as `hello_cell`.)
static void *mesh_demo_thread(void *arg) {
    (void)arg;
    ESP_LOGI(TAG, "starting...");

    led_init();

    // Bring up the cell-engine FIRST, before WiFi/ESP-NOW allocates its
    // chunky internal state. Two distinct walls had to be navigated:
    //
    //   1. WAMR's linear-memory mmap goes through heap_caps_malloc and
    //      needs a contiguous ~128 KB block. Once WiFi is up the heap
    //      is fragmented enough that the alloc fails ("allocate linear
    //      memory failed"). → init before cm_radio_init.
    //
    //   2. WAMR's pthread shim asserts `Failed to find current thread
    //      ID` if WAMR is invoked from a thread not registered via
    //      wasm_runtime_init_thread_env. The main task isn't pthread-
    //      managed by default. → register here, and route every later
    //      WAMR call (incl. scripted-cell dispatch) through the main
    //      task only (see s_pending_script mailbox).
#if MESH_DEMO_ENGINE_AT_BOOT
    if (!wasm_runtime_init_thread_env()) {
        ESP_LOGE(TAG, "wasm_runtime_init_thread_env failed");
    }
    ESP_LOGI(TAG, "heap before semantos_init: free=%u largest_8bit=%u largest_internal=%u",
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_8BIT),
             (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT),
             (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL));
    {
        semantos_config_t cfg = SEMANTOS_DEFAULT_CONFIG();
        if (semantos_init(&cfg, &s_engine) != ESP_OK) {
            ESP_LOGE(TAG, "semantos_init failed — scripted cells will be rejected");
            s_engine = NULL;
        } else {
            int rc = semantos_kernel_init(s_engine);
            ESP_LOGI(TAG, "cell-engine up (kernel_init rc=%d)", rc);
        }
    }
#else
    ESP_LOGI(TAG, "cell-engine: SKIPPED (MESH_DEMO_ENGINE_AT_BOOT=0) — see comment in main.c");
#endif

    ESP_ERROR_CHECK(cm_radio_init());
    if (cm_sig_init() != 0) {
        ESP_LOGE(TAG, "cm_sig_init failed");
        return NULL;
    }

    // Serial cell-injection: lets the x402 bridge relay a wallet-signed
    // cell onto the mesh over USB-CDC. Harmless on every node — only the
    // one physically wired to the bridge ever receives a frame.
    serial_inject_start();

    // ── Diagnostic: P2PKH test vector through cm_sig_verify ─────────
    // Routes the exact (pubkey, sighash, sig-as-raw-r||s) tuple from
    // the cell-engine's checksig-p2pkh.json through cm_sig_verify —
    // the same code path that verifies thousands of cell-frame sigs
    // per hour with zero failures on this build. If THIS returns 0
    // (accept), mbedTLS itself is fine for this tuple and the bug is
    // in host_checksig's setup. If it rejects, mbedTLS on this build
    // has a real verify bug for some ECDSA inputs.
    {
        static const uint8_t VECTOR_PUBKEY[33] = {
            0x02, 0x89, 0x1a, 0x00, 0xec, 0xcf, 0xcb, 0x89,
            0x99, 0x61, 0x8b, 0xd9, 0xdb, 0x7d, 0x3c, 0xa4,
            0xc9, 0xe1, 0x15, 0xed, 0x61, 0xfa, 0x5b, 0x75,
            0x6d, 0x49, 0xfd, 0x07, 0x18, 0xb3, 0x24, 0xc7,
            0x68,
        };
        static const uint8_t VECTOR_HASH[32] = {
            0xf9, 0x3c, 0x85, 0x4f, 0xfe, 0x35, 0xaa, 0xbd,
            0x30, 0x23, 0x71, 0xd7, 0xee, 0x11, 0x00, 0x15,
            0xec, 0x40, 0x4c, 0xa7, 0x30, 0xac, 0x38, 0x37,
            0x3b, 0x21, 0x62, 0x4e, 0xc4, 0xa3, 0xf6, 0x5a,
        };
        static const uint8_t VECTOR_RS[64] = {
            0x06, 0xec, 0x85, 0xca, 0x86, 0xd3, 0x2a, 0x20,
            0x06, 0xcd, 0x3a, 0xee, 0x10, 0xec, 0x92, 0xad,
            0xcd, 0x17, 0xb8, 0x1d, 0x2b, 0x09, 0x4a, 0x55,
            0xcb, 0xbf, 0xe7, 0xe6, 0x4a, 0x30, 0x1b, 0xdd,
            0x37, 0x33, 0x4c, 0x28, 0xda, 0x65, 0xdf, 0x62,
            0x31, 0xc5, 0x84, 0xe8, 0x75, 0x4e, 0xd8, 0xf3,
            0xce, 0x45, 0xd1, 0x84, 0xcf, 0xf3, 0x61, 0x80,
            0xb4, 0x64, 0xc1, 0x06, 0x4c, 0xc1, 0xed, 0x7a,
        };
        int vrc = cm_sig_verify(VECTOR_PUBKEY, VECTOR_HASH, VECTOR_RS);
        ESP_LOGI(TAG, "*** P2PKH VECTOR via cm_sig_verify: rc=%d (%s)",
                 vrc, vrc == 0 ? "ACCEPT" : "REJECT");
    }

    cm_reasm_init(&s_reasm);
    cm_ring_init(&s_ring);
    cm_rules_init(&s_rules);
    cm_radio_register_recv(on_radio_recv, NULL);

    ESP_ERROR_CHECK(cm_radio_get_mac(s_my_mac));
    format_mac(s_my_mac_str, s_my_mac);

    // No on-device private key — verify is against s_wallet_pubkey
    // (compiled-in). The matching privkey lives off-device in the host
    // signing tool (tools/sign-cell-deck.ts).

    // Compute the type_hashes once.
    mbedtls_sha256((const unsigned char *)HEARTBEAT_TYPE_NAME,
                   sizeof(HEARTBEAT_TYPE_NAME) - 1,
                   s_heartbeat_type_hash, 0);
    mbedtls_sha256((const unsigned char *)TAP_TYPE_NAME,
                   sizeof(TAP_TYPE_NAME) - 1,
                   s_tap_type_hash, 0);
    mbedtls_sha256((const unsigned char *)CONFIRMED_TAP_TYPE_NAME,
                   sizeof(CONFIRMED_TAP_TYPE_NAME) - 1,
                   s_confirmed_tap_type_hash, 0);
    mbedtls_sha256((const unsigned char *)RULE_TYPE_NAME,
                   sizeof(RULE_TYPE_NAME) - 1,
                   s_rule_type_hash, 0);
    mbedtls_sha256((const unsigned char *)FORWARD_TYPE_NAME,
                   sizeof(FORWARD_TYPE_NAME) - 1,
                   s_forward_type_hash, 0);
    mbedtls_sha256((const unsigned char *)FORWARD_V1_TYPE_NAME,
                   sizeof(FORWARD_V1_TYPE_NAME) - 1,
                   s_forward_v1_type_hash, 0);
    mbedtls_sha256((const unsigned char *)FORWARD_V2_TYPE_NAME,
                   sizeof(FORWARD_V2_TYPE_NAME) - 1,
                   s_forward_v2_type_hash, 0);
    mbedtls_sha256((const unsigned char *)ROUTING_CONT_V0_TYPE_NAME,
                   sizeof(ROUTING_CONT_V0_TYPE_NAME) - 1,
                   s_routing_cont_type_hash, 0);
    mbedtls_sha256((const unsigned char *)CHANNEL_OPEN_TYPE_NAME,
                   sizeof(CHANNEL_OPEN_TYPE_NAME) - 1,
                   s_channel_open_type_hash, 0);
    mbedtls_sha256((const unsigned char *)CHANNEL_COMMITMENT_TYPE_NAME,
                   sizeof(CHANNEL_COMMITMENT_TYPE_NAME) - 1,
                   s_channel_commitment_type_hash, 0);
    mbedtls_sha256((const unsigned char *)CHANNEL_CLOSE_TYPE_NAME,
                   sizeof(CHANNEL_CLOSE_TYPE_NAME) - 1,
                   s_channel_close_type_hash, 0);
    mbedtls_sha256((const unsigned char *)CHANNEL_SETTLE_TYPE_NAME,
                   sizeof(CHANNEL_SETTLE_TYPE_NAME) - 1,
                   s_channel_settle_type_hash, 0);
    mbedtls_sha256((const unsigned char *)SCRIPTED_TYPE_NAME,
                   sizeof(SCRIPTED_TYPE_NAME) - 1,
                   s_scripted_type_hash, 0);
    mbedtls_sha256((const unsigned char *)ACTUATOR_OFFER_TYPE_NAME,
                   sizeof(ACTUATOR_OFFER_TYPE_NAME) - 1,
                   s_actuator_offer_type_hash, 0);
    mbedtls_sha256((const unsigned char *)ACTUATOR_ACTIVATE_TYPE_NAME,
                   sizeof(ACTUATOR_ACTIVATE_TYPE_NAME) - 1,
                   s_actuator_activate_type_hash, 0);
    mbedtls_sha256((const unsigned char *)TELEM_TYPE_NAME,
                   sizeof(TELEM_TYPE_NAME) - 1,
                   s_telem_type_hash, 0);
    mbedtls_sha256((const unsigned char *)CAPABILITY_V0_TYPE_NAME,
                   sizeof(CAPABILITY_V0_TYPE_NAME) - 1,
                   s_capability_v0_type_hash, 0);
    cm_cap_table_init(&s_cap_table);
    cm_cap_set_domain(&s_cap_table, DEVICE_DOMAIN_FLAG);
    ESP_LOGI(TAG, "cap table: device domain 0x%08x (OP_CHECKDOMAINFLAG enforced)",
             (unsigned)DEVICE_DOMAIN_FLAG);
    domain_flag_selftest();
    mbedtls_sha256((const unsigned char *)MNCA_TILE_V0_TYPE_NAME,
                   sizeof(MNCA_TILE_V0_TYPE_NAME) - 1,
                   s_mnca_tile_v0_type_hash, 0);
    mbedtls_sha256((const unsigned char *)MNCA_CHANNEL_SETTLE_TYPE_NAME,
                   sizeof(MNCA_CHANNEL_SETTLE_TYPE_NAME) - 1,
                   s_mnca_channel_settle_type_hash, 0);
    cm_channel_init(&s_channel);
    cm_meter_init(&s_meter, CM_METER_RATE_MSAT_PER_SEC);

    // Pre-open the forward.v1 upstream channel so this device can accept
    // channel-gated forward cells from the source (control plane wallet).
    // channel_id = all-zeros (demo sentinel); peer_pubkey = wallet key.
    // Total capacity 1M sats; locktime far future.  Any relay or destination
    // device accepting forward.v1 cells holds one such channel.
    {
        cm_channel_open_t fwd_open = {0};
        // channel_id = 0x00..00 (demo)
        memcpy(fwd_open.peer_pubkey, s_wallet_pubkey, CM_SIG_PUBKEY_COMPRESSED);
        fwd_open.total_capacity      = FWD_V1_DEMO_CAPACITY;
        fwd_open.initial_locktime_ms = UINT64_MAX / 2;  // far future
        cm_channel_init(&s_fwd_channel);
        if (cm_channel_apply_open(&s_fwd_channel, &fwd_open) == CM_CHAN_OK) {
            ESP_LOGI(TAG, "forward.v1 channel pre-opened (capacity=%u sats)",
                     (unsigned)FWD_V1_DEMO_CAPACITY);
        }
    }

    // Build synthetic tap cell for CM_HOP_VERB_EVAL_RULES.
    // cm_rules_evaluate only reads the type_hash field, so a zeroed cell
    // with just the tap type_hash set is sufficient.
    memset(s_synthetic_tap_cell, 0, sizeof(s_synthetic_tap_cell));
    memcpy(cm_type_hash_mut(s_synthetic_tap_cell), s_tap_type_hash, 32);

    // Detect forward-demo role from our MAC.
    s_is_originator  = memcmp(s_my_mac, MAC_A, 6) == 0;
    s_is_relay       = memcmp(s_my_mac, MAC_B, 6) == 0;
    s_is_destination = memcmp(s_my_mac, MAC_C, 6) == 0;
    const char *role = s_is_originator ? "A=ORIGINATOR"
                     : s_is_relay       ? "B=RELAY"
                     : s_is_destination ? "C=DESTINATION"
                     : "spectator";
    ESP_LOGI(TAG, "forward-demo role: %s", role);

    // Init MNCA tile — ALL devices share the SAME (x=0, y=0, seed=12345) so
    // every device computes identical state sequences under the same rule.
    // Quorum fires when ≥2 devices broadcast a matching hash for the same
    // (x, y, generation): they independently confirmed the compute result.
    {
        cm_mnca_tile_init_random(&s_mnca_tile, 0, 0, 12345u);
        cm_mnca_quorum_init(&s_mnca_quorum);
        ESP_LOGI(TAG, "MNCA: shared tile (0,0) seed=12345 (tick every %u ms)",
                 (unsigned)MNCA_PERIOD_MS);
    }

    // Each device flies its own speeder. A/B/C map to 1/2/3; any other node
    // uses the low nibble of its MAC so spectators get a stable distinct id.
    s_telem_spd = s_is_originator  ? 1
                : s_is_relay        ? 2
                : s_is_destination ? 3
                : (int32_t)(s_my_mac[5] & 0x0f) + 4;
    ESP_LOGI(TAG, "telemetry: this device is speeder %d (figure-8 @ 20Hz, unsigned)", (int)s_telem_spd);

    install_demo_rules();

    // Walk the embedded deck once, bucket entries for this MAC.
    if (deck_init() != 0) {
        ESP_LOGE(TAG, "deck_init failed — halting");
        return NULL;
    }

    // ── Boot-time verify microbench ─────────────────────────────────
    // Times ECDSA-secp256k1 verify on the wallet pubkey with the C6's
    // HW SHA + HW MPI (interrupt-yield). Surfaces real mesh-load
    // budget: each verified RX costs ~the printed us. Cells flow at
    // ~1 Hz aggregate so we sit well under the throughput ceiling.
    //
    // Also benches the prepared-pubkey API for the record — see
    // cell_sig.h: not a win on C6, kept for reference.
    #define CM_BENCH_ITERS 30u
    if (s_q_heartbeat.count > 0) {
        const uint8_t *bench_cell = s_q_heartbeat.entries[0] + DECK_ENTRY_PREFIX;
        const uint8_t *bench_sig  = s_q_heartbeat.entries[0] + DECK_ENTRY_PREFIX + CM_CELL_SIZE;
        uint8_t bench_hash[32];
        cm_sig_hash_cell(bench_cell, bench_hash);

        uint64_t t0 = esp_timer_get_time();
        int okA = 0;
        for (unsigned i = 0; i < CM_BENCH_ITERS; i++) {
            if (cm_sig_verify(s_wallet_pubkey, bench_hash, bench_sig) == 0) okA++;
        }
        uint64_t dtA = esp_timer_get_time() - t0;
        ESP_LOGI(TAG, "bench: verify (parse-per-call)  %d/%u OK  %llu us/verify",
                 okA, (unsigned)CM_BENCH_ITERS,
                 (unsigned long long)(dtA / CM_BENCH_ITERS));

        cm_sig_pubkey_t *prepared = NULL;
        if (cm_sig_pubkey_load(s_wallet_pubkey, &prepared) == 0) {
            t0 = esp_timer_get_time();
            int okB = 0;
            for (unsigned i = 0; i < CM_BENCH_ITERS; i++) {
                if (cm_sig_verify_prepared(prepared, bench_hash, bench_sig) == 0) okB++;
            }
            uint64_t dtB = esp_timer_get_time() - t0;
            ESP_LOGI(TAG, "bench: verify (prepared)       %d/%u OK  %llu us/verify  (%+lld vs parse-per-call)",
                     okB, (unsigned)CM_BENCH_ITERS,
                     (unsigned long long)(dtB / CM_BENCH_ITERS),
                     (long long)(((int64_t)dtB - (int64_t)dtA) / CM_BENCH_ITERS));
            cm_sig_pubkey_free(prepared);
        }
    }

    ESP_LOGI(TAG, "mesh_demo up. mac=%s wallet_pubkey[0..3]=%02x%02x%02x%02x",
             s_my_mac_str,
             s_wallet_pubkey[0], s_wallet_pubkey[1],
             s_wallet_pubkey[2], s_wallet_pubkey[3]);
    ESP_LOGI(TAG, "auto-tapping every ~%u ms — peer LEDs will blink on receive",
             (unsigned)TAP_PERIOD_MS);

    // Stagger first heartbeat to reduce collision risk on simultaneous boot.
    vTaskDelay(pdMS_TO_TICKS(500 + (esp_random() & 0x3FF)));

    uint64_t last_heartbeat_us = 0;
    uint64_t last_telem_us     = 0;
    uint64_t next_tap_us       = esp_timer_get_time()
                               + 2000ULL * 1000ULL                    // 2s warmup
                               + (uint64_t)(esp_random() % TAP_JITTER_MS) * 1000ULL;
    const uint64_t HEARTBEAT_PERIOD_US = 5ULL * 1000ULL * 1000ULL;    // 5s
    uint64_t hot_swap_at_us    = esp_timer_get_time() + HOT_SWAP_BROADCAST_DELAY_US;
    bool     hot_swap_sent     = false;
    // Originator-only: first forward at boot+4s (after radio is settled
    // + every device has logged its role), then on FORWARD_PERIOD_MS.
    uint64_t next_forward_us   = esp_timer_get_time()
                               + 4000ULL * 1000ULL
                               + (uint64_t)(esp_random() % FORWARD_JITTER_MS) * 1000ULL;
    // Device A schedules the channel demo to start after the existing
    // hot-swap + early forward arcs have shown.
    uint64_t channel_demo_at_us = esp_timer_get_time()
                                + (uint64_t)CHANNEL_TX_START_DELAY_MS * 1000ULL;
    // Device A also paces scripted cells on its own cadence.
    uint64_t scripted_demo_at_us = esp_timer_get_time()
                                 + (uint64_t)SCRIPTED_TX_START_DELAY_MS * 1000ULL;
    // Rentable-device demo: device C offers starting at boot+8s
    // (interleaved with everything else); device A activations start
    // ~90s in, after the rest of the demo has had its moments.
    uint64_t actuator_offer_at_us    = esp_timer_get_time()
                                      + (uint64_t)ACTUATOR_OFFER_START_DELAY_MS * 1000ULL;
    uint64_t actuator_activate_at_us = esp_timer_get_time()
                                      + (uint64_t)ACTUATOR_ACTIVATE_START_DELAY_MS * 1000ULL;
    // MNCA: first tile tick at boot+5s (after radio settled), then every
    // MNCA_PERIOD_MS with a small random jitter so devices don't all
    // broadcast simultaneously (reduces collision probability on ESP-NOW).
    uint64_t next_mnca_us = esp_timer_get_time()
                          + 5000ULL * 1000ULL
                          + (uint64_t)(esp_random() % MNCA_JITTER_MS) * 1000ULL;

    while (1) {
        uint64_t now_us = esp_timer_get_time();

#if DEMO_SCRIPT_ONLY
        // Demo: fire the staged inject broadcast once the post-ack delay has
        // elapsed. This is the A → (air) → B hop the audience is watching for.
        if (s_demo_pending && now_us >= s_demo_broadcast_at_us) {
            s_demo_pending = false;
            uint32_t cell_id = (uint32_t)esp_random();
            esp_err_t e = cm_radio_send_cell(s_demo_cell, s_demo_sig, cell_id);
            ESP_LOGI(TAG, "*** CELL BROADCAST *** (demo: A->air->B) cell_id=0x%08x rc=%d",
                     (unsigned)cell_id, (int)e);
        }
#endif

        // Periodic heartbeat (no effect on receive; just confirms radio).
        if (now_us - last_heartbeat_us > HEARTBEAT_PERIOD_US) {
            broadcast_heartbeat();
            last_heartbeat_us = now_us;
        }

        // Speeder telemetry: every device broadcasts its own pose at 20 Hz,
        // unsigned. This is the "real-time piloting from the sideline" path.
        if (now_us - last_telem_us >= TELEM_PERIOD_US) {
            broadcast_telem(now_us);
            last_telem_us = now_us;
        }

        // Auto-tap on cadence.
        if (now_us >= next_tap_us) {
            broadcast_tap();
            next_tap_us = now_us
                        + (uint64_t)TAP_PERIOD_MS * 1000ULL
                        + (uint64_t)(esp_random() % TAP_JITTER_MS) * 1000ULL;
        }

        // MNCA: every device steps its tile and broadcasts state every ~3s.
        if (now_us >= next_mnca_us) {
            broadcast_mnca_tile();
            next_mnca_us = now_us
                         + (uint64_t)MNCA_PERIOD_MS * 1000ULL
                         + (uint64_t)(esp_random() % MNCA_JITTER_MS) * 1000ULL;
        }

        // One-shot hot-swap broadcast a fixed delay after boot.
        if (!hot_swap_sent && now_us >= hot_swap_at_us) {
            broadcast_hot_swap_rule();
            hot_swap_sent = true;
        }

        // Originator-only: periodic forward route.
        if (s_is_originator && now_us >= next_forward_us) {
            broadcast_forward_route();
            next_forward_us = now_us
                            + (uint64_t)FORWARD_PERIOD_MS * 1000ULL
                            + (uint64_t)(esp_random() % FORWARD_JITTER_MS) * 1000ULL;
        }

        // Drain any pending rule-driven emit.
        drain_pending_emit();

        // Drain any pending forward relay.
        drain_pending_forward();
        drain_pending_forward_v1();
        drain_pending_forward_v2();

        // Drain any rule install queued by a CM_HOP_VERB_INSTALL_RULE hop.
        drain_pending_fwd_rule();

        // Drain any pending scripted-cell dispatch (cell-engine runs
        // on the main task only — WAMR is registered with us here).
        drain_pending_script();
        // Same for actuator activations — engine verify on main pthread,
        // accept extends the LED-active window.
        drain_pending_actuator();

        // Device A: kick off the channel demo at T+25s, then channel_tx_tick
        // paces channel cells onto the radio at 1s intervals.
        if (s_is_originator) {
            if (!s_channel_tx_started && now_us >= channel_demo_at_us) {
                s_channel_tx_started = true;
                s_channel_tx_step    = 0;
                s_channel_tx_next_us = now_us;
                ESP_LOGI(TAG, "*** CHANNEL DEMO STARTING *** (wallet broadcasts open + %u commitments + close)",
                         (unsigned)CHANNEL_TX_COMMITMENT_COUNT);
            }
            channel_tx_tick(now_us);

            // Scripted cells on a separate cadence.
            if (!s_scripted_tx_started && now_us >= scripted_demo_at_us) {
                s_scripted_tx_started = true;
                s_scripted_tx_next_us = now_us;
                ESP_LOGI(TAG, "*** SCRIPTED DEMO STARTING *** (cell-engine on the wire)");
            }
            scripted_tx_tick(now_us);

            // Actuator activations (the wallet paying for the LED).
            if (!s_actuator_activate_started && now_us >= actuator_activate_at_us) {
                s_actuator_activate_started = true;
                s_actuator_activate_next_us = now_us;
                ESP_LOGI(TAG, "*** RENTABLE DEMO STARTING *** (wallet pays for the LED, x402-over-cells)");
            }
            actuator_activate_tx_tick(now_us);
        }

        // Device C: broadcast actuator_offer.v0 cells advertising rental
        // terms. Plays the "x402 server" role.
        if (s_is_destination) {
            if (!s_actuator_offer_started && now_us >= actuator_offer_at_us) {
                s_actuator_offer_started = true;
                s_actuator_offer_next_us = now_us;
                ESP_LOGI(TAG, "*** ACTUATOR OFFERS STARTING *** (advertising rentable-device terms)");
            }
            actuator_offer_tx_tick(now_us);
        }

        // Device C: periodic expiry tick + meter drain. The cm_channel
        // module transitions ACTIVE → EXPIRED when relative_now > expiry_ms;
        // the meter independently accrues consumed value while ACTIVE.
        bool meter_authorized = true;
        if ((DEMO_SCRIPT_ONLY || s_is_destination) && s_channel.state == CM_CHAN_ACTIVE) {
            uint64_t now_ms      = (uint64_t)esp_log_timestamp();
            uint64_t relative_now = (now_ms > s_channel_base_ms)
                                  ? (now_ms - s_channel_base_ms) : 0;
            cm_channel_state_t before = s_channel.state;
            cm_channel_tick_expiry(&s_channel, relative_now);
            if (before == CM_CHAN_ACTIVE && s_channel.state == CM_CHAN_EXPIRED) {
                cm_meter_stop(&s_meter, now_ms);
                ESP_LOGI(TAG, "*** CHANNEL EXPIRED *** (state=EXPIRED, LED off) seq=%u device_share=%u",
                         (unsigned)s_channel.current_seq,
                         (unsigned)s_channel.device_share);
            } else {
                // Drain the meter and evaluate the actuator value bound.
                cm_meter_tick(&s_meter, now_ms);
                meter_authorized = cm_meter_authorized(&s_meter,
                                                       s_channel.device_share,
                                                       CM_METER_TOLERANCE_SATS);
                // Edge-detect the prepaid drain reaching empty: consumed
                // value has overrun the last paid commitment + tolerance.
                if (!meter_authorized && !s_meter_cut) {
                    s_meter_cut = true;
                    ESP_LOGW(TAG, "*** METER EXHAUSTED *** consumed=%u sats > paid device_share=%u (+tol %u) -> actuator OFF (prepaid drain empty)",
                             (unsigned)cm_meter_consumed_sats(&s_meter),
                             (unsigned)s_channel.device_share,
                             (unsigned)CM_METER_TOLERANCE_SATS);
                } else if (meter_authorized && s_meter_cut) {
                    // A fresh commitment raised device_share back over the
                    // consumed line — service re-authorized (re-lit).
                    s_meter_cut = false;
                    ESP_LOGI(TAG, "*** METER RE-AUTHORIZED *** fresh commitment device_share=%u >= consumed=%u sats -> actuator ON",
                             (unsigned)s_channel.device_share,
                             (unsigned)cm_meter_consumed_sats(&s_meter));
                }
            }
        }

        // LED priority (highest → lowest):
        //   1. Device C with actuator window open → steady on (rentable
        //      LED is paid for; pay-per-second IoT)
        //   2. Device C, channel ACTIVE *and* paid ahead of metered
        //      consumption → steady on (the draining lightbulb-channel).
        //      Cut off the instant consumed value overruns the paid share.
        //   3. Any device with blink-until set → on for the remainder
        //   4. otherwise → off
        bool led_should_be_on = false;
#if DEMO_SCRIPT_ONLY
        // Inject-ack (highest priority): the board that received a serial
        // inject from the laptop pulses its LED 3× (250 ms on / 250 ms off)
        // to say "got it". Drives the LED directly and skips the rest of the
        // LED logic for this tick.
        if (s_inject_ack_start_us != 0) {
            uint64_t dt = now_us - s_inject_ack_start_us;
            const uint64_t PULSE = 250000ULL;            // 250 ms per phase
            if (dt < 6ULL * PULSE) {                      // on,off,on,off,on,off
                if (((dt / PULSE) % 2ULL) == 0ULL) led_on(); else led_off();
                vTaskDelay(pdMS_TO_TICKS(20));            // ~50 Hz for crisp pulses
                continue;
            }
            s_inject_ack_start_us = 0;                    // pattern complete
        }
#endif
        if ((DEMO_SCRIPT_ONLY || s_is_destination) && now_us < s_actuator_active_until_us) {
            led_should_be_on = true; // demo: any board lights its own actuator on a valid activation
        } else if ((DEMO_SCRIPT_ONLY || s_is_destination) && s_channel.state == CM_CHAN_ACTIVE && meter_authorized) {
            led_should_be_on = true;
        } else if (now_us < s_blink_until_us) {
            led_should_be_on = true;
        }
        if (led_should_be_on) led_on(); else led_off();

        // Edge-detect actuator window expiration for a clear log.
        if ((DEMO_SCRIPT_ONLY || s_is_destination) && s_actuator_active_until_us != 0
            && now_us >= s_actuator_active_until_us) {
            ESP_LOGI(TAG, "*** ACTUATOR DEACTIVATED *** activations=%u",
                     (unsigned)s_actuator_activations);
            s_actuator_active_until_us = 0;
        }

        // ~20 Hz polling.
        vTaskDelay(pdMS_TO_TICKS(50));
    }
    return NULL;
}

void app_main(void) {
    pthread_t       tid;
    pthread_attr_t  attr;
    pthread_attr_init(&attr);
    // 12 KB stack. WAMR's 128 KB linear-memory mmap needs (128 KB + 8)
    // for alignment padding; with default-sized stacks the largest free
    // block landed at *exactly* 128 KB (8 bytes short). Smaller stack
    // → contiguous block edges out enough room. Main loop's heaviest
    // stack consumer is ECDSA verify (a few KB), so 12 KB has headroom.
    pthread_attr_setstacksize(&attr, 12 * 1024);
    int rc = pthread_create(&tid, &attr, mesh_demo_thread, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "pthread_create(mesh_demo_thread) failed: %d", rc);
    }
    pthread_attr_destroy(&attr);
    // Detach — we don't join. The thread runs forever.
    if (rc == 0) pthread_detach(tid);
}
