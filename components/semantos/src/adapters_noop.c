// adapters_noop.c — no-op implementations for the four Semantos adapter
// patterns. Every callback returns SEMANTOS_ERR_DENIED (-2), which the
// kernel surfaces as a "feature not available" failure.
//
// Use this table as a scaffold: copy adapters_noop.c into your own app,
// rename functions, fill them in with real NVS / SPIFFS / MQTT / BLE /
// LoRa / HTTP implementations, then pass your table into
// semantos_init(cfg, ...) via cfg.adapters.

#include "semantos_adapters.h"
#include "semantos.h"

static int32_t noop_storage_read(const char *key, size_t key_len,
                                 uint8_t *out_buf, size_t *inout_len) {
    (void)key; (void)key_len; (void)out_buf;
    if (inout_len) *inout_len = 0;
    return SEMANTOS_ERR_DENIED;
}

static int32_t noop_storage_write(const char *key, size_t key_len,
                                  const uint8_t *data, size_t data_len) {
    (void)key; (void)key_len; (void)data; (void)data_len;
    return SEMANTOS_ERR_DENIED;
}

static int32_t noop_identity_resolve(const uint8_t *cert_id, size_t cert_id_len,
                                     uint8_t *out_json, size_t *inout_len) {
    (void)cert_id; (void)cert_id_len; (void)out_json;
    if (inout_len) *inout_len = 0;
    return SEMANTOS_ERR_DENIED;
}

static int32_t noop_identity_derive(const char *parent_cert, size_t parent_cert_len,
                                    const char *resource_id, size_t resource_id_len,
                                    uint32_t domain_flag,
                                    uint8_t *out_json, size_t *inout_len) {
    (void)parent_cert; (void)parent_cert_len;
    (void)resource_id; (void)resource_id_len;
    (void)domain_flag; (void)out_json;
    if (inout_len) *inout_len = 0;
    return SEMANTOS_ERR_DENIED;
}

static int32_t noop_anchor_submit(const uint8_t *state_hash, size_t state_hash_len,
                                  const char *metadata_json, size_t metadata_len,
                                  uint8_t *out_proof, size_t *inout_len) {
    (void)state_hash; (void)state_hash_len;
    (void)metadata_json; (void)metadata_len;
    (void)out_proof;
    if (inout_len) *inout_len = 0;
    return SEMANTOS_ERR_DENIED;
}

static int32_t noop_network_publish(const char *object_json, size_t object_len) {
    (void)object_json; (void)object_len;
    return SEMANTOS_ERR_DENIED;
}

static int32_t noop_network_resolve(const char *query_json, size_t query_len,
                                    uint8_t *out_results, size_t *inout_len) {
    (void)query_json; (void)query_len; (void)out_results;
    if (inout_len) *inout_len = 0;
    return SEMANTOS_ERR_DENIED;
}

const semantos_adapter_table_t semantos_adapters_noop = {
    .storage_read     = noop_storage_read,
    .storage_write    = noop_storage_write,
    .identity_resolve = noop_identity_resolve,
    .identity_derive  = noop_identity_derive,
    .anchor_submit    = noop_anchor_submit,
    .network_publish  = noop_network_publish,
    .network_resolve  = noop_network_resolve,
};
