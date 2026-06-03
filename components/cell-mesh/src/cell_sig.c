// cell_sig.c — ECDSA-secp256k1 sign + verify using mbedTLS.
//
// Pulls in: mbedtls/ecdsa.h, mbedtls/ecp.h, mbedtls/sha256.h.
// secp256k1 must be enabled in IDF Kconfig (CONFIG_MBEDTLS_ECP_DP_SECP256K1_ENABLED=y).

#include "cell_sig.h"
#include "cell_wire.h"

#include <string.h>
#include <stdlib.h>

#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/sha256.h"
#include "mbedtls/bignum.h"
#include "esp_log.h"
#include "esp_random.h"

static const char *TAG = "cell_sig";

static bool       s_initialized = false;
static mbedtls_ecp_group s_grp;

struct cm_sig_pubkey_s {
    mbedtls_ecp_point Q;
};

// RNG callback adapter — mbedTLS expects (int (*f)(void *ctx, unsigned char *buf, size_t len)).
// esp_fill_random uses the hardware RNG on C6 (TRNG seeded by WiFi/BT phy).
// Required by mbedtls_ecp_mul / mbedtls_ecdsa_sign_det_ext for blinding;
// passing NULL fails on current mbedTLS.
static int esp_mbedtls_rng(void *ctx, unsigned char *buf, size_t len) {
    (void)ctx;
    esp_fill_random(buf, len);
    return 0;
}

int cm_sig_init(void) {
    if (s_initialized) return 0;
    mbedtls_ecp_group_init(&s_grp);
    int rc = mbedtls_ecp_group_load(&s_grp, MBEDTLS_ECP_DP_SECP256K1);
    if (rc != 0) {
        ESP_LOGE(TAG, "ecp_group_load(secp256k1) failed: -0x%04x", -rc);
        mbedtls_ecp_group_free(&s_grp);
        return -1;
    }
    s_initialized = true;
    return 0;
}

int cm_sig_sign(const uint8_t privkey[CM_SIG_PRIVKEY_BYTES],
                const uint8_t msg_hash[32],
                uint8_t       out_sig[CM_SIG_BYTES]) {
    if (!privkey || !msg_hash || !out_sig) return -1;
    if (!s_initialized && cm_sig_init() != 0) return -1;

    int rc;
    mbedtls_mpi d, r, s;
    mbedtls_mpi_init(&d); mbedtls_mpi_init(&r); mbedtls_mpi_init(&s);

    rc = mbedtls_mpi_read_binary(&d, privkey, CM_SIG_PRIVKEY_BYTES);
    if (rc != 0) goto out;

    // Deterministic ECDSA (RFC 6979). The RNG is still used for blinding
    // even in the deterministic path — current mbedTLS rejects NULL.
    rc = mbedtls_ecdsa_sign_det_ext(&s_grp, &r, &s, &d,
                                    msg_hash, 32,
                                    MBEDTLS_MD_SHA256,
                                    esp_mbedtls_rng, NULL);
    if (rc != 0) goto out;

    rc = mbedtls_mpi_write_binary(&r, out_sig,      32);
    if (rc != 0) goto out;
    rc = mbedtls_mpi_write_binary(&s, out_sig + 32, 32);
    if (rc != 0) goto out;

out:
    mbedtls_mpi_free(&d);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    return rc == 0 ? 0 : -1;
}

int cm_sig_verify(const uint8_t pubkey_compressed[CM_SIG_PUBKEY_COMPRESSED],
                  const uint8_t msg_hash[32],
                  const uint8_t sig[CM_SIG_BYTES]) {
    if (!pubkey_compressed || !msg_hash || !sig) return -1;
    if (!s_initialized && cm_sig_init() != 0) return -1;

    int rc;
    mbedtls_ecp_point Q;
    mbedtls_mpi r, s;
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_init(&r); mbedtls_mpi_init(&s);

    rc = mbedtls_ecp_point_read_binary(&s_grp, &Q,
                                        pubkey_compressed,
                                        CM_SIG_PUBKEY_COMPRESSED);
    if (rc != 0) goto out;

    rc = mbedtls_mpi_read_binary(&r, sig,      32);
    if (rc != 0) goto out;
    rc = mbedtls_mpi_read_binary(&s, sig + 32, 32);
    if (rc != 0) goto out;

    rc = mbedtls_ecdsa_verify(&s_grp, msg_hash, 32, &Q, &r, &s);

out:
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    return rc == 0 ? 0 : -1;
}

int cm_sig_pubkey_load(const uint8_t pubkey_compressed[CM_SIG_PUBKEY_COMPRESSED],
                       cm_sig_pubkey_t **out) {
    if (!pubkey_compressed || !out) return -1;
    if (!s_initialized && cm_sig_init() != 0) return -1;

    cm_sig_pubkey_t *p = (cm_sig_pubkey_t *)calloc(1, sizeof(*p));
    if (!p) return -1;
    mbedtls_ecp_point_init(&p->Q);
    int rc = mbedtls_ecp_point_read_binary(&s_grp, &p->Q,
                                            pubkey_compressed,
                                            CM_SIG_PUBKEY_COMPRESSED);
    if (rc != 0) {
        mbedtls_ecp_point_free(&p->Q);
        free(p);
        return -1;
    }
    *out = p;
    return 0;
}

void cm_sig_pubkey_free(cm_sig_pubkey_t *pub) {
    if (!pub) return;
    mbedtls_ecp_point_free(&pub->Q);
    free(pub);
}

int cm_sig_verify_prepared(const cm_sig_pubkey_t *pub,
                           const uint8_t msg_hash[32],
                           const uint8_t sig[CM_SIG_BYTES]) {
    if (!pub || !msg_hash || !sig) return -1;
    if (!s_initialized && cm_sig_init() != 0) return -1;

    int rc;
    mbedtls_mpi r, s;
    mbedtls_mpi_init(&r); mbedtls_mpi_init(&s);

    rc = mbedtls_mpi_read_binary(&r, sig,      32);
    if (rc != 0) goto out;
    rc = mbedtls_mpi_read_binary(&s, sig + 32, 32);
    if (rc != 0) goto out;

    rc = mbedtls_ecdsa_verify(&s_grp, msg_hash, 32, &pub->Q, &r, &s);

out:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    return rc == 0 ? 0 : -1;
}

int cm_sig_derive_pubkey(const uint8_t privkey[CM_SIG_PRIVKEY_BYTES],
                         uint8_t out_pubkey_compressed[CM_SIG_PUBKEY_COMPRESSED]) {
    if (!privkey || !out_pubkey_compressed) return -1;
    if (!s_initialized && cm_sig_init() != 0) return -1;

    int rc;
    mbedtls_mpi d;
    mbedtls_ecp_point Q;
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&Q);

    rc = mbedtls_mpi_read_binary(&d, privkey, CM_SIG_PRIVKEY_BYTES);
    if (rc != 0) goto out;

    // Q = d * G  (scalar multiply on the curve). RNG is used for blinding.
    rc = mbedtls_ecp_mul(&s_grp, &Q, &d, &s_grp.G, esp_mbedtls_rng, NULL);
    if (rc != 0) goto out;

    size_t olen = 0;
    rc = mbedtls_ecp_point_write_binary(&s_grp, &Q,
                                        MBEDTLS_ECP_PF_COMPRESSED,
                                        &olen,
                                        out_pubkey_compressed,
                                        CM_SIG_PUBKEY_COMPRESSED);
    if (rc == 0 && olen != CM_SIG_PUBKEY_COMPRESSED) rc = -1;

out:
    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&Q);
    return rc == 0 ? 0 : -1;
}

void cm_sig_hash_cell(const uint8_t cell[CM_CELL_SIZE],
                      uint8_t out_hash[32]) {
    if (!cell || !out_hash) return;

    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0); // 0 == SHA-256 (not SHA-224)
    mbedtls_sha256_update(&ctx, cell, CM_CELL_SIZE);
    mbedtls_sha256_finish(&ctx, out_hash);
    mbedtls_sha256_free(&ctx);
}
