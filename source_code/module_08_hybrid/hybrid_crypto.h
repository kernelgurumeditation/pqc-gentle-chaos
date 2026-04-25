/* hybrid_crypto.h - Core API header */

#ifndef HYBRID_CRYPTO_H
#define HYBRID_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

/* Version information */
#define HYBRID_CRYPTO_VERSION_MAJOR 1
#define HYBRID_CRYPTO_VERSION_MINOR 0
#define HYBRID_CRYPTO_VERSION_PATCH 0

/* Error codes */
typedef enum {
    HC_SUCCESS = 0,
    HC_ERROR_INVALID_PARAM = -1,
    HC_ERROR_MEMORY = -2,
    HC_ERROR_CRYPTO = -3,
    HC_ERROR_NOT_SUPPORTED = -4,
    HC_ERROR_KEY_SIZE = -5,
    HC_ERROR_SIGNATURE = -6,
    HC_ERROR_VERIFICATION = -7,
    HC_ERROR_PROVIDER = -8,
    HC_ERROR_STATE = -9,
    HC_ERROR_BUFFER_SIZE = -10,
    HC_ERROR_RNG = -11,
    HC_ERROR_INTERNAL = -100
} hc_error_t;

/* Algorithm identifiers */
typedef enum {
    /* Classical signature algorithms */
    HC_ALG_ED25519 = 0x0001,
    HC_ALG_ECDSA_P256 = 0x0002,
    HC_ALG_ECDSA_P384 = 0x0003,
    HC_ALG_RSA_PSS_2048 = 0x0004,
    HC_ALG_RSA_PSS_3072 = 0x0005,

    /* PQC signature algorithms */
    HC_ALG_MLDSA44 = 0x0101,
    HC_ALG_MLDSA65 = 0x0102,
    HC_ALG_MLDSA87 = 0x0103,
    HC_ALG_SLHDSA_SHA2_128S = 0x0111,
    HC_ALG_SLHDSA_SHA2_128F = 0x0112,
    HC_ALG_SLHDSA_SHA2_192S = 0x0113,
    HC_ALG_SLHDSA_SHA2_192F = 0x0114,
    HC_ALG_SLHDSA_SHA2_256S = 0x0115,
    HC_ALG_SLHDSA_SHA2_256F = 0x0116,

    /* Classical KEM algorithms */
    HC_ALG_X25519 = 0x1001,
    HC_ALG_ECDH_P256 = 0x1002,
    HC_ALG_ECDH_P384 = 0x1003,

    /* PQC KEM algorithms */
    HC_ALG_MLKEM512 = 0x1101,
    HC_ALG_MLKEM768 = 0x1102,
    HC_ALG_MLKEM1024 = 0x1103,

    /* Hybrid combinations */
    HC_ALG_HYBRID_ED25519_MLDSA65 = 0x2001,
    HC_ALG_HYBRID_P256_MLDSA65 = 0x2002,
    HC_ALG_HYBRID_X25519_MLKEM768 = 0x2101,
    HC_ALG_HYBRID_P256_MLKEM768 = 0x2102
} hc_algorithm_t;

/* Key types */
typedef enum {
    HC_KEY_PUBLIC,
    HC_KEY_PRIVATE,
    HC_KEY_KEYPAIR
} hc_key_type_t;

/* Opaque key handle */
typedef struct hc_key_st hc_key_t;

/* Opaque context handles */
typedef struct hc_sign_ctx_st hc_sign_ctx_t;
typedef struct hc_verify_ctx_st hc_verify_ctx_t;
typedef struct hc_kem_ctx_st hc_kem_ctx_t;

/* Provider handle */
typedef struct hc_provider_st hc_provider_t;

/* Callback for random number generation */
typedef int (*hc_rng_callback_t)(void *ctx, uint8_t *buf, size_t len);

/* Library initialization and cleanup */
hc_error_t hc_init(void);
void hc_cleanup(void);
const char *hc_version_string(void);
const char *hc_error_string(hc_error_t err);

/* Provider management */
hc_error_t hc_provider_load(const char *name, hc_provider_t **provider);
hc_error_t hc_provider_unload(hc_provider_t *provider);
hc_error_t hc_provider_set_default(hc_provider_t *provider);

/* Algorithm queries */
int hc_algorithm_supported(hc_algorithm_t alg);
size_t hc_algorithm_public_key_size(hc_algorithm_t alg);
size_t hc_algorithm_private_key_size(hc_algorithm_t alg);
size_t hc_algorithm_signature_size(hc_algorithm_t alg);
size_t hc_algorithm_ciphertext_size(hc_algorithm_t alg);
size_t hc_algorithm_shared_secret_size(hc_algorithm_t alg);
const char *hc_algorithm_name(hc_algorithm_t alg);

/* Key management */
hc_error_t hc_key_generate(hc_algorithm_t alg, hc_key_t **key);
hc_error_t hc_key_generate_with_rng(hc_algorithm_t alg,
                                     hc_rng_callback_t rng,
                                     void *rng_ctx,
                                     hc_key_t **key);
hc_error_t hc_key_import(hc_algorithm_t alg,
                          hc_key_type_t type,
                          const uint8_t *data,
                          size_t len,
                          hc_key_t **key);
hc_error_t hc_key_export(const hc_key_t *key,
                          hc_key_type_t type,
                          uint8_t *data,
                          size_t *len);
hc_algorithm_t hc_key_algorithm(const hc_key_t *key);
void hc_key_free(hc_key_t *key);

/* Signature operations - single-shot */
hc_error_t hc_sign(const hc_key_t *private_key,
                    const uint8_t *message,
                    size_t message_len,
                    uint8_t *signature,
                    size_t *signature_len);

hc_error_t hc_verify(const hc_key_t *public_key,
                      const uint8_t *message,
                      size_t message_len,
                      const uint8_t *signature,
                      size_t signature_len);

/* Signature operations - streaming */
hc_error_t hc_sign_init(hc_sign_ctx_t **ctx, const hc_key_t *private_key);
hc_error_t hc_sign_update(hc_sign_ctx_t *ctx,
                           const uint8_t *data,
                           size_t len);
hc_error_t hc_sign_final(hc_sign_ctx_t *ctx,
                          uint8_t *signature,
                          size_t *signature_len);
void hc_sign_ctx_free(hc_sign_ctx_t *ctx);

hc_error_t hc_verify_init(hc_verify_ctx_t **ctx, const hc_key_t *public_key);
hc_error_t hc_verify_update(hc_verify_ctx_t *ctx,
                             const uint8_t *data,
                             size_t len);
hc_error_t hc_verify_final(hc_verify_ctx_t *ctx,
                            const uint8_t *signature,
                            size_t signature_len);
void hc_verify_ctx_free(hc_verify_ctx_t *ctx);

/* KEM operations */
hc_error_t hc_kem_encapsulate(const hc_key_t *public_key,
                               uint8_t *ciphertext,
                               size_t *ciphertext_len,
                               uint8_t *shared_secret,
                               size_t *shared_secret_len);

hc_error_t hc_kem_decapsulate(const hc_key_t *private_key,
                               const uint8_t *ciphertext,
                               size_t ciphertext_len,
                               uint8_t *shared_secret,
                               size_t *shared_secret_len);

/* Hybrid-specific operations */
hc_error_t hc_hybrid_get_classical_key(const hc_key_t *hybrid_key,
                                        hc_key_t **classical_key);
hc_error_t hc_hybrid_get_pqc_key(const hc_key_t *hybrid_key,
                                  hc_key_t **pqc_key);

#endif /* HYBRID_CRYPTO_H */
