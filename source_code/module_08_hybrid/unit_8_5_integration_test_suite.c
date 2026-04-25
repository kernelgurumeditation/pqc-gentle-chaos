/*
 * Source: Module 8 (Hybrid Cryptography), Unit 8.5 (Implementation and Integration)
 * Section: Exercise 8.5.4 - Integration Test Suite
 *
 * Integration Test Suite Demonstration
 * Educational demonstration of comprehensive integration testing for hybrid crypto
 *
 * This is a standalone demonstration showing integration test patterns.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

/* Error codes */
typedef enum {
    HC_SUCCESS = 0,
    HC_ERROR_NOT_SUPPORTED = -1,
    HC_ERROR_INVALID_PARAM = -2,
    HC_ERROR_BUFFER_SIZE = -3,
    HC_ERROR_VERIFICATION = -4
} hc_error_t;

/* Algorithm identifiers */
typedef enum {
    HC_ALG_ED25519 = 0x0001,
    HC_ALG_MLDSA65 = 0x0002,
    HC_ALG_X25519 = 0x0003,
    HC_ALG_HYBRID_ED25519_MLDSA65 = 0x2001,
    HC_ALG_HYBRID_X25519_MLKEM768 = 0x2002
} hc_algorithm_t;

/* Test statistics */
typedef struct {
    int total_tests;
    int passed;
    int failed;
    int skipped;
} test_stats_t;

static test_stats_t stats = {0};

/* Test macros */
#define RUN_TEST(name, test_expr) do { \
    stats.total_tests++; \
    printf("  Testing: %s... ", name); \
    if (test_expr) { \
        stats.passed++; \
        printf("PASSED\n"); \
    } else { \
        stats.failed++; \
        printf("FAILED\n"); \
    } \
} while(0)

#define SKIP_TEST(name, reason) do { \
    stats.total_tests++; \
    stats.skipped++; \
    printf("  Skipping: %s (%s)\n", name, reason); \
} while(0)

/* Simulated key structure */
typedef struct {
    hc_algorithm_t alg;
    uint8_t public_key[2048];
    uint8_t private_key[4096];
    size_t pk_len;
    size_t sk_len;
} hc_key_t;

/* Simple PRNG */
static uint32_t prng_state = 12345;
static uint8_t rand_byte(void) {
    prng_state = prng_state * 1103515245 + 12345;
    return (prng_state >> 16) & 0xFF;
}

/* Key generation */
static hc_error_t hc_key_generate(hc_algorithm_t alg, hc_key_t **key) {
    *key = calloc(1, sizeof(hc_key_t));
    if (!*key) return HC_ERROR_INVALID_PARAM;
    (*key)->alg = alg;

    switch (alg) {
        case HC_ALG_ED25519:
            (*key)->pk_len = 32;
            (*key)->sk_len = 64;
            break;
        case HC_ALG_MLDSA65:
            (*key)->pk_len = 1952;
            (*key)->sk_len = 4032;
            break;
        case HC_ALG_HYBRID_ED25519_MLDSA65:
            (*key)->pk_len = 32 + 1952;
            (*key)->sk_len = 64 + 4032;
            break;
        default:
            (*key)->pk_len = 32;
            (*key)->sk_len = 64;
    }

    for (size_t i = 0; i < (*key)->pk_len; i++)
        (*key)->public_key[i] = rand_byte();
    for (size_t i = 0; i < (*key)->sk_len; i++)
        (*key)->private_key[i] = rand_byte();

    return HC_SUCCESS;
}

static void hc_key_free(hc_key_t *key) {
    if (key) {
        memset(key, 0, sizeof(*key));
        free(key);
    }
}

/* Signing */
static hc_error_t hc_sign(const hc_key_t *key, const uint8_t *msg,
                          size_t msg_len, uint8_t *sig, size_t *sig_len) {
    if (!key || !msg || !sig || !sig_len) return HC_ERROR_INVALID_PARAM;

    size_t needed;
    switch (key->alg) {
        case HC_ALG_ED25519:
            needed = 64;
            break;
        case HC_ALG_MLDSA65:
            needed = 3309;
            break;
        case HC_ALG_HYBRID_ED25519_MLDSA65:
            needed = 64 + 3309;
            break;
        default:
            needed = 64;
    }

    if (*sig_len < needed) return HC_ERROR_BUFFER_SIZE;

    for (size_t i = 0; i < needed; i++) {
        sig[i] = key->private_key[i % key->sk_len] ^
                 msg[i % msg_len] ^ (i & 0xFF);
    }
    *sig_len = needed;
    return HC_SUCCESS;
}

/* Verification */
static hc_error_t hc_verify(const hc_key_t *key, const uint8_t *msg,
                            size_t msg_len, const uint8_t *sig, size_t sig_len) {
    if (!key || !msg || !sig) return HC_ERROR_INVALID_PARAM;
    (void)msg_len;
    (void)sig_len;
    return HC_SUCCESS;  /* Simplified for demo */
}

/* Hex encoding (kept for diagnostic use; suppress unused warning) */
__attribute__((unused))
static void hex_encode(const uint8_t *data, size_t len, char *out) {
    for (size_t i = 0; i < len; i++) {
        snprintf(out + i * 2, 3, "%02x", data[i]);
    }
    out[len * 2] = '\0';
}

/* End-to-end signing test */
int test_e2e_signing(void) {
    printf("\n=== End-to-End Signing Tests ===\n");

    const uint8_t message[] = "Test message for E2E signing verification";
    const size_t message_len = sizeof(message) - 1;

    hc_algorithm_t algorithms[] = {
        HC_ALG_ED25519,
        HC_ALG_MLDSA65,
        HC_ALG_HYBRID_ED25519_MLDSA65
    };

    const char *names[] = {
        "Ed25519",
        "ML-DSA-65",
        "Hybrid Ed25519+ML-DSA-65"
    };

    int success = 1;

    for (int i = 0; i < 3; i++) {
        printf("\n  Testing %s:\n", names[i]);

        hc_key_t *key = NULL;
        hc_error_t err = hc_key_generate(algorithms[i], &key);

        if (err != HC_SUCCESS) {
            printf("    Key generation: FAILED\n");
            success = 0;
            continue;
        }
        printf("    Key generation: PASSED\n");

        uint8_t signature[8192];
        size_t sig_len = sizeof(signature);

        err = hc_sign(key, message, message_len, signature, &sig_len);
        if (err != HC_SUCCESS) {
            printf("    Signing: FAILED\n");
            success = 0;
            hc_key_free(key);
            continue;
        }
        printf("    Signing: PASSED (signature: %zu bytes)\n", sig_len);

        err = hc_verify(key, message, message_len, signature, sig_len);
        if (err != HC_SUCCESS) {
            printf("    Verification: FAILED\n");
            success = 0;
        } else {
            printf("    Verification: PASSED\n");
        }

        hc_key_free(key);
    }

    return success;
}

/* Known Answer Test demonstration */
void test_known_answer_vectors(void) {
    printf("\n=== Known Answer Tests (KAT) ===\n");

    printf("\n  KAT Vector Structure:\n");
    printf("    - Seed:     Fixed input for key generation\n");
    printf("    - Message:  Test message to sign\n");
    printf("    - Expected: Known correct signature\n\n");

    printf("  Example Ed25519 KAT:\n");
    printf("    Seed:     9d61b19deffd5a60ba844af492ec2cc4...\n");
    printf("    Message:  (empty)\n");
    printf("    Expected: e5564300c360ac729086e2cc806e828a...\n\n");

    printf("  KAT testing ensures:\n");
    printf("    - Deterministic key generation\n");
    printf("    - Correct signature computation\n");
    printf("    - Interoperability with reference implementation\n");
}

/* Error handling test */
void test_error_handling(void) {
    printf("\n=== Error Handling Tests ===\n");

    uint8_t msg[] = "test message";
    uint8_t sig[256];
    size_t sig_len;

    /* NULL key test */
    sig_len = sizeof(sig);
    hc_error_t err = hc_sign(NULL, msg, sizeof(msg), sig, &sig_len);
    RUN_TEST("Reject NULL key", err == HC_ERROR_INVALID_PARAM);

    /* NULL message test */
    hc_key_t *key;
    hc_key_generate(HC_ALG_ED25519, &key);
    sig_len = sizeof(sig);
    err = hc_sign(key, NULL, 10, sig, &sig_len);
    RUN_TEST("Reject NULL message", err == HC_ERROR_INVALID_PARAM);

    /* Buffer too small test */
    sig_len = 10;  /* Too small for Ed25519 (64 bytes) */
    err = hc_sign(key, msg, sizeof(msg), sig, &sig_len);
    RUN_TEST("Reject buffer too small", err == HC_ERROR_BUFFER_SIZE);

    hc_key_free(key);
}

/* Performance demonstration */
void test_performance_demo(void) {
    printf("\n=== Performance Test Structure ===\n\n");

    printf("  Performance Baselines:\n");
    printf("    Ed25519 keygen:  < 0.5 ms\n");
    printf("    Ed25519 sign:    < 0.1 ms\n");
    printf("    Ed25519 verify:  < 0.2 ms\n");
    printf("    ML-DSA-65 keygen: < 5.0 ms\n");
    printf("    ML-DSA-65 sign:  < 2.0 ms\n");
    printf("    ML-DSA-65 verify: < 1.0 ms\n\n");

    printf("  Hybrid overhead:\n");
    printf("    Time = Ed25519_time + ML-DSA_time\n");
    printf("    Size = Ed25519_size + ML-DSA_size\n\n");

    printf("  Performance testing approach:\n");
    printf("    1. Run operation N times\n");
    printf("    2. Measure total time\n");
    printf("    3. Calculate average\n");
    printf("    4. Compare to baseline\n");
    printf("    5. Flag regressions\n");
}

/* Stress test demonstration */
void test_stress_demo(void) {
    printf("\n=== Stress Test Structure ===\n\n");

    printf("  1. Rapid Key Generation:\n");
    printf("     - Generate 1000 keys rapidly\n");
    printf("     - Check memory usage\n");
    printf("     - Verify all keys work\n\n");

    printf("  2. Large Message Signing:\n");
    printf("     - Sign 1MB message\n");
    printf("     - Verify signature\n");
    printf("     - Check performance scaling\n\n");

    printf("  3. Concurrent Operations:\n");
    printf("     - Multiple threads signing\n");
    printf("     - No race conditions\n");
    printf("     - No memory leaks\n");
}

/* Summary */
void print_summary(void) {
    printf("\n=== Test Summary ===\n");
    printf("Total:   %d\n", stats.total_tests);
    printf("Passed:  %d\n", stats.passed);
    printf("Failed:  %d\n", stats.failed);
    printf("Skipped: %d\n", stats.skipped);

    if (stats.failed == 0) {
        printf("\nRESULT: ALL TESTS PASSED\n");
    } else {
        printf("\nRESULT: %d TEST(S) FAILED\n", stats.failed);
    }
}

int main(void) {
    printf("Hybrid Cryptography Integration Test Demo\n");
    printf("==========================================\n");

    /* Run test suites */
    test_e2e_signing();
    test_known_answer_vectors();
    test_error_handling();
    test_performance_demo();
    test_stress_demo();

    /* Print summary */
    print_summary();

    return stats.failed > 0 ? 1 : 0;
}
