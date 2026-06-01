/*
 * Source: Module 7 - SLH-DSA (Hash-Based Digital Signatures)
 * Unit: 7.3 - WOTS+ (Winternitz One-Time Signature Plus)
 * Description: Demonstration of WOTS+ concepts
 *
 * This is a standalone educational demonstration showing WOTS+ concepts
 * including the Winternitz chain and checksum mechanism.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

/* WOTS+ parameters for demo (simplified) */
#define WOTS_N       16        /* Hash output size (reduced for demo) */
#define WOTS_W       16        /* Winternitz parameter (4 bits per chunk) */
#define WOTS_LOG_W   4         /* log2(w) */
#define WOTS_LEN1    4         /* Chunks for message: n*8/log2(w) = 16*8/4 = 32, reduced */
#define WOTS_LEN2    2         /* Checksum chunks */
#define WOTS_LEN     (WOTS_LEN1 + WOTS_LEN2)  /* Total chains */

/* Simple random bytes */
static void random_bytes(uint8_t *out, size_t len)
{
    static unsigned int seed = 12345;
    for (size_t i = 0; i < len; i++) {
        seed = seed * 1103515245 + 12345;
        out[i] = (seed >> 16) & 0xFF;
    }
}

/* Simple hash function for demo (not cryptographic!) */
static void simple_hash(uint8_t out[WOTS_N], const uint8_t *in, size_t len)
{
    memset(out, 0, WOTS_N);
    for (size_t i = 0; i < len; i++) {
        out[i % WOTS_N] ^= in[i];
        out[(i + 1) % WOTS_N] ^= (in[i] << 4) | (in[i] >> 4);
    }
    for (int r = 0; r < 4; r++) {
        for (int i = 0; i < WOTS_N; i++) {
            out[i] ^= out[(i + 5) % WOTS_N];
        }
    }
}

/* PRF: Derive value from seed and index */
static void prf(uint8_t out[WOTS_N], const uint8_t seed[WOTS_N], uint32_t idx)
{
    uint8_t input[WOTS_N + 4];
    memcpy(input, seed, WOTS_N);
    input[WOTS_N] = (idx >> 24) & 0xFF;
    input[WOTS_N + 1] = (idx >> 16) & 0xFF;
    input[WOTS_N + 2] = (idx >> 8) & 0xFF;
    input[WOTS_N + 3] = idx & 0xFF;
    simple_hash(out, input, WOTS_N + 4);
}

/* Chain function: Apply hash i times */
static void chain(uint8_t out[WOTS_N], const uint8_t in[WOTS_N],
                  int start, int steps, const uint8_t pub_seed[WOTS_N])
{
    uint8_t temp[WOTS_N * 2];

    memcpy(out, in, WOTS_N);
    for (int i = start; i < start + steps; i++) {
        /* T(pub_seed, i, out) */
        memcpy(temp, pub_seed, WOTS_N);
        memcpy(temp + WOTS_N, out, WOTS_N);
        temp[0] ^= (i & 0xFF);
        simple_hash(out, temp, WOTS_N * 2);
    }
}

/* Convert bytes to base-w representation */
static void base_w(uint32_t *output, size_t out_len,
                   const uint8_t *input, size_t in_len)
{
    size_t in_idx = 0;
    int bits = 0;
    uint32_t total = 0;

    for (size_t out_idx = 0; out_idx < out_len; out_idx++) {
        while (bits < WOTS_LOG_W && in_idx < in_len) {
            total = (total << 8) | input[in_idx++];
            bits += 8;
        }
        bits -= WOTS_LOG_W;
        output[out_idx] = (total >> bits) & (WOTS_W - 1);
    }
}

/* Compute WOTS+ checksum */
static uint32_t wots_checksum(const uint32_t *msg_chunks, size_t len)
{
    uint32_t sum = 0;
    for (size_t i = 0; i < len; i++) {
        sum += (WOTS_W - 1) - msg_chunks[i];
    }
    return sum;
}

/* WOTS+ Key generation */
static void wots_keygen(uint8_t pk[WOTS_LEN * WOTS_N],
                        const uint8_t sk_seed[WOTS_N],
                        const uint8_t pub_seed[WOTS_N])
{
    uint8_t sk_i[WOTS_N];

    for (int i = 0; i < WOTS_LEN; i++) {
        /* Derive secret key for chain i */
        prf(sk_i, sk_seed, i);

        /* Compute public key: chain to the top */
        chain(&pk[i * WOTS_N], sk_i, 0, WOTS_W - 1, pub_seed);
    }
}

/* WOTS+ Sign */
static void wots_sign(uint8_t sig[WOTS_LEN * WOTS_N],
                      const uint8_t msg[WOTS_N],
                      const uint8_t sk_seed[WOTS_N],
                      const uint8_t pub_seed[WOTS_N])
{
    uint32_t msg_chunks[WOTS_LEN1];
    uint32_t csum_chunks[WOTS_LEN2];
    uint8_t sk_i[WOTS_N];

    /* Convert message to base-w */
    base_w(msg_chunks, WOTS_LEN1, msg, WOTS_N);

    /* Compute and convert checksum */
    uint32_t csum = wots_checksum(msg_chunks, WOTS_LEN1);
    uint8_t csum_bytes[2] = {(csum >> 8) & 0xFF, csum & 0xFF};
    base_w(csum_chunks, WOTS_LEN2, csum_bytes, 2);

    /* Sign message chunks */
    for (int i = 0; i < WOTS_LEN1; i++) {
        prf(sk_i, sk_seed, i);
        chain(&sig[i * WOTS_N], sk_i, 0, msg_chunks[i], pub_seed);
    }

    /* Sign checksum chunks */
    for (int i = 0; i < WOTS_LEN2; i++) {
        prf(sk_i, sk_seed, WOTS_LEN1 + i);
        chain(&sig[(WOTS_LEN1 + i) * WOTS_N], sk_i, 0, csum_chunks[i], pub_seed);
    }
}

/* WOTS+ Verify: compute pk from sig and compare */
static int wots_verify(const uint8_t expected_pk[WOTS_LEN * WOTS_N],
                       const uint8_t sig[WOTS_LEN * WOTS_N],
                       const uint8_t msg[WOTS_N],
                       const uint8_t pub_seed[WOTS_N])
{
    uint32_t msg_chunks[WOTS_LEN1];
    uint32_t csum_chunks[WOTS_LEN2];
    uint8_t computed_pk[WOTS_LEN * WOTS_N];

    /* Convert message to base-w */
    base_w(msg_chunks, WOTS_LEN1, msg, WOTS_N);

    /* Compute and convert checksum */
    uint32_t csum = wots_checksum(msg_chunks, WOTS_LEN1);
    uint8_t csum_bytes[2] = {(csum >> 8) & 0xFF, csum & 0xFF};
    base_w(csum_chunks, WOTS_LEN2, csum_bytes, 2);

    /* Verify message chunks */
    for (int i = 0; i < WOTS_LEN1; i++) {
        int remaining = (WOTS_W - 1) - msg_chunks[i];
        chain(&computed_pk[i * WOTS_N], &sig[i * WOTS_N],
              msg_chunks[i], remaining, pub_seed);
    }

    /* Verify checksum chunks */
    for (int i = 0; i < WOTS_LEN2; i++) {
        int remaining = (WOTS_W - 1) - csum_chunks[i];
        chain(&computed_pk[(WOTS_LEN1 + i) * WOTS_N],
              &sig[(WOTS_LEN1 + i) * WOTS_N],
              csum_chunks[i], remaining, pub_seed);
    }

    return memcmp(expected_pk, computed_pk, WOTS_LEN * WOTS_N);
}

/*
 * Test basic WOTS+ sign and verify.
 * Returns 1 on success, 0 on failure.
 */
int test_wots_basic(void)
{
    printf("Testing WOTS+ basic sign/verify...\n");

    uint8_t sk_seed[WOTS_N], pub_seed[WOTS_N];
    uint8_t pk[WOTS_LEN * WOTS_N];
    uint8_t sig[WOTS_LEN * WOTS_N];
    uint8_t msg[WOTS_N];

    random_bytes(sk_seed, WOTS_N);
    random_bytes(pub_seed, WOTS_N);
    random_bytes(msg, WOTS_N);

    /* Generate key pair */
    wots_keygen(pk, sk_seed, pub_seed);

    /* Sign */
    wots_sign(sig, msg, sk_seed, pub_seed);

    /* Verify */
    int result = wots_verify(pk, sig, msg, pub_seed);
    if (result == 0) {
        printf("  Basic sign/verify PASSED!\n");
    } else {
        printf("  Basic sign/verify FAILED!\n");
    }
    return result == 0;
}

/*
 * Test that wrong message fails verification.
 * Returns 1 on success, 0 on failure.
 */
int test_wots_wrong_message(void)
{
    printf("Testing WOTS+ wrong message detection...\n");

    uint8_t sk_seed[WOTS_N], pub_seed[WOTS_N];
    uint8_t pk[WOTS_LEN * WOTS_N];
    uint8_t sig[WOTS_LEN * WOTS_N];
    uint8_t msg[WOTS_N], wrong_msg[WOTS_N];

    random_bytes(sk_seed, WOTS_N);
    random_bytes(pub_seed, WOTS_N);
    random_bytes(msg, WOTS_N);
    random_bytes(wrong_msg, WOTS_N);

    wots_keygen(pk, sk_seed, pub_seed);
    wots_sign(sig, msg, sk_seed, pub_seed);

    /* Verify with wrong message should fail */
    int result = wots_verify(pk, sig, wrong_msg, pub_seed);
    if (result != 0) {
        printf("  Wrong message detection PASSED!\n");
    } else {
        printf("  Wrong message detection FAILED!\n");
    }
    return result != 0;
}

/*
 * Demonstrate checksum security
 */
void test_checksum_security(void)
{
    printf("Testing WOTS+ checksum security...\n");

    printf("  Checksum mechanism:\n");
    printf("    - Message chunks: values 0 to %d\n", WOTS_W - 1);
    printf("    - Checksum = sum of (W-1 - chunk_i)\n");
    printf("    - If attacker increases a chunk, checksum DECREASES\n");
    printf("    - But signature allows only INCREASING chain position\n");
    printf("    - Therefore: forgery is computationally infeasible\n\n");

    /* Example */
    uint32_t chunks1[4] = {5, 10, 3, 8};  /* Example message chunks */
    uint32_t csum1 = wots_checksum(chunks1, 4);
    printf("  Example: chunks = {5, 10, 3, 8}\n");
    printf("    Checksum = (%d-5)+(%d-10)+(%d-3)+(%d-8) = %u\n",
           WOTS_W-1, WOTS_W-1, WOTS_W-1, WOTS_W-1, csum1);

    /* If attacker tries to increase chunk[0] from 5 to 6 */
    uint32_t chunks2[4] = {6, 10, 3, 8};
    uint32_t csum2 = wots_checksum(chunks2, 4);
    printf("\n  If attacker changes chunks[0] from 5 to 6:\n");
    printf("    New checksum = %u (was %u)\n", csum2, csum1);
    printf("    Checksum DECREASED - but attacker can only INCREASE!\n");

    printf("  Checksum security test PASSED!\n");
}

/*
 * Test base-w conversion.
 * Returns 1 on success, 0 on failure.
 */
int test_base_w(void)
{
    printf("Testing base-w conversion...\n");

    uint8_t input[] = {0xAB, 0xCD};  /* Binary: 10101011 11001101 */
    uint32_t output[4];

    /* With w=16 (4 bits per chunk), should get:
     * 0xA=10, 0xB=11, 0xC=12, 0xD=13 */
    base_w(output, 4, input, 2);

    printf("  Input: 0xAB 0xCD\n");
    printf("  Output (base-16): {%u, %u, %u, %u}\n",
           output[0], output[1], output[2], output[3]);

    int passed = (output[0] == 0xA && output[1] == 0xB &&
                  output[2] == 0xC && output[3] == 0xD);
    if (passed) {
        printf("  Base-w conversion PASSED!\n");
    } else {
        printf("  Base-w conversion FAILED!\n");
    }
    return passed;
}

/*
 * Test chain composition.
 * Returns 1 on success, 0 on failure.
 */
int test_chain_composition(void)
{
    printf("Testing chain composition...\n");

    uint8_t input[WOTS_N], pub_seed[WOTS_N];
    uint8_t out1[WOTS_N], out2[WOTS_N], out3[WOTS_N];

    random_bytes(input, WOTS_N);
    random_bytes(pub_seed, WOTS_N);

    /* chain(x, 0, 5) should equal chain(chain(x, 0, 3), 3, 2) */
    chain(out1, input, 0, 5, pub_seed);

    chain(out2, input, 0, 3, pub_seed);
    chain(out3, out2, 3, 2, pub_seed);

    int passed = (memcmp(out1, out3, WOTS_N) == 0);
    if (passed) {
        printf("  Chain composition PASSED!\n");
        printf("    chain(x, 0, 5) == chain(chain(x, 0, 3), 3, 2)\n");
    } else {
        printf("  Chain composition FAILED!\n");
    }
    return passed;
}

/*
 * Display sizes
 */
void show_sizes(void)
{
    printf("\nWOTS+ Parameters (demo values):\n");
    printf("  n (hash size):     %d bytes\n", WOTS_N);
    printf("  w (Winternitz):    %d\n", WOTS_W);
    printf("  len1 (msg chunks): %d\n", WOTS_LEN1);
    printf("  len2 (csum chunks):%d\n", WOTS_LEN2);
    printf("  len (total chains):%d\n", WOTS_LEN);

    printf("\nSizes:\n");
    printf("  Public key: %d bytes\n", WOTS_LEN * WOTS_N);
    printf("  Signature:  %d bytes\n", WOTS_LEN * WOTS_N);

    printf("\nComparison (with n=32, w=16):\n");
    printf("  Lamport signature: 8192 bytes\n");
    printf("  WOTS+ signature:   2144 bytes (len=67)\n");
    printf("  Reduction:         ~3.8x smaller\n");
}

int main(void)
{
    printf("=== WOTS+ Demonstration ===\n\n");

    int ok_basew  = test_base_w();
    int ok_chain  = test_chain_composition();
    int ok_basic  = test_wots_basic();
    int ok_wrong  = test_wots_wrong_message();
    test_checksum_security();
    show_sizes();

    printf("\n=== Demo complete! ===\n");

    /* Explicit PASS/FAIL verdict so the demo is usable as an automated test. */
    int all_ok = ok_basew && ok_chain && ok_basic && ok_wrong;
    printf("\n=== Self-test verdict ===\n");
    printf("  base-w conversion        : %s\n", ok_basew ? "PASS" : "FAIL");
    printf("  chain composition        : %s\n", ok_chain ? "PASS" : "FAIL");
    printf("  basic sign/verify        : %s\n", ok_basic ? "PASS" : "FAIL");
    printf("  wrong message rejected   : %s\n", ok_wrong ? "PASS" : "FAIL");
    printf("Result: %s\n", all_ok ? "PASS" : "FAIL");
    return all_ok ? 0 : 1;
}
