/*
 * Source: Module 8 (Hybrid Cryptography), Unit 8.2 (Hybrid Key Exchange)
 * Section: 8.2.8 Testing and Validation
 *
 * X-Wing Demonstration
 * Educational demonstration of X-Wing hybrid KEM concepts (X25519 + ML-KEM-768)
 *
 * This is a standalone demonstration that simulates X-Wing behavior.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

/* X-Wing size constants (from specification) */
#define XWING_PK_BYTES      1216    /* 32 + 1184 */
#define XWING_SK_BYTES      2432    /* 32 + 2400 */
#define XWING_CT_BYTES      1120    /* 32 + 1088 */
#define XWING_SS_BYTES      32

/* X25519 sizes */
#define X25519_PK_BYTES     32
#define X25519_SK_BYTES     32
#define X25519_SS_BYTES     32

/* ML-KEM-768 sizes */
#define MLKEM_PK_BYTES      1184
#define MLKEM_SK_BYTES      2400
#define MLKEM_CT_BYTES      1088
#define MLKEM_SS_BYTES      32

/* Simple PRNG for demo */
static uint32_t prng_state = 12345;

static void random_bytes(uint8_t *out, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        prng_state = prng_state * 1103515245 + 12345;
        out[i] = (prng_state >> 16) & 0xFF;
    }
}

/* Simple hash for demo (simulates SHA3-256) */
static void simple_hash(uint8_t out[32], const uint8_t *in, size_t len)
{
    memset(out, 0, 32);
    for (size_t i = 0; i < len; i++) {
        out[i % 32] ^= in[i];
        out[(i + 1) % 32] ^= (in[i] << 4) | (in[i] >> 4);
    }
    for (int r = 0; r < 8; r++) {
        for (int i = 0; i < 32; i++) {
            out[i] ^= out[(i + 7) % 32];
        }
    }
}

/* Simulated X25519 key exchange
 * Note: Real X25519 uses elliptic curve operations.
 * This simplified version simulates DH-like behavior.
 */
static void x25519_keygen(uint8_t pk[X25519_PK_BYTES], uint8_t sk[X25519_SK_BYTES])
{
    random_bytes(sk, X25519_SK_BYTES);
    /* pk = H(sk) simulates sk * G */
    simple_hash(pk, sk, X25519_SK_BYTES);
}

static void x25519_shared_secret(uint8_t ss[X25519_SS_BYTES],
                                  const uint8_t pk[X25519_PK_BYTES],
                                  const uint8_t sk[X25519_SK_BYTES])
{
    /* Simulated DH: ss = H(pk XOR H(sk))
     * This gives same result for: H(pk_b XOR H(sk_a)) = H(pk_a XOR H(sk_b))
     * when pk_a = H(sk_a) and pk_b = H(sk_b)
     * i.e., H(H(sk_b) XOR H(sk_a)) = H(H(sk_a) XOR H(sk_b))
     */
    uint8_t sk_hash[32];
    simple_hash(sk_hash, sk, X25519_SK_BYTES);

    uint8_t combined[32];
    for (int i = 0; i < 32; i++) {
        combined[i] = pk[i] ^ sk_hash[i];
    }
    simple_hash(ss, combined, 32);
}

/* Simulated ML-KEM-768 KEM */
static void mlkem_keygen(uint8_t pk[MLKEM_PK_BYTES], uint8_t sk[MLKEM_SK_BYTES])
{
    random_bytes(sk, MLKEM_SK_BYTES);
    /* pk derived from sk (simplified - XOR with pattern) */
    for (int i = 0; i < MLKEM_PK_BYTES; i++) {
        pk[i] = sk[i % MLKEM_SK_BYTES] ^ (uint8_t)(i * 7);
    }
}

static void mlkem_encaps(uint8_t ct[MLKEM_CT_BYTES], uint8_t ss[MLKEM_SS_BYTES],
                          const uint8_t pk[MLKEM_PK_BYTES])
{
    /* Generate random "ephemeral" value */
    uint8_t eph[32];
    random_bytes(eph, 32);

    /* Ciphertext contains ephemeral XORed with pk pattern */
    for (int i = 0; i < MLKEM_CT_BYTES; i++) {
        ct[i] = pk[i % MLKEM_PK_BYTES] ^ eph[i % 32] ^ (uint8_t)(i * 3);
    }

    /* Shared secret = H(eph || pk prefix) */
    uint8_t combined[64];
    memcpy(combined, eph, 32);
    memcpy(combined + 32, pk, 32);
    simple_hash(ss, combined, 64);
}

static void mlkem_decaps(uint8_t ss[MLKEM_SS_BYTES],
                          const uint8_t ct[MLKEM_CT_BYTES],
                          const uint8_t sk[MLKEM_SK_BYTES])
{
    /* Reconstruct pk from sk */
    uint8_t pk[MLKEM_PK_BYTES];
    for (int i = 0; i < MLKEM_PK_BYTES; i++) {
        pk[i] = sk[i % MLKEM_SK_BYTES] ^ (uint8_t)(i * 7);
    }

    /* Recover ephemeral from ciphertext */
    uint8_t eph[32];
    for (int i = 0; i < 32; i++) {
        eph[i] = ct[i] ^ pk[i] ^ (uint8_t)(i * 3);
    }

    /* Shared secret = H(eph || pk prefix) */
    uint8_t combined[64];
    memcpy(combined, eph, 32);
    memcpy(combined + 32, pk, 32);
    simple_hash(ss, combined, 64);
}

/* X-Wing KEM implementation */
static int xwing_keygen(uint8_t pk[XWING_PK_BYTES], uint8_t sk[XWING_SK_BYTES])
{
    /* Generate X25519 keypair */
    x25519_keygen(pk, sk);

    /* Generate ML-KEM-768 keypair */
    mlkem_keygen(pk + X25519_PK_BYTES, sk + X25519_SK_BYTES);

    return 0;
}

static int xwing_encaps(uint8_t ct[XWING_CT_BYTES], uint8_t ss[XWING_SS_BYTES],
                         const uint8_t pk[XWING_PK_BYTES])
{
    uint8_t x25519_eph_sk[X25519_SK_BYTES];
    uint8_t x25519_eph_pk[X25519_PK_BYTES];
    uint8_t x25519_ss[X25519_SS_BYTES];
    uint8_t mlkem_ss[MLKEM_SS_BYTES];
    uint8_t mlkem_ct[MLKEM_CT_BYTES];

    /* Generate ephemeral X25519 keypair */
    x25519_keygen(x25519_eph_pk, x25519_eph_sk);

    /* X25519 shared secret */
    x25519_shared_secret(x25519_ss, pk, x25519_eph_sk);

    /* ML-KEM encapsulation */
    mlkem_encaps(mlkem_ct, mlkem_ss, pk + X25519_PK_BYTES);

    /* Ciphertext = eph_pk || mlkem_ct */
    memcpy(ct, x25519_eph_pk, X25519_PK_BYTES);
    memcpy(ct + X25519_PK_BYTES, mlkem_ct, MLKEM_CT_BYTES);

    /* Combine shared secrets: ss = H(x25519_ss || mlkem_ss || label) */
    uint8_t combined[64 + 8];
    memcpy(combined, x25519_ss, 32);
    memcpy(combined + 32, mlkem_ss, 32);
    memcpy(combined + 64, "X-Wing", 6);
    simple_hash(ss, combined, 70);

    return 0;
}

static int xwing_decaps(uint8_t ss[XWING_SS_BYTES],
                         const uint8_t ct[XWING_CT_BYTES],
                         const uint8_t sk[XWING_SK_BYTES])
{
    uint8_t x25519_ss[X25519_SS_BYTES];
    uint8_t mlkem_ss[MLKEM_SS_BYTES];

    /* X25519 shared secret from ephemeral pk and our sk */
    x25519_shared_secret(x25519_ss, ct, sk);

    /* ML-KEM decapsulation */
    mlkem_decaps(mlkem_ss, ct + X25519_PK_BYTES, sk + X25519_SK_BYTES);

    /* Combine shared secrets: ss = H(x25519_ss || mlkem_ss || label) */
    uint8_t combined[64 + 8];
    memcpy(combined, x25519_ss, 32);
    memcpy(combined + 32, mlkem_ss, 32);
    memcpy(combined + 64, "X-Wing", 6);
    simple_hash(ss, combined, 70);

    return 0;
}

/*
 * Basic functionality test
 */
int test_xwing_basic(void)
{
    uint8_t pk[XWING_PK_BYTES];
    uint8_t sk[XWING_SK_BYTES];
    uint8_t ct[XWING_CT_BYTES];
    uint8_t ss_enc[XWING_SS_BYTES];
    uint8_t ss_dec[XWING_SS_BYTES];

    /* Key generation */
    xwing_keygen(pk, sk);

    /* Encapsulation */
    xwing_encaps(ct, ss_enc, pk);

    /* Decapsulation */
    xwing_decaps(ss_dec, ct, sk);

    /* Shared secrets must match */
    if (memcmp(ss_enc, ss_dec, XWING_SS_BYTES) == 0) {
        printf("test_xwing_basic: PASSED\n");
        return 0;
    } else {
        printf("test_xwing_basic: FAILED - shared secrets don't match\n");
        return 1;
    }
}

/*
 * Test that different key pairs produce different results
 */
int test_xwing_different_keys(void)
{
    uint8_t pk1[XWING_PK_BYTES], sk1[XWING_SK_BYTES];
    uint8_t pk2[XWING_PK_BYTES], sk2[XWING_SK_BYTES];
    uint8_t ct1[XWING_CT_BYTES], ct2[XWING_CT_BYTES];
    uint8_t ss1[XWING_SS_BYTES], ss2[XWING_SS_BYTES];

    xwing_keygen(pk1, sk1);
    xwing_keygen(pk2, sk2);

    xwing_encaps(ct1, ss1, pk1);
    xwing_encaps(ct2, ss2, pk2);

    /* Different keys should produce different shared secrets */
    if (memcmp(ss1, ss2, XWING_SS_BYTES) != 0) {
        printf("test_xwing_different_keys: PASSED\n");
        return 0;
    } else {
        printf("test_xwing_different_keys: FAILED\n");
        return 1;
    }
}

/*
 * Test ciphertext malleability resistance
 */
int test_xwing_malleability(void)
{
    uint8_t pk[XWING_PK_BYTES], sk[XWING_SK_BYTES];
    uint8_t ct[XWING_CT_BYTES];
    uint8_t ss_enc[XWING_SS_BYTES], ss_dec[XWING_SS_BYTES];
    uint8_t ct_modified[XWING_CT_BYTES];

    xwing_keygen(pk, sk);
    xwing_encaps(ct, ss_enc, pk);

    /* Modify one byte of ciphertext */
    memcpy(ct_modified, ct, XWING_CT_BYTES);
    ct_modified[50] ^= 0x01;

    /* Decapsulation should produce different result */
    xwing_decaps(ss_dec, ct_modified, sk);
    if (memcmp(ss_enc, ss_dec, XWING_SS_BYTES) != 0) {
        printf("test_xwing_malleability: PASSED\n");
        return 0;
    } else {
        printf("test_xwing_malleability: FAILED\n");
        return 1;
    }
}

/*
 * Display X-Wing structure
 */
void explain_xwing(void)
{
    printf("\n=== X-Wing Hybrid KEM Structure ===\n\n");

    printf("X-Wing combines:\n");
    printf("  - X25519 (Curve25519 ECDH): Classical security\n");
    printf("  - ML-KEM-768 (Kyber): Post-quantum security\n\n");

    printf("Sizes:\n");
    printf("  Public key:  %d bytes (%d + %d)\n",
           XWING_PK_BYTES, X25519_PK_BYTES, MLKEM_PK_BYTES);
    printf("  Secret key:  %d bytes (%d + %d)\n",
           XWING_SK_BYTES, X25519_SK_BYTES, MLKEM_SK_BYTES);
    printf("  Ciphertext:  %d bytes (%d + %d)\n",
           XWING_CT_BYTES, X25519_PK_BYTES, MLKEM_CT_BYTES);
    printf("  Shared secret: %d bytes\n\n", XWING_SS_BYTES);

    printf("Key Exchange Flow:\n");
    printf("  1. Alice: (pk_A, sk_A) = XWing.KeyGen()\n");
    printf("  2. Alice -> Bob: pk_A\n");
    printf("  3. Bob: (ct, ss_B) = XWing.Encaps(pk_A)\n");
    printf("  4. Bob -> Alice: ct\n");
    printf("  5. Alice: ss_A = XWing.Decaps(ct, sk_A)\n");
    printf("  6. ss_A == ss_B (both parties have shared secret)\n\n");

    printf("Security: IND-CCA secure if EITHER X25519 OR ML-KEM is secure\n");
    printf("  - Protects against both classical and quantum adversaries\n\n");
}

int main(void)
{
    int failures = 0;

    printf("=== X-Wing Hybrid KEM Demo ===\n\n");

    failures += test_xwing_basic();
    failures += test_xwing_different_keys();
    failures += test_xwing_malleability();

    explain_xwing();

    if (failures == 0) {
        printf("All tests passed!\n");
    } else {
        printf("%d test(s) failed\n", failures);
    }

    return failures;
}
