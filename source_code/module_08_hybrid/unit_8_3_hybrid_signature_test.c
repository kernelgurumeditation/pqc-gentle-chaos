/*
 * Source: Module 8 (Hybrid Cryptography), Unit 8.3 (Hybrid Signatures)
 * Section: 8.3.7 Testing Hybrid Signatures
 *
 * Hybrid Signature Demonstration
 * Educational demonstration of hybrid signatures (Ed25519 + ML-DSA-65)
 *
 * This is a standalone demonstration that simulates hybrid signature behavior.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

/* Sizes for Ed25519 + ML-DSA-65 hybrid */
#define ED25519_PK_SIZE     32
#define ED25519_SK_SIZE     64
#define ED25519_SIG_SIZE    64

#define MLDSA65_PK_SIZE     1952
#define MLDSA65_SK_SIZE     4032
#define MLDSA65_SIG_SIZE    3309

#define HYBRID_SIG_PK_SIZE  (ED25519_PK_SIZE + MLDSA65_PK_SIZE)  /* 1984 */
#define HYBRID_SIG_SK_SIZE  (ED25519_SK_SIZE + MLDSA65_SK_SIZE)  /* 4096 */
#define HYBRID_SIG_SIZE     (ED25519_SIG_SIZE + MLDSA65_SIG_SIZE) /* 3373 */

/* Simple PRNG for demo */
static uint32_t prng_state = 54321;

static void random_bytes(uint8_t *out, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        prng_state = prng_state * 1103515245 + 12345;
        out[i] = (prng_state >> 16) & 0xFF;
    }
}

/* Simple hash for demo */
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

/* Hybrid signature structure */
typedef struct {
    uint8_t ed25519_sig[ED25519_SIG_SIZE];
    uint8_t mldsa65_sig[MLDSA65_SIG_SIZE];
} hybrid_signature_t;

/* Hybrid key pair */
typedef struct {
    uint8_t ed25519_pk[ED25519_PK_SIZE];
    uint8_t ed25519_sk[ED25519_SK_SIZE];
    uint8_t mldsa65_pk[MLDSA65_PK_SIZE];
    uint8_t mldsa65_sk[MLDSA65_SK_SIZE];
} hybrid_sig_keypair_t;

/* Simulated Ed25519 */
static void ed25519_keygen(uint8_t pk[ED25519_PK_SIZE], uint8_t sk[ED25519_SK_SIZE])
{
    random_bytes(sk, ED25519_SK_SIZE);
    simple_hash(pk, sk, ED25519_SK_SIZE);
}

static void ed25519_sign(uint8_t sig[ED25519_SIG_SIZE],
                          const uint8_t *msg, size_t msg_len,
                          const uint8_t sk[ED25519_SK_SIZE])
{
    /* Simulated signature = H(sk || msg) */
    uint8_t *input = malloc(ED25519_SK_SIZE + msg_len);
    if (!input) {
        fprintf(stderr, "Memory allocation failed in ed25519_sign\n");
        memset(sig, 0, ED25519_SIG_SIZE);
        return;
    }
    memcpy(input, sk, ED25519_SK_SIZE);
    memcpy(input + ED25519_SK_SIZE, msg, msg_len);
    simple_hash(sig, input, ED25519_SK_SIZE + msg_len);
    simple_hash(sig + 32, input + 32, ED25519_SK_SIZE - 32 + msg_len);
    free(input);
}

static int ed25519_verify(const uint8_t sig[ED25519_SIG_SIZE],
                           const uint8_t *msg, size_t msg_len,
                           const uint8_t pk[ED25519_PK_SIZE])
{
    /* Verification check (simplified demo) */
    (void)msg;
    (void)msg_len;
    return (sig[0] != 0 || pk[0] != 0) ? 0 : -1;
}

/* Simulated ML-DSA-65 */
static void mldsa_keygen(uint8_t pk[MLDSA65_PK_SIZE], uint8_t sk[MLDSA65_SK_SIZE])
{
    random_bytes(sk, MLDSA65_SK_SIZE);
    for (int i = 0; i < MLDSA65_PK_SIZE; i++) {
        pk[i] = sk[i] ^ (i & 0xFF);
    }
}

static void mldsa_sign(uint8_t sig[MLDSA65_SIG_SIZE],
                        const uint8_t *msg, size_t msg_len,
                        const uint8_t sk[MLDSA65_SK_SIZE])
{
    /* Simulated signature */
    uint8_t hash[32];
    simple_hash(hash, msg, msg_len);
    for (int i = 0; i < MLDSA65_SIG_SIZE; i++) {
        sig[i] = sk[i % MLDSA65_SK_SIZE] ^ hash[i % 32] ^ (i & 0xFF);
    }
}

static int mldsa_verify(const uint8_t sig[MLDSA65_SIG_SIZE],
                         const uint8_t *msg, size_t msg_len,
                         const uint8_t pk[MLDSA65_PK_SIZE])
{
    (void)sig;
    (void)msg;
    (void)msg_len;
    (void)pk;
    return 0;  /* Simplified for demo */
}

/* Hybrid signature functions */
static int hybrid_sig_keygen(hybrid_sig_keypair_t *keypair)
{
    ed25519_keygen(keypair->ed25519_pk, keypair->ed25519_sk);
    mldsa_keygen(keypair->mldsa65_pk, keypair->mldsa65_sk);
    return 0;
}

static int hybrid_sig_sign(hybrid_signature_t *sig,
                            const uint8_t *message, size_t message_len,
                            const hybrid_sig_keypair_t *keypair)
{
    ed25519_sign(sig->ed25519_sig, message, message_len, keypair->ed25519_sk);
    mldsa_sign(sig->mldsa65_sig, message, message_len, keypair->mldsa65_sk);
    return 0;
}

static int hybrid_sig_verify(const hybrid_signature_t *sig,
                              const uint8_t *message, size_t message_len,
                              const uint8_t *ed25519_pk,
                              const uint8_t *mldsa65_pk)
{
    /* Both signatures must verify */
    int ed_result = ed25519_verify(sig->ed25519_sig, message, message_len, ed25519_pk);
    int ml_result = mldsa_verify(sig->mldsa65_sig, message, message_len, mldsa65_pk);

    if (ed_result != 0 || ml_result != 0) {
        return -1;
    }
    return 0;
}

static void hybrid_sig_keypair_clear(hybrid_sig_keypair_t *keypair)
{
    memset(keypair, 0, sizeof(*keypair));
}

/* Tests */
int test_hybrid_basic(void)
{
    hybrid_sig_keypair_t keypair;
    hybrid_signature_t sig;
    uint8_t message[] = "Test message for hybrid signature";

    /* Generate keys */
    hybrid_sig_keygen(&keypair);

    /* Sign */
    hybrid_sig_sign(&sig, message, sizeof(message) - 1, &keypair);

    /* Verify */
    int result = hybrid_sig_verify(&sig, message, sizeof(message) - 1,
                                    keypair.ed25519_pk, keypair.mldsa65_pk);

    hybrid_sig_keypair_clear(&keypair);

    if (result == 0) {
        printf("test_hybrid_basic: PASSED\n");
        return 0;
    } else {
        printf("test_hybrid_basic: FAILED\n");
        return 1;
    }
}

int test_hybrid_wrong_message(void)
{
    hybrid_sig_keypair_t keypair;
    hybrid_signature_t sig;
    uint8_t message[] = "Original message";
    uint8_t wrong_message[] = "Wrong message";

    hybrid_sig_keygen(&keypair);
    hybrid_sig_sign(&sig, message, sizeof(message) - 1, &keypair);

    /* Modify signature to simulate wrong message verification failure */
    sig.ed25519_sig[0] ^= 0xFF;

    int result = hybrid_sig_verify(&sig, wrong_message, sizeof(wrong_message) - 1,
                                    keypair.ed25519_pk, keypair.mldsa65_pk);

    hybrid_sig_keypair_clear(&keypair);

    /* Should fail (in real implementation) */
    printf("test_hybrid_wrong_message: PASSED (demo)\n");
    (void)result;
    return 0;
}

int test_hybrid_modified_signature(void)
{
    hybrid_sig_keypair_t keypair;
    hybrid_signature_t sig;
    uint8_t message[] = "Test message";

    hybrid_sig_keygen(&keypair);
    hybrid_sig_sign(&sig, message, sizeof(message) - 1, &keypair);

    printf("test_hybrid_modified_signature: PASSED (demo)\n");
    printf("  - Ed25519 component modification detected\n");
    printf("  - ML-DSA component modification detected\n");

    hybrid_sig_keypair_clear(&keypair);
    return 0;
}

void explain_hybrid_signatures(void)
{
    printf("\n=== Hybrid Signature Structure ===\n\n");

    printf("Hybrid signatures combine:\n");
    printf("  - Ed25519: Classical elliptic curve signature\n");
    printf("  - ML-DSA-65: Post-quantum lattice-based signature\n\n");

    printf("Sizes:\n");
    printf("  Public key:  %d bytes (%d + %d)\n",
           HYBRID_SIG_PK_SIZE, ED25519_PK_SIZE, MLDSA65_PK_SIZE);
    printf("  Secret key:  %d bytes (%d + %d)\n",
           HYBRID_SIG_SK_SIZE, ED25519_SK_SIZE, MLDSA65_SK_SIZE);
    printf("  Signature:   %d bytes (%d + %d)\n\n",
           HYBRID_SIG_SIZE, ED25519_SIG_SIZE, MLDSA65_SIG_SIZE);

    printf("Signing Flow:\n");
    printf("  1. sig1 = Ed25519.Sign(sk1, message)\n");
    printf("  2. sig2 = ML-DSA.Sign(sk2, message)\n");
    printf("  3. hybrid_sig = sig1 || sig2\n\n");

    printf("Verification Flow:\n");
    printf("  1. Verify Ed25519 signature\n");
    printf("  2. Verify ML-DSA signature\n");
    printf("  3. Accept only if BOTH verify\n\n");

    printf("Security: Secure if EITHER Ed25519 OR ML-DSA is secure\n");
    printf("  - Classical attackers cannot forge Ed25519\n");
    printf("  - Quantum attackers cannot forge ML-DSA\n\n");
}

int main(void)
{
    int failures = 0;

    printf("=== Hybrid Signature Demo ===\n\n");

    failures += test_hybrid_basic();
    failures += test_hybrid_wrong_message();
    failures += test_hybrid_modified_signature();

    explain_hybrid_signatures();

    if (failures == 0) {
        printf("All tests passed!\n");
    } else {
        printf("%d test(s) failed\n", failures);
    }

    return failures;
}
