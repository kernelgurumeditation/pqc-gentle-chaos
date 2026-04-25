/*
 * Source: PQC Learning Plan - Module 4: ML-KEM Deep Dive
 * Unit 4.1: KEM Concepts and Security Definitions
 *
 * Unit 4.1: KEM Interface Demonstration
 *
 * This code demonstrates the KEM API pattern using
 * a simplified (insecure) implementation.
 *
 * EDUCATIONAL PURPOSE ONLY - Not secure for any real use
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

/* ========== Simplified KEM Interface ========== */

#define EK_SIZE 32    /* Encapsulation key size (simplified) */
#define DK_SIZE 64    /* Decapsulation key size */
#define CT_SIZE 48    /* Ciphertext size */
#define SS_SIZE 32    /* Shared secret size */

typedef struct {
    uint8_t ek[EK_SIZE];    /* Public encapsulation key */
    uint8_t dk[DK_SIZE];    /* Private decapsulation key */
} kem_keypair_t;

typedef struct {
    uint8_t ct[CT_SIZE];    /* Ciphertext */
    uint8_t ss[SS_SIZE];    /* Shared secret */
} kem_encaps_result_t;

/* Simple XOR-based "encryption" (NOT SECURE - demo only) */
static void xor_bytes(uint8_t *out, const uint8_t *a, const uint8_t *b, size_t len) {
    for (size_t i = 0; i < len; i++) {
        out[i] = a[i] ^ b[i];
    }
}

/* Toy hash function (NOT SECURE - demo only) */
static void toy_hash(uint8_t *out, const uint8_t *in, size_t in_len) {
    uint32_t state = 0x12345678;
    for (size_t i = 0; i < in_len; i++) {
        state = state * 31 + in[i];
    }
    for (int i = 0; i < SS_SIZE; i++) {
        out[i] = (state >> (i % 4 * 8)) & 0xFF;
        state = state * 17 + i;
    }
}

/*
 * KeyGen: Generate KEM key pair
 */
int kem_keygen(kem_keypair_t *kp) {
    /* In real ML-KEM: sample matrix A, secrets s, compute t = As + e */
    /* Simplified: just random bytes */

    for (int i = 0; i < EK_SIZE; i++) {
        kp->ek[i] = rand() & 0xFF;
    }

    /* dk contains ek plus additional secret material */
    memcpy(kp->dk, kp->ek, EK_SIZE);
    for (int i = EK_SIZE; i < DK_SIZE; i++) {
        kp->dk[i] = rand() & 0xFF;
    }

    return 0;  /* Success */
}

/*
 * Encaps: Create ciphertext and shared secret
 */
int kem_encaps(kem_encaps_result_t *result, const uint8_t *ek) {
    /* In real ML-KEM:
     * 1. Generate random m
     * 2. Derive K, r from m
     * 3. Encrypt m under ek using randomness r
     * 4. Hash to get final K
     */

    /* Simplified: random secret, "encrypt" with ek */
    uint8_t random_seed[SS_SIZE];
    for (int i = 0; i < SS_SIZE; i++) {
        random_seed[i] = rand() & 0xFF;
    }

    /* "Ciphertext" = seed XOR ek (padded) - NOT SECURE */
    memset(result->ct, 0, CT_SIZE);
    xor_bytes(result->ct, random_seed, ek, SS_SIZE);

    /* Add some additional "randomness" to ciphertext */
    for (int i = SS_SIZE; i < CT_SIZE; i++) {
        result->ct[i] = rand() & 0xFF;
    }

    /* Shared secret = hash of seed */
    toy_hash(result->ss, random_seed, SS_SIZE);

    return 0;  /* Success */
}

/*
 * Decaps: Recover shared secret from ciphertext
 */
int kem_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *dk) {
    /* In real ML-KEM:
     * 1. Decrypt ciphertext to get m'
     * 2. Re-derive K', r' from m'
     * 3. Re-encrypt and compare
     * 4. If match: output K'. If not: implicit rejection
     */

    /* Simplified: recover seed, hash it */
    uint8_t recovered_seed[SS_SIZE];

    /* ek is first EK_SIZE bytes of dk */
    xor_bytes(recovered_seed, ct, dk, SS_SIZE);

    /* Shared secret = hash of recovered seed */
    toy_hash(ss, recovered_seed, SS_SIZE);

    return 0;  /* Success */
}

/* ========== Demonstration ========== */

void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len && i < 16; i++) {
        printf("%02x", data[i]);
    }
    if (len > 16) printf("...");
    printf("\n");
}

void demo_kem_usage(void) {
    printf("=== KEM Usage Demonstration ===\n\n");

    kem_keypair_t keypair;
    kem_encaps_result_t encaps_result;
    uint8_t decaps_ss[SS_SIZE];

    /* Step 1: Key Generation (done once by recipient) */
    printf("Step 1: Key Generation\n");
    kem_keygen(&keypair);
    print_hex("  Encapsulation key (public)", keypair.ek, EK_SIZE);
    print_hex("  Decapsulation key (private)", keypair.dk, DK_SIZE);
    printf("\n");

    /* Step 2: Encapsulation (done by sender) */
    printf("Step 2: Encapsulation (sender side)\n");
    kem_encaps(&encaps_result, keypair.ek);
    print_hex("  Ciphertext", encaps_result.ct, CT_SIZE);
    print_hex("  Sender's shared secret", encaps_result.ss, SS_SIZE);
    printf("\n");

    /* Step 3: Decapsulation (done by recipient) */
    printf("Step 3: Decapsulation (recipient side)\n");
    kem_decaps(decaps_ss, encaps_result.ct, keypair.dk);
    print_hex("  Recipient's shared secret", decaps_ss, SS_SIZE);
    printf("\n");

    /* Step 4: Verify match */
    printf("Step 4: Verification\n");
    if (memcmp(encaps_result.ss, decaps_ss, SS_SIZE) == 0) {
        printf("  ✓ Shared secrets MATCH\n");
    } else {
        printf("  ✗ Shared secrets DO NOT MATCH (error!)\n");
    }
}

void demo_cca_attack_attempt(void) {
    printf("\n=== CCA Attack Demonstration ===\n\n");

    kem_keypair_t keypair;
    kem_encaps_result_t encaps_result;
    uint8_t modified_ct[CT_SIZE];
    uint8_t decaps_ss[SS_SIZE];

    kem_keygen(&keypair);
    kem_encaps(&encaps_result, keypair.ek);

    printf("Original shared secret:\n");
    print_hex("  K", encaps_result.ss, SS_SIZE);

    /* Attacker modifies ciphertext */
    memcpy(modified_ct, encaps_result.ct, CT_SIZE);
    modified_ct[0] ^= 0x01;  /* Flip one bit */

    printf("\nAttacker flips bit in ciphertext...\n");

    /* Decapsulate modified ciphertext */
    kem_decaps(decaps_ss, modified_ct, keypair.dk);

    printf("\nDecapsulation of modified ciphertext:\n");
    print_hex("  K'", decaps_ss, SS_SIZE);

    /* In this toy example, modification is detectable */
    if (memcmp(encaps_result.ss, decaps_ss, SS_SIZE) != 0) {
        printf("\n  Note: K ≠ K' (modified ciphertext gives different key)\n");
        printf("  In real ML-KEM with FO transform:\n");
        printf("  - This is 'implicit rejection'\n");
        printf("  - Attacker can't tell if ciphertext was valid\n");
    }
}

int main(void) {
    srand(time(NULL));

    printf("╔════════════════════════════════════════════════════════╗\n");
    printf("║  Unit 4.1: KEM Concepts and Security Definitions       ║\n");
    printf("╚════════════════════════════════════════════════════════╝\n\n");

    demo_kem_usage();
    demo_cca_attack_attempt();

    printf("\n");
    printf("════════════════════════════════════════════════════════════\n");
    printf("Key Takeaways:\n");
    printf("  1. KEM generates random key (not sender-chosen message)\n");
    printf("  2. Three operations: KeyGen, Encaps, Decaps\n");
    printf("  3. Correctness: Decaps(dk, Encaps(ek)) = K\n");
    printf("  4. IND-CCA2 security protects against chosen-ciphertext attacks\n");
    printf("════════════════════════════════════════════════════════════\n");

    return 0;
}
