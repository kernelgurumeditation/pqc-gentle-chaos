/*
 * Source: PQC Learning Plan - Module 4: ML-KEM Deep Dive
 * Unit 4.3: Fujisaki-Okamoto Transform
 *
 * Unit 4.3: Fujisaki-Okamoto Transform
 *
 * Demonstrates the FO transform converting CPA-secure
 * encryption to CCA-secure KEM.
 *
 * EDUCATIONAL PURPOSE ONLY - Uses simplified primitives
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

/* ========== Parameters ========== */

#define MSG_SIZE 32      /* Message/seed size */
#define KEY_SIZE 32      /* Shared secret size */
#define CT_SIZE 64       /* Ciphertext size (simplified) */
#define EK_SIZE 32       /* Encapsulation key size */
#define Z_SIZE 32        /* Implicit rejection secret size */

/* ========== Simplified Primitives ========== */

/* Toy hash function (NOT CRYPTOGRAPHIC) */
static void toy_hash(uint8_t *out, size_t out_len,
                     const uint8_t *in, size_t in_len) {
    uint32_t state = 0x12345678;
    for (size_t i = 0; i < in_len; i++) {
        state = state * 31 + in[i];
    }
    for (size_t i = 0; i < out_len; i++) {
        out[i] = (state >> ((i % 4) * 8)) & 0xFF;
        state = state * 17 + i;
    }
}

/* G function: derive (K_bar, r) from m || H(ek) */
static void fo_g(uint8_t *k_bar, uint8_t *r,
                 const uint8_t *m, const uint8_t *ek_hash) {
    uint8_t input[MSG_SIZE + 32];
    memcpy(input, m, MSG_SIZE);
    memcpy(input + MSG_SIZE, ek_hash, 32);

    uint8_t output[64];
    toy_hash(output, 64, input, sizeof(input));

    memcpy(k_bar, output, KEY_SIZE);
    memcpy(r, output + KEY_SIZE, 32);
}

/* KDF function */
static void fo_kdf(uint8_t *K, const uint8_t *k_bar, const uint8_t *c_hash) {
    uint8_t input[KEY_SIZE + 32];
    memcpy(input, k_bar, KEY_SIZE);
    memcpy(input + KEY_SIZE, c_hash, 32);
    toy_hash(K, KEY_SIZE, input, sizeof(input));
}

/* Simplified K-PKE encrypt (deterministic given randomness r) */
static void kpke_encrypt(uint8_t *ct, const uint8_t *ek,
                         const uint8_t *m, const uint8_t *r) {
    /* Simplified: ct = ek XOR (m || r) - NOT REAL ENCRYPTION */
    for (size_t i = 0; i < MSG_SIZE; i++) {
        ct[i] = ek[i % EK_SIZE] ^ m[i] ^ r[i];
    }
    for (size_t i = MSG_SIZE; i < CT_SIZE; i++) {
        ct[i] = r[i - MSG_SIZE] ^ (i * 0x37);
    }
}

/* Simplified K-PKE decrypt */
static void kpke_decrypt(uint8_t *m, const uint8_t *dk,
                         const uint8_t *ek, const uint8_t *ct) {
    (void)dk;
    /* Simplified: reverse the toy encryption */
    uint8_t r_recovered[32];
    for (size_t i = 0; i < 32; i++) {
        r_recovered[i] = ct[MSG_SIZE + i] ^ ((MSG_SIZE + i) * 0x37);
    }
    for (size_t i = 0; i < MSG_SIZE; i++) {
        m[i] = ek[i % EK_SIZE] ^ ct[i] ^ r_recovered[i];
    }
}

/* ========== Constant-Time Utilities ========== */

/* Constant-time comparison: returns 0 if equal, non-zero otherwise */
static int ct_compare(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff;
}

/* Constant-time select: returns b if select != 0, else a */
static void ct_select_bytes(uint8_t *out, const uint8_t *a,
                            const uint8_t *b, size_t len, int select) {
    uint8_t mask = -(uint8_t)(select != 0);
    for (size_t i = 0; i < len; i++) {
        out[i] = (a[i] & ~mask) | (b[i] & mask);
    }
}

/* ========== ML-KEM (FO Transform) ========== */

typedef struct {
    uint8_t ek[EK_SIZE];           /* Public encapsulation key */
} mlkem_ek;

typedef struct {
    uint8_t dk_inner[EK_SIZE];     /* K-PKE secret key (simplified) */
    uint8_t ek_copy[EK_SIZE];      /* Copy of ek for re-encryption */
    uint8_t z[Z_SIZE];             /* Implicit rejection secret */
} mlkem_dk;

void mlkem_keygen(mlkem_ek *ek, mlkem_dk *dk) {
    /* Generate K-PKE key pair (simplified) */
    for (int i = 0; i < EK_SIZE; i++) {
        ek->ek[i] = rand() & 0xFF;
        dk->dk_inner[i] = rand() & 0xFF;
    }

    /* Store copy of ek in dk */
    memcpy(dk->ek_copy, ek->ek, EK_SIZE);

    /* Generate implicit rejection secret z */
    for (int i = 0; i < Z_SIZE; i++) {
        dk->z[i] = rand() & 0xFF;
    }
}

void mlkem_encaps(uint8_t *ct, uint8_t *K, const mlkem_ek *ek) {
    uint8_t m[MSG_SIZE];
    uint8_t k_bar[KEY_SIZE], r[32];
    uint8_t ek_hash[32], c_hash[32];

    /* Generate random seed m */
    for (int i = 0; i < MSG_SIZE; i++) {
        m[i] = rand() & 0xFF;
    }

    /* Hash ek */
    toy_hash(ek_hash, 32, ek->ek, EK_SIZE);

    /* Derive K_bar and r from m || H(ek) */
    fo_g(k_bar, r, m, ek_hash);

    /* Deterministic encryption */
    kpke_encrypt(ct, ek->ek, m, r);

    /* Hash ciphertext */
    toy_hash(c_hash, 32, ct, CT_SIZE);

    /* Final key K = KDF(K_bar || H(c)) */
    fo_kdf(K, k_bar, c_hash);
}

void mlkem_decaps(uint8_t *K, const uint8_t *ct, const mlkem_dk *dk) {
    uint8_t m_prime[MSG_SIZE];
    uint8_t k_bar_prime[KEY_SIZE], r_prime[32];
    uint8_t ct_prime[CT_SIZE];
    uint8_t K_prime[KEY_SIZE], K_reject[KEY_SIZE];
    uint8_t ek_hash[32], c_hash[32];

    /* Decrypt to get m' */
    kpke_decrypt(m_prime, dk->dk_inner, dk->ek_copy, ct);

    /* Hash ek */
    toy_hash(ek_hash, 32, dk->ek_copy, EK_SIZE);

    /* Re-derive K_bar' and r' */
    fo_g(k_bar_prime, r_prime, m_prime, ek_hash);

    /* Re-encrypt */
    kpke_encrypt(ct_prime, dk->ek_copy, m_prime, r_prime);

    /* Hash ciphertext */
    toy_hash(c_hash, 32, ct, CT_SIZE);

    /* Compute candidate key */
    fo_kdf(K_prime, k_bar_prime, c_hash);

    /* Compute rejection key */
    uint8_t reject_input[Z_SIZE + 32];
    memcpy(reject_input, dk->z, Z_SIZE);
    memcpy(reject_input + Z_SIZE, c_hash, 32);
    toy_hash(K_reject, KEY_SIZE, reject_input, sizeof(reject_input));

    /* Constant-time comparison and selection */
    int valid = (ct_compare(ct, ct_prime, CT_SIZE) == 0);
    ct_select_bytes(K, K_reject, K_prime, KEY_SIZE, valid);
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

void demo_valid_encaps(void) {
    printf("=== Valid Encapsulation/Decapsulation ===\n\n");

    mlkem_ek ek;
    mlkem_dk dk;
    uint8_t ct[CT_SIZE];
    uint8_t K_sender[KEY_SIZE], K_receiver[KEY_SIZE];

    /* Key generation */
    mlkem_keygen(&ek, &dk);
    print_hex("Public key (ek)", ek.ek, EK_SIZE);
    print_hex("Rejection secret (z)", dk.z, Z_SIZE);
    printf("\n");

    /* Encapsulation */
    mlkem_encaps(ct, K_sender, &ek);
    print_hex("Ciphertext", ct, CT_SIZE);
    print_hex("Sender's key", K_sender, KEY_SIZE);
    printf("\n");

    /* Decapsulation */
    mlkem_decaps(K_receiver, ct, &dk);
    print_hex("Receiver's key", K_receiver, KEY_SIZE);
    printf("\n");

    /* Verify */
    if (memcmp(K_sender, K_receiver, KEY_SIZE) == 0) {
        printf("✓ Keys MATCH - valid encapsulation\n");
    } else {
        printf("✗ Keys DO NOT MATCH - error!\n");
    }
}

void demo_invalid_ciphertext(void) {
    printf("\n=== Invalid Ciphertext (Modified) ===\n\n");

    mlkem_ek ek;
    mlkem_dk dk;
    uint8_t ct[CT_SIZE];
    uint8_t ct_modified[CT_SIZE];
    uint8_t K_sender[KEY_SIZE], K_receiver[KEY_SIZE];

    mlkem_keygen(&ek, &dk);
    mlkem_encaps(ct, K_sender, &ek);

    print_hex("Original ciphertext", ct, CT_SIZE);
    print_hex("Sender's key", K_sender, KEY_SIZE);
    printf("\n");

    /* Attacker modifies ciphertext */
    memcpy(ct_modified, ct, CT_SIZE);
    ct_modified[0] ^= 0x01;  /* Flip one bit */
    print_hex("Modified ciphertext", ct_modified, CT_SIZE);
    printf("(Attacker flipped bit 0)\n\n");

    /* Decapsulation of modified ciphertext */
    mlkem_decaps(K_receiver, ct_modified, &dk);
    print_hex("Receiver's key (from modified ct)", K_receiver, KEY_SIZE);
    printf("\n");

    /* Check result */
    if (memcmp(K_sender, K_receiver, KEY_SIZE) == 0) {
        printf("Keys match - ciphertext still valid?!\n");
    } else {
        printf("✓ Keys DO NOT MATCH - implicit rejection triggered\n");
        printf("  Attacker gets random-looking key, can't tell it's rejected\n");
    }
}

void demo_implicit_rejection_consistency(void) {
    printf("\n=== Implicit Rejection Consistency ===\n\n");

    mlkem_ek ek;
    mlkem_dk dk;
    uint8_t ct_garbage[CT_SIZE];
    uint8_t K1[KEY_SIZE], K2[KEY_SIZE];

    mlkem_keygen(&ek, &dk);

    /* Create garbage ciphertext */
    for (int i = 0; i < CT_SIZE; i++) {
        ct_garbage[i] = rand() & 0xFF;
    }
    print_hex("Garbage ciphertext", ct_garbage, CT_SIZE);

    /* Decapsulate same garbage twice */
    mlkem_decaps(K1, ct_garbage, &dk);
    mlkem_decaps(K2, ct_garbage, &dk);

    print_hex("First decaps result", K1, KEY_SIZE);
    print_hex("Second decaps result", K2, KEY_SIZE);

    if (memcmp(K1, K2, KEY_SIZE) == 0) {
        printf("\n✓ Same garbage → same key (deterministic rejection)\n");
        printf("  This is essential: attacker can't detect rejection\n");
        printf("  by querying same ciphertext multiple times\n");
    } else {
        printf("\n✗ ERROR: Different keys for same ciphertext!\n");
    }
}

int main(void) {
    /* Fixed default seed => reproducible teaching output; override with PQC_DEMO_SEED. */
    const char *demo_seed_env = getenv("PQC_DEMO_SEED");
    srand(demo_seed_env ? (unsigned)strtoul(demo_seed_env, NULL, 10) : 1234567u);

    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║  Unit 4.3: Fujisaki-Okamoto Transform                      ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n\n");

    demo_valid_encaps();
    demo_invalid_ciphertext();
    demo_implicit_rejection_consistency();

    printf("\n");
    printf("════════════════════════════════════════════════════════════\n");
    printf("Key Points:\n");
    printf("  1. FO transform: CPA encryption → CCA KEM\n");
    printf("  2. Re-encryption check detects tampering\n");
    printf("  3. Implicit rejection: invalid → random-looking key\n");
    printf("  4. Same invalid ct → same rejection key (consistent)\n");
    printf("  5. All comparisons must be constant-time\n");
    printf("════════════════════════════════════════════════════════════\n");

    return 0;
}
