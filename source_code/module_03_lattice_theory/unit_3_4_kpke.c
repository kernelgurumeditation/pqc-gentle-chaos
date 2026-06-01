/*
 * Source: PQC Learning Plan - Module 3: Lattice Cryptography Theory
 * Unit: 3.4 - From LWE to Public Key Encryption
 * Description: Module-LWE Public Key Encryption (K-PKE)
 *
 * This is an educational implementation - NOT for production use
 *
 * This implements the CPA-secure encryption underlying ML-KEM.
 * For CCA security, the FO transform must be applied (see Module 4).
 *
 * This program demonstrates:
 * - K-PKE key generation using Module-LWE
 * - IND-CPA secure encryption/decryption
 * - Message encoding/decoding for 256-bit messages
 * - Malleability attack (why CPA-only is insufficient)
 * - Key and ciphertext size analysis
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* Parameters for ML-KEM-768-like scheme */
#define N 256           /* Polynomial degree */
#define K 3             /* Module dimension */
#define Q 3329          /* Modulus */
#define ETA1 2          /* Distribution parameter for keygen */
#define ETA2 2          /* Distribution parameter for encryption */

/* Sizes */
#define POLY_BYTES ((N * 12) / 8)           /* 384 bytes per polynomial */
#define POLYVEC_BYTES (K * POLY_BYTES)      /* 1152 bytes for k polynomials */
#define PK_BYTES (32 + POLYVEC_BYTES)       /* 1184 bytes public key */
#define SK_BYTES POLYVEC_BYTES              /* 1152 bytes secret key */
#define CT_U_BYTES ((K * N * 10) / 8)       /* 960 bytes for compressed u */
#define CT_V_BYTES ((N * 4) / 8)            /* 128 bytes for compressed v */
#define CT_BYTES (CT_U_BYTES + CT_V_BYTES)  /* 1088 bytes ciphertext */

/* Polynomial type */
typedef struct {
    int16_t coeffs[N];
} poly;

/* Vector of polynomials */
typedef struct {
    poly vec[K];
} polyvec;

/*
 * Reduce a coefficient modulo Q to range [0, Q-1]
 */
static int16_t mod_q(int64_t a) {
    int16_t r = (int16_t)(a % Q);
    if (r < 0) r += Q;
    return r;
}

/*
 * Centered reduction: map to range [-(Q-1)/2, (Q-1)/2]
 */
static int16_t cmod_q(int16_t a) {
    a = mod_q(a);
    if (a > Q/2) a -= Q;
    return a;
}

/*
 * Sample from centered binomial distribution CBD_eta
 * Uses rejection-free sampling: sum of eta coin flips minus sum of eta coin flips
 */
static int16_t sample_cbd(int eta, uint8_t *random_bytes, int *byte_offset) {
    int a = 0, b = 0;

    for (int i = 0; i < eta; i++) {
        /* Get random bits (simplified - real impl uses bit manipulation) */
        uint8_t byte = random_bytes[(*byte_offset)++];
        a += (byte & 1);
        b += ((byte >> 1) & 1);
    }

    return (int16_t)(a - b);
}

/*
 * Sample a polynomial with CBD distribution
 */
static void poly_sample_cbd(poly *p, int eta, uint8_t *seed, int nonce) {
    /* In real implementation: derive randomness from seed and nonce using XOF */
    /* Here we use simplified random bytes */
    uint8_t random_bytes[512];

    /* Fake randomness for demonstration */
    for (int i = 0; i < 512; i++) {
        random_bytes[i] = (seed[i % 32] ^ nonce ^ i) & 0xFF;
    }

    int offset = 0;
    for (int i = 0; i < N; i++) {
        p->coeffs[i] = sample_cbd(eta, random_bytes, &offset);
    }
}

/*
 * Sample a polyvec with CBD distribution
 */
static void polyvec_sample_cbd(polyvec *v, int eta, uint8_t *seed, int *nonce) {
    for (int i = 0; i < K; i++) {
        poly_sample_cbd(&v->vec[i], eta, seed, (*nonce)++);
    }
}

/*
 * Generate a random polynomial with coefficients in [0, Q-1]
 * (Used for matrix A generation)
 */
static void poly_sample_uniform(poly *p, uint8_t *seed, int i, int j) {
    /* XOF expansion of seed || i || j */
    /* Simplified: deterministic but "random-looking" */
    for (int k = 0; k < N; k++) {
        uint32_t val = seed[k % 32];
        val = val * 1103515245 + 12345 + i * 1000 + j * 100 + k;
        p->coeffs[k] = mod_q(val);
    }
}

/*
 * Generate matrix A from seed (A-hat in NTT domain in real implementation)
 */
static void matrix_generate(poly A[K][K], uint8_t *seed) {
    for (int i = 0; i < K; i++) {
        for (int j = 0; j < K; j++) {
            poly_sample_uniform(&A[i][j], seed, i, j);
        }
    }
}

/*
 * Polynomial addition: r = a + b
 */
static void poly_add(poly *r, const poly *a, const poly *b) {
    for (int i = 0; i < N; i++) {
        r->coeffs[i] = mod_q(a->coeffs[i] + b->coeffs[i]);
    }
}

/*
 * Polynomial subtraction: r = a - b
 */
static void poly_sub(poly *r, const poly *a, const poly *b) {
    for (int i = 0; i < N; i++) {
        r->coeffs[i] = mod_q(a->coeffs[i] - b->coeffs[i]);
    }
}

/*
 * Polynomial multiplication in Rq = Zq[X]/(X^n + 1)
 * Schoolbook algorithm (O(n²)) - real implementations use NTT
 */
static void poly_mul(poly *r, const poly *a, const poly *b) {
    int64_t temp[2 * N] = {0};

    /* Standard polynomial multiplication */
    for (int i = 0; i < N; i++) {
        for (int j = 0; j < N; j++) {
            temp[i + j] += (int64_t)a->coeffs[i] * b->coeffs[j];
        }
    }

    /* Reduction modulo X^n + 1 */
    for (int i = 0; i < N; i++) {
        r->coeffs[i] = mod_q(temp[i] - temp[i + N]);
    }
}

/*
 * Polyvec addition: r = a + b
 */
static void polyvec_add(polyvec *r, const polyvec *a, const polyvec *b) {
    for (int i = 0; i < K; i++) {
        poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);
    }
}

/*
 * Inner product of two polyvecs: r = <a, b> = sum(a[i] * b[i])
 */
static void polyvec_inner_product(poly *r, const polyvec *a, const polyvec *b) {
    poly temp;

    /* Initialize result to zero */
    for (int i = 0; i < N; i++) {
        r->coeffs[i] = 0;
    }

    /* Accumulate a[i] * b[i] */
    for (int i = 0; i < K; i++) {
        poly_mul(&temp, &a->vec[i], &b->vec[i]);
        poly_add(r, r, &temp);
    }
}

/*
 * Matrix-vector product: r = A * v
 */
static void matrix_vec_mul(polyvec *r, const poly A[K][K], const polyvec *v) {
    poly temp;

    for (int i = 0; i < K; i++) {
        /* r[i] = sum_j A[i][j] * v[j] */
        for (int j = 0; j < N; j++) {
            r->vec[i].coeffs[j] = 0;
        }

        for (int j = 0; j < K; j++) {
            poly_mul(&temp, &A[i][j], &v->vec[j]);
            poly_add(&r->vec[i], &r->vec[i], &temp);
        }
    }
}

/*
 * Transpose matrix-vector product: r = A^T * v
 */
static void matrix_transpose_vec_mul(polyvec *r, const poly A[K][K], const polyvec *v) {
    poly temp;

    for (int i = 0; i < K; i++) {
        /* r[i] = sum_j A[j][i] * v[j] */
        for (int j = 0; j < N; j++) {
            r->vec[i].coeffs[j] = 0;
        }

        for (int j = 0; j < K; j++) {
            poly_mul(&temp, &A[j][i], &v->vec[j]);
            poly_add(&r->vec[i], &r->vec[i], &temp);
        }
    }
}

/*
 * Encode message: map 256 bits to polynomial
 * Each bit b maps to coefficient b * floor(Q/2)
 */
static void message_encode(poly *r, const uint8_t msg[32]) {
    int16_t scale = (Q + 1) / 2;  /* ceil(Q/2) = 1665 for Q=3329 */

    for (int i = 0; i < N; i++) {
        int byte_idx = i / 8;
        int bit_idx = i % 8;
        int bit = (msg[byte_idx] >> bit_idx) & 1;
        r->coeffs[i] = bit ? scale : 0;
    }
}

/*
 * Decode polynomial to message
 * Coefficient closer to 0 → bit 0
 * Coefficient closer to Q/2 → bit 1
 */
static void message_decode(uint8_t msg[32], const poly *p) {
    memset(msg, 0, 32);

    for (int i = 0; i < N; i++) {
        /* Centered coefficient in [-Q/2, Q/2) */
        int16_t c = cmod_q(p->coeffs[i]);

        /* Distance to 0 vs distance to Q/2 */
        int16_t dist_0 = (c < 0) ? -c : c;
        int16_t dist_half = (c < 0) ? (Q/2 + c) : (Q/2 - c);
        if (dist_half < 0) dist_half = -dist_half;

        /* Decode bit */
        int bit = (dist_half < dist_0) ? 1 : 0;

        /* Set bit in message */
        int byte_idx = i / 8;
        int bit_idx = i % 8;
        msg[byte_idx] |= (bit << bit_idx);
    }
}

/*
 * K-PKE Key Generation
 * Generates public key pk and secret key sk
 */
void kpke_keygen(uint8_t seed[32], polyvec *pk_t, polyvec *sk_s) {
    poly A[K][K];
    polyvec e;
    int nonce = 0;

    /* Generate matrix A from seed */
    matrix_generate(A, seed);

    /* Sample secret s from CBD */
    polyvec_sample_cbd(sk_s, ETA1, seed, &nonce);

    /* Sample error e from CBD */
    polyvec_sample_cbd(&e, ETA1, seed, &nonce);

    /* Compute t = A*s + e */
    matrix_vec_mul(pk_t, A, sk_s);
    polyvec_add(pk_t, pk_t, &e);

    printf("K-PKE KeyGen complete\n");
    printf("  Secret key s[0][0..3]: %d, %d, %d, %d\n",
           sk_s->vec[0].coeffs[0], sk_s->vec[0].coeffs[1],
           sk_s->vec[0].coeffs[2], sk_s->vec[0].coeffs[3]);
    printf("  Public key t[0][0..3]: %d, %d, %d, %d\n",
           pk_t->vec[0].coeffs[0], pk_t->vec[0].coeffs[1],
           pk_t->vec[0].coeffs[2], pk_t->vec[0].coeffs[3]);
}

/*
 * K-PKE Encryption
 * Encrypts 32-byte message to ciphertext (u, v)
 */
void kpke_encrypt(const uint8_t seed[32], const polyvec *pk_t,
                  const uint8_t msg[32], const uint8_t coins[32],
                  polyvec *ct_u, poly *ct_v) {
    poly A[K][K];
    polyvec r, e1;
    poly e2, mu;
    int nonce = 0;

    /* Regenerate matrix A from seed */
    matrix_generate(A, (uint8_t*)seed);

    /* Sample encryption randomness from coins */
    polyvec_sample_cbd(&r, ETA1, (uint8_t*)coins, &nonce);
    polyvec_sample_cbd(&e1, ETA2, (uint8_t*)coins, &nonce);
    poly_sample_cbd(&e2, ETA2, (uint8_t*)coins, nonce);

    /* Encode message */
    message_encode(&mu, msg);

    /* Compute u = A^T * r + e1 */
    matrix_transpose_vec_mul(ct_u, A, &r);
    polyvec_add(ct_u, ct_u, &e1);

    /* Compute v = t^T * r + e2 + mu */
    polyvec_inner_product(ct_v, pk_t, &r);
    poly_add(ct_v, ct_v, &e2);
    poly_add(ct_v, ct_v, &mu);

    printf("K-PKE Encrypt complete\n");
    printf("  Ciphertext u[0][0..3]: %d, %d, %d, %d\n",
           ct_u->vec[0].coeffs[0], ct_u->vec[0].coeffs[1],
           ct_u->vec[0].coeffs[2], ct_u->vec[0].coeffs[3]);
    printf("  Ciphertext v[0..3]: %d, %d, %d, %d\n",
           ct_v->coeffs[0], ct_v->coeffs[1],
           ct_v->coeffs[2], ct_v->coeffs[3]);
}

/*
 * K-PKE Decryption
 * Decrypts ciphertext (u, v) to 32-byte message
 */
void kpke_decrypt(const polyvec *sk_s, const polyvec *ct_u, const poly *ct_v,
                  uint8_t msg[32]) {
    poly temp, result;

    /* Compute s^T * u */
    polyvec_inner_product(&temp, sk_s, ct_u);

    /* Compute v - s^T * u */
    poly_sub(&result, ct_v, &temp);

    /* Decode message */
    message_decode(msg, &result);

    printf("K-PKE Decrypt complete\n");
    printf("  Intermediate v - s^T*u [0..3]: %d, %d, %d, %d\n",
           result.coeffs[0], result.coeffs[1],
           result.coeffs[2], result.coeffs[3]);
}

/*
 * Demonstrate CPA security limitation
 */
void demonstrate_malleability(void) {
    printf("\n=== Demonstrating CPA-Only Limitation (Malleability) ===\n\n");

    uint8_t seed[32] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
                        17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};
    uint8_t coins[32] = {0};  /* Fixed randomness for reproducibility */

    /* Key generation */
    polyvec pk_t, sk_s;
    kpke_keygen(seed, &pk_t, &sk_s);

    /* Original message */
    uint8_t msg[32] = {0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89};
    printf("\nOriginal message (first 8 bytes): ");
    for (int i = 0; i < 8; i++) printf("%02X ", msg[i]);
    printf("\n");

    /* Encrypt */
    polyvec ct_u;
    poly ct_v;
    kpke_encrypt(seed, &pk_t, msg, coins, &ct_u, &ct_v);

    /* Decrypt to verify */
    uint8_t decrypted[32];
    kpke_decrypt(&sk_s, &ct_u, &ct_v, decrypted);
    printf("Decrypted message (first 8 bytes): ");
    for (int i = 0; i < 8; i++) printf("%02X ", decrypted[i]);
    printf("\n");

    /* === ATTACK: Modify ciphertext to flip a bit === */
    printf("\n--- Malleability Attack ---\n");
    printf("Attacker modifies ciphertext to flip bit 0...\n");

    /* Create modification polynomial: flip coefficient 0 */
    poly delta;
    for (int i = 0; i < N; i++) delta.coeffs[i] = 0;
    delta.coeffs[0] = (Q + 1) / 2;  /* Add Q/2 to flip bit 0 */

    /* Modified ciphertext: v' = v + delta */
    poly modified_v;
    poly_add(&modified_v, &ct_v, &delta);

    /* Decrypt modified ciphertext */
    uint8_t attacked[32];
    kpke_decrypt(&sk_s, &ct_u, &modified_v, attacked);

    printf("Decrypted modified ciphertext: ");
    for (int i = 0; i < 8; i++) printf("%02X ", attacked[i]);
    printf("\n");

    /* Show the attack worked */
    printf("\nOriginal byte 0: 0x%02X = %d%d%d%d%d%d%d%db\n",
           msg[0],
           (msg[0]>>7)&1, (msg[0]>>6)&1, (msg[0]>>5)&1, (msg[0]>>4)&1,
           (msg[0]>>3)&1, (msg[0]>>2)&1, (msg[0]>>1)&1, msg[0]&1);
    printf("Attacked byte 0: 0x%02X = %d%d%d%d%d%d%d%db\n",
           attacked[0],
           (attacked[0]>>7)&1, (attacked[0]>>6)&1, (attacked[0]>>5)&1, (attacked[0]>>4)&1,
           (attacked[0]>>3)&1, (attacked[0]>>2)&1, (attacked[0]>>1)&1, attacked[0]&1);
    printf("Bit 0 was flipped: %d → %d\n", msg[0]&1, attacked[0]&1);

    printf("\n*** This attack is why we need the FO transform for CCA security! ***\n");
}

/*
 * Main demonstration
 */
int main(void) {
    printf("=== Module-LWE Public Key Encryption (K-PKE) ===\n\n");

    /* === Basic encryption/decryption test === */
    printf("--- Basic Encryption/Decryption Test ---\n\n");

    uint8_t seed[32] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
                        17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};
    uint8_t coins[32] = {0};

    /* Key generation */
    polyvec pk_t, sk_s;
    kpke_keygen(seed, &pk_t, &sk_s);

    /* Test message */
    uint8_t original[32] = "Hello, Post-Quantum World!!";
    printf("\nOriginal message: \"%s\"\n", original);
    printf("  Hex: ");
    for (int i = 0; i < 32; i++) printf("%02X", original[i]);
    printf("\n");

    /* Encrypt */
    polyvec ct_u;
    poly ct_v;
    kpke_encrypt(seed, &pk_t, original, coins, &ct_u, &ct_v);

    /* Decrypt */
    uint8_t recovered[32];
    kpke_decrypt(&sk_s, &ct_u, &ct_v, recovered);

    printf("\nRecovered message: \"%s\"\n", recovered);
    printf("  Hex: ");
    for (int i = 0; i < 32; i++) printf("%02X", recovered[i]);
    printf("\n");

    /* Verify correctness */
    int correct = 1;
    for (int i = 0; i < 32; i++) {
        if (original[i] != recovered[i]) {
            correct = 0;
            break;
        }
    }
    printf("\nDecryption %s!\n", correct ? "CORRECT" : "FAILED");

    /* === Demonstrate malleability attack === */
    demonstrate_malleability();

    /* === Size summary === */
    printf("\n=== K-PKE Size Summary (ML-KEM-768-like) ===\n");
    printf("Public key:  %d bytes (32 seed + %d for t)\n",
           PK_BYTES, POLYVEC_BYTES);
    printf("Secret key:  %d bytes (s vector)\n", SK_BYTES);
    printf("Ciphertext:  %d bytes (%d for u + %d for v)\n",
           CT_BYTES, CT_U_BYTES, CT_V_BYTES);
    printf("Message:     32 bytes (256 bits)\n");

    printf("\nNote: Real ML-KEM uses compression to achieve these sizes.\n");
    printf("This educational implementation doesn't include compression.\n");

    /* Explicit success/failure verdict: the basic encrypt/decrypt round-trip MUST
     * recover the original message for the fixed seed/coins. (The malleability
     * section above is an intentional attack demo, not a correctness failure.) */
    printf("\n=== RESULT: %s ===\n", correct ? "PASS" : "FAIL");
    return correct ? 0 : 1;
}
