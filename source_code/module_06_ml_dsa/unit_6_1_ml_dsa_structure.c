/*
 * Source: Module 6, Unit 6.1 - ML-DSA Structure and Security Model
 * From: PQC Learning Plan, lines 14473-14754
 *
 * ML-DSA Structure Demonstration
 * This code illustrates the data structures and flow of ML-DSA
 * NOT a secure implementation - for educational purposes only
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* ML-DSA-65 parameters */
#define MLDSA_N 256
#define MLDSA_Q 8380417
#define MLDSA_K 6
#define MLDSA_L 5
#define MLDSA_ETA 4
#define MLDSA_GAMMA1 (1 << 19)  /* 2^19 */
#define MLDSA_GAMMA2 ((MLDSA_Q - 1) / 32)
#define MLDSA_TAU 49
#define MLDSA_BETA (MLDSA_TAU * MLDSA_ETA)
#define MLDSA_OMEGA 55
#define MLDSA_D 13

/* Polynomial in Rq */
typedef struct {
    int32_t coeffs[MLDSA_N];
} poly;

/* Vector of polynomials */
typedef struct {
    poly vec[MLDSA_L];
} polyvecl;

typedef struct {
    poly vec[MLDSA_K];
} polyveck;

/* Public key structure */
typedef struct {
    uint8_t rho[32];           /* Seed for matrix A */
    polyveck t1;               /* High bits of t */
} mldsa_pk;

/* Secret key structure */
typedef struct {
    uint8_t rho[32];           /* Seed for matrix A */
    uint8_t K[32];             /* Signing key seed */
    uint8_t tr[64];            /* H(pk) - public key hash */
    polyvecl s1;               /* Secret vector s1 */
    polyveck s2;               /* Secret vector s2 */
    polyveck t0;               /* Low bits of t */
} mldsa_sk;

/* Signature structure */
typedef struct {
    uint8_t c_tilde[48];       /* Challenge hash */
    polyvecl z;                /* Response vector */
    uint8_t h[MLDSA_OMEGA + MLDSA_K];  /* Hint */
} mldsa_sig;

/* Reduce coefficient to range [0, q) */
int32_t mod_q(int32_t a) {
    a = a % MLDSA_Q;
    if (a < 0) a += MLDSA_Q;
    return a;
}

/* Check if polynomial has coefficients bounded by B */
int poly_check_bound(const poly *p, int32_t bound) {
    for (int i = 0; i < MLDSA_N; i++) {
        int32_t c = p->coeffs[i];
        /* Reduce to centered representation */
        if (c > MLDSA_Q/2) c -= MLDSA_Q;
        if (c < -bound || c > bound) {
            return 0;  /* Exceeds bound */
        }
    }
    return 1;  /* Within bound */
}

/* Check if vector has coefficients bounded by B */
int polyvecl_check_bound(const polyvecl *v, int32_t bound) {
    for (int i = 0; i < MLDSA_L; i++) {
        if (!poly_check_bound(&v->vec[i], bound)) {
            return 0;
        }
    }
    return 1;
}

/* High bits: returns high part of decomposition */
int32_t highbits(int32_t r, int32_t alpha) {
    int32_t r_plus = r % MLDSA_Q;
    if (r_plus < 0) r_plus += MLDSA_Q;

    /* Center r in (-q/2, q/2] */
    int32_t r_centered = r_plus;
    if (r_centered > MLDSA_Q/2) r_centered -= MLDSA_Q;

    /* Compute r1 = high bits */
    int32_t r1 = (r_plus + alpha/2) / alpha;

    /* Handle wrap-around */
    if (r1 == (MLDSA_Q - 1) / alpha + 1) r1 = 0;

    return r1;
}

/* Low bits: returns low part of decomposition */
int32_t lowbits(int32_t r, int32_t alpha) {
    int32_t r1 = highbits(r, alpha);
    int32_t r0 = r - r1 * alpha;

    /* Center r0 */
    if (r0 > alpha/2) r0 -= alpha;
    if (r0 < -alpha/2) r0 += alpha;

    return r0;
}

/* MakeHint: compute hint bit */
int makehint(int32_t z, int32_t r) {
    int32_t r1 = highbits(r, 2 * MLDSA_GAMMA2);
    int32_t v1 = highbits(r + z, 2 * MLDSA_GAMMA2);
    return (r1 != v1) ? 1 : 0;
}

/* UseHint: recover high bits using hint */
int32_t usehint(int hint, int32_t r) {
    int32_t m = (MLDSA_Q - 1) / (2 * MLDSA_GAMMA2);
    int32_t r1 = highbits(r, 2 * MLDSA_GAMMA2);
    int32_t r0 = lowbits(r, 2 * MLDSA_GAMMA2);

    if (hint == 0) {
        return r1;
    }

    if (r0 > 0) {
        return (r1 + 1) % m;
    } else {
        return (r1 - 1 + m) % m;
    }
}

/* Demonstration: Print parameter info */
void print_parameters(void) {
    printf("ML-DSA-65 Parameters:\n");
    printf("=====================\n");
    printf("Ring dimension n = %d\n", MLDSA_N);
    printf("Modulus q = %d (= 2^23 - 2^13 + 1)\n", MLDSA_Q);
    printf("Matrix dimensions (k, l) = (%d, %d)\n", MLDSA_K, MLDSA_L);
    printf("Secret coefficient bound η = %d\n", MLDSA_ETA);
    printf("Masking bound γ1 = %d (= 2^19)\n", MLDSA_GAMMA1);
    printf("Decomposition γ2 = %d (= (q-1)/32)\n", MLDSA_GAMMA2);
    printf("Challenge weight τ = %d\n", MLDSA_TAU);
    printf("Rejection bound β = τ·η = %d\n", MLDSA_BETA);
    printf("Max hint weight ω = %d\n", MLDSA_OMEGA);
    printf("Dropped bits d = %d\n", MLDSA_D);
    printf("\n");

    /* Size calculations */
    size_t pk_size = 32 + (MLDSA_K * MLDSA_N * 10) / 8;  /* 10 bits per t1 coeff */
    size_t sk_size = 32 + 32 + 64 +
                     (MLDSA_L * MLDSA_N * 4) / 8 +   /* s1: 4 bits per coeff */
                     (MLDSA_K * MLDSA_N * 4) / 8 +   /* s2: 4 bits per coeff */
                     (MLDSA_K * MLDSA_N * 13) / 8;   /* t0: 13 bits per coeff */
    size_t sig_size = 48 + (MLDSA_L * MLDSA_N * 20) / 8 + MLDSA_OMEGA + MLDSA_K;

    printf("Approximate sizes:\n");
    printf("  Public key:  ~%zu bytes\n", pk_size);
    printf("  Secret key:  ~%zu bytes\n", sk_size);
    printf("  Signature:   ~%zu bytes\n", sig_size);
}

/* Demonstration: Show decomposition */
void demo_decomposition(void) {
    printf("\nDecomposition Demo:\n");
    printf("===================\n");

    int32_t alpha = 2 * MLDSA_GAMMA2;
    printf("Using α = 2·γ2 = %d\n\n", alpha);

    int32_t test_values[] = {0, 100000, 1000000, 4000000, 8000000};

    for (int i = 0; i < 5; i++) {
        int32_t r = test_values[i];
        int32_t r1 = highbits(r, alpha);
        int32_t r0 = lowbits(r, alpha);

        printf("r = %8d: r1 (high) = %3d, r0 (low) = %8d\n", r, r1, r0);
        printf("  Verify: r1·α + r0 = %d·%d + %d = %d %s\n",
               r1, alpha, r0, r1 * alpha + r0,
               (mod_q(r1 * alpha + r0) == mod_q(r)) ? "✓" : "✗");
    }
}

/* Demonstration: Show hint mechanism */
void demo_hint(void) {
    printf("\nHint Mechanism Demo:\n");
    printf("====================\n");

    /* Hint is used when the verifier computes A·z - c·t1·2^d
     * which equals A·y - c·s2 + c·t0 (approximately)
     * The hint helps recover HighBits(A·y) from this value
     */

    printf("The hint encodes when adding a value changes the high bits.\n\n");

    int32_t r = 260000;  /* Some value */
    int32_t z_values[] = {0, 10000, 50000, -30000, -80000};

    printf("Base value r = %d\n", r);
    printf("HighBits(r) = %d\n\n", highbits(r, 2 * MLDSA_GAMMA2));

    for (int i = 0; i < 5; i++) {
        int32_t z = z_values[i];
        int h = makehint(z, r);
        int32_t r1_original = highbits(r, 2 * MLDSA_GAMMA2);
        int32_t r1_summed = highbits(r + z, 2 * MLDSA_GAMMA2);
        int32_t r1_recovered = usehint(h, r + z);

        printf("z = %7d: hint = %d, HighBits(r) = %d, HighBits(r+z) = %d, UseHint = %d\n",
               z, h, r1_original, r1_summed, r1_recovered);
    }
}

/* Demonstration: Rejection bound checking */
void demo_rejection_bounds(void) {
    printf("\nRejection Bound Demo:\n");
    printf("=====================\n");

    printf("In ML-DSA signing:\n");
    printf("1. Sample masking y with coefficients < γ1 = %d\n", MLDSA_GAMMA1);
    printf("2. Compute z = y + c·s1\n");
    printf("3. Reject if any coefficient of z has |z_i| ≥ γ1 - β = %d\n",
           MLDSA_GAMMA1 - MLDSA_BETA);
    printf("\n");

    printf("Why γ1 - β?\n");
    printf("  - s1 coefficients: |s1_i| ≤ η = %d\n", MLDSA_ETA);
    printf("  - Challenge c has τ = %d non-zero (±1) coefficients\n", MLDSA_TAU);
    printf("  - Product c·s1 has coefficients bounded by ~τ·η = β = %d\n", MLDSA_BETA);
    printf("  - If y_i ∈ [-(γ1-1), γ1-1], then z_i could be as large as γ1-1+β\n");
    printf("  - Rejection threshold γ1-β ensures z reveals nothing about s1\n");
    printf("\n");

    printf("Expected rejection probability: ~1/M where M ≈ 4-7\n");
    printf("This means ~4-7 loop iterations on average per signature.\n");
}

int main(void) {
    print_parameters();
    demo_decomposition();
    demo_hint();
    demo_rejection_bounds();

    printf("\n");
    printf("Key Structure Sizes (ML-DSA-65):\n");
    printf("================================\n");
    printf("Public key (pk):\n");
    printf("  - rho:  32 bytes (seed for A)\n");
    printf("  - t1:   %d polynomials × 10 bits × 256 coeffs / 8 = %d bytes\n",
           MLDSA_K, MLDSA_K * 256 * 10 / 8);
    printf("\n");
    printf("Secret key (sk):\n");
    printf("  - rho:  32 bytes\n");
    printf("  - K:    32 bytes (signing key seed)\n");
    printf("  - tr:   64 bytes (H(pk))\n");
    printf("  - s1:   %d polynomials (small coefficients)\n", MLDSA_L);
    printf("  - s2:   %d polynomials (small coefficients)\n", MLDSA_K);
    printf("  - t0:   %d polynomials (low bits of t)\n", MLDSA_K);
    printf("\n");
    printf("Signature (σ):\n");
    printf("  - c̃:    48 bytes (challenge hash)\n");
    printf("  - z:    %d polynomials × 20 bits × 256 coeffs / 8 = %d bytes\n",
           MLDSA_L, MLDSA_L * 256 * 20 / 8);
    printf("  - h:    ≤ ω + k = %d + %d = %d bytes\n",
           MLDSA_OMEGA, MLDSA_K, MLDSA_OMEGA + MLDSA_K);

    return 0;
}
