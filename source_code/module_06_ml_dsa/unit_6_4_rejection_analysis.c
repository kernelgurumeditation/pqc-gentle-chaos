#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <math.h>

/*
 * ML-DSA Rejection Sampling Analysis Demo
 *
 * This demonstrates the rejection sampling statistics during signing.
 * ML-DSA uses rejection sampling to ensure signatures don't leak
 * information about the secret key.
 */

/* ML-DSA-65 parameters */
#define N 256
#define Q 8380417
#define K 6
#define L 5
#define GAMMA1 (1 << 19)  /* 2^19 = 524288 */
#define GAMMA2 ((Q - 1) / 32)  /* ≈ 261888 */
#define BETA 196  /* tau * eta = 49 * 4 for ML-DSA-65 */
#define TAU 49
#define ETA 4
#define OMEGA 55

/* Polynomial and vector types */
typedef struct { int32_t coeffs[N]; } poly;
typedef struct { poly vec[L]; } polyvecl;
typedef struct { poly vec[K]; } polyveck;

/* Simple PRNG for simulation */
static uint64_t prng_state = 1;

static void prng_seed(uint64_t seed) {
    prng_state = seed ? seed : 1;
}

static int32_t prng_uniform(int32_t range) {
    prng_state ^= prng_state >> 12;
    prng_state ^= prng_state << 25;
    prng_state ^= prng_state >> 27;
    uint64_t r = prng_state * 0x2545F4914F6CDD1DULL;
    return (int32_t)((r >> 33) % (uint64_t)range);
}

/* Sample uniform in [-gamma1+1, gamma1] */
static void sample_y_coeff(int32_t *c) {
    *c = prng_uniform(2 * GAMMA1) - GAMMA1 + 1;
}

/* Sample small coefficient in [-eta, eta] */
static void sample_small(int32_t *c) {
    *c = prng_uniform(2 * ETA + 1) - ETA;
}

/* Sample challenge polynomial with TAU nonzero coefficients in {-1, 1} */
static void sample_challenge(poly *c) {
    memset(c->coeffs, 0, sizeof(c->coeffs));
    int count = 0;
    while (count < TAU) {
        int pos = prng_uniform(N);
        if (c->coeffs[pos] == 0) {
            c->coeffs[pos] = (prng_uniform(2) == 0) ? 1 : -1;
            count++;
        }
    }
}

/* Check infinity norm of polynomial */
static int check_norm(const poly *p, int32_t bound) {
    for (int i = 0; i < N; i++) {
        int32_t c = p->coeffs[i];
        if (c < 0) c = -c;
        if (c >= bound) return 0;
    }
    return 1;
}

/* Check infinity norm of vector */
static int check_vecl_norm(const polyvecl *v, int32_t bound) {
    for (int i = 0; i < L; i++) {
        if (!check_norm(&v->vec[i], bound)) return 0;
    }
    return 1;
}

static int check_veck_norm(const polyveck *v, int32_t bound) {
    for (int i = 0; i < K; i++) {
        if (!check_norm(&v->vec[i], bound)) return 0;
    }
    return 1;
}

/* Generate random small vector */
static void sample_small_vecl(polyvecl *s) {
    for (int i = 0; i < L; i++) {
        for (int j = 0; j < N; j++) {
            sample_small(&s->vec[i].coeffs[j]);
        }
    }
}

static void sample_small_veck(polyveck *s) {
    for (int i = 0; i < K; i++) {
        for (int j = 0; j < N; j++) {
            sample_small(&s->vec[i].coeffs[j]);
        }
    }
}

/* Sample masking vector y */
static void sample_y(polyvecl *y) {
    for (int i = 0; i < L; i++) {
        for (int j = 0; j < N; j++) {
            sample_y_coeff(&y->vec[i].coeffs[j]);
        }
    }
}

/* Multiply polynomial by challenge (simplified) */
static void poly_challenge_mul(poly *r, const poly *c, const poly *s) {
    int64_t temp[N] = {0};

    for (int i = 0; i < N; i++) {
        if (c->coeffs[i] != 0) {
            for (int j = 0; j < N; j++) {
                int k = (i + j) % N;
                int64_t prod = (int64_t)c->coeffs[i] * s->coeffs[j];
                if (i + j >= N) prod = -prod;  /* X^N = -1 */
                temp[k] += prod;
            }
        }
    }

    for (int i = 0; i < N; i++) {
        int64_t t = temp[i] % Q;
        if (t < 0) t += Q;
        if (t > Q/2) t -= Q;
        r->coeffs[i] = (int32_t)t;
    }
}

/* Add vectors */
static void polyvecl_add(polyvecl *r, const polyvecl *a, const polyvecl *b) {
    for (int i = 0; i < L; i++) {
        for (int j = 0; j < N; j++) {
            int64_t sum = (int64_t)a->vec[i].coeffs[j] + b->vec[i].coeffs[j];
            sum %= Q;
            if (sum < 0) sum += Q;
            if (sum > Q/2) sum -= Q;
            r->vec[i].coeffs[j] = (int32_t)sum;
        }
    }
}

/* Simulate one signing attempt */
typedef struct {
    int rejected_check1;  /* z norm too large */
    int rejected_check2;  /* r0 norm too large */
    int rejected_check3;  /* ct0 norm too large */
    int rejected_check4;  /* hint weight too high */
    int success;
} attempt_result;

static attempt_result simulate_signing_attempt(
    const polyvecl *s1,
    const polyveck *s2,
    const polyveck *t0
) {
    attempt_result result = {0, 0, 0, 0, 0};

    /* Sample masking y */
    polyvecl y;
    sample_y(&y);

    /* Sample random challenge */
    poly c;
    sample_challenge(&c);

    /* Compute z = y + c*s1 */
    polyvecl cs1, z;
    for (int i = 0; i < L; i++) {
        poly_challenge_mul(&cs1.vec[i], &c, &s1->vec[i]);
    }
    polyvecl_add(&z, &y, &cs1);

    /* Check 1: ||z||_∞ < γ1 - β */
    if (!check_vecl_norm(&z, GAMMA1 - BETA)) {
        result.rejected_check1 = 1;
        return result;
    }

    /* For checks 2-4, we simulate with simplified approximations */

    /* Check 2: ||LowBits(w - c*s2)||_∞ < γ2 - β */
    polyveck cs2;
    for (int i = 0; i < K; i++) {
        poly_challenge_mul(&cs2.vec[i], &c, &s2->vec[i]);
    }
    if (!check_veck_norm(&cs2, GAMMA2 - BETA)) {
        result.rejected_check2 = 1;
        return result;
    }

    /* Check 3: ||c*t0||_∞ < γ2 */
    polyveck ct0;
    for (int i = 0; i < K; i++) {
        poly_challenge_mul(&ct0.vec[i], &c, &t0->vec[i]);
    }
    if (!check_veck_norm(&ct0, GAMMA2)) {
        result.rejected_check3 = 1;
        return result;
    }

    /* Check 4: Hint weight ≤ ω (simplified) */
    int hint_estimate = 0;
    for (int i = 0; i < K; i++) {
        for (int j = 0; j < N; j++) {
            int32_t c0 = ct0.vec[i].coeffs[j];
            if (c0 < 0) c0 = -c0;
            if (c0 > GAMMA2 / 2) hint_estimate++;
        }
    }
    if (hint_estimate > OMEGA) {
        result.rejected_check4 = 1;
        return result;
    }

    result.success = 1;
    return result;
}

void analyze_rejection_distribution(void) {
    const int NUM_SIGNATURES = 100;
    const int MAX_ATTEMPTS = 50;

    /* Generate test secret key */
    polyvecl s1;
    polyveck s2, t0;

    sample_small_vecl(&s1);
    sample_small_veck(&s2);
    sample_small_veck(&t0);  /* Simplified: t0 should be from Power2Round */

    /* Statistics */
    int check1_rejects = 0;
    int check2_rejects = 0;
    int check3_rejects = 0;
    int check4_rejects = 0;
    int attempt_histogram[MAX_ATTEMPTS + 1];
    int total_attempts = 0;

    memset(attempt_histogram, 0, sizeof(attempt_histogram));

    printf("ML-DSA Rejection Sampling Analysis\n");
    printf("===================================\n\n");
    printf("Parameters (ML-DSA-65):\n");
    printf("  n = %d, k = %d, l = %d\n", N, K, L);
    printf("  γ1 = %d, γ2 = %d\n", GAMMA1, GAMMA2);
    printf("  β = %d, τ = %d, η = %d, ω = %d\n\n", BETA, TAU, ETA, OMEGA);
    printf("Simulating %d signature generations...\n\n", NUM_SIGNATURES);

    for (int sig = 0; sig < NUM_SIGNATURES; sig++) {
        int attempts = 0;

        while (attempts < MAX_ATTEMPTS) {
            attempts++;
            attempt_result r = simulate_signing_attempt(&s1, &s2, &t0);

            if (r.rejected_check1) check1_rejects++;
            else if (r.rejected_check2) check2_rejects++;
            else if (r.rejected_check3) check3_rejects++;
            else if (r.rejected_check4) check4_rejects++;
            else break;  /* Success */
        }

        total_attempts += attempts;
        if (attempts <= MAX_ATTEMPTS) {
            attempt_histogram[attempts]++;
        }
    }

    /* Report results */
    printf("=== Rejection Analysis Results ===\n\n");

    int total_rejects = check1_rejects + check2_rejects +
                        check3_rejects + check4_rejects;

    if (total_rejects > 0) {
        printf("Rejection breakdown:\n");
        printf("  Check 1 (z norm):    %4d (%5.1f%%)\n",
               check1_rejects, 100.0 * check1_rejects / total_rejects);
        printf("  Check 2 (r0 norm):   %4d (%5.1f%%)\n",
               check2_rejects, 100.0 * check2_rejects / total_rejects);
        printf("  Check 3 (ct0 norm):  %4d (%5.1f%%)\n",
               check3_rejects, 100.0 * check3_rejects / total_rejects);
        printf("  Check 4 (hint wt):   %4d (%5.1f%%)\n",
               check4_rejects, 100.0 * check4_rejects / total_rejects);
        printf("  Total rejections:    %4d\n\n", total_rejects);
    } else {
        printf("No rejections occurred (all first attempts succeeded)\n\n");
    }

    printf("Attempt distribution:\n");
    printf("  Average: %.2f attempts per signature\n",
           total_attempts / (double)NUM_SIGNATURES);
    printf("  Expected: ~4-5 attempts (from theory)\n\n");

    printf("  Attempts | Count | Histogram\n");
    printf("  ---------+-------+----------\n");
    for (int i = 1; i <= 10; i++) {
        printf("     %2d    |  %3d  | ", i, attempt_histogram[i]);
        for (int j = 0; j < attempt_histogram[i] && j < 40; j++) {
            printf("*");
        }
        printf("\n");
    }

    int overflow = 0;
    for (int i = 11; i <= MAX_ATTEMPTS; i++) {
        overflow += attempt_histogram[i];
    }
    if (overflow > 0) {
        printf("    >10    |  %3d  |\n", overflow);
    }

    /* Theoretical comparison */
    printf("\n=== Theoretical Analysis ===\n");
    double p_check1 = 1.0 - pow(1.0 - 2.0 * BETA / (2.0 * GAMMA1), L * N);
    printf("\nCheck 1 rejection probability (approximation):\n");
    printf("  P(||z||_∞ ≥ γ1 - β) ≈ 1 - (1 - 2β/2γ1)^(l*n)\n");
    printf("                      ≈ %.4f\n", p_check1);
    printf("\nNote: The full ML-DSA specification has more complex bounds.\n");
    printf("      This demo provides a simplified analysis.\n");
}

int main(void) {
    /* Fixed default seed => reproducible teaching output; override with
     * PQC_DEMO_SEED. */
    const char *demo_seed_env = getenv("PQC_DEMO_SEED");
    prng_seed(demo_seed_env ? (uint64_t)strtoul(demo_seed_env, NULL, 10)
                            : 1234567u);
    analyze_rejection_distribution();
    return 0;
}
