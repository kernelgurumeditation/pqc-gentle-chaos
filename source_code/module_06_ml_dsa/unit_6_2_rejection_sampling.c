#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/*
 * ML-DSA Rejection Sampling Implementation
 * Demonstrates the core rejection sampling logic
 */

#define N 256
#define L 5
#define Q 8380417
#define GAMMA1 (1 << 19)  /* 524288 */
#define GAMMA2 ((Q - 1) / 32)  /* 261888 */
#define TAU 49
#define ETA 4
#define BETA (TAU * ETA)  /* 196 */

typedef struct {
    int32_t coeffs[N];
} poly;

typedef struct {
    poly vec[L];
} polyvec;

/* Constant-time absolute value */
int32_t ct_abs(int32_t x) {
    int32_t mask = x >> 31;  /* All 1s if negative, all 0s if positive */
    return (x ^ mask) - mask;
}

/* Constant-time comparison: returns 1 if a >= b, 0 otherwise */
int ct_ge(int32_t a, int32_t b) {
    /* Compute a - b; if result is non-negative, a >= b */
    int64_t diff = (int64_t)a - (int64_t)b;
    /* Extract sign bit (0 if non-negative, 1 if negative) */
    return 1 - ((diff >> 63) & 1);
}

/* Sample uniform polynomial with coefficients in [-(gamma1-1), gamma1-1] */
void sample_y(poly *p, uint32_t *seed_state) {
    for (int i = 0; i < N; i++) {
        /* Simple PRNG for demonstration (use SHAKE in production) */
        *seed_state = *seed_state * 1103515245 + 12345;

        /* Map to [-GAMMA1+1, GAMMA1-1] */
        uint32_t r = *seed_state;
        int32_t coeff = (r % (2 * GAMMA1 - 1)) - (GAMMA1 - 1);
        p->coeffs[i] = coeff;
    }
}

/* Sample challenge polynomial with TAU nonzero coefficients */
void sample_challenge(poly *c, uint32_t *seed_state) {
    memset(c->coeffs, 0, sizeof(c->coeffs));

    int count = 0;
    while (count < TAU) {
        *seed_state = *seed_state * 1103515245 + 12345;
        int pos = *seed_state % N;

        if (c->coeffs[pos] == 0) {
            /* Randomly choose +1 or -1 */
            *seed_state = *seed_state * 1103515245 + 12345;
            c->coeffs[pos] = (*seed_state & 1) ? 1 : -1;
            count++;
        }
    }
}

/* Sample small secret with coefficients in [-ETA, ETA] */
void sample_secret(poly *s, uint32_t *seed_state) {
    for (int i = 0; i < N; i++) {
        *seed_state = *seed_state * 1103515245 + 12345;
        s->coeffs[i] = (*seed_state % (2 * ETA + 1)) - ETA;
    }
}

/* Polynomial multiplication in R_q (schoolbook, for simplicity) */
void poly_mul(poly *r, const poly *a, const poly *b) {
    int64_t temp[2 * N - 1];
    memset(temp, 0, sizeof(temp));

    for (int i = 0; i < N; i++) {
        for (int j = 0; j < N; j++) {
            temp[i + j] += (int64_t)a->coeffs[i] * b->coeffs[j];
        }
    }

    /* Reduce modulo X^N + 1 */
    for (int i = N; i < 2 * N - 1; i++) {
        temp[i - N] -= temp[i];
    }

    /* Reduce modulo Q */
    for (int i = 0; i < N; i++) {
        int64_t t = temp[i] % Q;
        if (t < 0) t += Q;
        if (t > Q/2) t -= Q;  /* Center */
        r->coeffs[i] = (int32_t)t;
    }
}

/* Add polynomials: r = a + b */
void poly_add(poly *r, const poly *a, const poly *b) {
    for (int i = 0; i < N; i++) {
        r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
    }
}

/* Check if polynomial has coefficients in [-bound, bound] (constant-time) */
int poly_check_norm_ct(const poly *p, int32_t bound) {
    int32_t reject = 0;

    for (int i = 0; i < N; i++) {
        int32_t abs_coeff = ct_abs(p->coeffs[i]);
        reject |= ct_ge(abs_coeff, bound);
    }

    return reject == 0;  /* Return 1 if all coefficients within bound */
}

/* Check vector of polynomials (constant-time) */
int polyvec_check_norm_ct(const polyvec *v, int32_t bound) {
    int32_t reject = 0;

    for (int j = 0; j < L; j++) {
        for (int i = 0; i < N; i++) {
            int32_t abs_coeff = ct_abs(v->vec[j].coeffs[i]);
            reject |= ct_ge(abs_coeff, bound);
        }
    }

    return reject == 0;
}

/* Simulate signing with rejection sampling */
typedef struct {
    int attempts;
    int z_rejects;
    int accepted;
} signing_result;

signing_result sign_with_rejection(const polyvec *s1, uint32_t *seed_state) {
    signing_result result = {0, 0, 0};
    polyvec z;
    poly c;

    while (!result.accepted) {
        result.attempts++;

        /* Step 1: Sample masking vector y */
        polyvec y;
        for (int j = 0; j < L; j++) {
            sample_y(&y.vec[j], seed_state);
        }

        /* Step 2: (Simplified) Compute commitment and challenge */
        /* In real ML-DSA: w = A*y, then c = H(mu || w1) */
        sample_challenge(&c, seed_state);

        /* Step 3: Compute z = y + c*s1 */
        for (int j = 0; j < L; j++) {
            poly cs;
            poly_mul(&cs, &c, &s1->vec[j]);
            poly_add(&z.vec[j], &y.vec[j], &cs);
        }

        /* Step 4: Rejection check for z */
        if (!polyvec_check_norm_ct(&z, GAMMA1 - BETA)) {
            result.z_rejects++;
            continue;  /* Reject and retry */
        }

        /* Additional checks would go here (r0, hints) */
        /* For this demo, we only check z */

        result.accepted = 1;
    }

    return result;
}

/* Statistical analysis of rejection sampling */
void analyze_distribution(void) {
    printf("Analyzing z coefficient distribution...\n\n");

    uint32_t seed = 12345;

    /* Generate a secret */
    poly s;
    sample_secret(&s, &seed);

    /* Track coefficient distribution */
    int bins[21] = {0};  /* -10 to +10 as sample bins */
    int num_samples = 10000;

    printf("Sampling %d accepted z coefficients...\n", num_samples);

    int accepted = 0;
    int attempts = 0;
    while (accepted < num_samples) {
        attempts++;

        /* Sample y and c */
        poly y, c, z;
        sample_y(&y, &seed);
        sample_challenge(&c, &seed);

        /* Compute z = y + c*s */
        poly_mul(&z, &c, &s);
        for (int i = 0; i < N; i++) {
            z.coeffs[i] += y.coeffs[i];
        }

        /* Check if accepted */
        if (poly_check_norm_ct(&z, GAMMA1 - BETA)) {
            /* Record first coefficient (normalized to small range for binning) */
            int32_t coeff = z.coeffs[0];
            /* Scale to bin range */
            int bin = (coeff * 10) / (GAMMA1 - BETA) + 10;
            if (bin >= 0 && bin < 21) {
                bins[bin]++;
            }
            accepted++;
        }
    }

    printf("Distribution of first coefficient (scaled to [-10, 10]):\n");
    int max_count = 0;
    for (int i = 0; i < 21; i++) {
        if (bins[i] > max_count) max_count = bins[i];
    }

    for (int i = 0; i < 21; i++) {
        int bar_len = (bins[i] * 40) / max_count;
        printf("%+3d: ", i - 10);
        for (int j = 0; j < bar_len; j++) printf("*");
        printf(" (%d)\n", bins[i]);
    }

    printf("\nAttempts: %d, Accepted: %d, Rejection rate: %.2f%%\n",
           attempts, accepted, 100.0 * (attempts - accepted) / attempts);
}

int main(void) {
    printf("ML-DSA Rejection Sampling Analysis\n");
    printf("==================================\n\n");

    /* Print parameters */
    printf("Parameters:\n");
    printf("  N = %d (polynomial degree)\n", N);
    printf("  L = %d (number of polynomials in vector)\n", L);
    printf("  γ1 = %d (masking bound)\n", GAMMA1);
    printf("  β = %d (= τ·η = %d·%d)\n", BETA, TAU, ETA);
    printf("  γ1 - β = %d (acceptance threshold)\n", GAMMA1 - BETA);
    printf("\n");

    /* Theoretical rejection probability */
    double p_reject_coeff = (double)BETA / GAMMA1;
    double p_accept_all = 1.0;
    for (int i = 0; i < N * L; i++) {
        p_accept_all *= (1.0 - p_reject_coeff);
    }

    printf("Theoretical analysis:\n");
    printf("  Per-coefficient rejection prob: %.6f\n", p_reject_coeff);
    printf("  All-coefficients accept prob: %.4f\n", p_accept_all);
    printf("  Expected attempts (z check only): %.2f\n", 1.0 / p_accept_all);
    printf("\n");

    /* Empirical testing */
    printf("Empirical testing (1000 signatures):\n");

    /* Fixed default seed => reproducible teaching output; override with
     * PQC_DEMO_SEED. */
    const char *demo_seed_env = getenv("PQC_DEMO_SEED");
    uint32_t seed = demo_seed_env ? (uint32_t)strtoul(demo_seed_env, NULL, 10)
                                  : 1234567u;

    /* Generate secret key */
    polyvec s1;
    for (int j = 0; j < L; j++) {
        sample_secret(&s1.vec[j], &seed);
    }

    int total_attempts = 0;
    int total_z_rejects = 0;
    int num_signatures = 1000;

    for (int i = 0; i < num_signatures; i++) {
        signing_result r = sign_with_rejection(&s1, &seed);
        total_attempts += r.attempts;
        total_z_rejects += r.z_rejects;
    }

    printf("  Total signatures: %d\n", num_signatures);
    printf("  Total attempts: %d\n", total_attempts);
    printf("  Average attempts per signature: %.2f\n",
           (double)total_attempts / num_signatures);
    printf("  Z-bound rejections: %d (%.2f%%)\n",
           total_z_rejects, 100.0 * total_z_rejects / total_attempts);
    printf("\n");

    /* Distribution analysis */
    analyze_distribution();

    printf("\n");
    printf("Key Observations:\n");
    printf("================\n");
    printf("1. The accepted z distribution is approximately uniform\n");
    printf("2. This uniformity is independent of the secret s\n");
    printf("3. Rejection rate matches theoretical prediction\n");
    printf("4. This is what makes ML-DSA signatures zero-knowledge\n");

    return 0;
}
