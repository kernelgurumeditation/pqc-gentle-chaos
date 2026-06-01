/*
 * Source: Module 5 - Digital Signatures Theory
 * Unit 5.3: Lattice-Based Signatures Overview
 * From: pqc-developers-handbook.md (lines 13389-13820)
 *
 * Unit 5.3: Lattice Signature Information Leakage
 *
 * This code demonstrates why naive lattice signatures leak
 * the secret key and how rejection sampling prevents this.
 *
 * EDUCATIONAL PURPOSE ONLY - Not secure for any real use
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <time.h>

/* M_PI is not guaranteed by the C standard (only by POSIX); define it here
 * so the file compiles cleanly under -std=c11. */
#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

/* ========== Parameters ========== */
#define M 3           /* Vector dimension */
#define Q 101         /* Modulus */
#define Y_RANGE 50    /* Masking: y_i in [-Y_RANGE, Y_RANGE] (naive demo only) */
#define SIGMA 14.0    /* Gaussian parameter for rejection sampling.
                       * Deliberately SMALL relative to the secret*challenge
                       * shift s = (7,-4,11) so that rejection sampling actually
                       * rejects a large fraction of candidates. With a huge
                       * sigma the accept probability is ~1 and the lesson
                       * (output independent of the secret) is invisible. */

/* ========== Helper Functions ========== */

/* Centered reduction mod q to [-q/2, q/2) */
int center_mod(int x, int q) {
    x = x % q;
    if (x < 0) x += q;
    if (x > q/2) x -= q;
    return x;
}

/* Sample uniform in [-range, range] */
int sample_uniform(int range) {
    return (rand() % (2 * range + 1)) - range;
}

/* Sample a (rounded) Gaussian with standard deviation sigma via Box-Muller.
 * Real lattice signatures use a discrete Gaussian; this approximation is
 * good enough to illustrate rejection sampling. Using a Gaussian proposal
 * (instead of uniform) keeps the rejection math self-consistent: both the
 * target and the proposal share the same bell-shaped distribution. */
int sample_gaussian(double sigma) {
    double u1, u2;
    do {
        u1 = (double)rand() / (double)RAND_MAX;
    } while (u1 < 1e-12);              /* avoid log(0) */
    u2 = (double)rand() / (double)RAND_MAX;
    double g = sqrt(-2.0 * log(u1)) * cos(2.0 * M_PI * u2);
    return (int)lround(g * sigma);
}

/* Gaussian PDF (unnormalized) */
double gaussian_pdf(int *v, int len, double sigma) {
    double norm_sq = 0;
    for (int i = 0; i < len; i++) {
        norm_sq += (double)v[i] * v[i];
    }
    return exp(-norm_sq / (2.0 * sigma * sigma));
}

/* Rejection-sampling normalization constant M (the "repetition rate").
 *
 * To make the output z independent of the secret-dependent shift c*s, we
 * accept a candidate with probability  D_sigma(z) / (M * D_{c*s,sigma}(z)),
 * i.e.  exp(-(||z||^2 - ||y||^2) / (2*sigma^2)) / M.
 *
 * M must be at least the supremum of that ratio so the acceptance
 * probability never exceeds 1. Without the M divisor the c=0 case (z = y)
 * would ALWAYS be accepted, the two challenge distributions could never be
 * forced to match, and the secret would still leak. M > 1 is exactly what
 * forces some c=0 candidates to be rejected too. The price is that signing
 * needs ~M attempts on average (Fiat-Shamir "with aborts").
 *
 * For s = (7,-4,11), ||s||^2 = 186, and the worst-case inner product
 * <y, c*s> is bounded by roughly k*sigma*||s|| (k ~ 2.2 std-devs), giving
 *   M = exp((2*k*sigma*||s|| + ||s||^2) / (2*sigma^2)).
 * With sigma = 14 this evaluates to M ~ 13.7, so ~14 attempts/signature. */
double rejection_M(double sigma, int *s, int len) {
    double norm_sq = 0;
    for (int i = 0; i < len; i++) {
        norm_sq += (double)s[i] * s[i];
    }
    const double k = 2.2;  /* tail cut-off in standard deviations */
    double exponent = (2.0 * k * sigma * sqrt(norm_sq) + norm_sq)
                      / (2.0 * sigma * sigma);
    return exp(exponent);
}

/* ========== Naive Signature (Insecure) ========== */

typedef struct {
    int s[M];           /* Secret key */
    int a[M];           /* Part of public key (simplified) */
    int t;              /* t = <a, s> mod q */
} naive_keys_t;

void naive_keygen(naive_keys_t *keys) {
    /* Generate random public vector a */
    for (int i = 0; i < M; i++) {
        keys->a[i] = rand() % Q;
    }

    /* Secret: small coefficients */
    keys->s[0] = 7;   /* Fixed for demonstration */
    keys->s[1] = -4;
    keys->s[2] = 11;

    /* Compute t = <a, s> mod q */
    keys->t = 0;
    for (int i = 0; i < M; i++) {
        keys->t += keys->a[i] * keys->s[i];
    }
    keys->t = center_mod(keys->t, Q);
}

typedef struct {
    int z[M];    /* Response */
    int c;       /* Challenge */
} naive_sig_t;

/* Naive sign (leaks information!) */
void naive_sign(naive_keys_t *keys, naive_sig_t *sig) {
    int y[M];

    /* Sample random masking */
    for (int i = 0; i < M; i++) {
        y[i] = sample_uniform(Y_RANGE);
    }

    /* Simplified: random challenge (in real scheme, hash of commitment) */
    sig->c = rand() % 2;

    /* Response: z = y + c*s */
    for (int i = 0; i < M; i++) {
        sig->z[i] = y[i] + sig->c * keys->s[i];
    }
}

/* ========== Information Leakage Attack ========== */

void leakage_attack_demo(void) {
    printf("=== Information Leakage Attack Demo ===\n\n");

    naive_keys_t keys;
    naive_keygen(&keys);

    printf("Secret key s = (%d, %d, %d)\n",
           keys.s[0], keys.s[1], keys.s[2]);
    printf("(Attacker doesn't know this)\n\n");

    /* Collect signatures and track averages */
    double sum_c0[M] = {0, 0, 0};
    double sum_c1[M] = {0, 0, 0};
    int count_c0 = 0, count_c1 = 0;

    int num_sigs = 1000;

    for (int n = 0; n < num_sigs; n++) {
        naive_sig_t sig;
        naive_sign(&keys, &sig);

        if (sig.c == 0) {
            for (int i = 0; i < M; i++) {
                sum_c0[i] += sig.z[i];
            }
            count_c0++;
        } else {
            for (int i = 0; i < M; i++) {
                sum_c1[i] += sig.z[i];
            }
            count_c1++;
        }
    }

    printf("After %d signatures:\n", num_sigs);
    printf("  %d with c=0, %d with c=1\n\n", count_c0, count_c1);

    /* Compute averages */
    double avg_c0[M], avg_c1[M];
    for (int i = 0; i < M; i++) {
        avg_c0[i] = (count_c0 > 0) ? sum_c0[i] / count_c0 : 0;
        avg_c1[i] = (count_c1 > 0) ? sum_c1[i] / count_c1 : 0;
    }

    printf("Average z when c=0: (%.2f, %.2f, %.2f)\n",
           avg_c0[0], avg_c0[1], avg_c0[2]);
    printf("Average z when c=1: (%.2f, %.2f, %.2f)\n",
           avg_c1[0], avg_c1[1], avg_c1[2]);

    /* Recover secret as difference */
    printf("\nRecovered s = E[z|c=1] - E[z|c=0]:\n");
    printf("  s ≈ (%.2f, %.2f, %.2f)\n",
           avg_c1[0] - avg_c0[0],
           avg_c1[1] - avg_c0[1],
           avg_c1[2] - avg_c0[2]);

    printf("\nActual s = (%d, %d, %d)\n",
           keys.s[0], keys.s[1], keys.s[2]);
    printf("\n*** SECRET KEY RECOVERED! ***\n");
}

/* ========== Rejection Sampling Signature ========== */

typedef struct {
    int z[M];
    int c;
    int attempts;  /* For statistics */
} rejection_sig_t;

/*
 * Sign with rejection sampling
 * Returns 1 if signature produced, 0 if max attempts exceeded
 */
int rejection_sign(naive_keys_t *keys, rejection_sig_t *sig, int max_attempts) {
    int y[M], z[M];
    double M_rej = rejection_M(SIGMA, keys->s, M);

    for (int attempt = 1; attempt <= max_attempts; attempt++) {
        /* Sample masking y from a (rounded) Gaussian of width sigma */
        for (int i = 0; i < M; i++) {
            y[i] = sample_gaussian(SIGMA);
        }

        /* Challenge (simplified) */
        sig->c = rand() % 2;

        /* Compute response */
        for (int i = 0; i < M; i++) {
            z[i] = y[i] + sig->c * keys->s[i];
        }

        /* Rejection sampling decision (Lyubashevsky):
         * accept with probability  D_sigma(z) / (M * D_{c*s,sigma}(z))
         *   = exp(-(||z||^2 - ||y||^2)/(2 sigma^2)) / M.
         * The division by M (> 1) is essential: it forces even c=0
         * candidates (where z == y, ratio == 1) to be rejected sometimes,
         * which is what makes the accepted z independent of the secret. */
        double p_z = gaussian_pdf(z, M, SIGMA);
        double p_y = gaussian_pdf(y, M, SIGMA);
        double accept_prob = (p_z / p_y) / M_rej;

        /* Clamp to [0, 1] and make probabilistic decision */
        if (accept_prob > 1.0) accept_prob = 1.0;

        double r = (double)rand() / (double)RAND_MAX;
        if (r < accept_prob) {
            /* Accept this signature */
            for (int i = 0; i < M; i++) {
                sig->z[i] = z[i];
            }
            sig->attempts = attempt;
            return 1;
        }
        /* Rejected - try again */
    }

    return 0;  /* Max attempts exceeded */
}

/* ========== Rejection Sampling Prevents Leakage ========== */

int rejection_demo(void) {
    printf("\n=== Rejection Sampling Demo ===\n\n");

    naive_keys_t keys;
    naive_keygen(&keys);

    printf("Secret key s = (%d, %d, %d)\n",
           keys.s[0], keys.s[1], keys.s[2]);
    printf("Gaussian parameter σ = %.1f\n", SIGMA);
    printf("Repetition rate M = %.2f (target ~%.0f attempts/signature)\n\n",
           rejection_M(SIGMA, keys.s, M), rejection_M(SIGMA, keys.s, M));

    /* Collect signatures with rejection sampling */
    double sum_c0[M] = {0, 0, 0};
    double sum_c1[M] = {0, 0, 0};
    int count_c0 = 0, count_c1 = 0;
    int total_attempts = 0;

    int num_sigs = 1000;

    for (int n = 0; n < num_sigs; n++) {
        rejection_sig_t sig;
        if (rejection_sign(&keys, &sig, 100)) {
            total_attempts += sig.attempts;

            if (sig.c == 0) {
                for (int i = 0; i < M; i++) {
                    sum_c0[i] += sig.z[i];
                }
                count_c0++;
            } else {
                for (int i = 0; i < M; i++) {
                    sum_c1[i] += sig.z[i];
                }
                count_c1++;
            }
        }
    }

    double avg_attempts = (double)total_attempts / num_sigs;
    printf("After %d signatures (avg %.2f attempts each):\n",
           num_sigs, avg_attempts);
    printf("  Rejection rate: %.1f%% of candidates rejected\n",
           100.0 * (1.0 - 1.0 / avg_attempts));
    printf("  %d with c=0, %d with c=1\n\n", count_c0, count_c1);

    /* Compute averages */
    double avg_c0[M], avg_c1[M];
    for (int i = 0; i < M; i++) {
        avg_c0[i] = (count_c0 > 0) ? sum_c0[i] / count_c0 : 0;
        avg_c1[i] = (count_c1 > 0) ? sum_c1[i] / count_c1 : 0;
    }

    printf("Average z when c=0: (%.2f, %.2f, %.2f)\n",
           avg_c0[0], avg_c0[1], avg_c0[2]);
    printf("Average z when c=1: (%.2f, %.2f, %.2f)\n",
           avg_c1[0], avg_c1[1], avg_c1[2]);

    /* Try to recover secret */
    printf("\nAttempted s = E[z|c=1] - E[z|c=0]:\n");
    printf("  s ≈ (%.2f, %.2f, %.2f)\n",
           avg_c1[0] - avg_c0[0],
           avg_c1[1] - avg_c0[1],
           avg_c1[2] - avg_c0[2]);

    printf("\nActual s = (%d, %d, %d)\n",
           keys.s[0], keys.s[1], keys.s[2]);
    printf("\n*** With rejection sampling, attack fails! ***\n");
    printf("(Both averages are near 0 - no difference to exploit)\n");

    /* PASS = rejection sampling still produced signatures to analyze. */
    return (count_c0 + count_c1) > 0;
}

/* ========== SIS Problem Demonstration ========== */

void sis_demo(void) {
    printf("\n=== SIS Problem Demo ===\n\n");

    /* Simple SIS instance: find z such that Az = 0 and z is short */
    int A[2][4] = {
        {23, 45, 12, 67},
        {78, 34, 89, 11}
    };

    printf("Matrix A (2×4 over Z_%d):\n", Q);
    printf("  [%2d %2d %2d %2d]\n", A[0][0], A[0][1], A[0][2], A[0][3]);
    printf("  [%2d %2d %2d %2d]\n\n", A[1][0], A[1][1], A[1][2], A[1][3]);

    printf("SIS Problem: Find short z ≠ 0 such that Az = 0 (mod %d)\n\n", Q);

    /* Brute force search for short solution */
    printf("Searching for solutions with ||z||_∞ ≤ 3...\n");
    int found = 0;

    for (int z0 = -3; z0 <= 3 && found < 3; z0++) {
        for (int z1 = -3; z1 <= 3 && found < 3; z1++) {
            for (int z2 = -3; z2 <= 3 && found < 3; z2++) {
                for (int z3 = -3; z3 <= 3 && found < 3; z3++) {
                    if (z0 == 0 && z1 == 0 && z2 == 0 && z3 == 0) continue;

                    int row0 = A[0][0]*z0 + A[0][1]*z1 + A[0][2]*z2 + A[0][3]*z3;
                    int row1 = A[1][0]*z0 + A[1][1]*z1 + A[1][2]*z2 + A[1][3]*z3;

                    row0 = center_mod(row0, Q);
                    row1 = center_mod(row1, Q);

                    if (row0 == 0 && row1 == 0) {
                        printf("  Found: z = (%d, %d, %d, %d)\n", z0, z1, z2, z3);
                        found++;
                    }
                }
            }
        }
    }

    if (found == 0) {
        printf("  No solutions found with ||z||_∞ ≤ 3\n");
        printf("  (This is expected - finding short solutions is hard!)\n");
    }

    printf("\nNote: With real parameters (n ≈ 256, q ≈ 2²³),\n");
    printf("finding short solutions is computationally infeasible.\n");
}

/* ========== Fiat-Shamir with Aborts Framework ========== */

int fiat_shamir_aborts_demo(void) {
    printf("\n=== Fiat-Shamir with Aborts Demo ===\n\n");

    naive_keys_t keys;
    naive_keygen(&keys);

    printf("This demonstrates the signing process with aborts.\n\n");

    int y[M], z[M];
    int attempt = 0;
    int accepted = 0;
    double M_rej = rejection_M(SIGMA, keys.s, M);

    printf("Attempting to sign with rejection sampling (M = %.2f):\n", M_rej);

    while (!accepted && attempt < 200) {
        attempt++;

        /* Step 1: Sample masking from a Gaussian of width sigma */
        for (int i = 0; i < M; i++) {
            y[i] = sample_gaussian(SIGMA);
        }

        /* Step 2: Compute commitment (w = Ay, simplified here) */
        int w = 0;
        for (int i = 0; i < M; i++) {
            w += keys.a[i] * y[i];
        }
        w = center_mod(w, Q);

        /* Step 3: Challenge via Fiat-Shamir */
        /* c = H(w || message) - simplified to random */
        int c = rand() % 2;

        /* Step 4: Response */
        for (int i = 0; i < M; i++) {
            z[i] = y[i] + c * keys.s[i];
        }

        /* Step 5: Rejection check (normalized by M, so ratio <= 1) */
        double p_z = gaussian_pdf(z, M, SIGMA);
        double p_y = gaussian_pdf(y, M, SIGMA);
        double ratio = (p_z / p_y) / M_rej;
        if (ratio > 1.0) ratio = 1.0;

        double r = (double)rand() / (double)RAND_MAX;

        /* Only print the first handful so the trace stays readable */
        if (attempt <= 12) {
            printf("  Attempt %d: c=%d, accept_prob=%.3f, random=%.3f → %s\n",
                   attempt, c, ratio, r, (r < ratio) ? "ACCEPT" : "REJECT (abort and retry)");
        } else if (attempt == 13) {
            printf("  ... (further rejected attempts omitted) ...\n");
        }

        if (r < ratio) {
            accepted = 1;
        }
    }

    if (accepted) {
        printf("\nSignature produced after %d attempt(s)\n", attempt);
        printf("z = (%d, %d, %d)\n", z[0], z[1], z[2]);
    } else {
        printf("\nNo signature produced within attempt budget!\n");
    }

    /* PASS = signing-with-aborts terminated with an accepted signature. */
    return accepted;
}

/* ========== Main ========== */

int main(void) {
    /* Fixed default seed => reproducible teaching output; override with PQC_DEMO_SEED. */
    const char *demo_seed_env = getenv("PQC_DEMO_SEED");
    srand(demo_seed_env ? (unsigned)strtoul(demo_seed_env, NULL, 10) : 1234567u);

    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║  Unit 5.3: Lattice-Based Signatures and Rejection Sampling   ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");

    int all_pass = 1;

    /* Demo 1: Information leakage in naive scheme (illustrative) */
    leakage_attack_demo();

    /* Demo 2: Rejection sampling prevents leakage */
    all_pass &= rejection_demo();

    /* Demo 3: SIS problem (illustrative brute-force search) */
    sis_demo();

    /* Demo 4: Fiat-Shamir with Aborts */
    all_pass &= fiat_shamir_aborts_demo();

    printf("\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("Key Takeaways:\n");
    printf("  1. Naive lattice signatures leak the secret key\n");
    printf("  2. Rejection sampling makes output independent of secret\n");
    printf("  3. Cost: Multiple attempts needed (Fiat-Shamir with Aborts)\n");
    printf("  4. ML-DSA uses this framework with Module-LWE/SIS\n");
    printf("═══════════════════════════════════════════════════════════════\n");

    printf("\n==============================================\n");
    printf("Overall result: %s\n",
           all_pass ? "PASS (signing demos produced valid signatures)"
                    : "FAIL (a signing demo failed to produce signatures)");
    printf("==============================================\n");

    return all_pass ? EXIT_SUCCESS : EXIT_FAILURE;
}
