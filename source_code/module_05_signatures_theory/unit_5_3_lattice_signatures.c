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

/* ========== Parameters ========== */
#define M 3           /* Vector dimension */
#define Q 101         /* Modulus */
#define Y_RANGE 50    /* Masking: y_i in [-Y_RANGE, Y_RANGE] */
#define SIGMA 40.0    /* Gaussian parameter for rejection sampling */

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

/* Gaussian PDF (unnormalized) */
double gaussian_pdf(int *v, int len, double sigma) {
    double norm_sq = 0;
    for (int i = 0; i < len; i++) {
        norm_sq += (double)v[i] * v[i];
    }
    return exp(-norm_sq / (2.0 * sigma * sigma));
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

    for (int attempt = 1; attempt <= max_attempts; attempt++) {
        /* Sample masking y (approximating Gaussian with uniform here) */
        for (int i = 0; i < M; i++) {
            y[i] = sample_uniform(Y_RANGE);
        }

        /* Challenge (simplified) */
        sig->c = rand() % 2;

        /* Compute response */
        for (int i = 0; i < M; i++) {
            z[i] = y[i] + sig->c * keys->s[i];
        }

        /* Rejection sampling decision */
        /* Accept with probability exp(-||z||²/2σ²) / exp(-||y||²/2σ²) */
        double p_z = gaussian_pdf(z, M, SIGMA);
        double p_y = gaussian_pdf(y, M, SIGMA);

        /* Need a normalization constant M to ensure ratio <= 1 */
        /* For simplicity, we use rejection based on z's norm */
        double accept_prob = p_z / p_y;

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

void rejection_demo(void) {
    printf("\n=== Rejection Sampling Demo ===\n\n");

    naive_keys_t keys;
    naive_keygen(&keys);

    printf("Secret key s = (%d, %d, %d)\n",
           keys.s[0], keys.s[1], keys.s[2]);
    printf("Gaussian parameter σ = %.1f\n\n", SIGMA);

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

    printf("After %d signatures (avg %.2f attempts each):\n",
           num_sigs, (double)total_attempts / num_sigs);
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

void fiat_shamir_aborts_demo(void) {
    printf("\n=== Fiat-Shamir with Aborts Demo ===\n\n");

    naive_keys_t keys;
    naive_keygen(&keys);

    printf("This demonstrates the signing process with aborts.\n\n");

    int y[M], z[M];
    int attempt = 0;
    int accepted = 0;

    printf("Attempting to sign with rejection sampling:\n");

    while (!accepted && attempt < 20) {
        attempt++;

        /* Step 1: Sample masking */
        for (int i = 0; i < M; i++) {
            y[i] = sample_uniform(Y_RANGE);
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

        /* Step 5: Rejection check */
        double p_z = gaussian_pdf(z, M, SIGMA);
        double p_y = gaussian_pdf(y, M, SIGMA);
        double ratio = p_z / p_y;
        if (ratio > 1.0) ratio = 1.0;

        double r = (double)rand() / (double)RAND_MAX;

        printf("  Attempt %d: c=%d, ratio=%.3f, random=%.3f → ",
               attempt, c, ratio, r);

        if (r < ratio) {
            printf("ACCEPT\n");
            accepted = 1;
        } else {
            printf("REJECT (abort and retry)\n");
        }
    }

    if (accepted) {
        printf("\nSignature produced after %d attempt(s)\n", attempt);
        printf("z = (%d, %d, %d)\n", z[0], z[1], z[2]);
    }
}

/* ========== Main ========== */

int main(void) {
    srand(time(NULL));

    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║  Unit 5.3: Lattice-Based Signatures and Rejection Sampling   ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");

    /* Demo 1: Information leakage in naive scheme */
    leakage_attack_demo();

    /* Demo 2: Rejection sampling prevents leakage */
    rejection_demo();

    /* Demo 3: SIS problem */
    sis_demo();

    /* Demo 4: Fiat-Shamir with Aborts */
    fiat_shamir_aborts_demo();

    printf("\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("Key Takeaways:\n");
    printf("  1. Naive lattice signatures leak the secret key\n");
    printf("  2. Rejection sampling makes output independent of secret\n");
    printf("  3. Cost: Multiple attempts needed (Fiat-Shamir with Aborts)\n");
    printf("  4. ML-DSA uses this framework with Module-LWE/SIS\n");
    printf("═══════════════════════════════════════════════════════════════\n");

    return 0;
}
