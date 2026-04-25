/*
 * Source: PQC Learning Plan - Module 3: Lattice Cryptography Theory
 * Unit: 3.2 - Learning With Errors (LWE)
 * Exercise: 3.2.7 - Brute Force LWE Solver
 * Description: Attempt to solve small LWE instance by exhaustive search
 *
 * This program demonstrates:
 * - Brute force attack on small LWE instances
 * - Complexity analysis (O(q^n) operations)
 * - Why LWE is secure for cryptographic parameters
 *
 * Note: For n=2, q=17, requires 289 attempts (feasible)
 *       For n=256, q=3329, requires 3329^256 ≈ 2^3000 attempts (infeasible!)
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#define N 2
#define Q 17
#define M 4
#define ERROR_BOUND 1

typedef struct {
    int32_t a[N];
    int32_t b;
} lwe_sample_t;

int32_t mod_q(int32_t x) {
    x = x % Q;
    return (x < 0) ? x + Q : x;
}

// Check if all samples are consistent with secret s and bounded errors
bool check_secret(const lwe_sample_t *samples, int num_samples, const int32_t *s) {
    for (int i = 0; i < num_samples; i++) {
        int32_t computed = 0;
        for (int j = 0; j < N; j++) {
            computed += samples[i].a[j] * s[j];
        }
        computed = mod_q(computed);

        // Check if error is within bounds
        int32_t diff = mod_q(samples[i].b - computed);
        // diff should be in [-ERROR_BOUND, ERROR_BOUND] mod Q
        if (diff > ERROR_BOUND && diff < Q - ERROR_BOUND) {
            return false;
        }
    }
    return true;
}

// Brute force search for LWE secret
bool brute_force_lwe(const lwe_sample_t *samples, int num_samples, int32_t *found_s) {
    int32_t s[N];

    // Try all possible secrets
    for (s[0] = 0; s[0] < Q; s[0]++) {
        for (s[1] = 0; s[1] < Q; s[1]++) {
            if (check_secret(samples, num_samples, s)) {
                found_s[0] = s[0];
                found_s[1] = s[1];
                return true;
            }
        }
    }
    return false;
}

int main(void) {
    printf("=== Brute Force LWE Solver ===\n");
    printf("n=%d, q=%d, error_bound=%d\n\n", N, Q, ERROR_BOUND);

    // True secret
    int32_t true_s[N] = {3, 5};

    // Generate samples
    lwe_sample_t samples[M] = {
        {{7, 11}, mod_q(7*3 + 11*5 + 1)},   // e=1
        {{2, 13}, mod_q(2*3 + 13*5 - 1)},   // e=-1
        {{15, 4}, mod_q(15*3 + 4*5 + 0)},   // e=0
        {{9, 1},  mod_q(9*3 + 1*5 + 1)}     // e=1
    };

    printf("True secret: (%d, %d)\n", true_s[0], true_s[1]);
    printf("Generated %d samples\n\n", M);

    // Try to recover secret
    int32_t found_s[N];
    if (brute_force_lwe(samples, M, found_s)) {
        printf("Found secret: (%d, %d)\n", found_s[0], found_s[1]);
        if (found_s[0] == true_s[0] && found_s[1] == true_s[1]) {
            printf("Correct! ✓\n");
        }
    } else {
        printf("No valid secret found\n");
    }

    printf("\nComplexity: O(q^n) = O(%d^%d) = O(%d) operations\n",
           Q, N, Q * Q);

    return 0;
}
