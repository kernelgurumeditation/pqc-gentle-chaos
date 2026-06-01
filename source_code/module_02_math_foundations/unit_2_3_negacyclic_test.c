// negacyclic_test.c - Verify negacyclic property
// Source: Module 2, Unit 2.3 - Polynomial Ring Arithmetic in Depth (Exercise 2.3.8)
// Compile: gcc -o negacyclic_test negacyclic_test.c

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define N 256
#define Q 3329

typedef struct {
    int16_t coeffs[N];
} poly;

static inline int16_t mod_q(int64_t a) {
    int16_t r = a % Q;
    return r < 0 ? r + Q : r;
}

void poly_mul_schoolbook(poly *r, const poly *a, const poly *b) {
    int64_t temp[2 * N] = {0};
    for (int i = 0; i < N; i++) {
        for (int j = 0; j < N; j++) {
            temp[i + j] += (int64_t)a->coeffs[i] * b->coeffs[j];
        }
    }
    for (int i = 0; i < N; i++) {
        r->coeffs[i] = mod_q(temp[i] - temp[i + N]);
    }
}

int main(void) {
    /* Fixed default seed => reproducible teaching output; override with PQC_DEMO_SEED. */
    const char *demo_seed_env = getenv("PQC_DEMO_SEED");
    srand(demo_seed_env ? (unsigned)strtoul(demo_seed_env, NULL, 10) : 1234567u);
    poly a = {{0}};

    // Random polynomial
    for (int i = 0; i < N; i++) {
        a.coeffs[i] = rand() % Q;
    }

    // X^N (which equals X^256)
    // In schoolbook, we represent X^N as the polynomial with coeff[N] = 1
    // But since we can only store degree < N, we use the identity X^N ≡ -1
    // So multiplying by X^N should give -a

    // Directly compute -a
    poly neg_a = {{0}};
    for (int i = 0; i < N; i++) {
        neg_a.coeffs[i] = mod_q(-a.coeffs[i]);
    }

    // Verify by multiplying a by X, N times? No, simpler:
    // Multiply by X, N times
    poly temp = a;
    for (int iter = 0; iter < N; iter++) {
        // Multiply by X: shift coefficients, wrap with negation
        int16_t last = temp.coeffs[N - 1];
        for (int i = N - 1; i > 0; i--) {
            temp.coeffs[i] = temp.coeffs[i - 1];
        }
        temp.coeffs[0] = mod_q(-last);  // X^N ≡ -1
    }

    // temp should now equal -a
    int match = 1;
    for (int i = 0; i < N; i++) {
        if (temp.coeffs[i] != neg_a.coeffs[i]) {
            match = 0;
            printf("Mismatch at %d: %d vs %d\n", i, temp.coeffs[i], neg_a.coeffs[i]);
        }
    }

    if (match) {
        printf("VERIFIED: a · X^%d ≡ -a in R_q\n", N);
    } else {
        printf("ERROR: Negacyclic property failed!\n");
    }

    /* Nonzero exit on failure so the test harness can detect it. */
    return match ? 0 : 1;
}
