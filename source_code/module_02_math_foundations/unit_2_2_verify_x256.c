// verify_x256.c
// Source: Module 2, Unit 2.2 - Algebraic Structures for Cryptography (Exercise 2.2.10)
// Compile: gcc -o verify_x256 verify_x256.c

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define N 256
#define Q 3329

typedef struct {
    int16_t coeffs[N];
} poly;

static inline int16_t mod_q(int64_t a) {
    int16_t r = a % Q;
    return r < 0 ? r + Q : r;
}

void poly_mul_naive(poly *r, const poly *a, const poly *b) {
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
    poly x128 = {0};
    x128.coeffs[128] = 1;  // X^128

    poly result = {0};
    poly_mul_naive(&result, &x128, &x128);  // X^128 × X^128 = X^256

    printf("Computing X^128 × X^128 in Z_%d[X]/(X^%d + 1):\n\n", Q, N);

    // Check result
    int is_minus_one = 1;
    for (int i = 0; i < N; i++) {
        if (i == 0) {
            // Coefficient of X^0 should be -1 ≡ Q-1
            if (result.coeffs[i] != Q - 1) {
                is_minus_one = 0;
                printf("coeffs[0] = %d (expected %d)\n", result.coeffs[i], Q-1);
            }
        } else {
            // All other coefficients should be 0
            if (result.coeffs[i] != 0) {
                is_minus_one = 0;
                printf("coeffs[%d] = %d (expected 0)\n", i, result.coeffs[i]);
            }
        }
    }

    if (is_minus_one) {
        printf("Result: X^256 ≡ %d ≡ -1 (mod %d)\n", Q-1, Q);
        printf("\nVERIFIED: X^256 ≡ -1 in this ring!\n");
    } else {
        printf("\nERROR: Unexpected result!\n");
    }

    /* Nonzero exit on failure so the test harness can detect it. */
    return is_minus_one ? 0 : 1;
}
