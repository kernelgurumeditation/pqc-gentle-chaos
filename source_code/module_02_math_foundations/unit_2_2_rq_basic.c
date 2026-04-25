// rq_basic.c - Basic operations in Rq = Z_q[X]/(X^256 + 1)
// Source: Module 2, Unit 2.2 - Algebraic Structures for Cryptography
// Compile: gcc -o rq_basic rq_basic.c

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define N 256
#define Q 3329

typedef struct {
    int16_t coeffs[N];
} poly;

// Reduce coefficient to [0, Q-1]
static inline int16_t mod_q(int64_t a) {
    int16_t r = a % Q;
    return r < 0 ? r + Q : r;
}

// Add two polynomials: r = a + b
void poly_add(poly *r, const poly *a, const poly *b) {
    for (int i = 0; i < N; i++) {
        r->coeffs[i] = mod_q((int32_t)a->coeffs[i] + b->coeffs[i]);
    }
}

// Subtract two polynomials: r = a - b
void poly_sub(poly *r, const poly *a, const poly *b) {
    for (int i = 0; i < N; i++) {
        r->coeffs[i] = mod_q((int32_t)a->coeffs[i] - b->coeffs[i]);
    }
}

// Naive polynomial multiplication in Rq (O(n²) - educational only!)
// Uses the fact that X^N ≡ -1 (mod X^N + 1)
void poly_mul_naive(poly *r, const poly *a, const poly *b) {
    int64_t temp[2 * N] = {0};

    // Standard polynomial multiplication
    for (int i = 0; i < N; i++) {
        for (int j = 0; j < N; j++) {
            temp[i + j] += (int64_t)a->coeffs[i] * b->coeffs[j];
        }
    }

    // Reduce mod X^N + 1: coefficients at index >= N wrap with negation
    for (int i = 0; i < N; i++) {
        int32_t coeff = temp[i] - temp[i + N];  // X^(N+i) ≡ -X^i
        r->coeffs[i] = mod_q(coeff);
    }
}

// Print polynomial (only non-zero terms, up to max_terms)
void poly_print(const char *name, const poly *p, int max_terms) {
    printf("%s = ", name);
    int printed = 0;
    for (int i = N - 1; i >= 0 && printed < max_terms; i--) {
        if (p->coeffs[i] != 0) {
            if (printed > 0) printf(" + ");
            if (i == 0) {
                printf("%d", p->coeffs[i]);
            } else if (i == 1) {
                printf("%dX", p->coeffs[i]);
            } else {
                printf("%dX^%d", p->coeffs[i], i);
            }
            printed++;
        }
    }
    if (printed == 0) printf("0");
    if (printed == max_terms) printf(" + ...");
    printf("\n");
}

int main(void) {
    poly a = {0}, b = {0}, r = {0};

    // Example: a = 2X² + 3X + 1, b = X + 4
    a.coeffs[0] = 1; a.coeffs[1] = 3; a.coeffs[2] = 2;
    b.coeffs[0] = 4; b.coeffs[1] = 1;

    printf("Polynomial arithmetic in R_q = Z_%d[X]/(X^%d + 1)\n\n", Q, N);

    poly_print("a(X)", &a, 10);
    poly_print("b(X)", &b, 10);

    poly_add(&r, &a, &b);
    poly_print("a + b", &r, 10);

    poly_sub(&r, &a, &b);
    poly_print("a - b", &r, 10);

    poly_mul_naive(&r, &a, &b);
    poly_print("a × b", &r, 10);

    // Demonstrate wraparound: multiply by X^255
    printf("\nDemonstrating X^N ≡ -1 reduction:\n");
    poly x255 = {0};
    x255.coeffs[255] = 1;  // X^255

    poly simple = {0};
    simple.coeffs[0] = 1;   // 1
    simple.coeffs[1] = 2;   // + 2X

    poly_print("p(X)", &simple, 10);
    poly_print("X^255", &x255, 10);

    poly_mul_naive(&r, &simple, &x255);
    poly_print("p(X) × X^255", &r, 10);
    // Expected: X^255 + 2X^256 = X^255 + 2(-1) = X^255 - 2

    return 0;
}
