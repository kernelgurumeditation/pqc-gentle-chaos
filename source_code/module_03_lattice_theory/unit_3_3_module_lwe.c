/*
 * Source: PQC Learning Plan - Module 3: Lattice Cryptography Theory
 * Unit: 3.3 - Ring-LWE and Module-LWE
 * Description: Module-LWE data structures and operations
 *
 * This program demonstrates:
 * - Polynomial and polynomial vector operations
 * - Module-LWE key generation structure
 * - Matrix-vector multiplication over polynomial rings
 * - Key size analysis for ML-KEM-768-like parameters
 *
 * Note: This demonstrates the structure, not a secure implementation
 *       Real implementations use NTT for efficient polynomial multiplication
 */

// module_lwe.c - Module-LWE data structures and operations
// This demonstrates the structure, not a secure implementation

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define N 256        // Polynomial degree
#define Q 3329       // Modulus
#define K 3          // Module rank (for ML-KEM-768)

// Polynomial: array of N coefficients
typedef struct {
    int16_t coeffs[N];
} poly;

// Vector of K polynomials
typedef struct {
    poly vec[K];
} polyvec;

// K x K matrix of polynomials
typedef struct {
    poly mat[K][K];
} polymat;

// Reduce coefficient to [0, Q-1]
int16_t mod_q(int64_t x) {
    x = x % Q;
    return (x < 0) ? x + Q : x;
}

// Add two polynomials
void poly_add(poly *r, const poly *a, const poly *b) {
    for (int i = 0; i < N; i++) {
        r->coeffs[i] = mod_q(a->coeffs[i] + b->coeffs[i]);
    }
}

// Naive polynomial multiplication (for illustration)
// In practice, use NTT!
void poly_mul_naive(poly *r, const poly *a, const poly *b) {
    int64_t temp[2*N] = {0};

    // Schoolbook multiplication
    for (int i = 0; i < N; i++) {
        for (int j = 0; j < N; j++) {
            temp[i + j] += (int64_t)a->coeffs[i] * b->coeffs[j];
        }
    }

    // Reduce mod X^N + 1 (negacyclic)
    for (int i = 0; i < N; i++) {
        r->coeffs[i] = mod_q(temp[i] - temp[i + N]);
    }
}

// Add two polynomial vectors
void polyvec_add(polyvec *r, const polyvec *a, const polyvec *b) {
    for (int i = 0; i < K; i++) {
        poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);
    }
}

// Inner product of two polynomial vectors
// Returns a single polynomial
void polyvec_inner_product(poly *r, const polyvec *a, const polyvec *b) {
    poly temp, acc;
    memset(&acc, 0, sizeof(acc));

    for (int i = 0; i < K; i++) {
        poly_mul_naive(&temp, &a->vec[i], &b->vec[i]);
        poly_add(&acc, &acc, &temp);
    }

    *r = acc;
}

// Matrix-vector multiplication: r = A * v
void polymat_vec_mul(polyvec *r, const polymat *A, const polyvec *v) {
    for (int i = 0; i < K; i++) {
        // r[i] = sum_j A[i][j] * v[j]
        poly temp, acc;
        memset(&acc, 0, sizeof(acc));

        for (int j = 0; j < K; j++) {
            poly_mul_naive(&temp, &A->mat[i][j], &v->vec[j]);
            poly_add(&acc, &acc, &temp);
        }
        r->vec[i] = acc;
    }
}

// Sample small polynomial (CBD-like, simplified)
void poly_sample_small(poly *r, int bound) {
    for (int i = 0; i < N; i++) {
        r->coeffs[i] = (rand() % (2*bound + 1)) - bound;
    }
}

// Sample random polynomial
void poly_sample_uniform(poly *r) {
    for (int i = 0; i < N; i++) {
        r->coeffs[i] = rand() % Q;
    }
}

void print_poly_short(const char *name, const poly *p) {
    printf("%s: [%d, %d, %d, ..., %d] (showing first 3 and last)\n",
           name, p->coeffs[0], p->coeffs[1], p->coeffs[2], p->coeffs[N-1]);
}

int main(void) {
    printf("=== Module-LWE Structure Demo (k=%d) ===\n\n", K);

    srand(42);  // Fixed seed for reproducibility

    // Key Generation (simplified)
    printf("--- Key Generation ---\n");

    // Generate random matrix A
    polymat A;
    for (int i = 0; i < K; i++) {
        for (int j = 0; j < K; j++) {
            poly_sample_uniform(&A.mat[i][j]);
        }
    }
    printf("Generated %dx%d matrix A (each entry is degree-%d polynomial)\n", K, K, N-1);

    // Sample small secret s
    polyvec s;
    for (int i = 0; i < K; i++) {
        poly_sample_small(&s.vec[i], 2);  // CBD_2 range
    }
    printf("Sampled secret s (k=%d polynomials with small coefficients)\n", K);
    print_poly_short("s[0]", &s.vec[0]);

    // Sample small error e
    polyvec e;
    for (int i = 0; i < K; i++) {
        poly_sample_small(&e.vec[i], 2);
    }

    // Compute t = A*s + e
    polyvec As, t;
    polymat_vec_mul(&As, &A, &s);
    polyvec_add(&t, &As, &e);

    printf("Computed t = A*s + e\n");
    print_poly_short("t[0]", &t.vec[0]);

    // Key sizes
    printf("\n--- Key Sizes ---\n");
    printf("Public key (A seed + t): 32 + %d * 384 = %d bytes\n",
           K, 32 + K * 384);
    printf("  (A is generated from 32-byte seed, not stored)\n");
    printf("Secret key (s): %d * 384 = %d bytes (uncompressed)\n",
           K, K * 384);

    // Module-LWE instance
    printf("\n--- Module-LWE Instance ---\n");
    printf("Given: Matrix A and vector t = A*s + e\n");
    printf("Task: Find secret vector s (k=%d polynomials)\n", K);
    printf("Difficulty: Requires solving Module-LWE with dimension k*n = %d\n", K * N);

    return 0;
}
