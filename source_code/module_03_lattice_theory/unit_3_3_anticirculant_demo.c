/*
 * Source: PQC Learning Plan - Module 3: Lattice Cryptography Theory
 * Unit: 3.3 - Ring-LWE and Module-LWE
 * Exercise: 3.3.7 - Anti-circulant Matrix Demonstration
 * Description: Verify polynomial multiplication equals matrix multiplication
 *
 * This program demonstrates:
 * - Building anti-circulant matrix from polynomial coefficients
 * - Polynomial multiplication in Zq[X]/(X^4+1)
 * - Equivalence between polynomial and matrix operations
 * - Negacyclic structure (X^n ≡ -1)
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#define N 4
#define Q 17

int16_t mod_q(int32_t x) {
    x = x % Q;
    return (x < 0) ? x + Q : x;
}

// Build anti-circulant matrix from polynomial coefficients
void build_anticirculant(int16_t M[N][N], const int16_t a[N]) {
    for (int i = 0; i < N; i++) {
        for (int j = 0; j < N; j++) {
            if (j <= i) {
                M[i][j] = a[i - j];
            } else {
                // Wrap with negation
                M[i][j] = mod_q(-a[N + i - j]);
            }
        }
    }
}

// Matrix-vector multiplication
void matvec_mul(int16_t result[N], const int16_t M[N][N], const int16_t v[N]) {
    for (int i = 0; i < N; i++) {
        int32_t sum = 0;
        for (int j = 0; j < N; j++) {
            sum += M[i][j] * v[j];
        }
        result[i] = mod_q(sum);
    }
}

// Direct polynomial multiplication mod X^N + 1
void poly_mul(int16_t result[N], const int16_t a[N], const int16_t s[N]) {
    int32_t temp[2*N] = {0};

    for (int i = 0; i < N; i++) {
        for (int j = 0; j < N; j++) {
            temp[i + j] += a[i] * s[j];
        }
    }

    for (int i = 0; i < N; i++) {
        result[i] = mod_q(temp[i] - temp[i + N]);
    }
}

void print_matrix(const int16_t M[N][N]) {
    for (int i = 0; i < N; i++) {
        printf("  [");
        for (int j = 0; j < N; j++) {
            printf("%3d", M[i][j]);
            if (j < N-1) printf(", ");
        }
        printf("]\n");
    }
}

void print_vector(const char *name, const int16_t v[N]) {
    printf("%s: [%d, %d, %d, %d]\n", name, v[0], v[1], v[2], v[3]);
}

int main(void) {
    int16_t a[N] = {5, 3, 7, 2};  // 5 + 3X + 7X² + 2X³
    int16_t s[N] = {1, 4, 2, 6};  // 1 + 4X + 2X² + 6X³

    printf("=== Anti-Circulant Matrix Demo ===\n\n");
    print_vector("a(X)", a);
    print_vector("s(X)", s);

    // Build anti-circulant matrix
    int16_t M[N][N];
    build_anticirculant(M, a);
    printf("\nAnti-circulant matrix M from a:\n");
    print_matrix(M);

    // Compute via matrix multiplication
    int16_t result_mat[N];
    matvec_mul(result_mat, M, s);
    printf("\nResult via M * s:\n");
    print_vector("M*s", result_mat);

    // Compute via polynomial multiplication
    int16_t result_poly[N];
    poly_mul(result_poly, a, s);
    printf("\nResult via a(X)*s(X) mod (X^4+1):\n");
    print_vector("a*s", result_poly);

    // Verify equality
    bool equal = true;
    for (int i = 0; i < N; i++) {
        if (result_mat[i] != result_poly[i]) equal = false;
    }
    printf("\nResults match: %s\n", equal ? "YES ✓" : "NO ✗");

    return 0;
}
