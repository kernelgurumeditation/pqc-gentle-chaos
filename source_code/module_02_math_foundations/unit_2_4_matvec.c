// matvec.c - Matrix-vector multiplication over Rq
// Source: Module 2, Unit 2.4 - Linear Algebra for Lattices
// Compile: gcc -O2 -o matvec matvec.c

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define N 256
#define Q 3329
#define K 3  // ML-KEM-768

typedef struct { int16_t coeffs[N]; } poly;
typedef struct { poly vec[K]; } polyvec;
typedef struct { poly mat[K][K]; } polymat;

static inline int16_t mod_q(int64_t a) {
    int16_t r = a % Q;
    return r < 0 ? r + Q : r;
}

void poly_add(poly *r, const poly *a, const poly *b) {
    for (int i = 0; i < N; i++)
        r->coeffs[i] = mod_q((int32_t)a->coeffs[i] + b->coeffs[i]);
}

// Schoolbook multiplication (will be replaced by NTT in practice)
void poly_mul(poly *r, const poly *a, const poly *b) {
    int64_t temp[2 * N] = {0};
    for (int i = 0; i < N; i++)
        for (int j = 0; j < N; j++)
            temp[i + j] += (int64_t)a->coeffs[i] * b->coeffs[j];
    for (int i = 0; i < N; i++)
        r->coeffs[i] = mod_q(temp[i] - temp[i + N]);
}

// r = A · v (matrix-vector multiplication)
void matvec_mul(polyvec *r, const polymat *A, const polyvec *v) {
    for (int i = 0; i < K; i++) {
        // r[i] = sum_j A[i][j] * v[j]
        memset(&r->vec[i], 0, sizeof(poly));

        for (int j = 0; j < K; j++) {
            poly prod;
            poly_mul(&prod, &A->mat[i][j], &v->vec[j]);
            poly_add(&r->vec[i], &r->vec[i], &prod);
        }
    }
}

// Inner product: r = <a, b> = sum_i a[i] * b[i]
void polyvec_inner(poly *r, const polyvec *a, const polyvec *b) {
    memset(r, 0, sizeof(poly));
    for (int i = 0; i < K; i++) {
        poly prod;
        poly_mul(&prod, &a->vec[i], &b->vec[i]);
        poly_add(r, r, &prod);
    }
}

int main(void) {
    // Simple test: identity-ish matrix times vector
    polymat A = {0};
    polyvec v = {0};
    polyvec r;

    // Set A to "almost identity" (1s on diagonal)
    for (int i = 0; i < K; i++) {
        A.mat[i][i].coeffs[0] = 1;
    }

    // Set v to small test values
    for (int i = 0; i < K; i++) {
        v.vec[i].coeffs[0] = i + 1;  // v = [1, 2, 3]
    }

    matvec_mul(&r, &A, &v);

    printf("Matrix-vector multiplication test:\n");
    printf("A = I (identity), v = [1, 2, 3] (as constant polynomials)\n");
    printf("Result r = A·v:\n");
    int ok = 1;
    for (int i = 0; i < K; i++) {
        printf("  r[%d].coeffs[0] = %d (expected %d)\n",
               i, r.vec[i].coeffs[0], i + 1);
        if (r.vec[i].coeffs[0] != i + 1) ok = 0;
    }

    printf(ok ? "[PASS] I·v == v (matrix-vector product correct)\n"
              : "[FAIL] matrix-vector product mismatch\n");

    /* Nonzero exit on failure so the test harness can detect it. */
    return ok ? 0 : 1;
}
