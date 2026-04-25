#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define N 256
#define Q 8380417
#define K 6
#define L 5
#define D 13

typedef struct { int32_t coeffs[N]; } poly;
typedef struct { poly vec[L]; } polyvecl;
typedef struct { poly vec[K]; } polyveck;

/* Reduce coefficient to [0, q) */
int32_t mod_q(int32_t x) {
    x = x % Q;
    if (x < 0) x += Q;
    return x;
}

/* Power2Round for verification */
void power2round(int32_t r, int32_t *r1, int32_t *r0) {
    r = mod_q(r);
    *r0 = r & ((1 << D) - 1);
    if (*r0 > (1 << (D - 1))) {
        *r0 -= (1 << D);
    }
    *r1 = (r - *r0) >> D;
}

/* Polynomial multiplication */
void poly_mul(poly *c, const poly *a, const poly *b) {
    int64_t temp[2 * N] = {0};

    for (int i = 0; i < N; i++) {
        for (int j = 0; j < N; j++) {
            temp[i + j] += (int64_t)a->coeffs[i] * b->coeffs[j];
        }
    }

    for (int i = N; i < 2 * N - 1; i++) {
        temp[i - N] -= temp[i];
    }

    for (int i = 0; i < N; i++) {
        c->coeffs[i] = mod_q((int32_t)(temp[i] % Q));
    }
}

/* Add polynomials */
void poly_add(poly *c, const poly *a, const poly *b) {
    for (int i = 0; i < N; i++) {
        c->coeffs[i] = mod_q(a->coeffs[i] + b->coeffs[i]);
    }
}

/*
 * Verify key pair consistency
 *
 * Checks:
 * 1. t = A·s1 + s2
 * 2. (t1, t0) = Power2Round(t)
 * 3. Secret coefficients are in valid range
 *
 * Returns: 0 on success, error code on failure
 */
typedef struct {
    int valid;
    int error_code;
    char error_msg[256];
} verification_result;

verification_result verify_keypair(
    const poly A[K][L],        /* Public matrix */
    const polyvecl *s1,        /* Secret vector */
    const polyveck *s2,        /* Secret vector */
    const polyveck *t1,        /* Public t1 */
    const polyveck *t0,        /* Secret t0 */
    int eta                    /* Coefficient bound */
) {
    verification_result result = {1, 0, ""};

    /* Check 1: Verify s1 coefficients are in [-eta, eta] */
    for (int i = 0; i < L; i++) {
        for (int j = 0; j < N; j++) {
            int32_t c = s1->vec[i].coeffs[j];
            /* Handle centered representation */
            if (c > Q/2) c -= Q;
            if (c < -eta || c > eta) {
                result.valid = 0;
                result.error_code = 1;
                snprintf(result.error_msg, sizeof(result.error_msg),
                        "s1[%d][%d] = %d out of range [-%d, %d]",
                        i, j, c, eta, eta);
                return result;
            }
        }
    }

    /* Check 2: Verify s2 coefficients are in [-eta, eta] */
    for (int i = 0; i < K; i++) {
        for (int j = 0; j < N; j++) {
            int32_t c = s2->vec[i].coeffs[j];
            if (c > Q/2) c -= Q;
            if (c < -eta || c > eta) {
                result.valid = 0;
                result.error_code = 2;
                snprintf(result.error_msg, sizeof(result.error_msg),
                        "s2[%d][%d] = %d out of range [-%d, %d]",
                        i, j, c, eta, eta);
                return result;
            }
        }
    }

    /* Check 3: Verify t0 coefficients are in (-2^(d-1), 2^(d-1)] */
    int32_t t0_bound = 1 << (D - 1);
    for (int i = 0; i < K; i++) {
        for (int j = 0; j < N; j++) {
            int32_t c = t0->vec[i].coeffs[j];
            if (c <= -t0_bound || c > t0_bound) {
                result.valid = 0;
                result.error_code = 3;
                snprintf(result.error_msg, sizeof(result.error_msg),
                        "t0[%d][%d] = %d out of range (-%d, %d]",
                        i, j, c, t0_bound, t0_bound);
                return result;
            }
        }
    }

    /* Check 4: Compute t = A·s1 + s2 and verify decomposition */
    for (int i = 0; i < K; i++) {
        poly t_computed;
        memset(t_computed.coeffs, 0, sizeof(t_computed.coeffs));

        /* t_computed = sum_j A[i][j] * s1[j] */
        for (int j = 0; j < L; j++) {
            poly product;
            poly_mul(&product, &A[i][j], &s1->vec[j]);
            poly_add(&t_computed, &t_computed, &product);
        }

        /* t_computed += s2[i] */
        poly_add(&t_computed, &t_computed, &s2->vec[i]);

        /* Verify Power2Round decomposition */
        for (int j = 0; j < N; j++) {
            int32_t r1_expected, r0_expected;
            power2round(t_computed.coeffs[j], &r1_expected, &r0_expected);

            if (r1_expected != t1->vec[i].coeffs[j]) {
                result.valid = 0;
                result.error_code = 4;
                snprintf(result.error_msg, sizeof(result.error_msg),
                        "t1[%d][%d] mismatch: expected %d, got %d",
                        i, j, r1_expected, t1->vec[i].coeffs[j]);
                return result;
            }

            if (r0_expected != t0->vec[i].coeffs[j]) {
                result.valid = 0;
                result.error_code = 5;
                snprintf(result.error_msg, sizeof(result.error_msg),
                        "t0[%d][%d] mismatch: expected %d, got %d",
                        i, j, r0_expected, t0->vec[i].coeffs[j]);
                return result;
            }
        }
    }

    snprintf(result.error_msg, sizeof(result.error_msg),
            "All checks passed");
    return result;
}

/* Demo with test data */
int main(void) {
    printf("Key Pair Verification Demo\n");
    printf("==========================\n\n");

    /* Create simple test data */
    poly A[K][L];
    polyvecl s1;
    polyveck s2, t1, t0;

    /* Initialize with small values for testing */
    for (int i = 0; i < K; i++) {
        for (int j = 0; j < L; j++) {
            for (int c = 0; c < N; c++) {
                A[i][j].coeffs[c] = (i * L + j + c) % Q;
            }
        }
    }

    for (int i = 0; i < L; i++) {
        for (int c = 0; c < N; c++) {
            s1.vec[i].coeffs[c] = (c % 9) - 4;  /* Values in [-4, 4] */
        }
    }

    for (int i = 0; i < K; i++) {
        for (int c = 0; c < N; c++) {
            s2.vec[i].coeffs[c] = ((c + i) % 9) - 4;
        }
    }

    /* Compute t = A*s1 + s2 and decompose */
    for (int i = 0; i < K; i++) {
        poly t_temp;
        memset(t_temp.coeffs, 0, sizeof(t_temp.coeffs));

        for (int j = 0; j < L; j++) {
            poly product;
            poly_mul(&product, &A[i][j], &s1.vec[j]);
            poly_add(&t_temp, &t_temp, &product);
        }
        poly_add(&t_temp, &t_temp, &s2.vec[i]);

        for (int c = 0; c < N; c++) {
            power2round(t_temp.coeffs[c], &t1.vec[i].coeffs[c], &t0.vec[i].coeffs[c]);
        }
    }

    /* Test 1: Valid key pair */
    printf("Test 1: Valid key pair\n");
    verification_result r = verify_keypair(A, &s1, &s2, &t1, &t0, 4);
    printf("  Result: %s\n", r.valid ? "VALID" : "INVALID");
    printf("  Message: %s\n\n", r.error_msg);

    /* Test 2: Corrupt s1 */
    printf("Test 2: Corrupted s1 (coefficient out of range)\n");
    s1.vec[0].coeffs[0] = 10;  /* Out of range for eta=4 */
    r = verify_keypair(A, &s1, &s2, &t1, &t0, 4);
    printf("  Result: %s\n", r.valid ? "VALID" : "INVALID");
    printf("  Message: %s\n\n", r.error_msg);
    s1.vec[0].coeffs[0] = -4;  /* Restore */

    /* Test 3: Corrupt t1 */
    printf("Test 3: Corrupted t1 (wrong decomposition)\n");
    int32_t original_t1 = t1.vec[0].coeffs[0];
    t1.vec[0].coeffs[0] = (original_t1 + 1) % 1024;
    r = verify_keypair(A, &s1, &s2, &t1, &t0, 4);
    printf("  Result: %s\n", r.valid ? "VALID" : "INVALID");
    printf("  Message: %s\n", r.error_msg);

    return 0;
}
