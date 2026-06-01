// poly_mul_naive.c - O(n²) polynomial multiplication
// Source: Module 2, Unit 2.3 - Polynomial Ring Arithmetic in Depth
// Compile: gcc -O2 -o poly_mul_naive poly_mul_naive.c

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

// Naive O(n²) multiplication in Rq = Zq[X]/(X^N + 1)
void poly_mul_schoolbook(poly *r, const poly *a, const poly *b) {
    int64_t temp[2 * N] = {0};

    // Step 1: Standard polynomial multiplication
    for (int i = 0; i < N; i++) {
        for (int j = 0; j < N; j++) {
            temp[i + j] += (int64_t)a->coeffs[i] * b->coeffs[j];
        }
    }

    // Step 2: Reduce mod X^N + 1
    // X^N ≡ -1, so X^(N+k) ≡ -X^k
    for (int i = 0; i < N; i++) {
        r->coeffs[i] = mod_q(temp[i] - temp[i + N]);
    }
}

// Print polynomial (sparse format)
void poly_print(const char *name, const poly *p) {
    printf("%s = ", name);
    int first = 1;
    for (int i = N - 1; i >= 0; i--) {
        if (p->coeffs[i] != 0) {
            if (!first) printf(" + ");
            if (i == 0) printf("%d", p->coeffs[i]);
            else if (i == 1) printf("%dX", p->coeffs[i]);
            else printf("%dX^%d", p->coeffs[i], i);
            first = 0;
            if (i < N - 5 && !first) { printf(" + ..."); break; }
        }
    }
    if (first) printf("0");
    printf("\n");
}

int main(void) {
    poly a = {{0}}, b = {{0}}, r = {{0}};

    // Small example in full ring
    a.coeffs[0] = 3; a.coeffs[1] = 1; a.coeffs[2] = 2;  // 2X² + X + 3
    b.coeffs[0] = 1; b.coeffs[1] = 2; b.coeffs[2] = 1;  // X² + 2X + 1

    printf("Polynomial multiplication in Z_%d[X]/(X^%d + 1):\n\n", Q, N);
    poly_print("a", &a);
    poly_print("b", &b);

    poly_mul_schoolbook(&r, &a, &b);
    poly_print("a × b", &r);

    // Verify: coefficient of X^0 should be 3*1 = 3
    // Coefficient of X^1 should be 3*2 + 1*1 = 7
    // Coefficient of X^2 should be 3*1 + 1*2 + 2*1 = 7
    // Coefficient of X^3 should be 1*1 + 2*2 = 5
    // Coefficient of X^4 should be 2*1 = 2, but wraps to -2 at X^0
    // So final X^0 = 3 - 2 = 1

    printf("\nVerification: const term = %d (expected 3; X^4 does NOT wrap for N=256)\n",
           r.coeffs[0]);

    // Known-answer check of the worked example.  With (2X^2+X+3)(X^2+2X+1):
    //   X^0 = 3*1                = 3
    //   X^1 = 3*2 + 1*1          = 7
    //   X^2 = 3*1 + 1*2 + 2*1    = 7
    //   X^3 = 1*1 + 2*2          = 5
    //   X^4 = 2*1                = 2
    // Since N=256, degree-4 terms stay put (no X^N+1 wraparound here).
    int ok = (r.coeffs[0] == 3) && (r.coeffs[1] == 7) && (r.coeffs[2] == 7) &&
             (r.coeffs[3] == 5) && (r.coeffs[4] == 2);
    printf(ok ? "[PASS] schoolbook product matches hand computation\n"
              : "[FAIL] schoolbook product mismatch\n");

    /* Nonzero exit on failure so the test harness can detect it. */
    return ok ? 0 : 1;
}
