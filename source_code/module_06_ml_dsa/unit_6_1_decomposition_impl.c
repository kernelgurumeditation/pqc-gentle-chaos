/*
 * Source: Module 6, Unit 6.1 - ML-DSA Structure (Exercise 6.1.4)
 * From: PQC Learning Plan, lines 14966-15125
 *
 * ML-DSA-65 Decomposition Implementation
 * Implements HighBits and LowBits decomposition functions
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define Q 8380417
#define GAMMA2 ((Q - 1) / 32)  /* 261888 */
#define ALPHA (2 * GAMMA2)      /* 523776 */

/*
 * Power2Round: Decompose r into (r1, r0) where r = r1·2^d + r0
 * Used for t = t1·2^d + t0 decomposition
 */
void power2round(int32_t r, int32_t *r1, int32_t *r0, int d) {
    /* Ensure r is positive */
    r = r % Q;
    if (r < 0) r += Q;

    /* r0 = r mod 2^d (centered) */
    *r0 = r & ((1 << d) - 1);
    if (*r0 > (1 << (d-1))) {
        *r0 -= (1 << d);
    }

    /* r1 = (r - r0) / 2^d */
    *r1 = (r - *r0) >> d;
}

/*
 * Decompose: Split r into high and low parts for signing
 * Returns (r1, r0) such that r = r1·α + r0 with r0 small
 */
void decompose(int32_t r, int32_t *r1, int32_t *r0) {
    /* Ensure r is in [0, q) */
    r = r % Q;
    if (r < 0) r += Q;

    /* Compute r1 = ceiling((r - (α-1)/2) / α) */
    *r1 = (r + ALPHA/2) / ALPHA;

    /* Handle wrap-around at q boundary */
    /* Number of possible high values = (q-1)/α = 16 for GAMMA2 = (q-1)/32 */
    int32_t m = (Q - 1) / ALPHA;  /* = 16 */
    if (*r1 > m) *r1 = 0;

    /* Compute r0 = r - r1·α (centered) */
    *r0 = r - (*r1) * ALPHA;

    /* Center r0 in (-α/2, α/2] */
    if (*r0 > ALPHA/2) {
        *r0 -= ALPHA;
        *r1 = (*r1 + 1) % (m + 1);
    }
    if (*r0 <= -ALPHA/2) {
        *r0 += ALPHA;
        *r1 = (*r1 - 1 + m + 1) % (m + 1);
    }
}

/*
 * HighBits: Extract high part of decomposition
 */
int32_t highbits(int32_t r) {
    int32_t r1, r0;
    decompose(r, &r1, &r0);
    return r1;
}

/*
 * LowBits: Extract low part of decomposition
 */
int32_t lowbits(int32_t r) {
    int32_t r1, r0;
    decompose(r, &r1, &r0);
    return r0;
}

/*
 * Verify reconstruction: r1·α + r0 ≡ r (mod q)
 */
int verify_decomposition(int32_t r) {
    int32_t r1 = highbits(r);
    int32_t r0 = lowbits(r);

    int64_t reconstructed = ((int64_t)r1 * ALPHA + r0) % Q;
    if (reconstructed < 0) reconstructed += Q;

    int32_t r_normalized = r % Q;
    if (r_normalized < 0) r_normalized += Q;

    return reconstructed == r_normalized;
}

int main(void) {
    printf("ML-DSA-65 Decomposition Implementation\n");
    printf("======================================\n\n");

    printf("Parameters:\n");
    printf("  q = %d\n", Q);
    printf("  γ2 = (q-1)/32 = %d\n", GAMMA2);
    printf("  α = 2·γ2 = %d\n", ALPHA);
    printf("  Number of high values = (q-1)/α = %d\n\n", (Q-1)/ALPHA);

    /* Test specific values */
    printf("Testing specific values:\n");
    int32_t test_values[] = {0, 1, Q/2, Q-1, ALPHA, ALPHA-1, ALPHA+1,
                             GAMMA2, 2*GAMMA2, 5000000, 8000000};
    int num_tests = sizeof(test_values) / sizeof(test_values[0]);

    for (int i = 0; i < num_tests; i++) {
        int32_t r = test_values[i];
        int32_t r1 = highbits(r);
        int32_t r0 = lowbits(r);
        int ok = verify_decomposition(r);

        printf("  r = %8d: r1 = %2d, r0 = %8d, r1·α + r0 = %d %s\n",
               r, r1, r0, (int)((int64_t)r1 * ALPHA + r0), ok ? "✓" : "✗");
    }

    /* Test random values */
    printf("\nTesting 10000 random values...\n");
    srand(time(NULL));

    int failures = 0;
    for (int i = 0; i < 10000; i++) {
        int32_t r = rand() % Q;
        if (!verify_decomposition(r)) {
            failures++;
            printf("  FAILED for r = %d\n", r);
        }

        /* Also verify r0 is in correct range */
        int32_t r0 = lowbits(r);
        if (r0 < -ALPHA/2 || r0 > ALPHA/2) {
            printf("  r0 out of range for r = %d: r0 = %d\n", r, r0);
            failures++;
        }
    }

    if (failures == 0) {
        printf("  All tests passed! ✓\n");
    } else {
        printf("  %d failures\n", failures);
    }

    /* Demonstrate the range of r0 */
    printf("\nRange verification:\n");
    printf("  r0 should be in (-%d, %d] = (-α/2, α/2]\n", ALPHA/2, ALPHA/2);

    int32_t min_r0 = ALPHA, max_r0 = -ALPHA;
    for (int32_t r = 0; r < Q; r += Q/1000) {
        int32_t r0 = lowbits(r);
        if (r0 < min_r0) min_r0 = r0;
        if (r0 > max_r0) max_r0 = r0;
    }
    printf("  Observed r0 range: [%d, %d]\n", min_r0, max_r0);

    return 0;
}
