// barrett.c - Barrett reduction for q = 3329
// Source: Module 2, Unit 2.1 - Modular Arithmetic Mastery
// Compile: gcc -O2 -o barrett barrett.c

#include <stdint.h>
#include <stdio.h>

#define KYBER_Q 3329

// Precomputed constant for Barrett reduction
// We use k = 26: μ = round(2^26 / 3329) = 20159  (floor would be 20158)
#define BARRETT_MU 20159
#define BARRETT_SHIFT 26

// Barrett reduction: reduce a to [0, q-1]
// Input: |a| < 2^15 * q (safe range for single conditional subtraction)
// Output: a mod q
// Constant-time: always performs same operations
static inline int16_t barrett_reduce(int32_t a) {
    int32_t t;

    // t = floor(a * μ / 2^26) ≈ floor(a / q)
    t = ((int64_t)a * BARRETT_MU) >> BARRETT_SHIFT;

    // a - t*q should be close to a mod q
    // May need one final subtraction
    t = a - t * KYBER_Q;

    // Constant-time conditional subtraction
    // If t >= q, subtract q
    t -= KYBER_Q & ((KYBER_Q - 1 - t) >> 31);

    return (int16_t)t;
}

// Constant-time comparison: returns 1 if a >= b, 0 otherwise
static inline int32_t ct_ge(int32_t a, int32_t b) {
    return 1 - (((uint32_t)(a - b)) >> 31);
}

// Alternative: Montgomery reduction (used in many NTT implementations)
// R = 2^16, R^{-1} mod q = 169, q^{-1} mod R = 62209

#define MONT_R 65536
#define MONT_RINV 169      // R^{-1} mod q
#define MONT_QINV 62209    // q^{-1} mod R  (as int16_t: -3327)

// Convert to Montgomery form: a -> a*R mod q
static inline int16_t to_mont(int16_t a) {
    return barrett_reduce((int32_t)a * MONT_R);
}

// Montgomery reduction: compute a*R^{-1} mod q
// Input: a in [0, q*R)
static inline int16_t mont_reduce(int32_t a) {
    int32_t t;

    // t = a * q^{-1} mod R  (int16_t cast takes low 16 bits, effectively -3327)
    t = (int16_t)((uint32_t)a * MONT_QINV);

    // t = (a - t*q) / R  (reference Kyber uses subtraction)
    t = (a - (int32_t)t * KYBER_Q) >> 16;

    // May need to add q once (result may be negative)
    t += KYBER_Q & ((KYBER_Q - 1 - t) >> 31);

    return (int16_t)t;
}

int main(void) {
    printf("Barrett Reduction Tests (q = %d):\n\n", KYBER_Q);

    int failures = 0;

    // Test Barrett reduction
    int32_t test_values[] = {0, 1, 3328, 3329, 3330, 10000, 100000};

    for (int i = 0; i < 7; i++) {
        int32_t a = test_values[i];
        int16_t reduced = barrett_reduce(a);
        printf("barrett_reduce(%d) = %d", a, reduced);
        printf(" (expected: %d)\n", a % KYBER_Q);
        // Compare congruence mod q (representative may differ).
        if ((((int32_t)reduced % KYBER_Q) + KYBER_Q) % KYBER_Q != a % KYBER_Q)
            failures++;
    }

    printf("\nMontgomery Form Tests:\n");
    // Convert to Montgomery form and back
    for (int16_t a = 0; a < 10; a++) {
        int16_t mont_a = to_mont(a);
        printf("to_mont(%d) = %d, ", a, mont_a);
        printf("expected: %d\n", ((int32_t)a * MONT_R) % KYBER_Q);
        if ((((int32_t)mont_a % KYBER_Q) + KYBER_Q) % KYBER_Q !=
            ((int32_t)a * MONT_R) % KYBER_Q)
            failures++;
    }

    if (failures == 0) {
        printf("\n[PASS] Barrett and Montgomery results match expected\n");
    } else {
        printf("\n[FAIL] %d reduction result(s) mismatched\n", failures);
    }

    /* Nonzero exit on failure so the test harness can detect it. */
    return failures == 0 ? 0 : 1;
}
