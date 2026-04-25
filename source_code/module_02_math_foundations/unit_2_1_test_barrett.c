// test_barrett.c
// Source: Module 2, Unit 2.1 - Modular Arithmetic Mastery (Exercise 2.1.12)
// Compile: gcc -o test_barrett test_barrett.c

#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>

#define Q 3329
#define BARRETT_MU 20159
#define BARRETT_SHIFT 26

int16_t barrett_reduce(int32_t a) {
    int32_t t = ((int64_t)a * BARRETT_MU) >> BARRETT_SHIFT;
    t = a - t * Q;
    // Constant-time correction
    int32_t mask = (Q - 1 - t) >> 31;  // -1 if t >= Q, 0 otherwise
    t -= Q & mask;
    return (int16_t)t;
}

int main(void) {
    int64_t max_val = (int64_t)Q * Q;
    int errors = 0;

    printf("Testing Barrett reduction for all a in [0, %" PRId64 ")...\n", max_val);

    for (int64_t a = 0; a < max_val; a++) {
        int16_t barrett = barrett_reduce((int32_t)a);
        int16_t naive = (int16_t)(a % Q);

        if (barrett != naive) {
            if (errors < 10) {
                printf("ERROR: barrett_reduce(%" PRId64 ") = %d, expected %d\n",
                       a, barrett, naive);
            }
            errors++;
        }

        // Progress indicator
        if (a % 1000000 == 0) {
            printf("Progress: %.1f%% (%" PRId64 " / %" PRId64 ")\r",
                   100.0 * a / max_val, a, max_val);
            fflush(stdout);
        }
    }

    printf("\n\nTest complete. %d errors found out of %" PRId64 " values.\n",
           errors, max_val);

    if (errors == 0) {
        printf("SUCCESS: Barrett reduction is correct for all inputs!\n");
    }

    return errors > 0 ? 1 : 0;
}
