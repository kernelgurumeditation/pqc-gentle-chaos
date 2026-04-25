#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

#define NUM_SAMPLES 10000

// Get high-resolution timestamp
static inline uint64_t rdtsc(void) {
    unsigned int lo, hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}

// Stub function for demonstration
// In real testing, replace with actual crypto function
static int function_under_test(const uint8_t *secret, size_t len) {
    volatile int sum = 0;  // volatile to prevent optimization
    for (size_t i = 0; i < len; i++) {
        sum += secret[i];
    }
    return sum;
}

void timing_test(void) {
    uint64_t times_zero[NUM_SAMPLES];
    uint64_t times_random[NUM_SAMPLES];

    uint8_t secret_zero[32] = {0};
    uint8_t secret_random[32];

    // Generate random secret
    for (int i = 0; i < 32; i++) {
        secret_random[i] = rand() & 0xFF;
    }

    // Collect timing samples
    for (int i = 0; i < NUM_SAMPLES; i++) {
        uint64_t start = rdtsc();
        function_under_test(secret_zero, 32);
        times_zero[i] = rdtsc() - start;

        start = rdtsc();
        function_under_test(secret_random, 32);
        times_random[i] = rdtsc() - start;
    }

    // Compute statistics
    double avg_zero = 0, avg_random = 0;
    for (int i = 0; i < NUM_SAMPLES; i++) {
        avg_zero += times_zero[i];
        avg_random += times_random[i];
    }
    avg_zero /= NUM_SAMPLES;
    avg_random /= NUM_SAMPLES;

    double var_zero = 0, var_random = 0;
    for (int i = 0; i < NUM_SAMPLES; i++) {
        var_zero += (times_zero[i] - avg_zero) * (times_zero[i] - avg_zero);
        var_random += (times_random[i] - avg_random) * (times_random[i] - avg_random);
    }
    var_zero /= NUM_SAMPLES;
    var_random /= NUM_SAMPLES;

    printf("Zero input:   avg = %.2f cycles, var = %.2f\n", avg_zero, var_zero);
    printf("Random input: avg = %.2f cycles, var = %.2f\n", avg_random, var_random);
    printf("Difference:   %.2f cycles (%.2f%%)\n",
           avg_random - avg_zero,
           100.0 * (avg_random - avg_zero) / avg_zero);

    // t-test for significance
    double t = (avg_random - avg_zero) /
               sqrt(var_zero/NUM_SAMPLES + var_random/NUM_SAMPLES);
    printf("t-statistic: %.2f (should be < 2 for constant time)\n", fabs(t));
}

int main(void) {
    printf("=== Constant-Time Testing Framework ===\n");
    printf("Demonstrating timing analysis with stub function.\n");
    printf("Replace function_under_test() with actual crypto code for real testing.\n\n");

    srand(time(NULL));
    timing_test();

    return 0;
}
