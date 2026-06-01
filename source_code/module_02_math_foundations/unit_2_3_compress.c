// compress.c - ML-KEM compression/decompression
// Source: Module 2, Unit 2.3 - Polynomial Ring Arithmetic in Depth
// Compile: gcc -O2 -o compress compress.c

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define Q 3329

// Compress: [0, Q-1] -> [0, 2^d - 1]
// compress_d(x) = round((2^d / Q) * x) mod 2^d
uint16_t compress(uint16_t x, int d) {
    uint32_t t = ((uint32_t)x << d) + Q / 2;  // Add Q/2 for rounding
    return (t / Q) & ((1 << d) - 1);
}

// Decompress: [0, 2^d - 1] -> [0, Q-1]
// decompress_d(y) = round((Q / 2^d) * y)
uint16_t decompress(uint16_t y, int d) {
    uint32_t t = ((uint32_t)y * Q) + (1 << (d - 1));  // Add 2^(d-1) for rounding
    return (t >> d) % Q;
}

int main(void) {
    printf("Compression/Decompression Examples (Q = %d)\n\n", Q);

    // Test different d values
    int d_values[] = {4, 10, 12};
    uint16_t test_values[] = {0, 100, 500, 1500, 2500, 3328};

    for (int di = 0; di < 3; di++) {
        int d = d_values[di];
        printf("d = %d (range [0, %d]):\n", d, (1 << d) - 1);

        for (int vi = 0; vi < 6; vi++) {
            uint16_t x = test_values[vi];
            uint16_t c = compress(x, d);
            uint16_t x_prime = decompress(c, d);
            int error = (int)x - (int)x_prime;

            printf("  %4d -> %4d -> %4d  (error: %+4d)\n", x, c, x_prime, error);
        }
        printf("\n");
    }

    // Show maximum error for each d
    printf("Maximum compression error analysis:\n");
    int ok = 1;
    for (int di = 0; di < 3; di++) {
        int d = d_values[di];
        int max_error = 0;

        for (int x = 0; x < Q; x++) {
            uint16_t c = compress(x, d);
            uint16_t x_prime = decompress(c, d);
            // Measure the error AS A DISTANCE MODULO Q (centered).  The raw
            // |x - x'| over-counts the wraparound boundary: e.g. x = Q-1
            // compresses to 0, and decompress(0) = 0, which is correct because
            // Q-1 ≡ -1 is the *nearest* representative to 0 mod Q.  The true
            // round-trip error is therefore min(|x-x'|, Q-|x-x'|).
            int diff = abs((int)x - (int)x_prime);
            int error = diff < Q - diff ? diff : Q - diff;
            if (error > max_error) max_error = error;
        }

        int theoretical = Q / (1 << (d + 1));
        printf("  d = %2d: max error = %d (theoretical: ~%d)\n",
               d, max_error, theoretical);
        // With the modular (centered) metric the round-trip error is bounded by
        // the quantization half-step; allow a small +1 slack for the asymmetric
        // integer rounding in compress()/decompress().
        if (max_error > theoretical + 1) ok = 0;
    }

    printf(ok ? "[PASS] compression error within theoretical bound\n"
              : "[FAIL] compression error exceeded theoretical bound\n");

    /* Nonzero exit on failure so the test harness can detect it. */
    return ok ? 0 : 1;
}
