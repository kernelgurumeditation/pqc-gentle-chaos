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
    for (int di = 0; di < 3; di++) {
        int d = d_values[di];
        int max_error = 0;

        for (int x = 0; x < Q; x++) {
            uint16_t c = compress(x, d);
            uint16_t x_prime = decompress(c, d);
            int error = abs((int)x - (int)x_prime);
            if (error > max_error) max_error = error;
        }

        printf("  d = %2d: max error = %d (theoretical: ~%d)\n",
               d, max_error, Q / (1 << (d + 1)));
    }

    return 0;
}
