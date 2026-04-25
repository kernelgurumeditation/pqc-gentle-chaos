// cbd.c - Centered Binomial Distribution sampling
// Source: Module 2, Unit 2.6 - Probability and Distributions
// Compile: gcc -O2 -o cbd cbd.c

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define N 256
#define ETA 2  // ML-KEM-768 uses η=2

typedef struct {
    int16_t coeffs[N];
} poly;

// Sample polynomial from CBD_η
// For η=2: each coefficient needs 4 bits (2 for a, 2 for b)
// 256 coefficients × 4 bits = 1024 bits = 128 bytes
void poly_cbd_eta2(poly *r, const uint8_t buf[128]) {
    for (int i = 0; i < N / 2; i++) {
        uint8_t byte = buf[i];

        // First coefficient from lower 4 bits
        uint8_t a0 = (byte >> 0) & 1;
        uint8_t a1 = (byte >> 1) & 1;
        uint8_t b0 = (byte >> 2) & 1;
        uint8_t b1 = (byte >> 3) & 1;
        r->coeffs[2*i] = (a0 + a1) - (b0 + b1);

        // Second coefficient from upper 4 bits
        a0 = (byte >> 4) & 1;
        a1 = (byte >> 5) & 1;
        b0 = (byte >> 6) & 1;
        b1 = (byte >> 7) & 1;
        r->coeffs[2*i + 1] = (a0 + a1) - (b0 + b1);
    }
}

// Constant-time version (no branching on secret data)
void poly_cbd_eta2_ct(poly *r, const uint8_t buf[128]) {
    for (int i = 0; i < N / 2; i++) {
        uint32_t t = buf[i];

        // Extract pairs of bits
        uint32_t d = t & 0x55555555u;  // Even bits
        d += (t >> 1) & 0x55555555u;   // Add odd bits

        // Now d contains 4 2-bit sums in the lower byte
        int16_t a = (d >> 0) & 3;
        int16_t b = (d >> 2) & 3;
        r->coeffs[2*i] = a - b;

        a = (d >> 4) & 3;
        b = (d >> 6) & 3;
        r->coeffs[2*i + 1] = a - b;
    }
}

int main(void) {
    uint8_t buf[128];
    poly p;

    // Fill with pseudo-random data
    for (int i = 0; i < 128; i++) {
        buf[i] = rand() & 0xFF;
    }

    poly_cbd_eta2(&p, buf);

    // Count distribution
    int counts[5] = {0};  // For values -2, -1, 0, 1, 2
    for (int i = 0; i < N; i++) {
        counts[p.coeffs[i] + 2]++;
    }

    printf("CBD_2 distribution over %d samples:\n", N);
    printf("Value | Count | Observed | Expected\n");
    printf("------+-------+----------+---------\n");
    float expected[] = {1.0/16, 4.0/16, 6.0/16, 4.0/16, 1.0/16};
    for (int v = -2; v <= 2; v++) {
        printf("  %+d  |  %3d  |  %.3f   |  %.3f\n",
               v, counts[v+2],
               (float)counts[v+2]/N,
               expected[v+2]);
    }

    return 0;
}
