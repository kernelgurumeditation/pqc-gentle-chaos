// verify_twiddle.c - Verify twiddle factors
// Source: Module 2, Unit 2.5 - Number Theoretic Transform (NTT) (Exercise 2.5.4)
// Compile: gcc -o verify_twiddle verify_twiddle.c

#include <stdint.h>
#include <stdio.h>

#define Q 3329
#define ZETA 17

uint64_t mod_exp(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t result = 1;
    base %= mod;
    while (exp > 0) {
        if (exp & 1) result = (result * base) % mod;
        exp >>= 1;
        base = (base * base) % mod;
    }
    return result;
}

// Bit reversal for 7 bits (indices 0-127)
unsigned int brv(unsigned int x) {
    unsigned int r = 0;
    for (int i = 0; i < 7; i++) {
        r = (r << 1) | (x & 1);
        x >>= 1;
    }
    return r;
}

int main(void) {
    printf("Verifying twiddle factors ζ^brv(i) mod %d:\n", Q);
    printf("ζ = %d\n\n", ZETA);

    int16_t expected[] = {2285, 2571, 2970, 1812, 1493};

    for (int i = 1; i <= 5; i++) {
        unsigned int exp = brv(i);
        uint64_t computed = mod_exp(ZETA, exp, Q);

        // Note: twiddle factors may be stored in Montgomery form
        // Let's compute raw value
        printf("i=%d, brv(i)=%3d, ζ^brv(i) = %4lu (expected in table: %d)\n",
               i, exp, computed, expected[i-1]);
    }

    return 0;
}
