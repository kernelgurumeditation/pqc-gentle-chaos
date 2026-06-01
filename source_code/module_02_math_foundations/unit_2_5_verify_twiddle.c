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

    // The zetas[] table in ntt.c stores the twiddle factors in Montgomery form,
    // i.e. (ζ^brv(i) * R) mod Q with R = 2^16 mod Q = 2285. To compare against
    // that table we must map our raw ζ^brv(i) into the same Montgomery domain.
    const uint64_t MONT_R = 2285;  // 2^16 mod 3329

    // Expected values are zetas[1..5] from the Montgomery table in ntt.c.
    // (zetas[0] = 2285 is the Montgomery form of zeta^0 = 1; the NTT butterfly
    //  loop uses zetas[1] onward, so we verify the twiddle factors it consumes.)
    int16_t expected[] = {2571, 2970, 1812, 1493, 1422};

    int fails = 0;
    for (int i = 1; i <= 5; i++) {
        unsigned int exp = brv(i);
        uint64_t raw = mod_exp(ZETA, exp, Q);
        // Convert the raw value into Montgomery form to match the table.
        uint64_t computed = (raw * MONT_R) % Q;

        const char *verdict = (computed == (uint64_t)expected[i-1]) ? "PASS" : "FAIL";
        if (computed != (uint64_t)expected[i-1]) fails++;

        printf("i=%d, brv(i)=%3d, raw ζ^brv(i) = %4lu, Montgomery = %4lu "
               "(expected in table: %d) [%s]\n",
               i, exp, raw, computed, expected[i-1], verdict);
    }

    printf("\n%s\n", fails == 0 ? "VERDICT: ALL PASS" : "VERDICT: FAIL");
    return fails == 0 ? 0 : 1;
}
