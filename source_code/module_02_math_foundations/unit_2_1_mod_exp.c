// mod_exp.c - Square-and-multiply modular exponentiation
// Source: Module 2, Unit 2.1 - Modular Arithmetic Mastery
// Compile: gcc -o mod_exp mod_exp.c

#include <stdint.h>
#include <stdio.h>

// Modular exponentiation: compute base^exp mod mod
// Uses square-and-multiply (right-to-left binary method)
uint64_t mod_exp(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t result = 1;
    base = base % mod;

    while (exp > 0) {
        // If exp is odd, multiply result by base
        if (exp & 1) {
            result = (result * base) % mod;
        }
        // Square base and halve exp
        exp = exp >> 1;
        base = (base * base) % mod;
    }

    return result;
}

// Version using __uint128_t to handle larger moduli safely
uint64_t mod_exp_safe(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t result = 1;
    base = base % mod;

    while (exp > 0) {
        if (exp & 1) {
            result = ((__uint128_t)result * base) % mod;
        }
        exp = exp >> 1;
        base = ((__uint128_t)base * base) % mod;
    }

    return result;
}

int main(void) {
    // Example from Worked Example 2.1.4
    printf("3^20 mod 97 = %lu\n", mod_exp(3, 20, 97));

    // Larger example relevant to ML-KEM
    // In ML-KEM, q = 3329 and we need to find primitive roots
    uint64_t q = 3329;

    // Check if 17 is a primitive 256th root of unity mod 3329
    // Need: 17^128 ≡ -1 (mod 3329) and 17^256 ≡ 1 (mod 3329)
    // Note: 3328 = 2^8 * 13, so the max power-of-2 order is 256
    uint64_t r128 = mod_exp(17, 128, q);
    printf("\n17^128 mod 3329 = %lu", r128);
    printf(" (should be %lu = -1 mod 3329)\n", q - 1);

    // Verify: 17^256 ≡ 1 (mod 3329)
    uint64_t r256 = mod_exp(17, 256, q);
    printf("17^256 mod 3329 = %lu (should be 1)\n", r256);

    // Known-answer checks: 3^20 mod 97 = 91, 17^128 ≡ -1 (= q-1), 17^256 ≡ 1.
    int ok = (mod_exp(3, 20, 97) == 91) && (r128 == q - 1) && (r256 == 1);
    if (ok) {
        printf("\n[PASS] modular exponentiation known-answer checks hold\n");
    } else {
        printf("\n[FAIL] modular exponentiation known-answer check failed\n");
    }

    /* Nonzero exit on failure so the test harness can detect it. */
    return ok ? 0 : 1;
}
