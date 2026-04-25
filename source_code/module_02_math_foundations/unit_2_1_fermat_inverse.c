// fermat_inverse.c
// Source: Module 2, Unit 2.1 - Modular Arithmetic Mastery (Exercise 2.1.11)
// Compile: gcc -o fermat_inverse fermat_inverse.c

#include <stdint.h>
#include <stdio.h>
#include <time.h>

// Modular exponentiation
uint32_t mod_exp(uint32_t base, uint32_t exp, uint32_t mod) {
    uint64_t result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp & 1) result = (result * base) % mod;
        exp >>= 1;
        base = ((uint64_t)base * base) % mod;
    }
    return (uint32_t)result;
}

// Fermat's method: a^(-1) = a^(p-2) mod p
uint32_t fermat_inverse(uint32_t a, uint32_t p) {
    return mod_exp(a, p - 2, p);
}

// Extended GCD method
int32_t extended_gcd(int32_t a, int32_t b, int32_t *x, int32_t *y) {
    if (b == 0) { *x = 1; *y = 0; return a; }
    int32_t x1, y1;
    int32_t g = extended_gcd(b, a % b, &x1, &y1);
    *x = y1;
    *y = x1 - (a / b) * y1;
    return g;
}

uint32_t egcd_inverse(uint32_t a, uint32_t p) {
    int32_t x, y;
    extended_gcd(a, p, &x, &y);
    return (x % (int32_t)p + p) % p;
}

int main(void) {
    uint32_t p = 3329;

    // Verify both methods give same result
    printf("Verification:\n");
    for (uint32_t a = 1; a <= 10; a++) {
        uint32_t f = fermat_inverse(a, p);
        uint32_t e = egcd_inverse(a, p);
        printf("%d^(-1) mod %d: Fermat=%d, EGCD=%d, match=%s\n",
               a, p, f, e, (f == e) ? "yes" : "NO");
    }

    // Performance comparison
    printf("\nPerformance (1,000,000 inversions):\n");

    clock_t start = clock();
    for (int i = 0; i < 1000000; i++) {
        fermat_inverse((i % 3328) + 1, p);
    }
    printf("Fermat: %.3f seconds\n",
           (double)(clock() - start) / CLOCKS_PER_SEC);

    start = clock();
    for (int i = 0; i < 1000000; i++) {
        egcd_inverse((i % 3328) + 1, p);
    }
    printf("EGCD:   %.3f seconds\n",
           (double)(clock() - start) / CLOCKS_PER_SEC);

    return 0;
}
