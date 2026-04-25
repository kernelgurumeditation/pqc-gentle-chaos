// check_inverse.c
// Source: Module 2, Unit 2.2 - Algebraic Structures for Cryptography (Exercise 2.2.9)
// Compile: gcc -o check_inverse check_inverse.c

#include <stdint.h>
#include <stdio.h>

// Extended GCD
int32_t extended_gcd(int32_t a, int32_t b, int32_t *x, int32_t *y) {
    if (b == 0) {
        *x = 1;
        *y = 0;
        return a;
    }
    int32_t x1, y1;
    int32_t g = extended_gcd(b, a % b, &x1, &y1);
    *x = y1;
    *y = x1 - (a / b) * y1;
    return g;
}

// Returns inverse of a mod n, or -1 if no inverse exists
// Also sets *has_inverse to 1 or 0
int32_t find_inverse(int32_t a, int32_t n, int *has_inverse) {
    int32_t x, y;
    int32_t g = extended_gcd(a, n, &x, &y);

    if (g != 1) {
        *has_inverse = 0;
        return -1;
    }

    *has_inverse = 1;
    int32_t inv = x % n;
    if (inv < 0) inv += n;
    return inv;
}

int main(void) {
    int test_cases[][2] = {
        {3, 7},    // 3 in Z_7 (prime, has inverse)
        {2, 6},    // 2 in Z_6 (gcd=2, no inverse)
        {5, 12},   // 5 in Z_12 (gcd=1, has inverse)
        {4, 12},   // 4 in Z_12 (gcd=4, no inverse)
        {17, 3329} // 17 in Z_3329 (ML-KEM modulus)
    };

    printf("Testing multiplicative inverses in Z_n:\n\n");

    for (int i = 0; i < 5; i++) {
        int32_t a = test_cases[i][0];
        int32_t n = test_cases[i][1];
        int has_inv;
        int32_t inv = find_inverse(a, n, &has_inv);

        printf("%d in Z_%d: ", a, n);
        if (has_inv) {
            printf("inverse = %d", inv);
            printf(" (verify: %d × %d = %d ≡ %d mod %d)\n",
                   a, inv, a * inv, (a * inv) % n, n);
        } else {
            printf("NO INVERSE (gcd(%d, %d) ≠ 1)\n", a, n);
        }
    }

    return 0;
}
