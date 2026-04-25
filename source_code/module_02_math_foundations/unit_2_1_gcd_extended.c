// extended_gcd.c - Extended Euclidean Algorithm
// Source: Module 2, Unit 2.1 - Modular Arithmetic Mastery
// Compile: gcc -o extended_gcd extended_gcd.c

#include <stdint.h>
#include <stdio.h>

// Extended GCD: returns gcd and sets x, y such that ax + by = gcd(a, b)
// Uses iterative version (avoids stack overflow for large inputs)
int32_t extended_gcd(int32_t a, int32_t b, int32_t *x, int32_t *y) {
    int32_t x0 = 1, x1 = 0;
    int32_t y0 = 0, y1 = 1;

    while (b != 0) {
        int32_t q = a / b;
        int32_t r = a % b;

        a = b;
        b = r;

        int32_t x_new = x0 - q * x1;
        x0 = x1;
        x1 = x_new;

        int32_t y_new = y0 - q * y1;
        y0 = y1;
        y1 = y_new;
    }

    *x = x0;
    *y = y0;
    return a;  // gcd
}

// Compute modular inverse of a modulo m
// Returns -1 if inverse doesn't exist
int32_t mod_inverse(int32_t a, int32_t m) {
    int32_t x, y;
    int32_t gcd = extended_gcd(a, m, &x, &y);

    if (gcd != 1) {
        return -1;  // No inverse exists
    }

    // Ensure result is positive
    int32_t result = x % m;
    if (result < 0) result += m;
    return result;
}

int main(void) {
    // Example from Worked Example 2.1.3
    int32_t a = 17, m = 97;
    int32_t x, y;

    int32_t gcd = extended_gcd(a, m, &x, &y);
    printf("Extended GCD:\n");
    printf("gcd(%d, %d) = %d\n", a, m, gcd);
    printf("%d × %d + %d × %d = %d\n", a, x, m, y, a*x + m*y);

    int32_t inv = mod_inverse(a, m);
    printf("\n%d⁻¹ mod %d = %d\n", a, m, inv);
    printf("Verify: %d × %d = %d ≡ %d (mod %d)\n",
           a, inv, a * inv, (a * inv) % m, m);

    // Test with non-coprime values
    printf("\n6⁻¹ mod 9 = %d (should be -1, no inverse)\n",
           mod_inverse(6, 9));

    return 0;
}
