// unit_2_1_mod_basic.c - Basic modular arithmetic operations
// From: PQC Learning Plan - Unit 2.1: Modular Arithmetic Mastery
// Compile: gcc -o unit_2_1_mod_basic unit_2_1_mod_basic.c

#include <stdint.h>
#include <stdio.h>

// Reduce a to range [0, q-1]
// Handles negative inputs correctly
static inline int32_t mod_reduce(int32_t a, int32_t q) {
    int32_t r = a % q;
    // In C, % can return negative values for negative a
    return r < 0 ? r + q : r;
}

// Reduce a to centered range [-(q-1)/2, (q-1)/2]
static inline int32_t mod_reduce_centered(int32_t a, int32_t q) {
    int32_t r = mod_reduce(a, q);
    if (r > q / 2) {
        r -= q;
    }
    return r;
}

// Modular addition
static inline int32_t mod_add(int32_t a, int32_t b, int32_t q) {
    return mod_reduce(a + b, q);
}

// Modular subtraction
static inline int32_t mod_sub(int32_t a, int32_t b, int32_t q) {
    return mod_reduce(a - b, q);
}

// Modular multiplication
static inline int32_t mod_mul(int32_t a, int32_t b, int32_t q) {
    // Use int64_t to avoid overflow for large q
    return (int32_t)(((int64_t)a * b) % q);
}

// Test the functions
int main(void) {
    int32_t q = 97;

    // Example from Worked Example 2.1.2
    int32_t result = mod_add(mod_mul(17, 23, q), 45, q);
    printf("(17 × 23 + 45) mod 97 = %d\n", result);

    // Test centered reduction
    printf("\nCentered representatives mod 7:\n");
    int32_t values[] = {-15, -8, 6, 13, 20};
    for (int i = 0; i < 5; i++) {
        printf("%d -> standard: %d, centered: %d\n",
               values[i],
               mod_reduce(values[i], 7),
               mod_reduce_centered(values[i], 7));
    }

    return 0;
}
