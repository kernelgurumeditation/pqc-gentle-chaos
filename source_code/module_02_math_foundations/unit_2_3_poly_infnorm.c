// poly_infnorm.c - Compute infinity norm of polynomial
// Source: Module 2, Unit 2.3 - Polynomial Ring Arithmetic in Depth (Exercise 2.3.7)
// Compile: gcc -o poly_infnorm poly_infnorm.c

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define N 256
#define Q 3329

typedef struct {
    int16_t coeffs[N];
} poly;

// Compute infinity norm (max |coeff| using centered representation)
int16_t poly_infnorm(const poly *p) {
    int16_t max = 0;
    for (int i = 0; i < N; i++) {
        int16_t c = p->coeffs[i];
        // Center: if c > Q/2, use c - Q
        if (c > Q / 2) c = c - Q;
        // Take absolute value
        if (c < 0) c = -c;
        if (c > max) max = c;
    }
    return max;
}

int main(void) {
    poly p = {{0}};

    // Test with some values
    p.coeffs[0] = 100;      // |100| = 100
    p.coeffs[1] = 3300;     // |3300 - 3329| = |-29| = 29
    p.coeffs[2] = 1664;     // |1664| = 1664 (just under Q/2)
    p.coeffs[3] = 1665;     // |1665 - 3329| = |-1664| = 1664

    printf("Infinity norm: %d\n", poly_infnorm(&p));
    printf("Expected: 1664\n");

    return 0;
}
