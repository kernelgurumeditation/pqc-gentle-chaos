// polyvec_infnorm.c - L∞ norm of polynomial vector
// Source: Module 2, Unit 2.4 - Linear Algebra for Lattices (Exercise 2.4.5)
// Compile: gcc -o polyvec_infnorm polyvec_infnorm.c

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define N 256
#define Q 3329
#define K 3

typedef struct { int16_t coeffs[N]; } poly;
typedef struct { poly vec[K]; } polyvec;

// L∞ norm of a single polynomial (centered coefficients)
int16_t poly_infnorm(const poly *p) {
    int16_t max = 0;
    for (int i = 0; i < N; i++) {
        int16_t c = p->coeffs[i];
        // Center: if c > Q/2, use c - Q
        if (c > Q / 2) c = c - Q;
        if (c < 0) c = -c;
        if (c > max) max = c;
    }
    return max;
}

// L∞ norm of a polynomial vector
int16_t polyvec_infnorm(const polyvec *v) {
    int16_t max = 0;
    for (int i = 0; i < K; i++) {
        int16_t norm = poly_infnorm(&v->vec[i]);
        if (norm > max) max = norm;
    }
    return max;
}

int main(void) {
    polyvec v = {0};

    // Set some test values
    v.vec[0].coeffs[0] = 3;
    v.vec[0].coeffs[1] = Q - 5;  // = -5 centered
    v.vec[1].coeffs[0] = 10;
    v.vec[2].coeffs[0] = Q - 2;  // = -2 centered

    printf("L∞ norm of v: %d\n", polyvec_infnorm(&v));
    printf("Expected: 10 (largest absolute centered coefficient)\n");

    return 0;
}
