// poly_add_sub.c - Polynomial addition and subtraction
// Source: Module 2, Unit 2.3 - Polynomial Ring Arithmetic in Depth
// Compile: gcc -O2 -o poly_add_sub poly_add_sub.c

#include <stdint.h>
#include <stdio.h>

#define N 256
#define Q 3329

typedef struct {
    int16_t coeffs[N];
} poly;

// Reduce to [0, Q-1]
static inline int16_t mod_q(int32_t a) {
    int16_t r = a % Q;
    return r < 0 ? r + Q : r;
}

// r = a + b
void poly_add(poly *r, const poly *a, const poly *b) {
    for (int i = 0; i < N; i++) {
        r->coeffs[i] = mod_q((int32_t)a->coeffs[i] + b->coeffs[i]);
    }
}

// r = a - b
void poly_sub(poly *r, const poly *a, const poly *b) {
    for (int i = 0; i < N; i++) {
        r->coeffs[i] = mod_q((int32_t)a->coeffs[i] - b->coeffs[i]);
    }
}

// Constant-time version (no branching in mod_q)
static inline int16_t cmod_q(int16_t a) {
    a += (a >> 15) & Q;  // If negative, add Q
    return a;
}

void poly_add_ct(poly *r, const poly *a, const poly *b) {
    for (int i = 0; i < N; i++) {
        int16_t sum = a->coeffs[i] + b->coeffs[i];
        sum -= Q;
        sum += (sum >> 15) & Q;  // If negative, add Q back
        r->coeffs[i] = sum;
    }
}

int main(void) {
    poly a = {{0}}, b = {{0}}, r = {{0}};

    // Set up example: a = 3X² + 1000X + 500
    a.coeffs[0] = 500;
    a.coeffs[1] = 1000;
    a.coeffs[2] = 3;

    // b = 2X² + 2500X + 3000
    b.coeffs[0] = 3000;
    b.coeffs[1] = 2500;
    b.coeffs[2] = 2;

    poly_add(&r, &a, &b);
    printf("a + b: %dX² + %dX + %d\n", r.coeffs[2], r.coeffs[1], r.coeffs[0]);

    poly_sub(&r, &a, &b);
    printf("a - b: %dX² + %dX + %d\n", r.coeffs[2], r.coeffs[1], r.coeffs[0]);

    return 0;
}
