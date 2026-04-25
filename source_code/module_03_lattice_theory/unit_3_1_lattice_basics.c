/*
 * Source: PQC Learning Plan - Module 3: Lattice Cryptography Theory
 * Unit: 3.1 - Lattices and Hard Problems
 * Description: Basic lattice operations for educational purposes
 *
 * This program demonstrates:
 * - Lattice point generation from basis vectors
 * - Shortest Vector Problem (SVP) via naive enumeration
 * - Closest Vector Problem (CVP) via rounding heuristic
 * - Lattice determinant computation
 */

// lattice_basics.c - Basic lattice operations for educational purposes
// Compile: gcc -o lattice_basics lattice_basics.c -lm

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <stdint.h>

#define MAX_DIM 8

typedef struct {
    double coords[MAX_DIM];
    int dim;
} vector_t;

typedef struct {
    vector_t basis[MAX_DIM];
    int rank;  // number of basis vectors
    int dim;   // dimension of ambient space
} lattice_t;

// Vector operations
double vector_norm(const vector_t *v) {
    double sum = 0;
    for (int i = 0; i < v->dim; i++) {
        sum += v->coords[i] * v->coords[i];
    }
    return sqrt(sum);
}

double vector_dot(const vector_t *u, const vector_t *v) {
    double sum = 0;
    for (int i = 0; i < u->dim; i++) {
        sum += u->coords[i] * v->coords[i];
    }
    return sum;
}

void vector_add(vector_t *result, const vector_t *u, const vector_t *v) {
    result->dim = u->dim;
    for (int i = 0; i < u->dim; i++) {
        result->coords[i] = u->coords[i] + v->coords[i];
    }
}

void vector_sub(vector_t *result, const vector_t *u, const vector_t *v) {
    result->dim = u->dim;
    for (int i = 0; i < u->dim; i++) {
        result->coords[i] = u->coords[i] - v->coords[i];
    }
}

void vector_scale(vector_t *result, const vector_t *v, double scalar) {
    result->dim = v->dim;
    for (int i = 0; i < v->dim; i++) {
        result->coords[i] = v->coords[i] * scalar;
    }
}

// Generate a lattice point from integer coefficients
void lattice_point(vector_t *result, const lattice_t *L, const int *coeffs) {
    result->dim = L->dim;
    for (int i = 0; i < L->dim; i++) {
        result->coords[i] = 0;
    }

    for (int i = 0; i < L->rank; i++) {
        for (int j = 0; j < L->dim; j++) {
            result->coords[j] += coeffs[i] * L->basis[i].coords[j];
        }
    }
}

// Compute 2D lattice determinant
double lattice_det_2d(const lattice_t *L) {
    if (L->rank != 2 || L->dim != 2) {
        return -1;  // Only for 2D full-rank lattices
    }
    return fabs(L->basis[0].coords[0] * L->basis[1].coords[1] -
                L->basis[0].coords[1] * L->basis[1].coords[0]);
}

// Naive enumeration to find short vectors (only for small lattices!)
void find_short_vector_naive(vector_t *result, const lattice_t *L, int search_radius) {
    double min_norm = INFINITY;
    int best_coeffs[MAX_DIM] = {0};
    int coeffs[MAX_DIM];
    vector_t candidate;

    // For 2D case:
    if (L->rank == 2) {
        for (int c0 = -search_radius; c0 <= search_radius; c0++) {
            for (int c1 = -search_radius; c1 <= search_radius; c1++) {
                if (c0 == 0 && c1 == 0) continue;

                coeffs[0] = c0;
                coeffs[1] = c1;
                lattice_point(&candidate, L, coeffs);

                double norm = vector_norm(&candidate);
                if (norm < min_norm) {
                    min_norm = norm;
                    best_coeffs[0] = c0;
                    best_coeffs[1] = c1;
                }
            }
        }
    }

    lattice_point(result, L, best_coeffs);
}

// Solve CVP by rounding (heuristic for nearly orthogonal bases)
void solve_cvp_rounding(vector_t *result, const lattice_t *L, const vector_t *target) {
    int coeffs[MAX_DIM];

    for (int i = 0; i < L->rank; i++) {
        double proj = vector_dot(target, &L->basis[i]) /
                      vector_dot(&L->basis[i], &L->basis[i]);
        coeffs[i] = (int)round(proj);
    }

    lattice_point(result, L, coeffs);
}

void print_vector(const char *label, const vector_t *v) {
    printf("%s: (", label);
    for (int i = 0; i < v->dim; i++) {
        printf("%.3f%s", v->coords[i], i < v->dim - 1 ? ", " : "");
    }
    printf("), norm = %.4f\n", vector_norm(v));
}

int main(void) {
    printf("=== Lattice Basics Demo ===\n\n");

    // Create a 2D lattice with "bad" basis
    lattice_t L;
    L.rank = 2;
    L.dim = 2;

    L.basis[0].dim = 2;
    L.basis[0].coords[0] = 10;
    L.basis[0].coords[1] = 1;

    L.basis[1].dim = 2;
    L.basis[1].coords[0] = 11;
    L.basis[1].coords[1] = 2;

    printf("Lattice with 'bad' basis:\n");
    print_vector("  b1", &L.basis[0]);
    print_vector("  b2", &L.basis[1]);
    printf("  Determinant: %.4f\n\n", lattice_det_2d(&L));

    // Find shortest vector
    printf("Finding short vectors (naive enumeration)...\n");
    vector_t shortest;
    find_short_vector_naive(&shortest, &L, 10);
    print_vector("  Shortest found", &shortest);
    printf("  (Much shorter than basis vectors!)\n\n");

    // CVP example
    printf("Closest Vector Problem:\n");
    vector_t target = {.dim = 2, .coords = {4.7, 2.3}};
    print_vector("  Target", &target);

    vector_t closest;
    solve_cvp_rounding(&closest, &L, &target);
    print_vector("  Closest lattice point", &closest);

    vector_t diff;
    vector_sub(&diff, &target, &closest);
    printf("  Distance: %.4f\n", vector_norm(&diff));

    return 0;
}
