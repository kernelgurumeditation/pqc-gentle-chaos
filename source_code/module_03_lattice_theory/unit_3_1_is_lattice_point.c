/* Unit 3.1 Exercise 3.1.7: Check if a point is in a 2D lattice
 * Demonstrates lattice membership testing using basis transformation
 */
#include <stdio.h>
#include <math.h>

#define EPSILON 1e-9

int is_integer(double x) {
    return fabs(x - round(x)) < EPSILON;
}

// Returns 1 if point t is in 2D lattice with basis b1, b2
int is_lattice_point_2d(double b1x, double b1y, double b2x, double b2y,
                        double tx, double ty) {
    // Solve: z1*b1 + z2*b2 = t
    double det = b1x * b2y - b1y * b2x;
    if (fabs(det) < EPSILON) return -1;  // Degenerate

    double z1 = (tx * b2y - ty * b2x) / det;
    double z2 = (b1x * ty - b1y * tx) / det;

    return is_integer(z1) && is_integer(z2);
}

int main(void) {
    printf("=== Lattice Point Membership Test ===\n\n");

    // Basis: (3, 1), (1, 2)
    printf("Lattice with basis:\n");
    printf("  b1 = (3, 1)\n");
    printf("  b2 = (1, 2)\n\n");

    printf("Testing points:\n");
    printf("  (4, 3): %s\n", is_lattice_point_2d(3,1,1,2, 4,3) ? "YES (in lattice)" : "NO");
    printf("  (3, 0): %s\n", is_lattice_point_2d(3,1,1,2, 3,0) ? "YES (in lattice)" : "NO");
    printf("  (6, 2): %s\n", is_lattice_point_2d(3,1,1,2, 6,2) ? "YES (in lattice)" : "NO");
    printf("  (2, 4): %s\n", is_lattice_point_2d(3,1,1,2, 2,4) ? "YES (in lattice)" : "NO");
    printf("  (0, 0): %s\n", is_lattice_point_2d(3,1,1,2, 0,0) ? "YES (in lattice)" : "NO");

    printf("\nVerification:\n");
    printf("  (4, 3) = 1*(3,1) + 1*(1,2) = (3+1, 1+2) = (4, 3) -> YES\n");
    printf("  (6, 2) = 2*(3,1) + 0*(1,2) = (6, 2) -> YES\n");
    printf("  (2, 4) = 0*(3,1) + 2*(1,2) = (2, 4) -> YES\n");
    printf("  (3, 0) cannot be written as integer combo -> NO\n");

    return 0;
}
