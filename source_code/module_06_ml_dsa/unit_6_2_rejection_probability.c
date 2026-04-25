#include <stdint.h>
#include <stdio.h>
#include <math.h>

/*
 * Compute exact and approximate rejection probabilities
 */

/*
 * For small gamma1, compute exact probability by enumeration
 */
double exact_rejection_prob(int gamma1, int beta, int n) {
    (void)n;
    /* y is uniform in [-(gamma1-1), gamma1-1], total 2*gamma1-1 values */
    /* z is in [-gamma1+1+max_cs, gamma1-1+max_cs] where max_cs = beta */
    /* Accept if |z| < gamma1 - beta */

    /* For a single coefficient with c*s uniform in [-beta, beta]: */
    /* This is an approximation - exact would need c*s distribution */

    int accept_count = 0;
    int total_count = 0;

    /* Enumerate y and c*s */
    for (int y = -(gamma1 - 1); y <= gamma1 - 1; y++) {
        for (int cs = -beta; cs <= beta; cs++) {
            total_count++;
            int z = y + cs;

            /* Check acceptance */
            if (z > -(gamma1 - beta) && z < (gamma1 - beta)) {
                accept_count++;
            }
        }
    }

    return 1.0 - (double)accept_count / total_count;
}

/*
 * Theoretical approximation (per-coefficient)
 */
double approx_rejection_prob(int gamma1, int beta) {
    return (double)beta / gamma1;
}

/*
 * Full vector rejection probability
 */
double vector_rejection_prob(double per_coeff_reject, int num_coeffs) {
    double per_coeff_accept = 1.0 - per_coeff_reject;
    double all_accept = pow(per_coeff_accept, num_coeffs);
    return 1.0 - all_accept;
}

int main(void) {
    printf("Rejection Probability Analysis\n");
    printf("==============================\n\n");

    /* Test with small parameters first */
    printf("Small parameter tests (exact enumeration):\n\n");

    int test_cases[][2] = {
        {100, 5},
        {100, 10},
        {1000, 10},
        {1000, 50},
        {10000, 100}
    };
    int num_tests = sizeof(test_cases) / sizeof(test_cases[0]);

    printf("| γ1 | β | Exact | Approx | Error |\n");
    printf("|------|------|---------|---------|--------|\n");

    for (int i = 0; i < num_tests; i++) {
        int g1 = test_cases[i][0];
        int b = test_cases[i][1];

        double exact = exact_rejection_prob(g1, b, 1);
        double approx = approx_rejection_prob(g1, b);
        double error = fabs(exact - approx) / exact * 100;

        printf("| %5d | %4d | %.5f | %.5f | %.2f%% |\n",
               g1, b, exact, approx, error);
    }

    printf("\n");

    /* ML-DSA parameters */
    printf("ML-DSA Parameter Analysis:\n\n");

    struct {
        const char *name;
        int gamma1;
        int beta;
        int n;
        int l;
    } mldsa_params[] = {
        {"ML-DSA-44", 131072, 78, 256, 4},
        {"ML-DSA-65", 524288, 196, 256, 5},
        {"ML-DSA-87", 524288, 120, 256, 7}
    };

    for (int i = 0; i < 3; i++) {
        printf("%s:\n", mldsa_params[i].name);
        printf("  γ1 = %d, β = %d\n", mldsa_params[i].gamma1, mldsa_params[i].beta);

        double per_coeff = approx_rejection_prob(mldsa_params[i].gamma1,
                                                  mldsa_params[i].beta);
        int total_coeffs = mldsa_params[i].n * mldsa_params[i].l;
        double vector_rej = vector_rejection_prob(per_coeff, total_coeffs);

        printf("  Per-coefficient rejection: %.6f\n", per_coeff);
        printf("  Total coefficients: %d\n", total_coeffs);
        printf("  Vector rejection prob: %.4f\n", vector_rej);
        printf("  Expected attempts (z only): %.2f\n", 1.0 / (1.0 - vector_rej));
        printf("\n");
    }

    /* Show how M changes with parameters */
    printf("Effect of γ1 on Expected Attempts:\n\n");
    printf("(Fixed: β = 196, n = 256, l = 5)\n\n");

    int beta_fixed = 196;
    int n_fixed = 256;
    int l_fixed = 5;
    int total_fixed = n_fixed * l_fixed;

    printf("| γ1 | β/γ1 | Vector Reject | E[attempts] |\n");
    printf("|----------|---------|---------------|-------------|\n");

    int gamma1_values[] = {262144, 524288, 1048576, 2097152};
    for (int i = 0; i < 4; i++) {
        int g1 = gamma1_values[i];
        double ratio = (double)beta_fixed / g1;
        double vec_rej = vector_rejection_prob(ratio, total_fixed);
        double exp_att = 1.0 / (1.0 - vec_rej);

        printf("| %8d | %.6f | %.4f | %.2f |\n",
               g1, ratio, vec_rej, exp_att);
    }

    printf("\n");
    printf("Key insight: Larger γ1 reduces rejections but increases signature size\n");
    printf("(more bits needed to encode z coefficients).\n");

    return 0;
}
