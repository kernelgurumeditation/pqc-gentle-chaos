// cbd_empirical.c - Empirical verification of CBD distribution
// Source: Module 2, Unit 2.6 - Probability and Distributions (Exercise 2.6.3)
// Compile: gcc -o cbd_empirical cbd_empirical.c

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int sample_cbd2(void) {
    int a1 = rand() & 1;
    int a2 = rand() & 1;
    int b1 = rand() & 1;
    int b2 = rand() & 1;
    return (a1 + a2) - (b1 + b2);
}

int main(void) {
    /* Fixed default seed => reproducible teaching output; override with PQC_DEMO_SEED. */
    const char *demo_seed_env = getenv("PQC_DEMO_SEED");
    srand(demo_seed_env ? (unsigned)strtoul(demo_seed_env, NULL, 10) : 1234567u);

    int counts[5] = {0};
    int n = 100000;

    for (int i = 0; i < n; i++) {
        int sample = sample_cbd2();
        counts[sample + 2]++;
    }

    printf("CBD_2 empirical distribution (%d samples):\n\n", n);
    printf("Value | Count  | Observed | Expected\n");
    printf("------+--------+----------+---------\n");

    double expected[] = {1.0/16, 4.0/16, 6.0/16, 4.0/16, 1.0/16};
    for (int v = -2; v <= 2; v++) {
        printf("  %+d  | %5d  |  %.4f  |  %.4f\n",
               v, counts[v+2],
               (float)counts[v+2]/n,
               expected[v+2]);
    }

    return 0;
}
