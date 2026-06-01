#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

/*
 * ML-DSA Key Generation Implementation
 * Demonstrates the key generation process
 */

/* ML-DSA-65 parameters */
#define MLDSA_N 256
#define MLDSA_Q 8380417
#define MLDSA_K 6
#define MLDSA_L 5
#define ETA 4
#define MLDSA_D 13

/* Polynomial structure */
typedef struct {
    int32_t coeffs[MLDSA_N];
} poly;

/* Vector structures */
typedef struct {
    poly vec[MLDSA_L];
} polyvecl;

typedef struct {
    poly vec[MLDSA_K];
} polyveck;

/* Matrix structure */
typedef struct {
    poly mat[MLDSA_K][MLDSA_L];
} polymat;

/* Key structures */
typedef struct {
    uint8_t rho[32];
    polyveck t1;
} public_key;

typedef struct {
    uint8_t rho[32];
    uint8_t K[32];
    uint8_t tr[64];
    polyvecl s1;
    polyveck s2;
    polyveck t0;
} secret_key;

/* Simple PRNG for demonstration (use SHAKE in production) */
typedef struct {
    uint64_t state;
} prng_state;

void prng_init(prng_state *prng, const uint8_t *seed, size_t seed_len) {
    prng->state = 0;
    for (size_t i = 0; i < seed_len && i < 8; i++) {
        prng->state |= ((uint64_t)seed[i]) << (i * 8);
    }
    if (prng->state == 0) prng->state = 1;
}

uint32_t prng_next(prng_state *prng) {
    prng->state ^= prng->state >> 12;
    prng->state ^= prng->state << 25;
    prng->state ^= prng->state >> 27;
    return (uint32_t)((prng->state * 0x2545F4914F6CDD1DULL) >> 32);
}

/* Sample uniform coefficient in [0, q) using rejection sampling */
int32_t sample_uniform(prng_state *prng) {
    while (1) {
        uint32_t r = prng_next(prng) & 0x7FFFFF;  /* 23 bits */
        if (r < MLDSA_Q) {
            return (int32_t)r;
        }
        /* Reject and try again */
    }
}

/* Sample small coefficient in [-eta, eta] */
int32_t sample_small(prng_state *prng, int eta) {
    uint32_t range = (uint32_t)(2 * eta + 1);
    while (1) {
        uint32_t r = prng_next(prng) & 0xFF;
        if (r < range) {
            return (int32_t)r - eta;
        }
    }
}

/* Generate polynomial with uniform coefficients */
void poly_uniform(poly *p, prng_state *prng) {
    for (int i = 0; i < MLDSA_N; i++) {
        p->coeffs[i] = sample_uniform(prng);
    }
}

/* Generate polynomial with small coefficients */
void poly_small(poly *p, prng_state *prng, int eta) {
    for (int i = 0; i < MLDSA_N; i++) {
        p->coeffs[i] = sample_small(prng, eta);
    }
}

/* Expand matrix A from seed */
void expand_A(polymat *A, const uint8_t *rho) {
    for (int i = 0; i < MLDSA_K; i++) {
        for (int j = 0; j < MLDSA_L; j++) {
            /* Create unique seed for this matrix entry */
            uint8_t entry_seed[34];
            memcpy(entry_seed, rho, 32);
            entry_seed[32] = (uint8_t)j;  /* Column first (FIPS 204 convention) */
            entry_seed[33] = (uint8_t)i;

            prng_state prng;
            prng_init(&prng, entry_seed, 34);
            poly_uniform(&A->mat[i][j], &prng);
        }
    }
}

/* Expand secrets s1, s2 from seed */
void expand_S(polyvecl *s1, polyveck *s2, const uint8_t *rhoprime) {
    for (int j = 0; j < MLDSA_L; j++) {
        uint8_t seed[66];
        memcpy(seed, rhoprime, 64);
        seed[64] = (uint8_t)(j & 0xFF);
        seed[65] = (uint8_t)(j >> 8);

        prng_state prng;
        prng_init(&prng, seed, 66);
        poly_small(&s1->vec[j], &prng, ETA);
    }

    for (int j = 0; j < MLDSA_K; j++) {
        uint8_t seed[66];
        memcpy(seed, rhoprime, 64);
        seed[64] = (uint8_t)((MLDSA_L + j) & 0xFF);
        seed[65] = (uint8_t)((MLDSA_L + j) >> 8);

        prng_state prng;
        prng_init(&prng, seed, 66);
        poly_small(&s2->vec[j], &prng, ETA);
    }
}

/* Polynomial multiplication (schoolbook) */
void poly_mul(poly *c, const poly *a, const poly *b) {
    int64_t temp[2 * MLDSA_N - 1];
    memset(temp, 0, sizeof(temp));

    for (int i = 0; i < MLDSA_N; i++) {
        for (int j = 0; j < MLDSA_N; j++) {
            temp[i + j] += (int64_t)a->coeffs[i] * (int64_t)b->coeffs[j];
        }
    }

    /* Reduce mod X^N + 1 */
    for (int i = MLDSA_N; i < 2 * MLDSA_N - 1; i++) {
        temp[i - MLDSA_N] -= temp[i];
    }

    /* Reduce mod Q */
    for (int i = 0; i < MLDSA_N; i++) {
        int64_t t = temp[i] % MLDSA_Q;
        if (t < 0) t += MLDSA_Q;
        c->coeffs[i] = (int32_t)t;
    }
}

/* Add polynomials */
void poly_add(poly *c, const poly *a, const poly *b) {
    for (int i = 0; i < MLDSA_N; i++) {
        int32_t sum = a->coeffs[i] + b->coeffs[i];
        sum %= MLDSA_Q;
        if (sum < 0) sum += MLDSA_Q;
        c->coeffs[i] = sum;
    }
}

/* Compute t = A * s1 + s2 */
void compute_t(polyveck *t, const polymat *A, const polyvecl *s1, const polyveck *s2) {
    for (int i = 0; i < MLDSA_K; i++) {
        /* t[i] = sum_j A[i][j] * s1[j] + s2[i] */
        poly sum;
        memset(sum.coeffs, 0, sizeof(sum.coeffs));

        for (int j = 0; j < MLDSA_L; j++) {
            poly prod;
            poly_mul(&prod, &A->mat[i][j], &s1->vec[j]);
            poly_add(&sum, &sum, &prod);
        }

        poly_add(&t->vec[i], &sum, &s2->vec[i]);
    }
}

/* Power2Round: decompose r into (r1, r0) where r = r1 * 2^D + r0 */
void power2round(int32_t r, int32_t *r1, int32_t *r0) {
    /* Ensure r is positive */
    r = r % MLDSA_Q;
    if (r < 0) r += MLDSA_Q;

    /* r0 = r mod 2^D, centered */
    *r0 = r & ((1 << MLDSA_D) - 1);
    if (*r0 > (1 << (MLDSA_D - 1))) {
        *r0 -= (1 << MLDSA_D);
    }

    /* r1 = (r - r0) >> D */
    *r1 = (r - *r0) >> MLDSA_D;
}

/* Apply Power2Round to polynomial vector */
void polyvec_power2round(polyveck *t1, polyveck *t0, const polyveck *t) {
    for (int i = 0; i < MLDSA_K; i++) {
        for (int j = 0; j < MLDSA_N; j++) {
            power2round(t->vec[i].coeffs[j],
                       &t1->vec[i].coeffs[j],
                       &t0->vec[i].coeffs[j]);
        }
    }
}

/* Simple hash function for demonstration */
void simple_hash(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen) {
    /* Use SHAKE256 in production */
    prng_state prng;
    prng_init(&prng, in, inlen);
    for (size_t i = 0; i < outlen; i++) {
        out[i] = (uint8_t)(prng_next(&prng) & 0xFF);
    }
}

/* Key generation */
void keygen(public_key *pk, secret_key *sk, const uint8_t *seed) {
    /* 1. Expand seed to (rho, rhoprime, K) */
    uint8_t expanded[128];
    simple_hash(expanded, 128, seed, 32);

    memcpy(pk->rho, expanded, 32);
    memcpy(sk->rho, expanded, 32);
    uint8_t rhoprime[64];
    memcpy(rhoprime, expanded + 32, 64);
    memcpy(sk->K, expanded + 96, 32);

    /* 2. Generate matrix A */
    polymat A;
    expand_A(&A, pk->rho);

    /* 3. Generate secret vectors */
    expand_S(&sk->s1, &sk->s2, rhoprime);

    /* 4. Compute t = A * s1 + s2 */
    polyveck t;
    compute_t(&t, &A, &sk->s1, &sk->s2);

    /* 5. Decompose t = t1 * 2^D + t0 */
    polyvec_power2round(&pk->t1, &sk->t0, &t);

    /* 6. Compute tr = H(pk) */
    /* In real implementation, serialize pk first */
    uint8_t pk_bytes[2048];
    memcpy(pk_bytes, pk->rho, 32);
    /* Simplified: just hash rho for demo */
    simple_hash(sk->tr, 64, pk->rho, 32);
}

/* Print polynomial statistics */
void poly_stats(const poly *p, const char *name) {
    int32_t min = p->coeffs[0], max = p->coeffs[0];
    int64_t sum = 0;

    for (int i = 0; i < MLDSA_N; i++) {
        if (p->coeffs[i] < min) min = p->coeffs[i];
        if (p->coeffs[i] > max) max = p->coeffs[i];
        sum += p->coeffs[i];
    }

    printf("  %s: min=%d, max=%d, mean=%.1f\n",
           name, min, max, (double)sum / MLDSA_N);
}

/* Verify key relationship */
int verify_key_relationship(const public_key *pk, const secret_key *sk) {
    /* Recompute t from sk and check against pk */
    polymat A;
    expand_A(&A, sk->rho);

    polyveck t;
    compute_t(&t, &A, &sk->s1, &sk->s2);

    polyveck t1_check, t0_check;
    polyvec_power2round(&t1_check, &t0_check, &t);

    /* Compare t1 */
    for (int i = 0; i < MLDSA_K; i++) {
        for (int j = 0; j < MLDSA_N; j++) {
            if (t1_check.vec[i].coeffs[j] != pk->t1.vec[i].coeffs[j]) {
                return 0;
            }
            if (t0_check.vec[i].coeffs[j] != sk->t0.vec[i].coeffs[j]) {
                return 0;
            }
        }
    }

    return 1;
}

int main(void) {
    printf("ML-DSA Key Generation Demo\n");
    printf("==========================\n\n");

    /* Generate random seed */
    uint8_t seed[32];
    /* Fixed default seed => reproducible teaching output; override with
     * PQC_DEMO_SEED. */
    const char *demo_seed_env = getenv("PQC_DEMO_SEED");
    srand(demo_seed_env ? (unsigned)strtoul(demo_seed_env, NULL, 10) : 1234567u);
    for (int i = 0; i < 32; i++) {
        seed[i] = rand() & 0xFF;
    }

    printf("Parameters (ML-DSA-65):\n");
    printf("  n = %d, q = %d\n", MLDSA_N, MLDSA_Q);
    printf("  k = %d, l = %d\n", MLDSA_K, MLDSA_L);
    printf("  η = %d, d = %d\n", ETA, MLDSA_D);
    printf("\n");

    /* Generate key pair */
    public_key pk;
    secret_key sk;

    printf("Generating key pair...\n\n");
    keygen(&pk, &sk, seed);

    /* Print key statistics */
    printf("Secret key statistics:\n");
    printf("  s1 (l=%d polynomials):\n", MLDSA_L);
    for (int i = 0; i < MLDSA_L; i++) {
        char name[16];
        snprintf(name, sizeof(name), "s1[%d]", i);
        poly_stats(&sk.s1.vec[i], name);
    }

    printf("\n  s2 (k=%d polynomials):\n", MLDSA_K);
    for (int i = 0; i < MLDSA_K; i++) {
        char name[16];
        snprintf(name, sizeof(name), "s2[%d]", i);
        poly_stats(&sk.s2.vec[i], name);
    }

    printf("\n  t0 (k=%d polynomials):\n", MLDSA_K);
    for (int i = 0; i < MLDSA_K; i++) {
        char name[16];
        snprintf(name, sizeof(name), "t0[%d]", i);
        poly_stats(&sk.t0.vec[i], name);
    }

    printf("\nPublic key statistics:\n");
    printf("  t1 (k=%d polynomials):\n", MLDSA_K);
    for (int i = 0; i < MLDSA_K; i++) {
        char name[16];
        snprintf(name, sizeof(name), "t1[%d]", i);
        poly_stats(&pk.t1.vec[i], name);
    }

    /* Verify key relationship */
    printf("\nVerifying key relationship (t = A*s1 + s2)...\n");
    if (verify_key_relationship(&pk, &sk)) {
        printf("  Key relationship verified successfully!\n");
    } else {
        printf("  ERROR: Key relationship verification failed!\n");
    }

    /* Demonstrate Power2Round */
    printf("\nPower2Round demonstration:\n");
    printf("  d = %d, so 2^d = %d\n", MLDSA_D, 1 << MLDSA_D);

    int32_t test_values[] = {0, 1000000, 4000000, 8000000, MLDSA_Q-1};
    for (int i = 0; i < 5; i++) {
        int32_t r = test_values[i];
        int32_t r1, r0;
        power2round(r, &r1, &r0);

        int32_t reconstructed = (r1 << MLDSA_D) + r0;
        if (reconstructed < 0) reconstructed += MLDSA_Q;
        reconstructed %= MLDSA_Q;

        printf("  r = %7d: r1 = %4d, r0 = %5d, r1*2^d + r0 = %7d %s\n",
               r, r1, r0, reconstructed,
               (reconstructed == r % MLDSA_Q) ? "✓" : "✗");
    }

    /* Size estimates */
    printf("\nKey sizes (ML-DSA-65):\n");
    size_t pk_size = 32 + (MLDSA_K * MLDSA_N * 10 + 7) / 8;  /* 10 bits per t1 coeff */
    size_t sk_size = 32 + 32 + 64 +
                     (MLDSA_L * MLDSA_N * 4 + 7) / 8 +   /* s1: 4 bits */
                     (MLDSA_K * MLDSA_N * 4 + 7) / 8 +   /* s2: 4 bits */
                     (MLDSA_K * MLDSA_N * MLDSA_D + 7) / 8;    /* t0: 13 bits */

    printf("  Public key:  ~%zu bytes (actual: 1952)\n", pk_size);
    printf("  Secret key:  ~%zu bytes (actual: 4032)\n", sk_size);

    return 0;
}
