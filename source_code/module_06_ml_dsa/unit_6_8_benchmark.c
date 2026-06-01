/* ML-DSA Performance Benchmarking Demo
 * Demonstrates benchmarking methodology for ML-DSA operations
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Read CPU cycle counter (x86) */
#ifdef __x86_64__
static inline uint64_t rdtsc(void) {
    uint32_t lo, hi;
    __asm__ volatile ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}
#else
/* Fallback to clock() for non-x86 */
static inline uint64_t rdtsc(void) {
    return (uint64_t)clock();
}
#endif

/* ML-DSA-65 parameters for size estimates */
#define MLDSA_N 256
#define MLDSA_K 6
#define MLDSA_L 5

/* Benchmark configuration */
#define BENCH_ITERATIONS 1000
#define WARMUP_ITERATIONS 100

/* Statistics structure */
typedef struct {
    uint64_t min;
    uint64_t max;
    uint64_t total;
    uint64_t count;
} bench_stats;

static void stats_init(bench_stats *s) {
    s->min = UINT64_MAX;
    s->max = 0;
    s->total = 0;
    s->count = 0;
}

static void stats_update(bench_stats *s, uint64_t cycles) {
    if (cycles < s->min) s->min = cycles;
    if (cycles > s->max) s->max = cycles;
    s->total += cycles;
    s->count++;
}

static void stats_print(const char *name, bench_stats *s) {
    uint64_t avg = s->total / s->count;
    printf("%-20s: avg=%8lu  min=%8lu  max=%8lu cycles\n",
           name, (unsigned long)avg, (unsigned long)s->min,
           (unsigned long)s->max);
}

/* Simulated key structure sizes */
typedef struct {
    uint8_t rho[32];
    uint8_t t1[MLDSA_K * MLDSA_N * 10 / 8];  /* ~1920 bytes */
} mldsa_pk;

typedef struct {
    uint8_t rho[32];
    uint8_t K[32];
    uint8_t tr[64];
    int32_t s1[MLDSA_L * MLDSA_N];
    int32_t s2[MLDSA_K * MLDSA_N];
    int32_t t0[MLDSA_K * MLDSA_N];
} mldsa_sk;

typedef struct {
    uint8_t c_tilde[32];
    int32_t z[MLDSA_L * MLDSA_N];
    uint8_t h[MLDSA_K * MLDSA_N / 8];  /* hint bits */
} mldsa_sig;

/* Simple PRNG for simulation */
static uint64_t prng_state = 1;

static uint32_t prng_next(void) {
    prng_state ^= prng_state >> 12;
    prng_state ^= prng_state << 25;
    prng_state ^= prng_state >> 27;
    return (uint32_t)(prng_state * 0x2545F4914F6CDD1DULL >> 32);
}

/* Simulate expensive operations with realistic delays */
static void simulate_matrix_vector_mul(void) {
    /* Simulate k*l polynomial multiplications via NTT */
    volatile int32_t dummy = 0;
    for (int i = 0; i < MLDSA_K * MLDSA_L * MLDSA_N; i++) {
        dummy += prng_next() & 0xFF;
    }
    (void)dummy;
}

static void simulate_ntt(void) {
    volatile int32_t dummy = 0;
    for (int i = 0; i < MLDSA_N * 8; i++) {
        dummy += prng_next() & 0xFF;
    }
    (void)dummy;
}

static void simulate_hash(void) {
    volatile int32_t dummy = 0;
    for (int i = 0; i < 1000; i++) {
        dummy += prng_next() & 0xFF;
    }
    (void)dummy;
}

/* Simulated ML-DSA operations */
static void mldsa_keygen(mldsa_pk *pk, mldsa_sk *sk, const uint8_t *seed) {
    /* Key generation: hash seed, expand matrix, sample secrets, compute t */
    simulate_hash();
    simulate_matrix_vector_mul();

    /* Fill with deterministic pseudo-random data */
    prng_state = seed[0] | ((uint64_t)seed[1] << 8);
    memset(pk, 0, sizeof(*pk));
    memset(sk, 0, sizeof(*sk));
    for (int i = 0; i < 32; i++) {
        pk->rho[i] = prng_next() & 0xFF;
        sk->rho[i] = pk->rho[i];
    }
}

static int mldsa_sign(mldsa_sig *sig, const uint8_t *msg, size_t msglen,
                      const mldsa_sk *sk) {
    (void)msg; (void)msglen; (void)sk;

    /* Signing with rejection sampling (simulated ~4 iterations on average) */
    int iterations = 1;
    while (prng_next() % 4 != 0 && iterations < 20) {
        simulate_ntt();
        simulate_hash();
        iterations++;
    }

    simulate_matrix_vector_mul();
    memset(sig, 0, sizeof(*sig));

    return iterations;
}

static int mldsa_verify(const mldsa_pk *pk, const uint8_t *msg, size_t msglen,
                        const mldsa_sig *sig) {
    (void)pk; (void)msg; (void)msglen; (void)sig;

    /* Verification: hash, matrix-vector mul, compare */
    simulate_hash();
    simulate_matrix_vector_mul();
    simulate_ntt();

    return 1;  /* Simulated success */
}

/* Run benchmarks */
void benchmark_mldsa(void) {
    bench_stats keygen_stats, sign_stats, verify_stats;
    uint64_t start, end;
    mldsa_pk pk;
    mldsa_sk sk;
    mldsa_sig sig;
    uint8_t seed[32];
    const uint8_t msg[] = "Benchmark message for ML-DSA performance testing";

    stats_init(&keygen_stats);
    stats_init(&sign_stats);
    stats_init(&verify_stats);

    printf("ML-DSA-65 Performance Benchmark (Simulated)\n");
    printf("============================================\n");
    printf("Note: This demo uses simulated operations.\n");
    printf("      Real benchmarks require full ML-DSA implementation.\n\n");
    printf("Iterations: %d (warmup: %d)\n\n", BENCH_ITERATIONS, WARMUP_ITERATIONS);

    /* Warmup */
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        for (int j = 0; j < 32; j++) seed[j] = (uint8_t)(i ^ j);
        mldsa_keygen(&pk, &sk, seed);
        mldsa_sign(&sig, msg, sizeof(msg), &sk);
        mldsa_verify(&pk, msg, sizeof(msg), &sig);
    }

    /* Benchmark key generation */
    printf("Benchmarking key generation...\n");
    for (int i = 0; i < BENCH_ITERATIONS; i++) {
        for (int j = 0; j < 32; j++) seed[j] = (uint8_t)(i ^ j);

        start = rdtsc();
        mldsa_keygen(&pk, &sk, seed);
        end = rdtsc();

        stats_update(&keygen_stats, end - start);
    }

    /* Benchmark signing */
    printf("Benchmarking signing...\n");
    for (int i = 0; i < BENCH_ITERATIONS; i++) {
        start = rdtsc();
        mldsa_sign(&sig, msg, sizeof(msg), &sk);
        end = rdtsc();

        stats_update(&sign_stats, end - start);
    }

    /* Benchmark verification */
    printf("Benchmarking verification...\n");
    for (int i = 0; i < BENCH_ITERATIONS; i++) {
        start = rdtsc();
        mldsa_verify(&pk, msg, sizeof(msg), &sig);
        end = rdtsc();

        stats_update(&verify_stats, end - start);
    }

    /* Print results */
    printf("\nResults (cycle counts):\n");
    printf("-----------------------\n");
    stats_print("Key Generation", &keygen_stats);
    stats_print("Signing", &sign_stats);
    stats_print("Verification", &verify_stats);

    /* Compare to expected real-world performance */
    printf("\nExpected real-world ML-DSA-65 performance:\n");
    printf("  Key Generation: ~1.5M cycles\n");
    printf("  Signing:        ~5-7M cycles (varies due to rejection)\n");
    printf("  Verification:   ~1.5M cycles\n");
}

/* Analyze signing iteration distribution */
void analyze_signing_iterations(void) {
    int iteration_counts[21] = {0};
    int total_iterations = 0;
    int num_signs = 10000;

    mldsa_pk pk;
    mldsa_sk sk;
    mldsa_sig sig;
    uint8_t seed[32] = {0};
    char msg[64];

    printf("\nSigning Iteration Analysis\n");
    printf("==========================\n");

    mldsa_keygen(&pk, &sk, seed);

    for (int i = 0; i < num_signs; i++) {
        snprintf(msg, sizeof(msg), "Message number %d", i);
        int iters = mldsa_sign(&sig, (uint8_t *)msg, strlen(msg), &sk);
        total_iterations += iters;
        if (iters <= 20) {
            iteration_counts[iters]++;
        } else {
            iteration_counts[20]++;
        }
    }

    printf("Total signatures: %d\n", num_signs);
    printf("Average iterations: %.2f\n", (double)total_iterations / num_signs);
    printf("Expected average: ~4-5 iterations\n\n");

    printf("Iteration distribution:\n");
    for (int i = 1; i <= 15; i++) {
        if (iteration_counts[i] > 0) {
            printf("  %2d iterations: %5d (%.1f%%)\n",
                   i, iteration_counts[i],
                   100.0 * iteration_counts[i] / num_signs);
        }
    }
    int over15 = 0;
    for (int i = 16; i <= 20; i++) {
        over15 += iteration_counts[i];
    }
    if (over15 > 0) {
        printf("  >15 iterations: %5d (%.1f%%)\n",
               over15, 100.0 * over15 / num_signs);
    }
}

/* Print theoretical complexity */
void print_complexity_analysis(void) {
    printf("\nML-DSA-65 Complexity Analysis\n");
    printf("=============================\n\n");

    printf("Key Generation:\n");
    printf("  - Expand seed: O(1)\n");
    printf("  - Matrix A expansion: k*l = 30 polynomial samplings\n");
    printf("  - Secret vectors: (k+l)*n = 11*256 = 2816 coefficients\n");
    printf("  - Matrix-vector multiply: k*l NTT multiplications\n");
    printf("  - Power2Round: k*n = 1536 decompositions\n\n");

    printf("Signing (per attempt):\n");
    printf("  - Sample y: l*n = 1280 random coefficients\n");
    printf("  - Compute w = Ay: k*l NTT multiplications\n");
    printf("  - Challenge hash: 1 SHAKE256\n");
    printf("  - Compute z = y + cs1: l NTT multiplications\n");
    printf("  - Rejection checks: 4 norm checks\n");
    printf("  - Expected attempts: ~4.25\n\n");

    printf("Verification:\n");
    printf("  - Hash commitment: 1 SHAKE256\n");
    printf("  - Compute Az: k*l NTT multiplications\n");
    printf("  - Compute ct1: k NTT multiplications\n");
    printf("  - UseHint: k*n operations\n");
    printf("  - Compare w1': 1 hash comparison\n\n");

    printf("Key and Signature Sizes:\n");
    printf("  Public key:  1952 bytes\n");
    printf("  Secret key:  4032 bytes\n");
    printf("  Signature:   3309 bytes\n");
}

int main(void) {
    /* Fixed default seed => reproducible teaching output; override with
     * PQC_DEMO_SEED. */
    const char *demo_seed_env = getenv("PQC_DEMO_SEED");
    unsigned demo_seed = demo_seed_env
                             ? (unsigned)strtoul(demo_seed_env, NULL, 10)
                             : 1234567u;
    srand(demo_seed);
    prng_state = (uint64_t)demo_seed;

    benchmark_mldsa();
    analyze_signing_iterations();
    print_complexity_analysis();

    return 0;
}
