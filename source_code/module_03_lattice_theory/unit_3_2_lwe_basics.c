/*
 * Source: PQC Learning Plan - Module 3: Lattice Cryptography Theory
 * Unit: 3.2 - Learning With Errors (LWE)
 * Description: Educational LWE implementation
 *
 * This program demonstrates:
 * - LWE key generation (public/secret key pairs)
 * - Regev encryption scheme (encrypt single bits)
 * - LWE decryption with error tolerance
 * - Decryption failure rate testing
 */

// lwe_basics.c - Educational LWE implementation
// Compile: gcc -o lwe_basics lwe_basics.c

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

#define N 4          // Dimension
#define Q 97         // Modulus (small for demo)
#define M 8          // Number of samples
#define ERROR_BOUND 2 // Errors in [-2, 2]

typedef struct {
    int32_t a[N];
    int32_t b;
} lwe_sample_t;

typedef struct {
    lwe_sample_t samples[M];
} lwe_public_key_t;

typedef struct {
    int32_t s[N];
} lwe_secret_key_t;

// Modular reduction to [0, q-1]
int32_t mod_q(int32_t x) {
    x = x % Q;
    if (x < 0) x += Q;
    return x;
}

// Sample small error
int32_t sample_error(void) {
    return (rand() % (2 * ERROR_BOUND + 1)) - ERROR_BOUND;
}

// Inner product mod q (int64_t accumulator to prevent overflow for large N or Q)
int32_t inner_product(const int32_t *a, const int32_t *s) {
    int64_t sum = 0;
    for (int i = 0; i < N; i++) {
        sum += (int64_t)a[i] * s[i];
    }
    return mod_q((int32_t)(sum % Q));
}

// Generate LWE key pair
void lwe_keygen(lwe_public_key_t *pk, lwe_secret_key_t *sk) {
    // Generate random secret
    for (int i = 0; i < N; i++) {
        sk->s[i] = rand() % Q;
    }

    // Generate LWE samples (public key)
    for (int j = 0; j < M; j++) {
        // Random a vector
        for (int i = 0; i < N; i++) {
            pk->samples[j].a[i] = rand() % Q;
        }
        // b = <a, s> + e
        int32_t e = sample_error();
        pk->samples[j].b = mod_q(inner_product(pk->samples[j].a, sk->s) + e);
    }
}

// Encrypt a single bit
void lwe_encrypt(int32_t *u, int32_t *v, const lwe_public_key_t *pk, int bit) {
    // Initialize accumulators
    for (int i = 0; i < N; i++) {
        u[i] = 0;
    }
    *v = 0;

    // Sum random subset of samples
    for (int j = 0; j < M; j++) {
        if (rand() % 2) {  // Include with probability 1/2
            for (int i = 0; i < N; i++) {
                u[i] = mod_q(u[i] + pk->samples[j].a[i]);
            }
            *v = mod_q(*v + pk->samples[j].b);
        }
    }

    // Add message encoding
    if (bit) {
        *v = mod_q(*v + Q / 2);
    }
}

// Decrypt a ciphertext
int lwe_decrypt(const int32_t *u, int32_t v, const lwe_secret_key_t *sk) {
    // Compute w = v - <u, s>
    int32_t w = mod_q(v - inner_product(u, sk->s));

    // Decode: if w is closer to 0 than to Q/2, output 0
    int32_t dist_to_0 = (w < Q / 2) ? w : Q - w;
    int32_t dist_to_half = (w > Q / 2) ? w - Q / 2 : Q / 2 - w;

    return (dist_to_half < dist_to_0) ? 1 : 0;
}

void print_vector(const char *name, const int32_t *v, int len) {
    printf("%s: (", name);
    for (int i = 0; i < len; i++) {
        printf("%d%s", v[i], i < len - 1 ? ", " : "");
    }
    printf(")\n");
}

int main(void) {
    /* Fixed default seed => reproducible teaching output; override with PQC_DEMO_SEED. */
    const char *demo_seed_env = getenv("PQC_DEMO_SEED");
    srand(demo_seed_env ? (unsigned)strtoul(demo_seed_env, NULL, 10) : 1234567u);

    printf("=== LWE Encryption Demo ===\n");
    printf("Parameters: n=%d, q=%d, m=%d, error_bound=%d\n\n", N, Q, M, ERROR_BOUND);

    lwe_public_key_t pk;
    lwe_secret_key_t sk;

    // Key generation
    printf("--- Key Generation ---\n");
    lwe_keygen(&pk, &sk);
    print_vector("Secret key s", sk.s, N);
    printf("Public key: %d LWE samples\n\n", M);

    // Test encryption/decryption
    printf("--- Encryption Test ---\n");
    int32_t u[N];
    int32_t v;

    int errors = 0;
    int trials = 100;

    for (int t = 0; t < trials; t++) {
        int bit = rand() % 2;
        lwe_encrypt(u, &v, &pk, bit);
        int decrypted = lwe_decrypt(u, v, &sk);

        if (decrypted != bit) {
            errors++;
        }
    }

    printf("Tested %d encryptions: %d errors (%.2f%% failure rate)\n",
           trials, errors, 100.0 * errors / trials);

    // Detailed single example
    printf("\n--- Detailed Example ---\n");
    int bit = 1;
    lwe_encrypt(u, &v, &pk, bit);
    print_vector("Ciphertext u", u, N);
    printf("Ciphertext v: %d\n", v);

    int32_t w = mod_q(v - inner_product(u, sk.s));
    printf("Decryption value w = v - <u,s> = %d\n", w);
    printf("Q/2 = %d\n", Q / 2);

    int decrypted = lwe_decrypt(u, v, &sk);
    printf("Original bit: %d, Decrypted: %d %s\n",
           bit, decrypted, bit == decrypted ? "✓" : "✗");

    /* Explicit success/failure verdict.
     * For these tiny demo parameters (q=97, error_bound=2) decryption should
     * never fail, so any error - or a wrong detailed example - is a real failure. */
    int ok = (errors == 0) && (decrypted == bit);
    printf("\n=== RESULT: %s ===\n", ok ? "PASS" : "FAIL");
    if (!ok) {
        printf("Decryption errors detected (errors=%d, detailed bit %s).\n",
               errors, (decrypted == bit) ? "ok" : "wrong");
        return 1;
    }

    return 0;
}
