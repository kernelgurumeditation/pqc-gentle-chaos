#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#define LWE_N 16      // Secret dimension
#define LWE_M 32      // Number of samples
#define LWE_Q 97      // Modulus (prime)
#define LWE_E_MAX 2   // Error bound: e ∈ {-2, -1, 0, 1, 2}

typedef struct {
    int16_t A[LWE_M][LWE_N];
    int16_t b[LWE_M];
} lwe_public_key;

typedef struct {
    int16_t s[LWE_N];
} lwe_secret_key;

typedef struct {
    int16_t u[LWE_N];
    int16_t v;
} lwe_ciphertext;

// Modular reduction to [0, q-1]
static inline int16_t mod(int32_t x, int16_t q) {
    int16_t r = x % q;
    return r < 0 ? r + q : r;
}

// Sample small error
static inline int16_t sample_error(void) {
    return (rand() % (2 * LWE_E_MAX + 1)) - LWE_E_MAX;
}

// Key generation
void lwe_keygen(lwe_public_key *pk, lwe_secret_key *sk) {
    // Generate random secret
    for (int i = 0; i < LWE_N; i++) {
        sk->s[i] = rand() % LWE_Q;
    }

    // Generate random matrix A and compute b = As + e
    for (int i = 0; i < LWE_M; i++) {
        int32_t dot = 0;
        for (int j = 0; j < LWE_N; j++) {
            pk->A[i][j] = rand() % LWE_Q;
            dot += (int32_t)pk->A[i][j] * sk->s[j];
        }
        int16_t e = sample_error();
        pk->b[i] = mod(dot + e, LWE_Q);
    }
}

// Encrypt a single bit
void lwe_encrypt(const lwe_public_key *pk, int bit, lwe_ciphertext *ct) {
    // Generate random binary vector r
    int r[LWE_M];
    for (int i = 0; i < LWE_M; i++) {
        r[i] = rand() % 2;
    }

    // u = A^T * r
    for (int j = 0; j < LWE_N; j++) {
        int32_t sum = 0;
        for (int i = 0; i < LWE_M; i++) {
            sum += pk->A[i][j] * r[i];
        }
        ct->u[j] = mod(sum, LWE_Q);
    }

    // v = b^T * r + bit * floor(q/2)
    int32_t sum = 0;
    for (int i = 0; i < LWE_M; i++) {
        sum += pk->b[i] * r[i];
    }
    ct->v = mod(sum + bit * (LWE_Q / 2), LWE_Q);
}

// Decrypt ciphertext
int lwe_decrypt(const lwe_secret_key *sk, const lwe_ciphertext *ct) {
    // w = v - s^T * u
    int32_t dot = 0;
    for (int j = 0; j < LWE_N; j++) {
        dot += (int32_t)sk->s[j] * ct->u[j];
    }
    int16_t w = mod(ct->v - dot, LWE_Q);

    // Decision: closer to 0 or q/2?
    int16_t half_q = LWE_Q / 2;
    int16_t dist_to_0 = (w < half_q) ? w : LWE_Q - w;
    int16_t dist_to_half = (w < half_q) ? half_q - w : w - half_q;

    return (dist_to_half < dist_to_0) ? 1 : 0;
}

int main(void) {
    srand(time(NULL));

    lwe_public_key pk;
    lwe_secret_key sk;
    lwe_ciphertext ct;

    printf("=== Toy LWE Encryption ===\n");
    printf("Parameters: n=%d, m=%d, q=%d\n\n", LWE_N, LWE_M, LWE_Q);

    // Generate keys
    lwe_keygen(&pk, &sk);
    printf("Keys generated.\n");

    // Test encryption/decryption
    int errors = 0;
    int tests = 1000;

    for (int i = 0; i < tests; i++) {
        int bit = rand() % 2;
        lwe_encrypt(&pk, bit, &ct);
        int decrypted = lwe_decrypt(&sk, &ct);
        if (bit != decrypted) errors++;
    }

    printf("Tested %d encryptions\n", tests);
    printf("Decryption errors: %d (%.2f%%)\n", errors, 100.0 * errors / tests);

    // Detailed example
    printf("\n--- Detailed Example ---\n");
    int msg = 1;
    lwe_encrypt(&pk, msg, &ct);
    int dec = lwe_decrypt(&sk, &ct);
    printf("Original:  %d\n", msg);
    printf("Decrypted: %d\n", dec);
    printf("Status: %s\n", msg == dec ? "SUCCESS" : "FAILURE");

    return 0;
}
