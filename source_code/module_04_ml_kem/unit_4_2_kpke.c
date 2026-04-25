/*
 * Source: PQC Learning Plan - Module 4: ML-KEM Deep Dive
 * Unit 4.2: K-PKE
 *
 * Unit 4.2: K-PKE Implementation
 *
 * This implements a simplified K-PKE scheme to demonstrate
 * the core encryption/decryption algorithms.
 *
 * EDUCATIONAL PURPOSE ONLY - Uses toy parameters
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

/* ========== Parameters ========== */

#define N 8           /* Polynomial degree (toy size) */
#define K 2           /* Module rank */
#define Q 257         /* Modulus (prime, close to 2^8 for easy compression) */
#define ETA1 2        /* Secret/error bound */
#define ETA2 2        /* Ciphertext error bound */
#define DU 4          /* Compression bits for u */
#define DV 3          /* Compression bits for v */

/* ========== Polynomial Operations ========== */

typedef int16_t poly[N];
typedef poly polyvec[K];

/* Reduce to centered representation [-Q/2, Q/2] */
int16_t center_reduce(int32_t x) {
    x = x % Q;
    if (x < 0) x += Q;
    if (x > Q/2) x -= Q;
    return (int16_t)x;
}

/* Reduce to [0, Q-1] */
int16_t pos_reduce(int32_t x) {
    x = x % Q;
    if (x < 0) x += Q;
    return (int16_t)x;
}

/* Polynomial multiplication in R_q = Z_q[X]/(X^N + 1) */
void poly_mul(poly c, const poly a, const poly b) {
    int32_t temp[2*N] = {0};

    /* Standard multiplication */
    for (int i = 0; i < N; i++) {
        for (int j = 0; j < N; j++) {
            temp[i + j] += (int32_t)a[i] * b[j];
        }
    }

    /* Reduce mod X^N + 1 (subtract high terms) */
    for (int i = 0; i < N; i++) {
        c[i] = center_reduce(temp[i] - temp[i + N]);
    }
}

/* Polynomial addition */
void poly_add(poly c, const poly a, const poly b) {
    for (int i = 0; i < N; i++) {
        c[i] = center_reduce(a[i] + b[i]);
    }
}

/* Polynomial subtraction */
void poly_sub(poly c, const poly a, const poly b) {
    for (int i = 0; i < N; i++) {
        c[i] = center_reduce(a[i] - b[i]);
    }
}

/* Inner product of polynomial vectors */
void polyvec_inner(poly c, const polyvec a, const polyvec b) {
    poly temp;
    memset(c, 0, sizeof(poly));
    for (int i = 0; i < K; i++) {
        poly_mul(temp, a[i], b[i]);
        poly_add(c, c, temp);
    }
}

/* ========== Sampling ========== */

/* Sample polynomial with small coefficients in [-eta, eta] */
void sample_small(poly p, int eta) {
    for (int i = 0; i < N; i++) {
        p[i] = (rand() % (2 * eta + 1)) - eta;
    }
}

/* Sample random polynomial in Z_q */
void sample_uniform(poly p) {
    for (int i = 0; i < N; i++) {
        p[i] = rand() % Q;
    }
}

/* ========== Compression ========== */

/* Compress coefficient from [0, Q-1] to [0, 2^d - 1] */
uint16_t compress(int16_t x, int d) {
    /* Make positive */
    if (x < 0) x += Q;
    /* Round((2^d / Q) * x) mod 2^d */
    uint32_t t = ((uint32_t)x << d) + Q / 2;
    return (t / Q) & ((1 << d) - 1);
}

/* Decompress from [0, 2^d - 1] to approximately [0, Q-1] */
int16_t decompress(uint16_t y, int d) {
    /* Round((Q / 2^d) * y) */
    return ((uint32_t)y * Q + (1 << (d - 1))) >> d;
}

/* Compress/decompress polynomial */
void poly_compress(uint16_t *out, const poly p, int d) {
    for (int i = 0; i < N; i++) {
        out[i] = compress(p[i], d);
    }
}

void poly_decompress(poly p, const uint16_t *in, int d) {
    for (int i = 0; i < N; i++) {
        p[i] = decompress(in[i], d);
    }
}

/* ========== Message Encoding ========== */

/* Encode message bit into coefficient: 0 → 0, 1 → Q/2 */
void encode_message(poly mu, const uint8_t *msg) {
    for (int i = 0; i < N; i++) {
        int byte_idx = i / 8;
        int bit_idx = i % 8;
        int bit = (msg[byte_idx] >> bit_idx) & 1;
        mu[i] = bit ? (Q + 1) / 2 : 0;
    }
}

/* Decode coefficient to message bit: closer to 0 → 0, closer to Q/2 → 1 */
void decode_message(uint8_t *msg, const poly mu) {
    memset(msg, 0, N / 8);
    for (int i = 0; i < N; i++) {
        int16_t x = mu[i];
        if (x < 0) x += Q;
        /* Decision boundary at Q/4 and 3Q/4 */
        int bit = (x > Q/4 && x < 3*Q/4) ? 1 : 0;
        msg[i / 8] |= bit << (i % 8);
    }
}

/* ========== K-PKE ========== */

typedef struct {
    polyvec a[K];    /* Matrix A (for simplicity, stored explicitly) */
    polyvec t;       /* Public vector t = As + e */
} kpke_pk;

typedef struct {
    polyvec s;       /* Secret vector */
} kpke_sk;

typedef struct {
    uint16_t u[K][N];  /* Compressed u */
    uint16_t v[N];     /* Compressed v */
} kpke_ct;

void kpke_keygen(kpke_pk *pk, kpke_sk *sk) {
    polyvec e;

    /* Sample matrix A */
    for (int i = 0; i < K; i++) {
        for (int j = 0; j < K; j++) {
            sample_uniform(pk->a[i][j]);
        }
    }

    /* Sample secret s and error e */
    for (int i = 0; i < K; i++) {
        sample_small(sk->s[i], ETA1);
        sample_small(e[i], ETA1);
    }

    /* Compute t = As + e */
    for (int i = 0; i < K; i++) {
        polyvec_inner(pk->t[i], pk->a[i], sk->s);
        poly_add(pk->t[i], pk->t[i], e[i]);
    }
}

void kpke_encrypt(kpke_ct *ct, const kpke_pk *pk, const uint8_t *msg) {
    polyvec r, e1;
    poly e2, mu, v;
    polyvec u;

    /* Sample encryption randomness */
    for (int i = 0; i < K; i++) {
        sample_small(r[i], ETA1);
        sample_small(e1[i], ETA2);
    }
    sample_small(e2, ETA2);

    /* Encode message */
    encode_message(mu, msg);

    /* Compute u = A^T r + e1 */
    for (int i = 0; i < K; i++) {
        poly temp;
        memset(u[i], 0, sizeof(poly));
        for (int j = 0; j < K; j++) {
            poly_mul(temp, pk->a[j][i], r[j]);
            poly_add(u[i], u[i], temp);
        }
        poly_add(u[i], u[i], e1[i]);
    }

    /* Compute v = t^T r + e2 + mu */
    polyvec_inner(v, pk->t, r);
    poly_add(v, v, e2);
    poly_add(v, v, mu);

    /* Compress */
    for (int i = 0; i < K; i++) {
        poly_compress(ct->u[i], u[i], DU);
    }
    poly_compress(ct->v, v, DV);
}

int kpke_decrypt(uint8_t *msg, const kpke_ct *ct, const kpke_sk *sk) {
    polyvec u;
    poly v, w, su;

    /* Decompress */
    for (int i = 0; i < K; i++) {
        poly_decompress(u[i], ct->u[i], DU);
    }
    poly_decompress(v, ct->v, DV);

    /* Compute w = v - s^T u */
    polyvec_inner(su, sk->s, u);
    poly_sub(w, v, su);

    /* Decode message */
    decode_message(msg, w);

    return 0;
}

/* ========== Demonstration ========== */

void print_poly(const char *name, const poly p) {
    printf("%s: [", name);
    for (int i = 0; i < N && i < 4; i++) {
        printf("%d", p[i]);
        if (i < 3) printf(", ");
    }
    if (N > 4) printf(", ...");
    printf("]\n");
}

void print_bytes(const char *name, const uint8_t *data, int len) {
    printf("%s: ", name);
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main(void) {
    srand(time(NULL));

    printf("╔════════════════════════════════════════════════════════╗\n");
    printf("║  Unit 4.2: K-PKE Implementation Demo                   ║\n");
    printf("╚════════════════════════════════════════════════════════╝\n\n");

    printf("Parameters: N=%d, K=%d, Q=%d, η₁=%d, η₂=%d\n", N, K, Q, ETA1, ETA2);
    printf("Compression: d_u=%d, d_v=%d\n\n", DU, DV);

    kpke_pk pk;
    kpke_sk sk;
    kpke_ct ct;

    /* Key generation */
    printf("=== Key Generation ===\n");
    kpke_keygen(&pk, &sk);
    print_poly("Secret s[0]", sk.s[0]);
    print_poly("Public t[0]", pk.t[0]);
    printf("\n");

    /* Encryption */
    uint8_t msg[N/8] = {0xAB};  /* Test message */
    printf("=== Encryption ===\n");
    print_bytes("Original message", msg, N/8);

    kpke_encrypt(&ct, &pk, msg);
    printf("Ciphertext u[0]: [%d, %d, %d, ...]\n",
           ct.u[0][0], ct.u[0][1], ct.u[0][2]);
    printf("Ciphertext v: [%d, %d, %d, ...]\n",
           ct.v[0], ct.v[1], ct.v[2]);
    printf("\n");

    /* Decryption */
    uint8_t recovered[N/8];
    printf("=== Decryption ===\n");
    kpke_decrypt(recovered, &ct, &sk);
    print_bytes("Recovered message", recovered, N/8);
    printf("\n");

    /* Verify */
    if (memcmp(msg, recovered, N/8) == 0) {
        printf("✓ Decryption SUCCESSFUL - messages match!\n");
    } else {
        printf("✗ Decryption FAILED - messages differ!\n");
    }

    /* Noise analysis */
    printf("\n=== Noise Analysis ===\n");
    printf("With η=%d, typical coefficient noise ≈ %d\n", ETA1, 4 * ETA1);
    printf("Decision threshold = Q/4 = %d\n", Q/4);
    printf("Margin for error = %d - %d = %d\n", Q/4, 4*ETA1, Q/4 - 4*ETA1);

    printf("\n");
    printf("════════════════════════════════════════════════════════════\n");
    printf("K-PKE Flow:\n");
    printf("  1. KeyGen: A random, s small, t = As + e\n");
    printf("  2. Encrypt: u = A^T r + e1, v = t^T r + e2 + encode(m)\n");
    printf("  3. Decrypt: w = v - s^T u = m + noise, decode(w)\n");
    printf("════════════════════════════════════════════════════════════\n");

    return 0;
}
