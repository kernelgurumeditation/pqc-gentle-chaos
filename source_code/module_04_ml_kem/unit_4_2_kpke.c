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
#define Q 3329        /* Modulus (the real ML-KEM prime; ~2^11.7) */
#define ETA1 2        /* Secret/error bound */
#define ETA2 2        /* Ciphertext error bound */
#define DU 11         /* Compression bits for u (near-lossless: d ~ log2(Q)) */
#define DV 11         /* Compression bits for v (near-lossless: d ~ log2(Q)) */

/*
 * Why these compression parameters?
 * -----------------------------------------------------------------------
 * Decryption recovers  w = v - s^T u = encode(m) + noise.  For correct
 * decoding every |noise coefficient| must stay below the Q/4 threshold.
 * The noise has two sources:
 *
 *   1. Inherent LWE noise   e^T r + e2 - s^T e1     (bounded by ~ETA)
 *   2. Compression error    introduced by Compress/Decompress of u and v
 *
 * The compression error of a single coefficient compressed with d bits is
 * bounded by  Q / 2^(d+1).  The u-error is additionally amplified by s^T
 * (K*N secret coefficients, each up to ETA).  The original toy set
 * (Q=257, d_u=4, d_v=3) gave a per-coefficient compression error of up to
 * ~Q/16 ≈ 16, which combined with the s^T amplification overran the Q/4
 * margin and made decryption fail ~30% of the time.
 *
 * We therefore keep the toy ring size (N=8, K=2) but use the real ML-KEM
 * prime Q=3329 with d_u = d_v = 11 (~log2(Q)), making compression nearly
 * lossless (error <= Q/2^12 ≈ 0.8 per coefficient).  This leaves the full
 * Q/4 margin for the small inherent LWE noise, so decryption is reliable.
 * The Noise Analysis printed at the end reports both terms honestly.
 */

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
    /* Fixed default seed => reproducible teaching output; override with PQC_DEMO_SEED. */
    const char *demo_seed_env = getenv("PQC_DEMO_SEED");
    srand(demo_seed_env ? (unsigned)strtoul(demo_seed_env, NULL, 10) : 1234567u);

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

    /* Noise analysis (honest: includes BOTH inherent and compression noise) */
    printf("\n=== Noise Analysis ===\n");
    printf("Decryption recovers  w = v - s^T u = encode(m) + noise.\n");
    printf("Correct decoding needs every |noise coeff| < Q/4 = %d.\n\n", Q/4);

    /* 1. Inherent LWE noise: e^T r + e2 - s^T e1.
     *    Each of the ~2*K*N products is bounded by ETA*ETA, plus the e2 term. */
    int inherent = 2 * K * N * ETA1 * ETA2 + ETA2;
    printf("1) Inherent LWE noise  (e^T r + e2 - s^T e1)\n");
    printf("   worst-case bound ≈ 2*K*N*η₁*η₂ + η₂ = %d\n", inherent);

    /* 2. Compression error. Per-coefficient error is bounded by Q/2^(d+1).
     *    The u-error is amplified by s^T (K*N secret coeffs, each up to ETA1). */
    int v_comp = (Q + (1 << DV)) / (1 << (DV + 1));        /* ceil(Q/2^(dv+1)) */
    int u_comp = (Q + (1 << DU)) / (1 << (DU + 1));        /* ceil(Q/2^(du+1)) */
    int u_comp_amp = K * N * ETA1 * u_comp;                /* amplified by s^T */
    printf("2) Compression error   (Decompress(Compress(.)) rounding)\n");
    printf("   v term  <= Q/2^(d_v+1)            = %d\n", v_comp);
    printf("   u term  <= K*N*η₁ * Q/2^(d_u+1)   = %d\n", u_comp_amp);

    /* Honest total margin */
    int total_noise = inherent + v_comp + u_comp_amp;
    printf("\nTotal worst-case noise ≈ %d (inherent %d + compression %d)\n",
           total_noise, inherent, v_comp + u_comp_amp);
    printf("Decision threshold     = Q/4 = %d\n", Q/4);
    printf("Margin for error       = %d - %d = %d  (%s)\n",
           Q/4, total_noise, Q/4 - total_noise,
           (Q/4 - total_noise > 0) ? "OK: reliable decryption"
                                   : "TOO TIGHT: decryption may fail");

    printf("\n");
    printf("════════════════════════════════════════════════════════════\n");
    printf("K-PKE Flow:\n");
    printf("  1. KeyGen: A random, s small, t = As + e\n");
    printf("  2. Encrypt: u = A^T r + e1, v = t^T r + e2 + encode(m)\n");
    printf("  3. Decrypt: w = v - s^T u = m + noise, decode(w)\n");
    printf("════════════════════════════════════════════════════════════\n");

    return 0;
}
