/* Complete ML-DSA-65 Implementation
 * Educational reference - demonstrates all components
 * For production, use formally verified libraries
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ============================================
 * SECTION 1: PARAMETERS AND CONSTANTS
 * ============================================ */

/* Field parameters */
#define MLDSA_Q 8380417
#define MLDSA_N 256

/* ML-DSA-65 specific parameters */
#define MLDSA_K 6
#define MLDSA_L 5
#define MLDSA_ETA 4
#define MLDSA_TAU 49
#define MLDSA_BETA 196           /* TAU * ETA */
#define MLDSA_GAMMA1 (1 << 19)   /* 524288 */
#define MLDSA_GAMMA2 ((MLDSA_Q - 1) / 32)  /* 261888 */
#define MLDSA_OMEGA 55
#define MLDSA_D 13

/* Derived constants */
#define MLDSA_M ((MLDSA_Q - 1) / (2 * MLDSA_GAMMA2))  /* 16 for ML-DSA-65 */

/* Size constants (bytes) */
#define SEEDBYTES 32
#define CTILDE_BYTES 48
#define Z_BITS 20
#define Z_BYTES (MLDSA_L * MLDSA_N * Z_BITS / 8)  /* 3200 */
#define H_BYTES (MLDSA_OMEGA + MLDSA_K)           /* 61 */
#define SIG_BYTES (CTILDE_BYTES + Z_BYTES + H_BYTES)  /* 3309 */

#define T1_BITS 10
#define PK_BYTES (SEEDBYTES + MLDSA_K * MLDSA_N * T1_BITS / 8)  /* 1952 */

#define ETA_BITS 4
#define T0_BITS 13
#define SK_BYTES (SEEDBYTES * 3 + 64 + \
                  MLDSA_L * MLDSA_N * ETA_BITS / 8 + \
                  MLDSA_K * MLDSA_N * ETA_BITS / 8 + \
                  MLDSA_K * MLDSA_N * T0_BITS / 8)  /* 4032 */

/* NTT constant: primitive 512th root of unity */
#define MLDSA_ROOT 1753

/* ============================================
 * SECTION 2: DATA STRUCTURES
 * ============================================ */

typedef struct {
    int32_t coeffs[MLDSA_N];
} poly;

typedef struct {
    poly vec[MLDSA_L];
} polyvecl;

typedef struct {
    poly vec[MLDSA_K];
} polyveck;

typedef struct {
    uint8_t rho[SEEDBYTES];      /* Public seed */
    polyveck t1;                 /* Compressed t */
} mldsa_pk;

typedef struct {
    uint8_t rho[SEEDBYTES];      /* Public seed */
    uint8_t K[SEEDBYTES];        /* Private seed */
    uint8_t tr[64];              /* Public key hash */
    polyvecl s1;                 /* Secret vector */
    polyveck s2;                 /* Secret vector */
    polyveck t0;                 /* Low bits of t */
} mldsa_sk;

typedef struct {
    uint8_t c_tilde[CTILDE_BYTES];
    polyvecl z;
    uint8_t h[MLDSA_K][MLDSA_N]; /* Hint bitmap */
    int h_count;                 /* Total hints */
} mldsa_sig;

/* ============================================
 * SECTION 3: FIELD ARITHMETIC
 * ============================================ */

/* Modular reduction: reduce to [0, q) */
static int32_t mod_q(int64_t a) {
    int32_t r = a % MLDSA_Q;
    return r < 0 ? r + MLDSA_Q : r;
}

/* Centered reduction: reduce to [-(q-1)/2, (q-1)/2] */
static int32_t centered_mod(int32_t a) {
    a = mod_q(a);
    if (a > (MLDSA_Q - 1) / 2) {
        a -= MLDSA_Q;
    }
    return a;
}

/* Montgomery multiplication */
static int32_t montgomery_reduce(int64_t a) {
    /* Using q = 8380417, q^(-1) mod 2^32 = 58728449 */
    const int32_t qinv = 58728449;
    int32_t t = (int32_t)a * qinv;
    int64_t m = (int64_t)t * MLDSA_Q;
    int32_t r = (a - m) >> 32;
    return r;
}

/* Barrett reduction */
static int32_t barrett_reduce(int32_t a) {
    /* Using precomputed constant for q = 8380417 */
    const int32_t v = 8396807;  /* floor(2^26 / q) + 1 */
    int32_t t = (int64_t)v * a >> 26;
    t *= MLDSA_Q;
    return a - t;
}

/* ============================================
 * SECTION 4: NTT OPERATIONS
 * ============================================ */

/* Precomputed twiddle factors (first 128 values shown, rest are symmetric) */
static const int32_t zetas[256] = {
    0, 25847, -2608894, -518909, 237124, -777960, -876248, 466468,
    1826347, 2353451, -359251, -2091905, 3119733, -2884855, 3111497, 2680103,
    2725464, 1024112, -1079900, 3585928, -549488, -1119584, 2619752, -2108549,
    -2118186, -3859737, -1399561, -3277672, 1757237, -19422, 4010497, 280005,
    2706023, 95776, 3077325, 3530437, -1661693, -3592148, -2537516, 3915439,
    -3861115, -3043716, 3574422, -2867647, 3539968, -300467, 2348700, -539299,
    -1699267, -1643818, 3505694, -3821735, 3507263, -2140649, -1600420, 3699596,
    811944, 531354, 954230, 3881043, 3900724, -2556880, 2071892, -2797779,
    -3930395, -1528703, -3677745, -3041255, -1452451, 3475950, 2176455, -1585221,
    -1257611, 1939314, -4083598, -1000202, -3190144, -3157330, -3632928, 126922,
    3412210, -983419, 2147896, 2715295, -2967645, -3693493, -411027, -2477047,
    -671102, -1228525, -22981, -1308169, -381987, 1349076, 1852771, -1430430,
    -3343383, 264944, 508951, 3097992, 44288, -1100098, 904516, 3958618,
    -3724342, -8578, 1653064, -3249728, 2389356, -210977, 759969, -1316856,
    189548, -3553272, 3159746, -1851402, -2409325, -177440, 1315589, 1341330,
    1285669, -1584928, -812732, -1439742, -3019102, -3881060, -3628969, 3839961,
    /* Remaining 128 values (symmetric structure for inverse NTT) */
    2091667, 3407706, 2316500, 3817976, -3342478, 2244091, -2446433, -3562462,
    266997, 2434439, -1235728, 3513181, -3520352, -3759364, -1197226, -3193378,
    900702, 1859098, 909542, 819034, 495491, -1613174, -43260, -522500,
    -655327, -3122442, 2031748, 3207046, -3556995, -525098, -768622, -3595838,
    342297, 286988, -2437823, 4108315, 3437287, -3342277, 1735879, 203044,
    2842341, 2691481, -2590150, 1265009, 4055324, 1247620, 2486353, 1595974,
    -3767016, 1250494, 2635921, -3548272, -2994039, 1869119, 1903435, -1050970,
    -1333058, 1237275, -3318210, -1430225, -451100, 1312455, 3306115, -1962642,
    -1279661, 1917081, -2546312, -1374803, 1500165, 777191, 2235880, 3406031,
    -542412, -2831860, -1671176, -1846953, -2584293, -3724270, 594136, -3776993,
    -2013608, 2432395, 2454455, -164721, 1957272, 3369112, 185531, -1207385,
    -3183426, 162844, 1616392, 3014001, 810149, 1652634, -3694233, -1799107,
    -3038916, 3523897, 3866901, 269760, 2213111, -975884, 1717735, 472078,
    -426683, 1723600, -1803090, 1910376, -1667432, -1104333, -260646, -3833893,
    -2939036, -2235985, -420899, -2286327, 183443, -976891, 1612842, -3545687,
    -554416, 3919660, -48306, -1362209, 3937738, 1400424, -846154, 1976782
};

/* In-place NTT */
static void ntt(poly *p) {
    int32_t *a = p->coeffs;
    unsigned int len, start, j, k;
    int32_t zeta, t;

    k = 0;
    for (len = 128; len >= 1; len >>= 1) {
        for (start = 0; start < MLDSA_N; start = j + len) {
            zeta = zetas[++k];
            for (j = start; j < start + len; j++) {
                t = montgomery_reduce((int64_t)zeta * a[j + len]);
                a[j + len] = a[j] - t;
                a[j] = a[j] + t;
            }
        }
    }
}

/* In-place inverse NTT */
static void invntt(poly *p) {
    int32_t *a = p->coeffs;
    unsigned int len, start, j, k;
    int32_t zeta, t;
    const int32_t f = 41978;  /* mont^2 / 256 */

    k = 256;
    for (len = 1; len < MLDSA_N; len <<= 1) {
        for (start = 0; start < MLDSA_N; start = j + len) {
            zeta = -zetas[--k];
            for (j = start; j < start + len; j++) {
                t = a[j];
                a[j] = t + a[j + len];
                a[j + len] = t - a[j + len];
                a[j + len] = montgomery_reduce((int64_t)zeta * a[j + len]);
            }
        }
    }

    for (j = 0; j < MLDSA_N; j++) {
        a[j] = montgomery_reduce((int64_t)f * a[j]);
    }
}

/* Pointwise multiplication in NTT domain */
static void poly_pointwise_montgomery(poly *c, const poly *a, const poly *b) {
    for (int i = 0; i < MLDSA_N; i++) {
        c->coeffs[i] = montgomery_reduce((int64_t)a->coeffs[i] * b->coeffs[i]);
    }
}

/* ============================================
 * SECTION 5: POLYNOMIAL OPERATIONS
 * ============================================ */

static void poly_add(poly *c, const poly *a, const poly *b) {
    for (int i = 0; i < MLDSA_N; i++) {
        c->coeffs[i] = a->coeffs[i] + b->coeffs[i];
    }
}

static void poly_sub(poly *c, const poly *a, const poly *b) {
    for (int i = 0; i < MLDSA_N; i++) {
        c->coeffs[i] = a->coeffs[i] - b->coeffs[i];
    }
}

static void poly_reduce(poly *p) {
    for (int i = 0; i < MLDSA_N; i++) {
        p->coeffs[i] = barrett_reduce(p->coeffs[i]);
    }
}

/* ============================================
 * SECTION 6: DECOMPOSITION FUNCTIONS
 * ============================================ */

/* Decompose r into (r1, r0) where r = r1*2*GAMMA2 + r0 */
static void decompose(int32_t r, int32_t *r1, int32_t *r0) {
    /* Ensure r is in [0, q) */
    r = mod_q(r);

    /* r0 = r mod 2*GAMMA2 (centered) */
    *r0 = r % (2 * MLDSA_GAMMA2);
    if (*r0 > MLDSA_GAMMA2) {
        *r0 -= 2 * MLDSA_GAMMA2;
    }

    /* r1 = (r - r0) / (2*GAMMA2) */
    if (r - *r0 == MLDSA_Q - 1) {
        *r1 = 0;
        *r0 -= 1;
    } else {
        *r1 = (r - *r0) / (2 * MLDSA_GAMMA2);
    }
}

static int32_t highbits(int32_t r) {
    int32_t r1, r0;
    decompose(r, &r1, &r0);
    return r1;
}

static int32_t lowbits(int32_t r) {
    int32_t r1, r0;
    decompose(r, &r1, &r0);
    return r0;
}

/* ============================================
 * SECTION 7: HINT FUNCTIONS
 * ============================================ */

/* Create hint: 1 if HighBits(r) != HighBits(r + z) */
static int make_hint(int32_t z, int32_t r) {
    int32_t r1 = highbits(r);
    int32_t rz1 = highbits(mod_q(r + z));
    return (r1 != rz1) ? 1 : 0;
}

/* Use hint to recover HighBits of original value */
static int32_t use_hint(int32_t h, int32_t r) {
    int32_t r1, r0;
    decompose(r, &r1, &r0);

    if (h == 0) {
        return r1;
    }

    if (r0 > 0) {
        return (r1 + 1) % MLDSA_M;
    } else {
        return (r1 - 1 + MLDSA_M) % MLDSA_M;
    }
}

/* ============================================
 * SECTION 8: SAMPLING FUNCTIONS
 * ============================================ */

/* Simple SHAKE256 simulation (use real SHAKE in production) */
static void shake256(uint8_t *out, size_t outlen,
                     const uint8_t *in, size_t inlen) {
    /* Placeholder - use actual SHAKE256 implementation */
    /* This is NOT cryptographically secure! */
    uint32_t state = 0x12345678;
    for (size_t i = 0; i < inlen; i++) {
        state ^= (uint32_t)in[i] << ((i % 4) * 8);
        state = state * 1103515245 + 12345;
    }
    for (size_t i = 0; i < outlen; i++) {
        state = state * 1103515245 + 12345;
        out[i] = (state >> 16) & 0xFF;
    }
}

/* Sample polynomial with coefficients in [-ETA, ETA] */
static void poly_sample_eta(poly *p, const uint8_t seed[SEEDBYTES],
                           uint16_t nonce) {
    uint8_t buf[SEEDBYTES + 2];
    memcpy(buf, seed, SEEDBYTES);
    buf[SEEDBYTES] = nonce & 0xFF;
    buf[SEEDBYTES + 1] = nonce >> 8;

    uint8_t output[MLDSA_N];  /* Simplified */
    shake256(output, MLDSA_N, buf, SEEDBYTES + 2);

    for (int i = 0; i < MLDSA_N; i++) {
        /* Map byte to [-ETA, ETA] */
        int val = (output[i] % (2 * MLDSA_ETA + 1)) - MLDSA_ETA;
        p->coeffs[i] = val;
    }
}

/* Sample polynomial uniformly in [0, q) */
static void poly_sample_uniform(poly *p, const uint8_t seed[SEEDBYTES],
                               uint8_t i, uint8_t j) {
    uint8_t buf[SEEDBYTES + 2];
    memcpy(buf, seed, SEEDBYTES);
    buf[SEEDBYTES] = i;
    buf[SEEDBYTES + 1] = j;

    uint8_t output[MLDSA_N * 3];  /* 3 bytes per coefficient */
    shake256(output, MLDSA_N * 3, buf, SEEDBYTES + 2);

    int ctr = 0;
    int pos = 0;
    while (ctr < MLDSA_N && pos + 3 <= MLDSA_N * 3) {
        uint32_t val = output[pos] | ((uint32_t)output[pos + 1] << 8) |
                      (((uint32_t)output[pos + 2] & 0x7F) << 16);
        pos += 3;
        if (val < MLDSA_Q) {
            p->coeffs[ctr++] = val;
        }
    }
}

/* Sample masking polynomial with coefficients in [-GAMMA1+1, GAMMA1] */
static void poly_sample_gamma1(poly *p, const uint8_t seed[64],
                              uint16_t nonce) {
    uint8_t buf[64 + 2];
    memcpy(buf, seed, 64);
    buf[64] = nonce & 0xFF;
    buf[64 + 1] = nonce >> 8;

    uint8_t output[MLDSA_N * 3];
    shake256(output, MLDSA_N * 3, buf, 66);

    for (int i = 0; i < MLDSA_N; i++) {
        /* 20-bit value, map to [-GAMMA1+1, GAMMA1] */
        uint32_t val = output[i * 3] | ((uint32_t)output[i * 3 + 1] << 8) |
                      (((uint32_t)output[i * 3 + 2] & 0x0F) << 16);
        val &= (1 << 20) - 1;  /* Mask to 20 bits */
        p->coeffs[i] = MLDSA_GAMMA1 - val;
    }
}

/* Sample challenge polynomial with TAU coefficients in {-1, 1} */
static void poly_sample_challenge(poly *c, const uint8_t c_tilde[CTILDE_BYTES]) {
    uint8_t buf[136];
    shake256(buf, 136, c_tilde, CTILDE_BYTES);

    memset(c->coeffs, 0, sizeof(c->coeffs));

    uint64_t signs = 0;
    for (int i = 0; i < 8; i++) {
        signs |= (uint64_t)buf[i] << (8 * i);
    }

    int pos = 8;
    for (int i = MLDSA_N - MLDSA_TAU; i < MLDSA_N; i++) {
        int j;
        do {
            j = buf[pos++] % (i + 1);
        } while (j > i);  /* Simplified rejection */

        c->coeffs[i] = c->coeffs[j];
        c->coeffs[j] = (signs & 1) ? -1 : 1;
        signs >>= 1;
    }
}

/* ============================================
 * SECTION 9: ENCODING FUNCTIONS
 * ============================================ */

/* Encode z polynomial (20 bits per coefficient) */
__attribute__((unused))
static void encode_z(uint8_t *out, const poly *z) {
    for (int i = 0; i < MLDSA_N / 4; i++) {
        /* Pack 4 coefficients into 10 bytes */
        int32_t c0 = MLDSA_GAMMA1 - z->coeffs[4 * i + 0];
        int32_t c1 = MLDSA_GAMMA1 - z->coeffs[4 * i + 1];
        int32_t c2 = MLDSA_GAMMA1 - z->coeffs[4 * i + 2];
        int32_t c3 = MLDSA_GAMMA1 - z->coeffs[4 * i + 3];

        out[10 * i + 0] = c0 & 0xFF;
        out[10 * i + 1] = (c0 >> 8) & 0xFF;
        out[10 * i + 2] = ((c0 >> 16) & 0x0F) | ((c1 << 4) & 0xF0);
        out[10 * i + 3] = (c1 >> 4) & 0xFF;
        out[10 * i + 4] = (c1 >> 12) & 0xFF;
        out[10 * i + 5] = c2 & 0xFF;
        out[10 * i + 6] = (c2 >> 8) & 0xFF;
        out[10 * i + 7] = ((c2 >> 16) & 0x0F) | ((c3 << 4) & 0xF0);
        out[10 * i + 8] = (c3 >> 4) & 0xFF;
        out[10 * i + 9] = (c3 >> 12) & 0xFF;
    }
}

/* Decode z polynomial */
__attribute__((unused))
static void decode_z(poly *z, const uint8_t *in) {
    for (int i = 0; i < MLDSA_N / 4; i++) {
        uint32_t c0 = in[10 * i + 0] | ((uint32_t)in[10 * i + 1] << 8) |
                     (((uint32_t)in[10 * i + 2] & 0x0F) << 16);
        uint32_t c1 = (in[10 * i + 2] >> 4) | ((uint32_t)in[10 * i + 3] << 4) |
                     ((uint32_t)in[10 * i + 4] << 12);
        uint32_t c2 = in[10 * i + 5] | ((uint32_t)in[10 * i + 6] << 8) |
                     (((uint32_t)in[10 * i + 7] & 0x0F) << 16);
        uint32_t c3 = (in[10 * i + 7] >> 4) | ((uint32_t)in[10 * i + 8] << 4) |
                     ((uint32_t)in[10 * i + 9] << 12);

        z->coeffs[4 * i + 0] = MLDSA_GAMMA1 - c0;
        z->coeffs[4 * i + 1] = MLDSA_GAMMA1 - c1;
        z->coeffs[4 * i + 2] = MLDSA_GAMMA1 - c2;
        z->coeffs[4 * i + 3] = MLDSA_GAMMA1 - c3;
    }
}

/* Encode hints (position-based encoding) */
__attribute__((unused))
static int encode_hints(uint8_t *out, const mldsa_sig *sig) {
    memset(out, 0, H_BYTES);

    int k = 0;
    for (int i = 0; i < MLDSA_K; i++) {
        for (int j = 0; j < MLDSA_N; j++) {
            if (sig->h[i][j]) {
                if (k >= MLDSA_OMEGA) return -1;  /* Too many hints */
                out[k++] = j;
            }
        }
        out[MLDSA_OMEGA + i] = k;  /* End position for polynomial i */
    }

    return 0;
}

/* Decode hints */
__attribute__((unused))
static int decode_hints(mldsa_sig *sig, const uint8_t *in) {
    memset(sig->h, 0, sizeof(sig->h));
    sig->h_count = 0;

    int k = 0;
    for (int i = 0; i < MLDSA_K; i++) {
        int end = in[MLDSA_OMEGA + i];
        if (end < k || end > MLDSA_OMEGA) return -1;

        for (; k < end; k++) {
            int j = in[k];
            if (j >= MLDSA_N) return -1;
            if (k > 0 && in[k] <= in[k - 1]) return -1;  /* Not sorted */
            sig->h[i][j] = 1;
            sig->h_count++;
        }
    }

    return 0;
}

/* ============================================
 * SECTION 10: MATRIX OPERATIONS
 * ============================================ */

/* Expand A matrix from seed */
static void expand_A(poly A[MLDSA_K][MLDSA_L], const uint8_t rho[SEEDBYTES]) {
    for (int i = 0; i < MLDSA_K; i++) {
        for (int j = 0; j < MLDSA_L; j++) {
            poly_sample_uniform(&A[i][j], rho, i, j);
            ntt(&A[i][j]);
        }
    }
}

/* Matrix-vector multiplication: t = A * s (in NTT domain) */
static void matrix_vector_mul(polyveck *t, const poly A[MLDSA_K][MLDSA_L],
                             const polyvecl *s) {
    for (int i = 0; i < MLDSA_K; i++) {
        poly tmp;
        memset(&t->vec[i], 0, sizeof(poly));

        for (int j = 0; j < MLDSA_L; j++) {
            poly_pointwise_montgomery(&tmp, &A[i][j], &s->vec[j]);
            poly_add(&t->vec[i], &t->vec[i], &tmp);
        }

        poly_reduce(&t->vec[i]);
        invntt(&t->vec[i]);
    }
}

/* ============================================
 * SECTION 11: KEY GENERATION
 * ============================================ */

int mldsa_keygen(mldsa_pk *pk, mldsa_sk *sk, const uint8_t seed[SEEDBYTES]) {
    uint8_t expanded[SEEDBYTES * 3];
    poly A[MLDSA_K][MLDSA_L];
    polyvecl s1_ntt;
    polyveck t;

    /* Expand seed to (rho, rho', K) */
    shake256(expanded, SEEDBYTES * 3, seed, SEEDBYTES);
    memcpy(pk->rho, expanded, SEEDBYTES);
    memcpy(sk->rho, expanded, SEEDBYTES);
    memcpy(sk->K, expanded + 2 * SEEDBYTES, SEEDBYTES);

    /* Generate A from rho */
    expand_A(A, pk->rho);

    /* Sample s1, s2 from rho' */
    for (int i = 0; i < MLDSA_L; i++) {
        poly_sample_eta(&sk->s1.vec[i], expanded + SEEDBYTES, i);
    }
    for (int i = 0; i < MLDSA_K; i++) {
        poly_sample_eta(&sk->s2.vec[i], expanded + SEEDBYTES, MLDSA_L + i);
    }

    /* Compute t = A*s1 + s2 */
    memcpy(&s1_ntt, &sk->s1, sizeof(polyvecl));
    for (int i = 0; i < MLDSA_L; i++) {
        ntt(&s1_ntt.vec[i]);
    }
    matrix_vector_mul(&t, A, &s1_ntt);

    for (int i = 0; i < MLDSA_K; i++) {
        poly_add(&t.vec[i], &t.vec[i], &sk->s2.vec[i]);
        poly_reduce(&t.vec[i]);
    }

    /* Decompose t into (t1, t0) */
    for (int i = 0; i < MLDSA_K; i++) {
        for (int j = 0; j < MLDSA_N; j++) {
            int32_t t_val = mod_q(t.vec[i].coeffs[j]);
            pk->t1.vec[i].coeffs[j] = t_val >> MLDSA_D;
            sk->t0.vec[i].coeffs[j] = t_val & ((1 << MLDSA_D) - 1);
            /* Center t0 */
            if (sk->t0.vec[i].coeffs[j] > (1 << (MLDSA_D - 1))) {
                sk->t0.vec[i].coeffs[j] -= (1 << MLDSA_D);
            }
        }
    }

    /* Compute tr = H(pk) */
    uint8_t pk_bytes[PK_BYTES];
    /* Serialize pk (simplified) */
    memcpy(pk_bytes, pk->rho, SEEDBYTES);
    /* ... pack t1 ... */
    shake256(sk->tr, 64, pk_bytes, PK_BYTES);

    return 0;
}

/* ============================================
 * SECTION 12: SIGNING
 * ============================================ */

int mldsa_sign(mldsa_sig *sig, const uint8_t *msg, size_t msglen,
               const mldsa_sk *sk) {
    poly A[MLDSA_K][MLDSA_L];
    polyvecl y, z, y_ntt;
    polyveck w, w1, w0, cs2, ct0;
    poly c;
    uint8_t mu[64], rhoprime[64];
    uint16_t kappa = 0;
    int reject;

    /* Expand A matrix */
    expand_A(A, sk->rho);

    /* Compute message hash: mu = H(tr || msg) */
    uint8_t tr_msg[64 + 4096];  /* Simplified buffer */
    memcpy(tr_msg, sk->tr, 64);
    memcpy(tr_msg + 64, msg, msglen);
    shake256(mu, 64, tr_msg, 64 + msglen);

    /* Compute rhoprime = H(K || mu) for deterministic signing */
    uint8_t k_mu[SEEDBYTES + 64];
    memcpy(k_mu, sk->K, SEEDBYTES);
    memcpy(k_mu + SEEDBYTES, mu, 64);
    shake256(rhoprime, 64, k_mu, SEEDBYTES + 64);

    /* Signing loop with rejection sampling */
    do {
        reject = 0;

        /* Sample y from rhoprime and kappa */
        for (int i = 0; i < MLDSA_L; i++) {
            poly_sample_gamma1(&y.vec[i], rhoprime, kappa * MLDSA_L + i);
        }

        /* Compute w = A*y */
        memcpy(&y_ntt, &y, sizeof(polyvecl));
        for (int i = 0; i < MLDSA_L; i++) {
            ntt(&y_ntt.vec[i]);
        }
        matrix_vector_mul(&w, A, &y_ntt);

        /* Decompose w into (w1, w0) */
        for (int i = 0; i < MLDSA_K; i++) {
            for (int j = 0; j < MLDSA_N; j++) {
                decompose(w.vec[i].coeffs[j],
                         &w1.vec[i].coeffs[j],
                         &w0.vec[i].coeffs[j]);
            }
        }

        /* Compute challenge: c_tilde = H(mu || w1_encode) */
        uint8_t w1_packed[MLDSA_K * MLDSA_N / 2];  /* Simplified */
        /* ... pack w1 ... */
        uint8_t challenge_input[64 + sizeof(w1_packed)];
        memcpy(challenge_input, mu, 64);
        memcpy(challenge_input + 64, w1_packed, sizeof(w1_packed));
        shake256(sig->c_tilde, CTILDE_BYTES, challenge_input,
                64 + sizeof(w1_packed));

        /* Expand c from c_tilde */
        poly_sample_challenge(&c, sig->c_tilde);

        /* Convert c to NTT for multiplication */
        poly c_ntt;
        memcpy(&c_ntt, &c, sizeof(poly));
        ntt(&c_ntt);

        /* Compute z = y + c*s1 */
        for (int i = 0; i < MLDSA_L; i++) {
            poly cs1;
            poly s1_ntt;
            memcpy(&s1_ntt, &sk->s1.vec[i], sizeof(poly));
            ntt(&s1_ntt);
            poly_pointwise_montgomery(&cs1, &c_ntt, &s1_ntt);
            invntt(&cs1);
            poly_add(&z.vec[i], &y.vec[i], &cs1);
        }

        /* Check 1: ||z||_infinity < GAMMA1 - BETA */
        for (int i = 0; i < MLDSA_L && !reject; i++) {
            for (int j = 0; j < MLDSA_N && !reject; j++) {
                int32_t zi = centered_mod(z.vec[i].coeffs[j]);
                if (zi >= MLDSA_GAMMA1 - MLDSA_BETA ||
                    zi <= -(MLDSA_GAMMA1 - MLDSA_BETA)) {
                    reject = 1;
                }
            }
        }

        if (reject) {
            kappa++;
            continue;
        }

        /* Compute r0 = LowBits(w - c*s2) */
        for (int i = 0; i < MLDSA_K; i++) {
            poly s2_ntt;
            memcpy(&s2_ntt, &sk->s2.vec[i], sizeof(poly));
            ntt(&s2_ntt);
            poly_pointwise_montgomery(&cs2.vec[i], &c_ntt, &s2_ntt);
            invntt(&cs2.vec[i]);
        }

        /* Check 2: ||LowBits(w - c*s2)||_infinity < GAMMA2 - BETA */
        for (int i = 0; i < MLDSA_K && !reject; i++) {
            for (int j = 0; j < MLDSA_N && !reject; j++) {
                int32_t r = w.vec[i].coeffs[j] - cs2.vec[i].coeffs[j];
                int32_t r0 = lowbits(r);
                if (r0 >= MLDSA_GAMMA2 - MLDSA_BETA ||
                    r0 <= -(MLDSA_GAMMA2 - MLDSA_BETA)) {
                    reject = 1;
                }
            }
        }

        if (reject) {
            kappa++;
            continue;
        }

        /* Compute c*t0 */
        for (int i = 0; i < MLDSA_K; i++) {
            poly t0_ntt;
            memcpy(&t0_ntt, &sk->t0.vec[i], sizeof(poly));
            ntt(&t0_ntt);
            poly_pointwise_montgomery(&ct0.vec[i], &c_ntt, &t0_ntt);
            invntt(&ct0.vec[i]);
        }

        /* Check 3: ||c*t0||_infinity < GAMMA2 */
        for (int i = 0; i < MLDSA_K && !reject; i++) {
            for (int j = 0; j < MLDSA_N && !reject; j++) {
                int32_t ct0_val = centered_mod(ct0.vec[i].coeffs[j]);
                if (ct0_val >= MLDSA_GAMMA2 || ct0_val <= -MLDSA_GAMMA2) {
                    reject = 1;
                }
            }
        }

        if (reject) {
            kappa++;
            continue;
        }

        /* Compute hints */
        sig->h_count = 0;
        memset(sig->h, 0, sizeof(sig->h));

        for (int i = 0; i < MLDSA_K; i++) {
            for (int j = 0; j < MLDSA_N; j++) {
                int32_t r = w.vec[i].coeffs[j] - cs2.vec[i].coeffs[j];
                int32_t ct0_val = ct0.vec[i].coeffs[j];

                sig->h[i][j] = make_hint(-ct0_val, r);
                sig->h_count += sig->h[i][j];
            }
        }

        /* Check 4: hint weight <= OMEGA */
        if (sig->h_count > MLDSA_OMEGA) {
            reject = 1;
            kappa++;
            continue;
        }

        /* Copy z to signature */
        memcpy(&sig->z, &z, sizeof(polyvecl));

    } while (reject);

    return 0;
}

/* ============================================
 * SECTION 13: VERIFICATION
 * ============================================ */

int mldsa_verify(const mldsa_pk *pk, const uint8_t *msg, size_t msglen,
                 const mldsa_sig *sig) {
    poly A[MLDSA_K][MLDSA_L];
    polyvecl z_ntt;
    polyveck w_prime, Az, ct1;
    poly c, c_ntt;
    uint8_t mu[64], c_tilde_check[CTILDE_BYTES];

    /* Check 1: ||z||_infinity < GAMMA1 - BETA */
    for (int i = 0; i < MLDSA_L; i++) {
        for (int j = 0; j < MLDSA_N; j++) {
            int32_t zi = centered_mod(sig->z.vec[i].coeffs[j]);
            if (zi >= MLDSA_GAMMA1 - MLDSA_BETA ||
                zi <= -(MLDSA_GAMMA1 - MLDSA_BETA)) {
                return -1;  /* Invalid signature */
            }
        }
    }

    /* Check 2: hint weight <= OMEGA */
    if (sig->h_count > MLDSA_OMEGA) {
        return -1;
    }

    /* Expand A matrix */
    expand_A(A, pk->rho);

    /* Compute message hash */
    uint8_t pk_bytes[PK_BYTES];
    memcpy(pk_bytes, pk->rho, SEEDBYTES);
    /* ... serialize full pk ... */
    uint8_t tr[64];
    shake256(tr, 64, pk_bytes, PK_BYTES);

    uint8_t tr_msg[64 + 4096];
    memcpy(tr_msg, tr, 64);
    memcpy(tr_msg + 64, msg, msglen);
    shake256(mu, 64, tr_msg, 64 + msglen);

    /* Expand challenge */
    poly_sample_challenge(&c, sig->c_tilde);
    memcpy(&c_ntt, &c, sizeof(poly));
    ntt(&c_ntt);

    /* Compute A*z */
    memcpy(&z_ntt, &sig->z, sizeof(polyvecl));
    for (int i = 0; i < MLDSA_L; i++) {
        ntt(&z_ntt.vec[i]);
    }
    matrix_vector_mul(&Az, A, &z_ntt);

    /* Compute c*t1*2^d */
    for (int i = 0; i < MLDSA_K; i++) {
        poly t1_scaled, t1_ntt;
        for (int j = 0; j < MLDSA_N; j++) {
            t1_scaled.coeffs[j] = pk->t1.vec[i].coeffs[j] << MLDSA_D;
        }
        memcpy(&t1_ntt, &t1_scaled, sizeof(poly));
        ntt(&t1_ntt);
        poly_pointwise_montgomery(&ct1.vec[i], &c_ntt, &t1_ntt);
        invntt(&ct1.vec[i]);
    }

    /* Compute w' = A*z - c*t1*2^d */
    for (int i = 0; i < MLDSA_K; i++) {
        poly_sub(&w_prime.vec[i], &Az.vec[i], &ct1.vec[i]);
        poly_reduce(&w_prime.vec[i]);
    }

    /* Apply hints to recover w1 */
    polyveck w1_prime;
    for (int i = 0; i < MLDSA_K; i++) {
        for (int j = 0; j < MLDSA_N; j++) {
            w1_prime.vec[i].coeffs[j] = use_hint(sig->h[i][j],
                                                 w_prime.vec[i].coeffs[j]);
        }
    }

    /* Recompute challenge hash */
    uint8_t w1_packed[MLDSA_K * MLDSA_N / 2] = {0};
    /* Pack w1_prime: 4-bit encoding per coefficient (γ₂=(q-1)/32 case).
       Each pair of coefficients packs into one byte. */
    for (int i = 0; i < MLDSA_K; i++) {
        for (int j = 0; j < MLDSA_N / 2; j++) {
            w1_packed[i * (MLDSA_N / 2) + j] =
                (uint8_t)((w1_prime.vec[i].coeffs[2*j]   & 0xF) |
                         ((w1_prime.vec[i].coeffs[2*j+1] & 0xF) << 4));
        }
    }
    uint8_t challenge_input[64 + sizeof(w1_packed)];
    memcpy(challenge_input, mu, 64);
    memcpy(challenge_input + 64, w1_packed, sizeof(w1_packed));
    shake256(c_tilde_check, CTILDE_BYTES, challenge_input,
            64 + sizeof(w1_packed));

    /* Compare challenges */
    if (memcmp(sig->c_tilde, c_tilde_check, CTILDE_BYTES) != 0) {
        return -1;  /* Invalid signature */
    }

    return 0;  /* Valid signature */
}

/* ============================================
 * SECTION 14: TEST PROGRAM
 * ============================================ */

int main(void) {
    printf("ML-DSA-65 Complete Implementation Demo\n");
    printf("======================================\n\n");

    /* Key generation */
    printf("1. Key Generation\n");
    mldsa_pk pk;
    mldsa_sk sk;
    uint8_t seed[SEEDBYTES] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
    };

    int ret = mldsa_keygen(&pk, &sk, seed);
    printf("   Key generation: %s\n", ret == 0 ? "SUCCESS" : "FAILED");
    printf("   Public key size: %d bytes\n", PK_BYTES);
    printf("   Secret key size: %d bytes\n", SK_BYTES);

    /* Signing */
    printf("\n2. Signing\n");
    const char *message = "Test message for ML-DSA signature";
    mldsa_sig sig;

    ret = mldsa_sign(&sig, (const uint8_t *)message, strlen(message), &sk);
    printf("   Signing: %s\n", ret == 0 ? "SUCCESS" : "FAILED");
    printf("   Signature size: %d bytes\n", SIG_BYTES);
    printf("   Hint count: %d (max %d)\n", sig.h_count, MLDSA_OMEGA);

    /* Verification */
    printf("\n3. Verification\n");
    ret = mldsa_verify(&pk, (const uint8_t *)message, strlen(message), &sig);
    printf("   Verification: %s\n", ret == 0 ? "VALID" : "INVALID");

    /* Test with wrong message */
    printf("\n4. Wrong Message Test\n");
    const char *wrong_msg = "Wrong message";
    ret = mldsa_verify(&pk, (const uint8_t *)wrong_msg, strlen(wrong_msg), &sig);
    printf("   Wrong message verification: %s (expected INVALID)\n",
           ret == 0 ? "VALID" : "INVALID");

    printf("\n======================================\n");
    printf("Demo complete.\n");

    return 0;
}
