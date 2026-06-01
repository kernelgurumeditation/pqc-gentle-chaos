/*
 * ============================================================================
 *  GRADED CAPSTONE PROJECT - "Hybrid Secure Channel" End-to-End Demo
 *  PQC Developer's Handbook  (integrates Modules 4, 6 and 8)
 * ============================================================================
 *
 *  This single, self-contained program walks a client and a server through
 *  every stage needed to stand up a post-quantum-safe secure channel and then
 *  authenticates the handshake transcript:
 *
 *    Stage A  HYBRID KEM   (Module 8 / Module 4) : a toy X25519 + ML-KEM-768
 *                          combiner (X-Wing combiner shape) so BOTH sides
 *                          derive the SAME hybrid shared secret.
 *    Stage B  KDF          (Module 4)            : HKDF-style extract+expand
 *                          turns the shared secret into a 32-byte session key.
 *    Stage C  SIGN/VERIFY  (Module 6)            : a toy ML-DSA-65-style
 *                          Fiat-Shamir lattice signature over the handshake
 *                          transcript hash; verify must PASS on the valid
 *                          signature and FAIL on a 1-bit-flipped transcript.
 *    Stage D  SELF-TEST    (KAT)                 : assert fixed known values
 *                          (session key + transcript) so a fixed-seed run is
 *                          byte-for-byte reproducible.
 *    Stage E  CONST-TIME   : all secret comparisons go through a constant-time
 *                          helper (ct_memcmp) to avoid timing side channels.
 *
 *  ------------------------------------------------------------------------
 *  EDUCATIONAL, NOT PRODUCTION.
 *  ------------------------------------------------------------------------
 *  Like the rest of source_code/, this uses TOY primitives: the "hash" is a
 *  small deterministic mixing function (NOT SHA-3/SHAKE), "X25519" is a
 *  DH-shaped hash construction (NOT Curve25519), the lattice signature runs
 *  at a tiny scale, and the RNG is a fixed-seed LCG. The shapes mirror the
 *  real algorithms (X-Wing combiner, HKDF, ML-DSA commit/challenge/response)
 *  so the data flow is faithful, but NONE of it is cryptographically secure.
 *  Use liboqs / a FIPS-validated library for anything real.
 *
 *  Determinism: any randomness is seeded from getenv("PQC_DEMO_SEED") with a
 *  fixed default of 1234567u, matching the rest of the repository.
 *
 *  Build:  gcc -Wall -Wextra -Wshadow -O2 -std=c11 -o capstone_hybrid_channel \
 *              capstone_hybrid_channel.c -lm
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

/* ========================================================================== *
 *  0.  Sizes and toy parameters                                              *
 * ========================================================================== */

#define HASH_BYTES   32          /* digest / shared-secret / key width        */
#define SEED_BYTES   32          /* seed material width                       */

/* Toy "X25519" classical DH (hash-shaped, NOT Curve25519). */
#define X_SK_BYTES   32
#define X_PK_BYTES   32
#define X_SS_BYTES   32

/* Toy "ML-KEM-768" KEM (hash-shaped, NOT a real lattice KEM). */
#define MLKEM_SK_BYTES 32
#define MLKEM_PK_BYTES 32
#define MLKEM_CT_BYTES 32
#define MLKEM_SS_BYTES 32

/* Toy ML-DSA-65-style Fiat-Shamir lattice signature, tiny scale.
 * Real ML-DSA-65 uses N=256, K=6, L=5, Q=8380417; here we keep the SHAPE
 * (matrix A, secret s, commit w=A*y, challenge c, response z=y+c*s,
 * verify A*z - c*t == w) but at a size a learner can read end to end. */
#define DSA_N        16          /* vector dimension (toy; real N=256)        */
#define DSA_Q        8380417     /* real ML-DSA modulus, kept for flavor      */
#define DSA_TAU      3           /* # of +/-1 entries in the challenge        */
#define DSA_GAMMA1   524288      /* (1<<19), real ML-DSA-65 gamma1            */
#define DSA_ETA      4           /* secret coeff bound, real ML-DSA-65 eta    */
#define DSA_BETA     (DSA_TAU * DSA_ETA)   /* = 12, real ML-DSA-65 beta=49*4  */

/* ========================================================================== *
 *  1.  Deterministic toy RNG (fixed-seed LCG)                                *
 * ========================================================================== */

static uint32_t g_rng_state = 1234567u;

static void rng_seed(uint32_t s) { g_rng_state = s; }

static uint32_t rng_next(void) {
    /* glibc-style LCG; deterministic, NOT cryptographic. */
    g_rng_state = g_rng_state * 1103515245u + 12345u;
    return g_rng_state;
}

static void rng_bytes(uint8_t *out, size_t len) {
    for (size_t i = 0; i < len; i++)
        out[i] = (uint8_t)((rng_next() >> 16) & 0xFF);
}

/* ========================================================================== *
 *  2.  Toy hash (deterministic mixing; NOT SHA-3 / SHAKE)                    *
 * ========================================================================== *
 *  A single small routine plays every symmetric role (H, PRF, XOF). It is
 *  deterministic, which is all the round trips here require. It is a teaching
 *  stand-in only and has none of SHA-3's security properties.               */

static void toy_hash(uint8_t *out, size_t out_len,
                     const uint8_t *in, size_t in_len) {
    uint32_t state = 0x9E3779B1u;            /* fixed IV (golden ratio)       */
    for (size_t i = 0; i < in_len; i++)
        state = state * 31u + in[i] + (uint32_t)i;
    for (size_t i = 0; i < out_len; i++) {
        state = state * 1103515245u + 12345u;
        out[i] = (uint8_t)((state >> 16) & 0xFF);
    }
}

/* Convenience: hash the concatenation of up to four labeled chunks. */
static void toy_hash_cat(uint8_t *out, size_t out_len,
                         const uint8_t *a, size_t alen,
                         const uint8_t *b, size_t blen,
                         const uint8_t *c, size_t clen,
                         const uint8_t *d, size_t dlen) {
    /* Bounded scratch: every caller stays well under 512 bytes total. */
    uint8_t buf[512];
    size_t off = 0;
    if (a && alen) { memcpy(buf + off, a, alen); off += alen; }
    if (b && blen) { memcpy(buf + off, b, blen); off += blen; }
    if (c && clen) { memcpy(buf + off, c, clen); off += clen; }
    if (d && dlen) { memcpy(buf + off, d, dlen); off += dlen; }
    toy_hash(out, out_len, buf, off);
}

/* ========================================================================== *
 *  3.  Constant-time compare (Stage E)                                       *
 * ========================================================================== *
 *  Secret-dependent comparisons (shared secrets, session keys, signature     *
 *  challenges) MUST NOT short-circuit: an attacker who can time a byte-by-    *
 *  byte memcmp learns how many leading bytes matched and can forge values    *
 *  one byte at a time. ct_memcmp folds every byte into an accumulator so the  *
 *  running time is independent of WHERE the first difference is. Returns 0    *
 *  iff the buffers are equal.                                                 */

static int ct_memcmp(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++)
        diff |= (uint8_t)(a[i] ^ b[i]);
    return diff != 0;   /* 0 == equal, 1 == differ (no early exit) */
}

/* ========================================================================== *
 *  STAGE A.  HYBRID KEM  (Modules 8 + 4)                                     *
 * ========================================================================== *
 *  Toy X25519 (classical) + toy ML-KEM-768 (post-quantum), combined with the *
 *  X-Wing combiner shape:                                                     *
 *      ss = H( ss_pq || ss_classical || ct || pk || "capstone-xwing-v1" )    *
 *  Binding ct and pk into the hash makes the combiner non-malleable, exactly  *
 *  as X-Wing binds the ML-KEM ciphertext and X25519 public key.              */

static const char XWING_LABEL[] = "capstone-xwing-v1";

/* ---- toy X25519: pk = H(sk); DH(sk_a, pk_b) is symmetric ----------------- */

static void x_keygen(uint8_t pk[X_PK_BYTES], uint8_t sk[X_SK_BYTES]) {
    rng_bytes(sk, X_SK_BYTES);
    toy_hash(pk, X_PK_BYTES, sk, X_SK_BYTES);     /* pk = H(sk) ~ sk*G        */
}

static void x_dh(uint8_t ss[X_SS_BYTES],
                 const uint8_t peer_pk[X_PK_BYTES],
                 const uint8_t my_sk[X_SK_BYTES]) {
    /* ss = H( peer_pk XOR H(my_sk) ).  With pk = H(sk) this is symmetric:
     * H(H(sk_b) XOR H(sk_a)) == H(H(sk_a) XOR H(sk_b)).                      */
    uint8_t my_sk_hash[X_PK_BYTES];
    uint8_t mixed[X_PK_BYTES];
    toy_hash(my_sk_hash, X_PK_BYTES, my_sk, X_SK_BYTES);
    for (int i = 0; i < X_PK_BYTES; i++)
        mixed[i] = peer_pk[i] ^ my_sk_hash[i];
    toy_hash(ss, X_SS_BYTES, mixed, X_PK_BYTES);
}

/* ---- toy ML-KEM-768: keygen / encaps / decaps --------------------------- */

static void mlkem_keygen(uint8_t pk[MLKEM_PK_BYTES], uint8_t sk[MLKEM_SK_BYTES]) {
    rng_bytes(sk, MLKEM_SK_BYTES);
    toy_hash(pk, MLKEM_PK_BYTES, sk, MLKEM_SK_BYTES);   /* pk = H(sk)         */
}

static void mlkem_encaps(uint8_t ct[MLKEM_CT_BYTES], uint8_t ss[MLKEM_SS_BYTES],
                         const uint8_t pk[MLKEM_PK_BYTES]) {
    /* Sample an ephemeral message m; ct hides m under pk; ss = H(m || pk).
     * Mirrors the FO transform's "ss bound to ciphertext and key" shape.    */
    uint8_t m[SEED_BYTES];
    rng_bytes(m, SEED_BYTES);
    uint8_t pk_pad[MLKEM_CT_BYTES];
    toy_hash(pk_pad, MLKEM_CT_BYTES, pk, MLKEM_PK_BYTES);
    for (int i = 0; i < MLKEM_CT_BYTES; i++)
        ct[i] = (uint8_t)(m[i % SEED_BYTES] ^ pk_pad[i]);
    toy_hash_cat(ss, MLKEM_SS_BYTES, m, SEED_BYTES, pk, MLKEM_PK_BYTES,
                 NULL, 0, NULL, 0);
}

static void mlkem_decaps(uint8_t ss[MLKEM_SS_BYTES],
                         const uint8_t ct[MLKEM_CT_BYTES],
                         const uint8_t sk[MLKEM_SK_BYTES]) {
    /* Reconstruct pk = H(sk), recover m from ct, recompute ss = H(m || pk). */
    uint8_t pk[MLKEM_PK_BYTES];
    uint8_t pk_pad[MLKEM_CT_BYTES];
    uint8_t m[SEED_BYTES] = {0};
    toy_hash(pk, MLKEM_PK_BYTES, sk, MLKEM_SK_BYTES);
    toy_hash(pk_pad, MLKEM_CT_BYTES, pk, MLKEM_PK_BYTES);
    for (int i = 0; i < MLKEM_CT_BYTES; i++)
        m[i % SEED_BYTES] = (uint8_t)(ct[i] ^ pk_pad[i]);
    toy_hash_cat(ss, MLKEM_SS_BYTES, m, SEED_BYTES, pk, MLKEM_PK_BYTES,
                 NULL, 0, NULL, 0);
}

/* ---- X-Wing combiner ----------------------------------------------------- */

static void xwing_combine(uint8_t ss[HASH_BYTES],
                          const uint8_t ss_pq[MLKEM_SS_BYTES],
                          const uint8_t ss_cl[X_SS_BYTES],
                          const uint8_t ct[MLKEM_CT_BYTES],
                          const uint8_t pk[X_PK_BYTES]) {
    /* ss = H( ss_pq || ss_classical || ct || pk || label ) */
    uint8_t buf[MLKEM_SS_BYTES + X_SS_BYTES + MLKEM_CT_BYTES + X_PK_BYTES +
                sizeof(XWING_LABEL) - 1];
    size_t off = 0;
    memcpy(buf + off, ss_pq, MLKEM_SS_BYTES); off += MLKEM_SS_BYTES;
    memcpy(buf + off, ss_cl, X_SS_BYTES);     off += X_SS_BYTES;
    memcpy(buf + off, ct,    MLKEM_CT_BYTES); off += MLKEM_CT_BYTES;
    memcpy(buf + off, pk,    X_PK_BYTES);     off += X_PK_BYTES;
    memcpy(buf + off, XWING_LABEL, sizeof(XWING_LABEL) - 1);
    off += sizeof(XWING_LABEL) - 1;
    toy_hash(ss, HASH_BYTES, buf, off);
}

/* ========================================================================== *
 *  STAGE B.  KDF  (Module 4) - HKDF-style extract + expand                   *
 * ========================================================================== *
 *  PRK     = HKDF-Extract(salt, IKM)  = H(salt || IKM)                        *
 *  OKM[32] = HKDF-Expand(PRK, info)   = H(PRK || info || 0x01)               *
 *  Toy hash stands in for HMAC-SHA-256; the extract-then-expand SHAPE is the  *
 *  load-bearing teaching point.                                               */

static void hkdf_extract(uint8_t prk[HASH_BYTES],
                         const uint8_t *salt, size_t salt_len,
                         const uint8_t *ikm,  size_t ikm_len) {
    toy_hash_cat(prk, HASH_BYTES, salt, salt_len, ikm, ikm_len,
                 NULL, 0, NULL, 0);
}

static void hkdf_expand(uint8_t okm[HASH_BYTES],
                        const uint8_t prk[HASH_BYTES],
                        const uint8_t *info, size_t info_len) {
    uint8_t ctr = 0x01;
    toy_hash_cat(okm, HASH_BYTES, prk, HASH_BYTES, info, info_len,
                 &ctr, 1, NULL, 0);
}

/* ========================================================================== *
 *  STAGE C.  SIGN / VERIFY  (Module 6) - toy ML-DSA-65-style FS signature    *
 * ========================================================================== *
 *  Keeps the ML-DSA / Fiat-Shamir SHAPE at toy dimension N=DSA_N:            *
 *    KeyGen  : A (N x N) from a seed; secret s small; t = A*s          (mod q)*
 *    Sign(m) : y small mask; w = A*y; c = H(w || m) -> sparse +/-1 poly;     *
 *              z = y + c*s; reject if ||z|| too large; sig = (c_tilde, z)    *
 *    Verify  : w' = A*z - c*t; c' = H(w' || m); accept iff c' == c_tilde     *
 *  This is the Fiat-Shamir-with-aborts structure of ML-DSA, minus NTT,       *
 *  hints, and bit-packing.                                                    */

typedef struct { int64_t v[DSA_N]; }            dsa_vec;
typedef struct { int64_t a[DSA_N][DSA_N]; }     dsa_mat;

typedef struct {
    dsa_mat A;                       /* public matrix (from seed)             */
    dsa_vec t;                       /* public vector t = A*s mod q           */
} dsa_pk;

typedef struct {
    dsa_vec s;                       /* secret vector, small coefficients     */
} dsa_sk;

typedef struct {
    uint8_t c_tilde[HASH_BYTES];     /* challenge digest (Fiat-Shamir)        */
    dsa_vec z;                       /* response                              */
} dsa_sig;

static int64_t dsa_modq(int64_t x) {
    int64_t r = x % DSA_Q;
    if (r < 0) r += DSA_Q;
    return r;
}

/* Centered representative in (-q/2, q/2]. */
static int64_t dsa_cmodq(int64_t x) {
    int64_t r = dsa_modq(x);
    if (r > DSA_Q / 2) r -= DSA_Q;
    return r;
}

/* Serialize a vector (centered) to bytes, for hashing into the challenge. */
static void dsa_vec_bytes(uint8_t out[DSA_N * 8], const dsa_vec *vc) {
    for (int i = 0; i < DSA_N; i++) {
        uint64_t u = (uint64_t)dsa_cmodq(vc->v[i]);
        for (int b = 0; b < 8; b++)
            out[i * 8 + b] = (uint8_t)((u >> (8 * b)) & 0xFF);
    }
}

/* Expand public matrix A from a 32-byte seed (toy uniform sampling). */
static void dsa_expand_A(dsa_mat *A, const uint8_t seed[SEED_BYTES]) {
    for (int i = 0; i < DSA_N; i++) {
        for (int j = 0; j < DSA_N; j++) {
            uint8_t h[8];
            uint8_t in[SEED_BYTES + 2];
            memcpy(in, seed, SEED_BYTES);
            in[SEED_BYTES]     = (uint8_t)i;
            in[SEED_BYTES + 1] = (uint8_t)j;
            toy_hash(h, 8, in, sizeof(in));
            uint64_t u = 0;
            for (int b = 0; b < 8; b++) u |= (uint64_t)h[b] << (8 * b);
            A->a[i][j] = (int64_t)(u % DSA_Q);
        }
    }
}

/* Sample a small secret vector with coefficients in [-DSA_ETA, DSA_ETA]. */
static void dsa_sample_small(dsa_vec *vc, const uint8_t seed[SEED_BYTES],
                             uint8_t nonce) {
    uint8_t buf[DSA_N];
    uint8_t in[SEED_BYTES + 1];
    memcpy(in, seed, SEED_BYTES);
    in[SEED_BYTES] = nonce;
    toy_hash(buf, DSA_N, in, sizeof(in));
    for (int i = 0; i < DSA_N; i++)
        vc->v[i] = (int64_t)(buf[i] % (2 * DSA_ETA + 1)) - DSA_ETA;
}

/* Sample a mask y with coefficients in [-(GAMMA1-1), GAMMA1-1]. */
static void dsa_sample_mask(dsa_vec *vc, const uint8_t seed[SEED_BYTES],
                            uint16_t nonce) {
    uint8_t buf[DSA_N * 4];
    uint8_t in[SEED_BYTES + 2];
    memcpy(in, seed, SEED_BYTES);
    in[SEED_BYTES]     = (uint8_t)(nonce & 0xFF);
    in[SEED_BYTES + 1] = (uint8_t)(nonce >> 8);
    toy_hash(buf, sizeof(buf), in, sizeof(in));
    for (int i = 0; i < DSA_N; i++) {
        uint32_t u = (uint32_t)buf[i * 4]
                   | ((uint32_t)buf[i * 4 + 1] << 8)
                   | ((uint32_t)buf[i * 4 + 2] << 16)
                   | ((uint32_t)buf[i * 4 + 3] << 24);
        vc->v[i] = (int64_t)(u % (2u * DSA_GAMMA1 - 1)) - (DSA_GAMMA1 - 1);
    }
}

/* Matrix-vector multiply mod q: r = A * x. */
static void dsa_matvec(dsa_vec *r, const dsa_mat *A, const dsa_vec *x) {
    for (int i = 0; i < DSA_N; i++) {
        int64_t acc = 0;
        for (int j = 0; j < DSA_N; j++)
            acc += A->a[i][j] * x->v[j];   /* int64 holds N * q^2 worst case */
        r->v[i] = dsa_modq(acc);
    }
}

/* Derive a sparse challenge from c_tilde (TAU entries of +/-1, like ML-DSA's
 * challenge polynomial) and fold it into a single challenge SCALAR. A scalar
 * is used (rather than a ring/convolution product) because the toy public
 * matrix A is an arbitrary matrix: only scalar multiplication commutes with
 * A, i.e. A*(c*s) == c*(A*s) == c*t. Real ML-DSA gets commutativity for free
 * because A and c both live in the same polynomial ring R_q. The +/-1 sparse
 * structure (and thus the small norm of c) is preserved so the rejection
 * bound BETA = TAU*ETA stays meaningful. */
static int64_t dsa_challenge_from_tilde(const uint8_t c_tilde[HASH_BYTES]) {
    uint8_t buf[DSA_N + 16];
    toy_hash(buf, sizeof(buf), c_tilde, HASH_BYTES);
    int8_t c[DSA_N];
    for (int i = 0; i < DSA_N; i++) c[i] = 0;
    uint64_t signs = 0;
    for (int i = 0; i < 8; i++) signs |= (uint64_t)buf[i] << (8 * i);
    int pos = 8, placed = 0;
    while (placed < DSA_TAU && pos < (int)sizeof(buf)) {
        int idx = buf[pos++] % DSA_N;
        if (c[idx] != 0) continue;             /* keep TAU distinct slots */
        c[idx] = (signs & 1) ? -1 : 1;
        signs >>= 1;
        placed++;
    }
    /* Fold the sparse +/-1 pattern into one scalar in (-TAU .. +TAU). */
    int64_t c_scalar = 0;
    for (int i = 0; i < DSA_N; i++) c_scalar += c[i];
    return c_scalar;
}

/* r = c_scalar * x mod q. */
static void dsa_cmul(dsa_vec *r, int64_t c_scalar, const dsa_vec *x) {
    for (int i = 0; i < DSA_N; i++)
        r->v[i] = dsa_modq(c_scalar * x->v[i]);
}

/* Compute c_tilde = H( w_bytes || msg ). */
static void dsa_challenge_hash(uint8_t c_tilde[HASH_BYTES],
                               const dsa_vec *w,
                               const uint8_t *msg, size_t msg_len) {
    uint8_t wb[DSA_N * 8];
    dsa_vec_bytes(wb, w);
    toy_hash_cat(c_tilde, HASH_BYTES, wb, sizeof(wb), msg, msg_len,
                 NULL, 0, NULL, 0);
}

static void dsa_keygen(dsa_pk *pk, dsa_sk *sk, const uint8_t seed[SEED_BYTES]) {
    uint8_t sub[SEED_BYTES * 2];
    toy_hash(sub, sizeof(sub), seed, SEED_BYTES);   /* (rho || rhoprime)      */
    dsa_expand_A(&pk->A, sub);                       /* A from rho            */
    dsa_sample_small(&sk->s, sub + SEED_BYTES, 0);   /* s from rhoprime       */
    dsa_matvec(&pk->t, &pk->A, &sk->s);              /* t = A*s mod q         */
}

/* Sign with Fiat-Shamir-with-aborts. Deterministic given (sk, msg) because the
 * mask seed folds in the attempt counter kappa. Returns # of attempts used. */
static int dsa_sign(dsa_sig *sig, const dsa_pk *pk, const dsa_sk *sk,
                    const uint8_t *msg, size_t msg_len) {
    uint8_t mask_seed[SEED_BYTES];
    /* mask_seed = H(s || msg) so signing is deterministic per (key, msg). */
    {
        uint8_t sb[DSA_N * 8];
        dsa_vec_bytes(sb, &sk->s);
        toy_hash_cat(mask_seed, SEED_BYTES, sb, sizeof(sb), msg, msg_len,
                     NULL, 0, NULL, 0);
    }
    for (uint16_t kappa = 0; ; kappa++) {
        dsa_vec y, w, cs, z;
        dsa_sample_mask(&y, mask_seed, kappa);
        dsa_matvec(&w, &pk->A, &y);                  /* w = A*y               */
        dsa_challenge_hash(sig->c_tilde, &w, msg, msg_len);
        int64_t c = dsa_challenge_from_tilde(sig->c_tilde); /* c from c_tilde */
        dsa_cmul(&cs, c, &sk->s);                     /* c*s                  */
        for (int i = 0; i < DSA_N; i++)
            z.v[i] = y.v[i] + cs.v[i];               /* z = y + c*s           */
        /* Rejection: ||z||_inf must stay below GAMMA1 - BETA (centered). */
        int reject = 0;
        for (int i = 0; i < DSA_N; i++) {
            int64_t zi = dsa_cmodq(z.v[i]);
            if (zi >= DSA_GAMMA1 - DSA_BETA || zi <= -(DSA_GAMMA1 - DSA_BETA)) {
                reject = 1; break;
            }
        }
        if (!reject) {
            sig->z = z;
            return (int)kappa + 1;
        }
        /* safety valve: the toy params accept quickly; cap attempts anyway */
        if (kappa > 4096) { sig->z = z; return (int)kappa + 1; }
    }
}

/* Verify: recompute w' = A*z - c*t, then check H(w'||msg) == c_tilde. */
static int dsa_verify(const dsa_pk *pk, const dsa_sig *sig,
                      const uint8_t *msg, size_t msg_len) {
    dsa_vec ct, az, wprime;
    /* Reject obviously-out-of-range z up front (norm check). */
    for (int i = 0; i < DSA_N; i++) {
        int64_t zi = dsa_cmodq(sig->z.v[i]);
        if (zi >= DSA_GAMMA1 - DSA_BETA || zi <= -(DSA_GAMMA1 - DSA_BETA))
            return 0;
    }
    int64_t c = dsa_challenge_from_tilde(sig->c_tilde);
    dsa_matvec(&az, &pk->A, &sig->z);                /* A*z                   */
    dsa_cmul(&ct, c, &pk->t);                         /* c*t                  */
    for (int i = 0; i < DSA_N; i++)
        wprime.v[i] = dsa_modq(az.v[i] - ct.v[i]);    /* w' = A*z - c*t        */
    uint8_t c_check[HASH_BYTES];
    dsa_challenge_hash(c_check, &wprime, msg, msg_len);
    /* constant-time compare of the challenge digest */
    return ct_memcmp(c_check, sig->c_tilde, HASH_BYTES) == 0 ? 1 : 0;
}

/* ========================================================================== *
 *  Output helpers                                                            *
 * ========================================================================== */

static void print_hex(const char *label, const uint8_t *d, size_t len) {
    printf("%s", label);
    for (size_t i = 0; i < len; i++) printf("%02x", d[i]);
    printf("\n");
}

static void step(const char *title) {
    printf("\n------------------------------------------------------------\n");
    printf("%s\n", title);
    printf("------------------------------------------------------------\n");
}

/* Fixed KAT expectations for the default seed 1234567u. These are produced by
 * the reference run and asserted in Stage D so the demo is self-checking.    */
static const uint8_t KAT_SHARED_SECRET[HASH_BYTES] = {
    0x51, 0x80, 0xb1, 0x50, 0x8f, 0x6b, 0xdc, 0xe2,
    0x72, 0x76, 0x93, 0xa1, 0x61, 0x64, 0x57, 0x11,
    0xa8, 0x00, 0x0a, 0xfb, 0x5c, 0xc5, 0x29, 0xfc,
    0xf2, 0x50, 0xc9, 0xc9, 0x9e, 0x86, 0x53, 0x43
};
static const uint8_t KAT_SESSION_KEY[HASH_BYTES] = {
    0xb0, 0x88, 0x6d, 0x98, 0xd2, 0xef, 0x78, 0xbd,
    0x85, 0xba, 0x00, 0xb0, 0x90, 0x91, 0x1a, 0x3a,
    0x7e, 0xad, 0x68, 0x6b, 0xe5, 0x34, 0x46, 0x56,
    0x73, 0x55, 0xb9, 0x8f, 0xbe, 0x28, 0x18, 0x65
};

/* ========================================================================== *
 *  main                                                                      *
 * ========================================================================== */

int main(void) {
    /* Deterministic: fixed default seed, override with PQC_DEMO_SEED. */
    const char *seed_env = getenv("PQC_DEMO_SEED");
    uint32_t seed = seed_env ? (uint32_t)strtoul(seed_env, NULL, 10) : 1234567u;
    rng_seed(seed);

    int ok = 1;   /* overall pass/fail accumulator */

    printf("============================================================\n");
    printf("  PQC HANDBOOK - GRADED CAPSTONE: Hybrid Secure Channel\n");
    printf("  (toy/educational - NOT production; integrates M4, M6, M8)\n");
    printf("============================================================\n");
    printf("RNG seed (PQC_DEMO_SEED or default): %u\n", seed);

    /* ---------------------------------------------------------------- *
     *  STAGE A: HYBRID KEM (X25519 + ML-KEM-768, X-Wing combiner)       *
     * ---------------------------------------------------------------- */
    step("STAGE A  HYBRID KEM  (Module 8 X-Wing combiner + Module 4 KEM)");

    /* Server long-term hybrid keypair (classical + PQ). */
    uint8_t srv_x_pk[X_PK_BYTES],  srv_x_sk[X_SK_BYTES];
    uint8_t srv_k_pk[MLKEM_PK_BYTES], srv_k_sk[MLKEM_SK_BYTES];
    x_keygen(srv_x_pk, srv_x_sk);
    mlkem_keygen(srv_k_pk, srv_k_sk);

    /* CLIENT side: ephemeral X25519 + ML-KEM encapsulation to the server. */
    uint8_t cli_x_pk[X_PK_BYTES], cli_x_sk[X_SK_BYTES];
    x_keygen(cli_x_pk, cli_x_sk);
    uint8_t cli_x_ss[X_SS_BYTES];
    x_dh(cli_x_ss, srv_x_pk, cli_x_sk);            /* classical DH (client)   */

    uint8_t kem_ct[MLKEM_CT_BYTES], cli_k_ss[MLKEM_SS_BYTES];
    mlkem_encaps(kem_ct, cli_k_ss, srv_k_pk);      /* PQ encaps (client)      */

    uint8_t client_ss[HASH_BYTES];
    xwing_combine(client_ss, cli_k_ss, cli_x_ss, kem_ct, cli_x_pk);

    /* SERVER side: classical DH + ML-KEM decapsulation, then same combiner. */
    uint8_t srv_x_ss[X_SS_BYTES];
    x_dh(srv_x_ss, cli_x_pk, srv_x_sk);            /* classical DH (server)   */
    uint8_t srv_k_ss[MLKEM_SS_BYTES];
    mlkem_decaps(srv_k_ss, kem_ct, srv_k_sk);      /* PQ decaps (server)      */

    uint8_t server_ss[HASH_BYTES];
    xwing_combine(server_ss, srv_k_ss, srv_x_ss, kem_ct, cli_x_pk);

    print_hex("  client hybrid ss : ", client_ss, HASH_BYTES);
    print_hex("  server hybrid ss : ", server_ss, HASH_BYTES);

    int ss_match = (ct_memcmp(client_ss, server_ss, HASH_BYTES) == 0);
    printf("  [%s] client and server derived the SAME hybrid shared secret\n",
           ss_match ? "PASS" : "FAIL");
    ok &= ss_match;

    /* ---------------------------------------------------------------- *
     *  STAGE B: KDF (HKDF-style extract + expand -> 32-byte key)        *
     * ---------------------------------------------------------------- */
    step("STAGE B  KDF  (Module 4 HKDF-style extract + expand)");

    static const uint8_t kdf_salt[] = "capstone-hkdf-salt";
    static const uint8_t kdf_info[] = "capstone session key v1";
    uint8_t prk[HASH_BYTES], session_key[HASH_BYTES];
    hkdf_extract(prk, kdf_salt, sizeof(kdf_salt) - 1, server_ss, HASH_BYTES);
    hkdf_expand(session_key, prk, kdf_info, sizeof(kdf_info) - 1);

    print_hex("  PRK (extract)    : ", prk, HASH_BYTES);
    print_hex("  session key (exp): ", session_key, HASH_BYTES);
    printf("  [PASS] derived a %d-byte session key from the shared secret\n",
           HASH_BYTES);

    /* ---------------------------------------------------------------- *
     *  STAGE C: SIGN / VERIFY transcript (toy ML-DSA-65-style)          *
     * ---------------------------------------------------------------- */
    step("STAGE C  SIGN / VERIFY  (Module 6 ML-DSA-style FS signature)");

    /* Transcript = everything that was exchanged in the handshake. The server
     * signs H(transcript) so the client can authenticate the handshake.     */
    uint8_t transcript_hash[HASH_BYTES];
    {
        uint8_t tbuf[X_PK_BYTES + MLKEM_PK_BYTES + X_PK_BYTES + MLKEM_CT_BYTES];
        size_t off = 0;
        memcpy(tbuf + off, srv_x_pk, X_PK_BYTES);    off += X_PK_BYTES;
        memcpy(tbuf + off, srv_k_pk, MLKEM_PK_BYTES);off += MLKEM_PK_BYTES;
        memcpy(tbuf + off, cli_x_pk, X_PK_BYTES);    off += X_PK_BYTES;
        memcpy(tbuf + off, kem_ct,   MLKEM_CT_BYTES);off += MLKEM_CT_BYTES;
        toy_hash(transcript_hash, HASH_BYTES, tbuf, off);
    }
    print_hex("  transcript hash  : ", transcript_hash, HASH_BYTES);

    /* Server signing keypair (toy ML-DSA-65-style). */
    uint8_t sig_seed[SEED_BYTES];
    rng_bytes(sig_seed, SEED_BYTES);
    dsa_pk spk;
    dsa_sk ssk;
    dsa_keygen(&spk, &ssk, sig_seed);

    dsa_sig sig;
    int attempts = dsa_sign(&sig, &spk, &ssk, transcript_hash, HASH_BYTES);
    print_hex("  sig c_tilde      : ", sig.c_tilde, HASH_BYTES);
    printf("  Fiat-Shamir attempts (rejection sampling): %d\n", attempts);

    int valid = dsa_verify(&spk, &sig, transcript_hash, HASH_BYTES);
    printf("  [%s] verify accepts the valid signature\n",
           valid ? "PASS" : "FAIL");
    ok &= valid;

    /* Tamper: flip ONE bit of the transcript; verify MUST now fail. */
    uint8_t bad_transcript[HASH_BYTES];
    memcpy(bad_transcript, transcript_hash, HASH_BYTES);
    bad_transcript[0] ^= 0x01;
    int bad_valid = dsa_verify(&spk, &sig, bad_transcript, HASH_BYTES);
    printf("  [%s] verify REJECTS the 1-bit-flipped transcript\n",
           !bad_valid ? "PASS" : "FAIL");
    ok &= (!bad_valid);

    /* ---------------------------------------------------------------- *
     *  STAGE D: SELF-TEST / KAT (fixed known values, reproducibility)   *
     * ---------------------------------------------------------------- */
    step("STAGE D  SELF-TEST / KAT  (fixed known-answer values)");

    int kat_ss  = (ct_memcmp(server_ss, KAT_SHARED_SECRET, HASH_BYTES) == 0);
    int kat_key = (ct_memcmp(session_key, KAT_SESSION_KEY, HASH_BYTES) == 0);

    if (seed == 1234567u) {
        printf("  [%s] hybrid shared secret matches fixed KAT\n",
               kat_ss ? "PASS" : "FAIL");
        printf("  [%s] derived session key matches fixed KAT\n",
               kat_key ? "PASS" : "FAIL");
        ok &= kat_ss;
        ok &= kat_key;
    } else {
        printf("  [SKIP] KAT only applies to the default seed 1234567 "
               "(seed=%u)\n", seed);
    }

    /* ---------------------------------------------------------------- *
     *  STAGE E: CONSTANT-TIME compare note                              *
     * ---------------------------------------------------------------- */
    step("STAGE E  CONSTANT-TIME compare  (timing side-channel note)");
    printf("  All secret comparisons above (shared secret, session key,\n");
    printf("  signature challenge, KAT checks) use ct_memcmp(), which folds\n");
    printf("  every byte into one accumulator and never early-exits, so its\n");
    printf("  run time does NOT leak how many leading bytes matched.\n");
    {
        /* Demonstrate the helper detects a difference without short-circuit. */
        uint8_t a[8] = {1,2,3,4,5,6,7,8};
        uint8_t b[8] = {1,2,3,4,5,6,7,9};
        printf("  [%s] ct_memcmp(equal)   == 0\n",
               ct_memcmp(a, a, 8) == 0 ? "PASS" : "FAIL");
        printf("  [%s] ct_memcmp(differ)  != 0\n",
               ct_memcmp(a, b, 8) != 0 ? "PASS" : "FAIL");
        ok &= (ct_memcmp(a, a, 8) == 0);
        ok &= (ct_memcmp(a, b, 8) != 0);
    }

    /* ---------------------------------------------------------------- *
     *  Verdict                                                          *
     * ---------------------------------------------------------------- */
    printf("\n============================================================\n");
    if (ok) {
        printf("CAPSTONE: PASS\n");
        printf("============================================================\n");
        return EXIT_SUCCESS;
    }
    printf("CAPSTONE: FAIL\n");
    printf("============================================================\n");
    return EXIT_FAILURE;
}
