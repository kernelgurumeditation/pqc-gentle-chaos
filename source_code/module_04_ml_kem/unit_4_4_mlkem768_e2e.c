/*
 * Source: PQC Learning Plan - Module 4: ML-KEM Deep Dive
 * Unit 4.4: ML-KEM-768 End-to-End KEM Demo
 *
 * Unit 4.4: Putting it all together
 *
 * This program JOINS the two halves of ML-KEM that the earlier units
 * developed in isolation:
 *
 *   - The CPA-secure K-PKE encryption with ML-KEM-768-like parameters
 *     (N=256, K=3, Q=3329)            ... see unit_4_2_kpke_full.c
 *   - The Fujisaki-Okamoto (FO) transform that wraps K-PKE into a
 *     CCA-secure KEM with implicit rejection
 *                                       ... see unit_4_3_fo_transform.c
 *
 * The result is a complete, self-consistent ML-KEM-768-STYLE KEM round
 * trip:   KeyGen -> Encaps -> Decaps,  with the standard assertion that
 * the encapsulator's shared secret ss_A equals the decapsulator's ss_B.
 *
 * EDUCATIONAL PURPOSE ONLY.  It is NOT bit-exact to FIPS 203:
 *   - "hashes" G/H/J are a toy mixing function, not SHA3/SHAKE
 *   - matrix A is expanded with a toy PRG, not SHAKE128
 *   - no NTT, no byte-level (de)serialization, no Compress/Decompress
 * It IS a correct, deterministic, self-consistent KEM: valid ciphertexts
 * always decapsulate to the same shared secret, and tampered ciphertexts
 * are rejected (implicit rejection -> a different, random-looking secret).
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/* ========== K-PKE parameters (ML-KEM-768-like) ========== */

#define N 256           /* Polynomial degree */
#define K 3             /* Module dimension */
#define Q 3329          /* Modulus */
#define ETA1 2          /* CBD parameter for keygen secret/error */
#define ETA2 2          /* CBD parameter for encryption error */

#define SEED_BYTES 32   /* size of m, coins, z, shared secret */

/* Wire sizes reported to the learner (uncompressed, educational).
 * Real ML-KEM-768 compresses these to ek=1184, dk=2400, ct=1088. */
#define POLY_BYTES    ((N * 12) / 8)            /* 384 bytes per polynomial   */
#define POLYVEC_BYTES (K * POLY_BYTES)          /* 1152 bytes for k polys      */
#define EK_BYTES      (POLYVEC_BYTES + SEED_BYTES) /* t-vector + matrix seed   */
#define DK_BYTES      (POLYVEC_BYTES + EK_BYTES + SEED_BYTES + SEED_BYTES)
                       /* s-vector + ek copy + H(ek) + z (implicit reject)     */
#define CT_U_BYTES    POLYVEC_BYTES             /* u vector (uncompressed)      */
#define CT_V_BYTES    POLY_BYTES                /* v poly  (uncompressed)       */
#define CT_BYTES      (CT_U_BYTES + CT_V_BYTES)
#define SS_BYTES      SEED_BYTES                /* 32-byte shared secret        */

/* Internal serialization sizes for hashing (2 raw bytes per coefficient).
 * These differ from the *reported* wire sizes above (which use the 12-bit
 * packing of POLY_BYTES): here we hash the simple little-endian int16 form,
 * so each polynomial is N*2 bytes, not (N*12)/8. */
#define POLY_RAW_BYTES    (N * 2)               /* 512 bytes per polynomial    */
#define POLYVEC_RAW_BYTES (K * POLY_RAW_BYTES)  /* 1536 bytes for k polys      */
#define CT_RAW_BYTES      (POLYVEC_RAW_BYTES + POLY_RAW_BYTES)

/* ========== Polynomial types (mirroring unit_4_2_kpke_full.c) ========== */

typedef struct { int16_t coeffs[N]; } poly;
typedef struct { poly vec[K]; } polyvec;

/* ========== Modular arithmetic ========== */

static int16_t mod_q(int32_t a) {
    int16_t r = a % Q;
    if (r < 0) r += Q;
    return r;
}

static int16_t cmod_q(int16_t a) {
    a = mod_q(a);
    if (a > Q / 2) a -= Q;
    return a;
}

/* ========== Toy symmetric primitives (NOT cryptographic) ==========
 *
 * Real ML-KEM uses SHA3-256 (H), SHA3-512 (G), SHAKE256 (J / PRF) and
 * SHAKE128 (matrix expansion).  Here a single small mixing routine plays
 * all roles.  It is deterministic, which is all the round trip requires.
 */
static void toy_hash(uint8_t *out, size_t out_len,
                     const uint8_t *in, size_t in_len) {
    uint32_t state = 0x9E3779B1u;          /* arbitrary fixed IV */
    for (size_t i = 0; i < in_len; i++) {
        state = state * 31u + in[i] + (uint32_t)i;
    }
    for (size_t i = 0; i < out_len; i++) {
        state = state * 1103515245u + 12345u;
        out[i] = (uint8_t)((state >> 16) & 0xFF);
    }
}

/* G: (m || H(ek)) -> (K_bar || coins), each SEED_BYTES wide. */
static void fo_g(uint8_t k_bar[SEED_BYTES], uint8_t coins[SEED_BYTES],
                 const uint8_t m[SEED_BYTES], const uint8_t ek_hash[SEED_BYTES]) {
    uint8_t in[2 * SEED_BYTES];
    uint8_t out[2 * SEED_BYTES];
    memcpy(in, m, SEED_BYTES);
    memcpy(in + SEED_BYTES, ek_hash, SEED_BYTES);
    toy_hash(out, sizeof(out), in, sizeof(in));
    memcpy(k_bar, out, SEED_BYTES);
    memcpy(coins, out + SEED_BYTES, SEED_BYTES);
}

/* KDF: ss = J(K_bar || H(ct)). */
static void fo_kdf(uint8_t ss[SS_BYTES],
                   const uint8_t k_bar[SEED_BYTES], const uint8_t c_hash[SEED_BYTES]) {
    uint8_t in[2 * SEED_BYTES];
    memcpy(in, k_bar, SEED_BYTES);
    memcpy(in + SEED_BYTES, c_hash, SEED_BYTES);
    toy_hash(ss, SS_BYTES, in, sizeof(in));
}

/* ========== CBD sampling (mirroring unit_4_2_kpke_full.c) ========== */

static int16_t sample_cbd(int eta, const uint8_t *random_bytes, int *byte_offset) {
    int a = 0, b = 0;
    for (int i = 0; i < eta; i++) {
        uint8_t byte = random_bytes[(*byte_offset)++];
        a += (byte & 1);
        b += ((byte >> 1) & 1);
    }
    return (int16_t)(a - b);
}

static void poly_sample_cbd(poly *p, int eta, const uint8_t *seed, int nonce) {
    uint8_t random_bytes[512];
    /* Toy PRF(seed, nonce): real ML-KEM uses SHAKE256.  Deterministic only. */
    for (int i = 0; i < 512; i++) {
        random_bytes[i] = (uint8_t)((seed[i % SEED_BYTES] ^ nonce ^ i) & 0xFF);
    }
    int offset = 0;
    for (int i = 0; i < N; i++) {
        p->coeffs[i] = sample_cbd(eta, random_bytes, &offset);
    }
}

static void polyvec_sample_cbd(polyvec *v, int eta, const uint8_t *seed, int *nonce) {
    for (int i = 0; i < K; i++) {
        poly_sample_cbd(&v->vec[i], eta, seed, (*nonce)++);
    }
}

/* Toy uniform expansion of A from a 32-byte matrix seed. */
static void poly_sample_uniform(poly *p, const uint8_t *seed, int i, int j) {
    for (int k = 0; k < N; k++) {
        uint32_t val = seed[k % SEED_BYTES];
        val = val * 1103515245u + 12345u + (uint32_t)(i * 1000 + j * 100 + k);
        p->coeffs[k] = mod_q((int32_t)val);
    }
}

static void matrix_generate(poly A[K][K], const uint8_t *seed) {
    for (int i = 0; i < K; i++)
        for (int j = 0; j < K; j++)
            poly_sample_uniform(&A[i][j], seed, i, j);
}

/* ========== Polynomial / vector arithmetic ========== */

static void poly_add(poly *r, const poly *a, const poly *b) {
    for (int i = 0; i < N; i++) r->coeffs[i] = mod_q(a->coeffs[i] + b->coeffs[i]);
}

static void poly_sub(poly *r, const poly *a, const poly *b) {
    for (int i = 0; i < N; i++) r->coeffs[i] = mod_q(a->coeffs[i] - b->coeffs[i]);
}

static void poly_mul(poly *r, const poly *a, const poly *b) {
    int64_t temp[2 * N] = {0};  /* int64_t: N products can overflow int32_t */
    for (int i = 0; i < N; i++)
        for (int j = 0; j < N; j++)
            temp[i + j] += (int64_t)a->coeffs[i] * b->coeffs[j];
    /* Reduce mod X^N + 1 */
    for (int i = 0; i < N; i++) r->coeffs[i] = mod_q((int32_t)(temp[i] - temp[i + N]));
}

static void polyvec_add(polyvec *r, const polyvec *a, const polyvec *b) {
    for (int i = 0; i < K; i++) poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);
}

static void polyvec_inner_product(poly *r, const polyvec *a, const polyvec *b) {
    poly temp;
    for (int i = 0; i < N; i++) r->coeffs[i] = 0;
    for (int i = 0; i < K; i++) {
        poly_mul(&temp, &a->vec[i], &b->vec[i]);
        poly_add(r, r, &temp);
    }
}

static void matrix_vec_mul(polyvec *r, const poly A[K][K], const polyvec *v) {
    poly temp;
    for (int i = 0; i < K; i++) {
        for (int j = 0; j < N; j++) r->vec[i].coeffs[j] = 0;
        for (int j = 0; j < K; j++) {
            poly_mul(&temp, &A[i][j], &v->vec[j]);
            poly_add(&r->vec[i], &r->vec[i], &temp);
        }
    }
}

static void matrix_transpose_vec_mul(polyvec *r, const poly A[K][K], const polyvec *v) {
    poly temp;
    for (int i = 0; i < K; i++) {
        for (int j = 0; j < N; j++) r->vec[i].coeffs[j] = 0;
        for (int j = 0; j < K; j++) {
            poly_mul(&temp, &A[j][i], &v->vec[j]);
            poly_add(&r->vec[i], &r->vec[i], &temp);
        }
    }
}

/* ========== Message <-> polynomial encoding ========== */

static void message_encode(poly *r, const uint8_t msg[SEED_BYTES]) {
    int16_t scale = (Q + 1) / 2;   /* ceil(Q/2) = 1665 for Q=3329 */
    for (int i = 0; i < N; i++) {
        int bit = (msg[i / 8] >> (i % 8)) & 1;
        r->coeffs[i] = bit ? scale : 0;
    }
}

static void message_decode(uint8_t msg[SEED_BYTES], const poly *p) {
    memset(msg, 0, SEED_BYTES);
    for (int i = 0; i < N; i++) {
        int16_t c = cmod_q(p->coeffs[i]);
        int16_t dist_0 = (c < 0) ? -c : c;
        int16_t dist_half = (c < 0) ? (int16_t)(Q / 2 + c) : (int16_t)(Q / 2 - c);
        if (dist_half < 0) dist_half = -dist_half;
        int bit = (dist_half < dist_0) ? 1 : 0;
        msg[i / 8] |= (uint8_t)(bit << (i % 8));
    }
}

/* ========== K-PKE core (CPA-secure) ========== */

typedef struct {
    polyvec t;                  /* public vector t = A s + e            */
    uint8_t matrix_seed[SEED_BYTES]; /* seed that expands A             */
} kpke_pk;

typedef struct {
    polyvec s;                  /* secret vector                        */
} kpke_sk;

typedef struct {
    polyvec u;                  /* u = A^T r + e1                       */
    poly    v;                  /* v = t^T r + e2 + encode(m)          */
} kpke_ct;

/* Deterministic K-PKE keygen driven entirely by a 32-byte d seed. */
static void kpke_keygen(const uint8_t d[SEED_BYTES], kpke_pk *pk, kpke_sk *sk) {
    poly A[K][K];
    polyvec e;
    int nonce = 0;

    memcpy(pk->matrix_seed, d, SEED_BYTES);
    matrix_generate(A, pk->matrix_seed);
    polyvec_sample_cbd(&sk->s, ETA1, d, &nonce);
    polyvec_sample_cbd(&e,    ETA1, d, &nonce);
    matrix_vec_mul(&pk->t, A, &sk->s);
    polyvec_add(&pk->t, &pk->t, &e);
}

/* Deterministic K-PKE encrypt: randomness comes solely from `coins`. */
static void kpke_encrypt(const kpke_pk *pk, const uint8_t m[SEED_BYTES],
                         const uint8_t coins[SEED_BYTES], kpke_ct *ct) {
    poly A[K][K];
    polyvec r, e1;
    poly e2, mu;
    int nonce = 0;

    matrix_generate(A, pk->matrix_seed);
    polyvec_sample_cbd(&r,  ETA1, coins, &nonce);
    polyvec_sample_cbd(&e1, ETA2, coins, &nonce);
    poly_sample_cbd(&e2, ETA2, coins, nonce++);

    message_encode(&mu, m);

    matrix_transpose_vec_mul(&ct->u, A, &r);
    polyvec_add(&ct->u, &ct->u, &e1);

    polyvec_inner_product(&ct->v, &pk->t, &r);
    poly_add(&ct->v, &ct->v, &e2);
    poly_add(&ct->v, &ct->v, &mu);
}

static void kpke_decrypt(const kpke_sk *sk, const kpke_ct *ct, uint8_t m[SEED_BYTES]) {
    poly temp, result;
    polyvec_inner_product(&temp, &sk->s, &ct->u);
    poly_sub(&result, &ct->v, &temp);
    message_decode(m, &result);
}

/* ========== ML-KEM (FO transform around K-PKE) ========== */

typedef struct {
    kpke_pk pk;                       /* encapsulation key = K-PKE public key */
} mlkem_ek;

typedef struct {
    kpke_sk sk;                       /* K-PKE secret key                     */
    kpke_pk pk;                       /* embedded copy for re-encryption      */
    uint8_t ek_hash[SEED_BYTES];      /* H(ek), bound into G                  */
    uint8_t z[SEED_BYTES];            /* implicit-rejection secret            */
} mlkem_dk;

/* Hash an encapsulation key (here: its t-vector + matrix seed). */
static void hash_ek(uint8_t out[SEED_BYTES], const kpke_pk *pk) {
    uint8_t buf[POLYVEC_RAW_BYTES + SEED_BYTES];
    size_t off = 0;
    for (int i = 0; i < K; i++)
        for (int j = 0; j < N; j++) {
            uint16_t c = (uint16_t)pk->t.vec[i].coeffs[j];
            buf[off++] = (uint8_t)(c & 0xFF);
            buf[off++] = (uint8_t)(c >> 8);
        }
    memcpy(buf + off, pk->matrix_seed, SEED_BYTES);
    off += SEED_BYTES;
    toy_hash(out, SEED_BYTES, buf, off);
}

/* Hash a ciphertext (u-vector + v-poly). */
static void hash_ct(uint8_t out[SEED_BYTES], const kpke_ct *ct) {
    uint8_t buf[CT_RAW_BYTES];
    size_t off = 0;
    for (int i = 0; i < K; i++)
        for (int j = 0; j < N; j++) {
            uint16_t c = (uint16_t)ct->u.vec[i].coeffs[j];
            buf[off++] = (uint8_t)(c & 0xFF);
            buf[off++] = (uint8_t)(c >> 8);
        }
    for (int j = 0; j < N; j++) {
        uint16_t c = (uint16_t)ct->v.coeffs[j];
        buf[off++] = (uint8_t)(c & 0xFF);
        buf[off++] = (uint8_t)(c >> 8);
    }
    toy_hash(out, SEED_BYTES, buf, off);
}

static int ct_equal(const kpke_ct *a, const kpke_ct *b) {
    int diff = 0;
    for (int i = 0; i < K; i++)
        for (int j = 0; j < N; j++)
            diff |= (a->u.vec[i].coeffs[j] ^ b->u.vec[i].coeffs[j]);
    for (int j = 0; j < N; j++)
        diff |= (a->v.coeffs[j] ^ b->v.coeffs[j]);
    return diff == 0;
}

static void mlkem_keygen(const uint8_t d[SEED_BYTES], const uint8_t z[SEED_BYTES],
                         mlkem_ek *ek, mlkem_dk *dk) {
    kpke_keygen(d, &ek->pk, &dk->sk);
    dk->pk = ek->pk;                       /* bundle ek for re-encryption */
    hash_ek(dk->ek_hash, &ek->pk);
    memcpy(dk->z, z, SEED_BYTES);
}

static void mlkem_encaps(const mlkem_ek *ek, kpke_ct *ct, uint8_t ss[SS_BYTES],
                         const uint8_t m[SEED_BYTES]) {
    uint8_t ek_hash[SEED_BYTES], k_bar[SEED_BYTES], coins[SEED_BYTES], c_hash[SEED_BYTES];

    hash_ek(ek_hash, &ek->pk);
    fo_g(k_bar, coins, m, ek_hash);        /* (K_bar, coins) = G(m || H(ek)) */
    kpke_encrypt(&ek->pk, m, coins, ct);   /* deterministic encryption       */
    hash_ct(c_hash, ct);
    fo_kdf(ss, k_bar, c_hash);             /* ss = J(K_bar || H(ct))         */
}

static void mlkem_decaps(const mlkem_dk *dk, const kpke_ct *ct, uint8_t ss[SS_BYTES]) {
    uint8_t m_prime[SEED_BYTES], k_bar[SEED_BYTES], coins[SEED_BYTES];
    uint8_t c_hash[SEED_BYTES], ss_valid[SS_BYTES], ss_reject[SS_BYTES];
    kpke_ct ct_reenc;

    kpke_decrypt(&dk->sk, ct, m_prime);            /* m' = Decrypt(ct)        */
    fo_g(k_bar, coins, m_prime, dk->ek_hash);      /* re-derive (K_bar, coins)*/
    kpke_encrypt(&dk->pk, m_prime, coins, &ct_reenc); /* re-encrypt           */

    hash_ct(c_hash, ct);
    fo_kdf(ss_valid, k_bar, c_hash);               /* candidate valid key     */

    /* Implicit rejection key: J(z || H(ct)). */
    {
        uint8_t in[2 * SEED_BYTES];
        memcpy(in, dk->z, SEED_BYTES);
        memcpy(in + SEED_BYTES, c_hash, SEED_BYTES);
        toy_hash(ss_reject, SS_BYTES, in, sizeof(in));
    }

    /* Constant-time-style select: re-encryption must reproduce ct exactly. */
    int valid = ct_equal(ct, &ct_reenc);
    uint8_t mask = (uint8_t)(-(int)(valid != 0));   /* 0xFF if valid else 0 */
    for (int i = 0; i < SS_BYTES; i++)
        ss[i] = (uint8_t)((ss_valid[i] & mask) | (ss_reject[i] & ~mask));
}

/* ========== Demonstration ========== */

static void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len && i < 16; i++) printf("%02x", data[i]);
    if (len > 16) printf("...");
    printf("\n");
}

int main(void) {
    /* Fixed default seed => reproducible teaching output; override with PQC_DEMO_SEED. */
    const char *demo_seed_env = getenv("PQC_DEMO_SEED");
    srand(demo_seed_env ? (unsigned)strtoul(demo_seed_env, NULL, 10) : 1234567u);

    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║  Unit 4.4: ML-KEM-768-style End-to-End KEM (K-PKE + FO)     ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n\n");
    printf("Parameters: N=%d, K=%d, Q=%d, eta1=%d, eta2=%d\n\n", N, K, Q, ETA1, ETA2);

    /* ---- KeyGen ---- */
    uint8_t d[SEED_BYTES], z[SEED_BYTES];
    for (int i = 0; i < SEED_BYTES; i++) {
        d[i] = (uint8_t)(rand() & 0xFF);   /* keygen seed d (PRG-expanded)     */
        z[i] = (uint8_t)(rand() & 0xFF);   /* implicit-rejection secret z      */
    }

    mlkem_ek ek;
    mlkem_dk dk;
    mlkem_keygen(d, z, &ek, &dk);
    printf("=== KeyGen ===\n");
    print_hex("  ek H(ek)", dk.ek_hash, SEED_BYTES);
    print_hex("  z (reject)", dk.z, SEED_BYTES);
    printf("  t[0][0..3] = %d, %d, %d, %d\n\n",
           ek.pk.t.vec[0].coeffs[0], ek.pk.t.vec[0].coeffs[1],
           ek.pk.t.vec[0].coeffs[2], ek.pk.t.vec[0].coeffs[3]);

    /* ---- Encaps (party A) ---- */
    uint8_t m[SEED_BYTES];
    for (int i = 0; i < SEED_BYTES; i++) m[i] = (uint8_t)(rand() & 0xFF);

    kpke_ct ct;
    uint8_t ss_A[SS_BYTES];
    mlkem_encaps(&ek, &ct, ss_A, m);
    printf("=== Encaps (party A) ===\n");
    print_hex("  random m", m, SEED_BYTES);
    printf("  ct u[0][0..3] = %d, %d, %d, %d\n",
           ct.u.vec[0].coeffs[0], ct.u.vec[0].coeffs[1],
           ct.u.vec[0].coeffs[2], ct.u.vec[0].coeffs[3]);
    print_hex("  ss_A", ss_A, SS_BYTES);
    printf("\n");

    /* ---- Decaps (party B) ---- */
    uint8_t ss_B[SS_BYTES];
    mlkem_decaps(&dk, &ct, ss_B);
    printf("=== Decaps (party B) ===\n");
    print_hex("  ss_B", ss_B, SS_BYTES);
    printf("\n");

    /* ---- Sanity check: a tampered ciphertext must be rejected ---- */
    kpke_ct ct_bad = ct;
    ct_bad.v.coeffs[0] ^= 0x1;             /* flip one coefficient bit         */
    uint8_t ss_bad[SS_BYTES];
    mlkem_decaps(&dk, &ct_bad, ss_bad);
    int rejected = (memcmp(ss_A, ss_bad, SS_BYTES) != 0);
    printf("=== Tamper check (implicit rejection) ===\n");
    print_hex("  ss(tampered)", ss_bad, SS_BYTES);
    printf("  tampered ct -> %s\n\n",
           rejected ? "different secret (rejected, as expected)"
                    : "SAME secret (UNEXPECTED!)");

    /* ---- Size summary ---- */
    printf("=== Size Summary (uncompressed, educational) ===\n");
    printf("  ek (encapsulation key): %5d bytes\n", EK_BYTES);
    printf("  dk (decapsulation key): %5d bytes\n", DK_BYTES);
    printf("  ct (ciphertext):        %5d bytes\n", CT_BYTES);
    printf("  ss (shared secret):     %5d bytes\n", SS_BYTES);
    printf("  (Real ML-KEM-768 compresses to ek=1184, dk=2400, ct=1088, ss=32.)\n\n");

    /* ---- Verdict: the whole point of a KEM is ss_A == ss_B ---- */
    int match = (memcmp(ss_A, ss_B, SS_BYTES) == 0);
    if (!match || !rejected) {
        if (!match)
            fprintf(stderr, "FAIL: shared secret mismatch\n");
        if (!rejected)
            fprintf(stderr, "FAIL: tampered ciphertext was not rejected\n");
        return EXIT_FAILURE;
    }
    printf("PASS: ss_A == ss_B (KEM round-trip correct)\n");

    printf("\n════════════════════════════════════════════════════════════\n");
    printf("End-to-End Flow:\n");
    printf("  KeyGen : (ek, dk) from seeds d, z;  ek = K-PKE public key\n");
    printf("  Encaps : m random; (K_bar,coins)=G(m||H(ek)); ct=Enc(ek,m;coins)\n");
    printf("           ss_A = J(K_bar || H(ct))\n");
    printf("  Decaps : m'=Dec(dk,ct); re-derive, re-encrypt, compare ct\n");
    printf("           match -> ss_B=J(K_bar||H(ct));  else -> J(z||H(ct))\n");
    printf("════════════════════════════════════════════════════════════\n");

    return EXIT_SUCCESS;
}
