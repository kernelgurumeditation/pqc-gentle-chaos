/*
 * Module 6: ML-DSA (Dilithium) - Complete Implementation
 * Unit 6.7: Full Reference Implementation (with explicit self-test verdict)
 *
 * This is a complete, working (educational) signature scheme that follows
 * the Fiat-Shamir-with-aborts STRUCTURE of ML-DSA-65 (FIPS 204). It uses a
 * deliberately small, self-contained ring so the whole sign/verify loop runs
 * and is genuinely checkable end to end. The published ML-DSA-65 parameters
 * are still displayed for reference.
 *
 * The self-test at the end gives an EXPLICIT verdict:
 *   - a VALID signature MUST verify (PASS)
 *   - a 1-bit-flipped signature MUST be REJECTED
 *   - a 1-bit-flipped message MUST be REJECTED
 * If any of these properties fails, main() returns EXIT_FAILURE.
 *
 * WARNING: This is for EDUCATIONAL purposes. Do not use in production.
 * Production code must use constant-time operations, a proper CSPRNG/SHAKE,
 * and extensive testing against known-answer tests (KATs). This program is a
 * structural demonstration and a self-CONSISTENCY check, NOT a NIST KAT.
 *
 * Compile: gcc -Wall -Wextra -Wshadow -O2 -std=c11 -o unit_6_7_full \
 *              unit_6_7_complete_impl_full.c
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/* ML-DSA-65 Parameters (FIPS 204) - shown for reference */
#define MLDSA_Q 8380417
#define MLDSA_N 256
#define MLDSA_K 6
#define MLDSA_L 5
#define MLDSA_ETA 4
#define MLDSA_TAU 49
#define MLDSA_BETA 196
#define MLDSA_GAMMA1 (1 << 19)   /* ML-DSA-65 uses gamma1 = 2^19 */
#define MLDSA_GAMMA2 261888
#define MLDSA_OMEGA 55
#define MLDSA_D 13
#define MLDSA_CTILDE_BYTES 48
#define MLDSA_POLYT1_PACKEDBYTES 320
#define MLDSA_PK_BYTES 1952
#define MLDSA_SIG_BYTES 3309

/*
 * ---------------------------------------------------------------------------
 * Reproducible RNG seam
 * ---------------------------------------------------------------------------
 * Fixed default seed => reproducible teaching output; override with
 * PQC_DEMO_SEED. NOT cryptographically secure. Real ML-DSA uses SHAKE-256 /
 * SHAKE-128 over a securely generated seed.
 */
static uint32_t prng_state = 0x12345678u;

static void prng_seed(uint32_t s) {
    prng_state = s ? s : 0x12345678u;
}

static uint32_t prng_u32(void) {
    prng_state = prng_state * 1103515245u + 12345u;
    /* Mix the high bits down for better-distributed low bits. */
    return prng_state ^ (prng_state >> 16);
}

static uint8_t prng_byte(void) {
    return (uint8_t)(prng_u32() >> 8);
}

static void fill_random(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buf[i] = prng_byte();
    }
}

/*
 * ---------------------------------------------------------------------------
 * A small but FUNCTIONAL Fiat-Shamir signature scheme (Schnorr-over-a-ring).
 * ---------------------------------------------------------------------------
 * We work in a single polynomial ring Z_q[X]/(X^DEMO_N + 1) with a public
 * "matrix" a (one polynomial here for clarity). This mirrors the ML-DSA flow
 * (commit / challenge / response with rejection) while staying EXACT so that
 * a correct signature always verifies:
 *
 *   keygen:  s small;  t = a*s
 *   sign:    y small;  w = a*y;  c = H(w || msg);  z = y + c*s
 *            (reject and resample if ||z|| too large -> "with aborts")
 *   verify:  w' = a*z - c*t = a*(y + c*s) - c*(a*s) = a*y = w
 *            recompute c' = H(w' || msg); accept iff c' == c AND ||z|| small
 *
 * Because w' reconstructs w EXACTLY (no rounding / hints needed in this toy
 * ring), a valid signature ALWAYS verifies, for every RNG seed. Any tamper of
 * the message or of z changes w' (or the recomputed challenge) and is
 * REJECTED. Real ML-DSA additionally compresses t (Power2Round) and bridges
 * the resulting rounding gap with hints; that machinery is shown separately in
 * unit_6_7_complete_impl.c. Here we keep the algebra exact so the self-test
 * verdict is unambiguous.
 */

#define DEMO_Q 8380417
#define DEMO_N 8            /* tiny ring for a fast, fully-checkable demo */
#define DEMO_ETA 4          /* secret coeff bound */
#define DEMO_GAMMA1 131072  /* y coeff bound (2^17), keeps z in range */
#define DEMO_TAU 2          /* challenge nonzero coeffs (+/-1) */
#define DEMO_BETA (DEMO_TAU * DEMO_ETA) /* z infinity-norm slack */

typedef struct { int32_t c[DEMO_N]; } dpoly;

/* Reduce x into the range [0, DEMO_Q). */
static int32_t modq(int64_t x) {
    int64_t r = x % DEMO_Q;
    if (r < 0) r += DEMO_Q;
    return (int32_t)r;
}

/* Centered representative in (-q/2, q/2]. */
static int32_t centered(int32_t x) {
    if (x > DEMO_Q / 2) x -= DEMO_Q;
    return x;
}

/* Negacyclic polynomial multiplication mod (X^N + 1) mod q. */
static dpoly poly_mul(const dpoly *u, const dpoly *v) {
    int64_t tmp[2 * DEMO_N] = {0};
    for (int i = 0; i < DEMO_N; i++)
        for (int j = 0; j < DEMO_N; j++)
            tmp[i + j] += (int64_t)u->c[i] * v->c[j];
    dpoly r;
    for (int i = 0; i < DEMO_N; i++) {
        /* X^N = -1, so fold the upper half back with a sign flip. */
        int64_t v_ = tmp[i] - tmp[i + DEMO_N];
        r.c[i] = modq(v_);
    }
    return r;
}

static dpoly poly_add(const dpoly *u, const dpoly *v) {
    dpoly r;
    for (int i = 0; i < DEMO_N; i++) r.c[i] = modq((int64_t)u->c[i] + v->c[i]);
    return r;
}

static dpoly poly_sub(const dpoly *u, const dpoly *v) {
    dpoly r;
    for (int i = 0; i < DEMO_N; i++) r.c[i] = modq((int64_t)u->c[i] - v->c[i]);
    return r;
}

/* Sample a small polynomial with coeffs in [-eta, eta]. */
static dpoly sample_small(int eta) {
    dpoly r;
    for (int i = 0; i < DEMO_N; i++) {
        int v = (int)(prng_u32() % (uint32_t)(2 * eta + 1)) - eta;
        r.c[i] = modq(v);
    }
    return r;
}

/* Sample y with coeffs in (-gamma1, gamma1]. */
static dpoly sample_y(void) {
    dpoly r;
    for (int i = 0; i < DEMO_N; i++) {
        int v = (int)(prng_u32() % (uint32_t)(2 * DEMO_GAMMA1)) - (DEMO_GAMMA1 - 1);
        r.c[i] = modq(v);
    }
    return r;
}

/*
 * Educational FNV-1a hash over a byte buffer. Used to derive a deterministic
 * challenge from (w || message). NOT SHAKE; for structure demonstration only.
 */
static uint32_t fnv1a(const uint8_t *data, size_t len, uint32_t seed) {
    uint32_t h = seed ? seed : 0x811c9dc5u;
    for (size_t i = 0; i < len; i++) {
        h ^= data[i];
        h *= 16777619u;
    }
    return h;
}

/*
 * Challenge digest c_tilde = H(w || msg). This is the Fiat-Shamir hash, the
 * analogue of ML-DSA's c_tilde. The SIGNATURE carries this digest; the
 * verifier recomputes it from the reconstructed w' and the message and
 * compares the FULL digest. Comparing the full digest (not just the sparse
 * polynomial below) is what makes message tampering reliably detectable: the
 * sparse challenge polynomial lives in a small space and can collide, but the
 * digest essentially cannot.
 */
static uint32_t challenge_digest(const dpoly *w,
                                 const uint8_t *msg, size_t msglen) {
    uint8_t buf[DEMO_N * 4 + 256];
    size_t pos = 0;
    for (int i = 0; i < DEMO_N; i++) {
        uint32_t v = (uint32_t)w->c[i];
        buf[pos++] = (uint8_t)(v);
        buf[pos++] = (uint8_t)(v >> 8);
        buf[pos++] = (uint8_t)(v >> 16);
        buf[pos++] = (uint8_t)(v >> 24);
    }
    size_t mcopy = msglen < 256 ? msglen : 256;
    memcpy(buf + pos, msg, mcopy);
    pos += mcopy;
    return fnv1a(buf, pos, 0);
}

/*
 * Expand the challenge digest into a sparse challenge polynomial c (TAU coeffs
 * in {-1,+1}). Both signer and verifier derive c from the SAME digest, so c is
 * identical on both sides whenever the digests match.
 */
static dpoly challenge_from_digest(uint32_t digest) {
    uint32_t h = digest;
    dpoly c;
    memset(&c, 0, sizeof(c));
    int placed = 0;
    /* Deterministically place TAU signed unit coefficients. */
    while (placed < DEMO_TAU) {
        h = h * 1103515245u + 12345u;
        int idx = (int)((h >> 8) % DEMO_N);
        if (c.c[idx] != 0) continue;            /* slot already used */
        c.c[idx] = (h & 1) ? 1 : (DEMO_Q - 1);  /* +1 or -1 (= q-1) */
        placed++;
    }
    return c;
}

/* Infinity norm of the centered coefficients. */
static int32_t poly_inf_norm(const dpoly *u) {
    int32_t m = 0;
    for (int i = 0; i < DEMO_N; i++) {
        int32_t v = centered(u->c[i]);
        if (v < 0) v = -v;
        if (v > m) m = v;
    }
    return m;
}

/* Keypair / signature containers. The signature carries the challenge digest
 * c_tilde and the response z (as in ML-DSA, which carries c_tilde and z). */
typedef struct { dpoly a, t; } pubkey;   /* a (public), t = a*s */
typedef struct { dpoly s; } seckey;
typedef struct { dpoly z; uint32_t c_tilde; } signature;

static void keygen(pubkey *pk, seckey *sk) {
    /* Public "matrix" element a is sampled uniformly mod q. */
    for (int i = 0; i < DEMO_N; i++) pk->a.c[i] = modq((int64_t)prng_u32());
    sk->s = sample_small(DEMO_ETA);
    pk->t = poly_mul(&pk->a, &sk->s);   /* t = a*s */
}

/* Returns 0 on success (rejection-sampling loop bounded by max_tries). */
static int sign(signature *sig, const pubkey *pk, const seckey *sk,
                const uint8_t *msg, size_t msglen) {
    for (int tries = 0; tries < 10000; tries++) {
        dpoly y = sample_y();
        dpoly w = poly_mul(&pk->a, &y);          /* commitment w = a*y */

        uint32_t c_tilde = challenge_digest(&w, msg, msglen);
        dpoly c = challenge_from_digest(c_tilde);
        dpoly cs = poly_mul(&c, &sk->s);
        dpoly z = poly_add(&y, &cs);             /* z = y + c*s */

        /* Rejection: keep z within (gamma1 - beta) like ML-DSA "with aborts". */
        if (poly_inf_norm(&z) >= (DEMO_GAMMA1 - DEMO_BETA)) continue;

        sig->z = z;
        sig->c_tilde = c_tilde;
        return 0;
    }
    return -1; /* exhausted (extremely unlikely for these params) */
}

/* Returns 1 if the signature is VALID, 0 if it must be REJECTED. */
static int verify(const signature *sig, const pubkey *pk,
                  const uint8_t *msg, size_t msglen) {
    /* Bound check on z. */
    if (poly_inf_norm(&sig->z) >= (DEMO_GAMMA1 - DEMO_BETA)) return 0;

    /* Expand the challenge from the digest carried in the signature. */
    dpoly c = challenge_from_digest(sig->c_tilde);

    /* Reconstruct w' = a*z - c*t. For an honest signature this equals
     * a*y = w exactly (no rounding/hints in this toy ring). */
    dpoly az = poly_mul(&pk->a, &sig->z);
    dpoly ct = poly_mul(&c, &pk->t);
    dpoly wprime = poly_sub(&az, &ct);

    /* Recompute the challenge digest from w' and the message; it must equal the
     * digest carried in the signature. Comparing the FULL digest (not just the
     * sparse challenge polynomial) reliably catches BOTH a tampered z (changes
     * w') AND a tampered message (changes the digest), even though the sparse
     * challenge polynomial lives in a small, collision-prone space. */
    uint32_t c_tilde_check = challenge_digest(&wprime, msg, msglen);
    return c_tilde_check == sig->c_tilde;
}

/*
 * ---------------------------------------------------------------------------
 * Self-test with an EXPLICIT verdict.
 * ---------------------------------------------------------------------------
 */
static int run_self_test(void) {
    int all_ok = 1;
    printf("Self-test (sign / verify / tamper detection):\n");

    pubkey pk;
    seckey sk;
    keygen(&pk, &sk);

    const char *message = "Hello, ML-DSA!";
    size_t msglen = strlen(message);

    signature sig;
    if (sign(&sig, &pk, &sk, (const uint8_t *)message, msglen) != 0) {
        printf("  [FAIL] signing exhausted rejection-sampling budget\n");
        return 0;
    }

    /* Property 1: a valid signature MUST verify. */
    int ok_valid = verify(&sig, &pk, (const uint8_t *)message, msglen);
    printf("  [%s] valid signature verifies\n", ok_valid ? "PASS" : "FAIL");
    if (!ok_valid) all_ok = 0;

    /* Property 2: a 1-bit-flipped signature MUST be rejected. */
    signature tampered_sig = sig;
    tampered_sig.z.c[0] ^= 1;  /* flip one bit of one coefficient */
    int ok_sigtamper = !verify(&tampered_sig, &pk,
                               (const uint8_t *)message, msglen);
    printf("  [%s] 1-bit-flipped signature is REJECTED\n",
           ok_sigtamper ? "PASS" : "FAIL");
    if (!ok_sigtamper) all_ok = 0;

    /* Property 3: a 1-bit-flipped message MUST be rejected. */
    char tampered_msg[64];
    snprintf(tampered_msg, sizeof(tampered_msg), "%s", message);
    tampered_msg[0] ^= 0x01;  /* flip one bit of the message */
    int ok_msgtamper = !verify(&sig, &pk,
                               (const uint8_t *)tampered_msg, msglen);
    printf("  [%s] 1-bit-flipped message is REJECTED\n",
           ok_msgtamper ? "PASS" : "FAIL");
    if (!ok_msgtamper) all_ok = 0;

    printf("\n");
    return all_ok;
}

int main(void) {
    /* Fixed default seed => reproducible teaching output; override with
     * PQC_DEMO_SEED. */
    const char *demo_seed_env = getenv("PQC_DEMO_SEED");
    prng_seed(demo_seed_env ? (uint32_t)strtoul(demo_seed_env, NULL, 10)
                            : 1234567u);

    printf("=== ML-DSA-65 Complete Implementation ===\n\n");
    printf("This educational implementation demonstrates the structure\n");
    printf("of ML-DSA signing and verification.\n\n");

    /* Display the published ML-DSA-65 parameters for reference. */
    printf("Parameters (ML-DSA-65, FIPS 204):\n");
    printf("  q       = %d\n", MLDSA_Q);
    printf("  n       = %d\n", MLDSA_N);
    printf("  (k, l)  = (%d, %d)\n", MLDSA_K, MLDSA_L);
    printf("  eta     = %d\n", MLDSA_ETA);
    printf("  tau     = %d\n", MLDSA_TAU);
    printf("  beta    = %d\n", MLDSA_BETA);
    printf("  gamma1  = %d\n", MLDSA_GAMMA1);
    printf("  gamma2  = %d\n", MLDSA_GAMMA2);
    printf("  omega   = %d\n", MLDSA_OMEGA);
    printf("  d       = %d\n", MLDSA_D);
    printf("  c_tilde = %d bytes\n", MLDSA_CTILDE_BYTES);
    printf("  pk      = %d bytes\n", MLDSA_PK_BYTES);
    printf("  sig     = %d bytes\n", MLDSA_SIG_BYTES);
    printf("\n");

    /* Use the placeholder buffers so the reference sizes stay visible. */
    uint8_t seed[32];
    fill_random(seed, sizeof(seed));
    printf("Generated %zu-byte seed (reproducible PRNG).\n\n", sizeof(seed));

    /* The functional demo runs on the small DEMO_* ring (see comments). */
    int ok = run_self_test();

    if (ok) {
        printf("=== Self-test PASSED: all properties hold ===\n");
        return EXIT_SUCCESS;
    }
    printf("=== Self-test FAILED: a required property did not hold ===\n");
    return EXIT_FAILURE;
}
