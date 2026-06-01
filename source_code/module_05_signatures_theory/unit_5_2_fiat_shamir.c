/*
 * Source: Module 5 - Digital Signatures Theory
 * Unit 5.2: Fiat-Shamir Transform
 * From: pqc-developers-handbook.md (lines 12348-12707)
 *
 * Fiat-Shamir Transform Implementation
 * Educational code demonstrating ID → Signature conversion
 *
 * Shows both interactive Schnorr ID and non-interactive Schnorr signature
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

/* Toy parameters - NOT SECURE */
#define P 997        /* Prime modulus */
#define Q 83         /* Order of generator (prime factor of P-1: 996 = 4*3*83) */
#define G 9          /* Generator of order Q in Z*_P: 7^((P-1)/Q) mod P */

/* Types */
typedef struct {
    uint32_t x;          /* Secret key */
} SecretKey;

typedef struct {
    uint32_t y;          /* Public key: g^x mod P */
} PublicKey;

typedef struct {
    uint32_t R;          /* Commitment: g^k */
    uint32_t s;          /* Response: k + c*x */
} Signature;

/* ID Protocol transcript */
typedef struct {
    uint32_t a;          /* Commitment */
    uint32_t c;          /* Challenge */
    uint32_t z;          /* Response */
} IDTranscript;

/*
 * Modular exponentiation
 */
static uint32_t mod_exp(uint32_t base, uint32_t exp, uint32_t mod) {
    uint64_t result = 1;
    uint64_t b = base % mod;
    while (exp > 0) {
        if (exp & 1) result = (result * b) % mod;
        exp >>= 1;
        b = (b * b) % mod;
    }
    return (uint32_t)result;
}

/*
 * Modular inverse using extended Euclidean algorithm
 */
static uint32_t mod_inverse(uint32_t a, uint32_t mod) {
    int32_t t = 0, newt = 1;
    int32_t r = mod, newr = a;
    while (newr != 0) {
        int32_t quotient = r / newr;
        int32_t tmp = t - quotient * newt;
        t = newt; newt = tmp;
        tmp = r - quotient * newr;
        r = newr; newr = tmp;
    }
    if (t < 0) t += mod;
    return (uint32_t)t;
}

/*
 * Simple hash function (NOT cryptographic)
 */
static uint32_t hash(const uint8_t *data, size_t len) {
    uint32_t h = 0x811c9dc5;
    for (size_t i = 0; i < len; i++) {
        h ^= data[i];
        h *= 0x01000193;
    }
    return h % Q;
}

/*
 * Hash for Fiat-Shamir: H(R || pk || m)
 */
static uint32_t fiat_shamir_hash(uint32_t R, uint32_t pk,
                                  const char *msg) {
    uint8_t buffer[256];
    int len = snprintf((char*)buffer, sizeof(buffer),
                       "%u|%u|%s", R, pk, msg);
    return hash(buffer, len);
}

/*
 * Key generation
 */
void keygen(PublicKey *pk, SecretKey *sk) {
    sk->x = (rand() % (Q - 1)) + 1;
    pk->y = mod_exp(G, sk->x, P);
}

/* ========== INTERACTIVE ID PROTOCOL ========== */

/*
 * Prover: Generate commitment
 */
uint32_t id_prover_commit(uint32_t *k_out) {
    *k_out = (rand() % (Q - 1)) + 1;
    return mod_exp(G, *k_out, P);
}

/*
 * Verifier: Generate random challenge
 */
uint32_t id_verifier_challenge(void) {
    return rand() % Q;
}

/*
 * Prover: Compute response
 */
uint32_t id_prover_respond(uint32_t k, uint32_t c, const SecretKey *sk) {
    return (k + (uint64_t)c * sk->x) % Q;
}

/*
 * Verifier: Check response
 */
int id_verifier_check(const PublicKey *pk, uint32_t a, uint32_t c, uint32_t z) {
    uint32_t lhs = mod_exp(G, z, P);
    uint32_t rhs = ((uint64_t)a * mod_exp(pk->y, c, P)) % P;
    return lhs == rhs;
}

/*
 * Run interactive ID protocol
 */
int run_id_protocol(const PublicKey *pk, const SecretKey *sk,
                     IDTranscript *transcript) {
    printf("\n=== Interactive Schnorr ID Protocol ===\n\n");

    /* Round 1: Prover commitment */
    uint32_t k;
    transcript->a = id_prover_commit(&k);
    printf("Round 1 - Prover commits:\n");
    printf("  k = %u (secret nonce)\n", k);
    printf("  a = g^k = %u\n", transcript->a);
    printf("  Prover → Verifier: a = %u\n\n", transcript->a);

    /* Round 2: Verifier challenge */
    transcript->c = id_verifier_challenge();
    printf("Round 2 - Verifier challenges:\n");
    printf("  c = %u (random)\n", transcript->c);
    printf("  Verifier → Prover: c = %u\n\n", transcript->c);

    /* Round 3: Prover response */
    transcript->z = id_prover_respond(k, transcript->c, sk);
    printf("Round 3 - Prover responds:\n");
    printf("  z = k + c*x = %u + %u*%u = %u (mod %u)\n",
           k, transcript->c, sk->x, transcript->z, Q);
    printf("  Prover → Verifier: z = %u\n\n", transcript->z);

    /* Verification */
    int valid = id_verifier_check(pk, transcript->a, transcript->c, transcript->z);
    printf("Verification:\n");
    printf("  g^z = %lu\n", (unsigned long)mod_exp(G, transcript->z, P));
    printf("  a * y^c = %lu * %lu^%lu = %lu\n",
           (unsigned long)transcript->a, (unsigned long)pk->y,
           (unsigned long)transcript->c,
           (unsigned long)(((uint64_t)transcript->a * mod_exp(pk->y, transcript->c, P)) % P));
    printf("  Result: %s\n", valid ? "ACCEPT ✓" : "REJECT ✗");

    /* PASS = honest prover is accepted (completeness). */
    return valid;
}

/* ========== FIAT-SHAMIR SIGNATURE ========== */

/*
 * Sign using Fiat-Shamir transform
 */
void fs_sign(const PublicKey *pk, const SecretKey *sk,
             const char *msg, Signature *sig) {
    /* Commitment */
    uint32_t k = (rand() % (Q - 1)) + 1;
    sig->R = mod_exp(G, k, P);

    /* Fiat-Shamir: c = H(R || pk || m) */
    uint32_t c = fiat_shamir_hash(sig->R, pk->y, msg);

    /* Response */
    sig->s = (k + (uint64_t)c * sk->x) % Q;
}

/*
 * Verify Fiat-Shamir signature
 */
int fs_verify(const PublicKey *pk, const char *msg, const Signature *sig) {
    /* Recompute challenge */
    uint32_t c = fiat_shamir_hash(sig->R, pk->y, msg);

    /* Check g^s = R * y^c */
    uint32_t lhs = mod_exp(G, sig->s, P);
    uint32_t rhs = ((uint64_t)sig->R * mod_exp(pk->y, c, P)) % P;
    return lhs == rhs;
}

/*
 * Demonstrate Fiat-Shamir signature
 */
int demo_fiat_shamir_signature(const PublicKey *pk, const SecretKey *sk) {
    printf("\n=== Fiat-Shamir Signature (Non-Interactive) ===\n\n");

    const char *msg = "Hello, Fiat-Shamir!";
    Signature sig;

    printf("Message: \"%s\"\n\n", msg);

    /* Sign */
    fs_sign(pk, sk, msg, &sig);
    printf("Signing:\n");
    printf("  R = g^k = %u\n", sig.R);
    printf("  c = H(R || pk || m) = %u\n",
           fiat_shamir_hash(sig.R, pk->y, msg));
    printf("  s = k + c*x = %u\n", sig.s);
    printf("  Signature: (R=%u, s=%u)\n\n", sig.R, sig.s);

    /* Verify */
    int valid = fs_verify(pk, msg, &sig);
    uint32_t c = fiat_shamir_hash(sig.R, pk->y, msg);
    printf("Verification:\n");
    printf("  Recompute c = H(R || pk || m) = %lu\n", (unsigned long)c);
    printf("  Check g^s = R * y^c:\n");
    printf("    g^s = %lu\n", (unsigned long)mod_exp(G, sig.s, P));
    printf("    R * y^c = %lu\n",
           (unsigned long)(((uint64_t)sig.R * mod_exp(pk->y, c, P)) % P));
    printf("  Result: %s\n", valid ? "VALID ✓" : "INVALID ✗");

    /* PASS = the non-interactive signature verifies (completeness). */
    return valid;
}

/* ========== SPECIAL SOUNDNESS DEMO ========== */

/*
 * Demonstrate secret extraction from two transcripts
 */
int demo_special_soundness(const SecretKey *sk) {
    printf("\n=== Special Soundness Demonstration ===\n\n");

    printf("Goal: Extract secret key from two transcripts with same commitment\n\n");

    /* Generate two transcripts with same k (same commitment) */
    uint32_t k = 42;  /* Fixed nonce for demo */
    uint32_t a = mod_exp(G, k, P);

    uint32_t c1 = 7, c2 = 13;
    uint32_t z1 = (k + (uint64_t)c1 * sk->x) % Q;
    uint32_t z2 = (k + (uint64_t)c2 * sk->x) % Q;

    printf("Transcript 1: (a=%u, c=%u, z=%u)\n", a, c1, z1);
    printf("  Equation: z1 = k + c1*x → %u = %u + %u*x\n", z1, k, c1);
    printf("\nTranscript 2: (a=%u, c=%u, z=%u)\n", a, c2, z2);
    printf("  Equation: z2 = k + c2*x → %u = %u + %u*x\n\n", z2, k, c2);

    /* Extract secret */
    printf("Extraction:\n");
    printf("  z1 - z2 = (c1 - c2) * x\n");

    int32_t z_diff = (int32_t)z1 - (int32_t)z2;
    if (z_diff < 0) z_diff += Q;
    int32_t c_diff = (int32_t)c1 - (int32_t)c2;
    if (c_diff < 0) c_diff += Q;

    printf("  %d - %d = (%d - %d) * x (mod %u)\n", z1, z2, c1, c2, Q);
    printf("  %d = %d * x (mod %u)\n", z_diff, c_diff, Q);

    uint32_t c_diff_inv = mod_inverse(c_diff, Q);
    uint32_t extracted_x = ((uint64_t)z_diff * c_diff_inv) % Q;

    printf("  x = %d * %u^(-1) = %d * %u = %u (mod %u)\n\n",
           z_diff, c_diff, z_diff, c_diff_inv, extracted_x, Q);

    printf("Extracted secret: x = %u\n", extracted_x);
    printf("Actual secret:    x = %u\n", sk->x);
    printf("Extraction %s!\n",
           (extracted_x == sk->x) ? "SUCCEEDED" : "FAILED");

    /* PASS = two transcripts extract the secret (special soundness). */
    return (extracted_x == sk->x);
}

/* ========== HVZK SIMULATION DEMO ========== */

/*
 * Simulate transcript without knowing secret
 */
int demo_hvzk_simulation(const PublicKey *pk) {
    printf("\n=== HVZK Simulation Demonstration ===\n\n");

    printf("Goal: Create valid-looking transcript without knowing sk\n\n");

    /* Choose random z and c */
    uint32_t z = rand() % Q;
    uint32_t c = rand() % Q;

    /* Compute a = g^z * y^(-c) */
    uint32_t y_neg_c = mod_inverse(mod_exp(pk->y, c, P), P);
    uint32_t a = ((uint64_t)mod_exp(G, z, P) * y_neg_c) % P;

    printf("Simulation (no secret key used!):\n");
    printf("  Choose random z = %u\n", z);
    printf("  Choose random c = %u\n", c);
    printf("  Compute a = g^z * y^(-c) = %u * %u^(-%u) = %u\n\n",
           mod_exp(G, z, P), pk->y, c, a);

    printf("Simulated transcript: (a=%u, c=%u, z=%u)\n\n", a, c, z);

    /* Verify the simulated transcript */
    int valid = id_verifier_check(pk, a, c, z);
    printf("Verification of simulated transcript:\n");
    printf("  g^z = %lu\n", (unsigned long)mod_exp(G, z, P));
    printf("  a * y^c = %lu\n", (unsigned long)(((uint64_t)a * mod_exp(pk->y, c, P)) % P));
    printf("  Result: %s\n\n", valid ? "VALID ✓" : "INVALID ✗");

    printf("This proves zero-knowledge: transcripts can be faked!\n");
    printf("Verifier learns nothing about sk from the protocol.\n");

    /* PASS = the simulated (no-secret) transcript verifies (HVZK). */
    return valid;
}

/*
 * Main demonstration
 */
int main(void) {
    /* Fixed default seed => reproducible teaching output; override with PQC_DEMO_SEED. */
    const char *demo_seed_env = getenv("PQC_DEMO_SEED");
    srand(demo_seed_env ? (unsigned)strtoul(demo_seed_env, NULL, 10) : 1234567u);

    printf("=== Fiat-Shamir Transform: ID Protocol → Signature ===\n");
    printf("Parameters: P=%u, Q=%u, G=%u (NOT SECURE)\n", P, Q, G);

    /* Generate keys */
    PublicKey pk;
    SecretKey sk;
    keygen(&pk, &sk);
    printf("\nKey Generation:\n");
    printf("  Secret key: x = %u\n", sk.x);
    printf("  Public key: y = g^x = %u\n", pk.y);

    int all_pass = 1;

    /* Interactive ID protocol */
    IDTranscript transcript;
    all_pass &= run_id_protocol(&pk, &sk, &transcript);

    /* Fiat-Shamir signature */
    all_pass &= demo_fiat_shamir_signature(&pk, &sk);

    /* Special soundness */
    all_pass &= demo_special_soundness(&sk);

    /* HVZK simulation */
    all_pass &= demo_hvzk_simulation(&pk);

    /* Summary */
    printf("\n=== Summary ===\n\n");
    printf("1. Interactive ID Protocol: 3 rounds (commit → challenge → respond)\n");
    printf("2. Fiat-Shamir Transform: c = H(a || m) makes it non-interactive\n");
    printf("3. Special Soundness: Two transcripts reveal secret\n");
    printf("4. HVZK: Transcripts can be simulated without secret\n");
    printf("5. Security: ROM proof from special soundness + HVZK\n");

    printf("\n==============================================\n");
    printf("Overall result: %s\n",
           all_pass ? "PASS (all checks behaved as expected)"
                    : "FAIL (a check did not behave as expected)");
    printf("==============================================\n");

    return all_pass ? EXIT_SUCCESS : EXIT_FAILURE;
}
