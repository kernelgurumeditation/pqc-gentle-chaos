/*
 * Source: Module 5 - Digital Signatures Theory
 * Unit 5.1: Signature Security Definitions
 * From: pqc-developers-handbook.md (lines 11237-11544)
 *
 * Digital Signature Framework
 * Educational implementation demonstrating signature concepts
 *
 * This implements a simple Schnorr-like signature for illustration.
 * NOT cryptographically secure - uses small parameters for clarity.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

/* Toy parameters - NOT SECURE, for illustration only */
#define P 997        /* Prime modulus */
#define G 9          /* Generator of order Q in Z*_P: 7^((P-1)/Q) mod P */
#define Q 83         /* Order of G (prime factor of P-1: 996 = 4*3*83) */

typedef struct {
    uint32_t x;      /* Secret key: random in [1, Q-1] */
} secret_key;

typedef struct {
    uint32_t y;      /* Public key: g^x mod P */
} public_key;

typedef struct {
    uint32_t r;      /* First component: g^k mod P */
    uint32_t s;      /* Second component: k + x*e mod Q */
} signature;

/*
 * Simple hash function (NOT cryptographic - for illustration)
 */
static uint32_t hash_message(const uint8_t *msg, size_t len, uint32_t r) {
    uint32_t h = r;  /* Include r in hash (Fiat-Shamir style) */
    for (size_t i = 0; i < len; i++) {
        h = (h * 31 + msg[i]) % Q;
    }
    return h % Q;
}

/*
 * Modular exponentiation: base^exp mod mod
 */
static uint32_t mod_exp(uint32_t base, uint32_t exp, uint32_t mod) {
    uint64_t result = 1;
    uint64_t b = base % mod;

    while (exp > 0) {
        if (exp & 1) {
            result = (result * b) % mod;
        }
        exp >>= 1;
        b = (b * b) % mod;
    }

    return (uint32_t)result;
}

/*
 * Key Generation
 */
void keygen(public_key *pk, secret_key *sk) {
    /* Sample random secret key */
    sk->x = (rand() % (Q - 1)) + 1;  /* x ∈ [1, Q-1] */

    /* Compute public key: y = g^x mod P */
    pk->y = mod_exp(G, sk->x, P);

    printf("KeyGen complete:\n");
    printf("  Secret key x = %u\n", sk->x);
    printf("  Public key y = g^x = %u^%u = %u (mod %u)\n",
           G, sk->x, pk->y, P);
}

/*
 * Signing Algorithm (Schnorr-like)
 */
void sign(const secret_key *sk, const uint8_t *msg, size_t msg_len,
          signature *sig) {
    /* Sample random nonce k */
    uint32_t k = (rand() % (Q - 1)) + 1;

    /* Compute r = g^k mod P */
    sig->r = mod_exp(G, k, P);

    /* Compute challenge e = H(r || m) */
    uint32_t e = hash_message(msg, msg_len, sig->r);

    /* Compute s = k + x*e mod Q */
    sig->s = (k + (uint64_t)sk->x * e) % Q;

    printf("Sign complete:\n");
    printf("  Nonce k = %u\n", k);
    printf("  r = g^k = %u\n", sig->r);
    printf("  e = H(r,m) = %u\n", e);
    printf("  s = k + x*e = %u + %u*%u = %u (mod %u)\n",
           k, sk->x, e, sig->s, Q);
}

/*
 * Verification Algorithm
 */
int verify(const public_key *pk, const uint8_t *msg, size_t msg_len,
           const signature *sig) {
    /* Recompute challenge e = H(r || m) */
    uint32_t e = hash_message(msg, msg_len, sig->r);

    /* Check: g^s = r * y^e mod P */
    uint32_t lhs = mod_exp(G, sig->s, P);              /* g^s */
    uint32_t rhs = ((uint64_t)sig->r * mod_exp(pk->y, e, P)) % P;  /* r * y^e */

    printf("Verify:\n");
    printf("  e = H(r,m) = %u\n", e);
    printf("  LHS: g^s = %u^%u = %u\n", G, sig->s, lhs);
    printf("  RHS: r * y^e = %u * %u^%u = %u\n", sig->r, pk->y, e, rhs);

    return (lhs == rhs) ? 1 : 0;
}

/*
 * Demonstrate correctness
 */
void demo_correctness(void) {
    printf("\n=== Correctness Demonstration ===\n\n");

    public_key pk;
    secret_key sk;
    signature sig;

    /* Generate keys */
    keygen(&pk, &sk);
    printf("\n");

    /* Sign a message */
    const char *msg = "Hello, signatures!";
    sign(&sk, (const uint8_t *)msg, strlen(msg), &sig);
    printf("\n");

    /* Verify the signature */
    int valid = verify(&pk, (const uint8_t *)msg, strlen(msg), &sig);
    printf("\n");

    printf("Message: \"%s\"\n", msg);
    printf("Signature: (r=%u, s=%u)\n", sig.r, sig.s);
    printf("Verification: %s\n", valid ? "VALID ✓" : "INVALID ✗");
}

/*
 * Demonstrate EUF-CMA game
 */
void demo_eufcma(void) {
    printf("\n=== EUF-CMA Game Demonstration ===\n\n");

    /* Challenger generates keys */
    printf("--- Challenger Setup ---\n");
    public_key pk;
    secret_key sk;  /* Adversary doesn't see this */
    keygen(&pk, &sk);
    printf("Challenger sends pk to Adversary\n\n");

    /* Track signed messages */
    signature signatures[10];
    int num_signed = 0;

    /* Adversary makes signing queries */
    printf("--- Query Phase ---\n");

    const char *m1 = "Message 1";
    printf("Adversary requests signature on: \"%s\"\n", m1);
    sign(&sk, (const uint8_t *)m1, strlen(m1), &signatures[num_signed]);
    num_signed++;
    printf("\n");

    const char *m2 = "Message 2";
    printf("Adversary requests signature on: \"%s\"\n", m2);
    sign(&sk, (const uint8_t *)m2, strlen(m2), &signatures[num_signed]);
    num_signed++;
    printf("\n");

    /* Adversary attempts forgery */
    printf("--- Forgery Phase ---\n\n");

    /* Attempt 1: Replay attack (not a forgery) */
    printf("Attempt 1: Replay signed message\n");
    printf("  Adversary outputs: (\"%s\", signature from query)\n", m1);
    printf("  Result: NOT A FORGERY - message was in query set Q\n\n");

    /* Attempt 2: Random forgery (should fail) */
    printf("Attempt 2: Forge on new message\n");
    const char *m_new = "New message";
    signature fake_sig = {123, 456};  /* Random guess */
    printf("  Adversary outputs: (\"%s\", random signature)\n", m_new);
    int forged = verify(&pk, (const uint8_t *)m_new, strlen(m_new), &fake_sig);
    printf("  Verification: %s\n", forged ? "VALID (forgery!)" : "INVALID (failed)");
    printf("  Result: %s\n\n", forged ? "SUCCESSFUL FORGERY!" : "Forgery attempt failed (as expected)");

    /* In a real attack, adversary would need to solve discrete log */
    printf("To forge, adversary would need to:\n");
    printf("  1. Compute discrete log: find x such that y = g^x\n");
    printf("  2. Or find collision in hash function\n");
    printf("  Both are computationally hard for real parameters.\n");
}

/*
 * Demonstrate nonce reuse vulnerability
 */
void demo_nonce_reuse_attack(void) {
    printf("\n=== Nonce Reuse Attack Demonstration ===\n\n");

    public_key pk;
    secret_key sk;
    keygen(&pk, &sk);

    uint32_t secret_x = sk.x;  /* We'll recover this */
    printf("Target secret key: x = %u (attacker doesn't know this)\n\n", secret_x);

    /* Simulate signing with SAME nonce (vulnerability!) */
    uint32_t reused_k = 42;  /* Same nonce used twice */

    /* Signature 1 */
    const char *m1 = "First message";
    signature sig1;
    sig1.r = mod_exp(G, reused_k, P);
    uint32_t e1 = hash_message((const uint8_t *)m1, strlen(m1), sig1.r);
    sig1.s = (reused_k + (uint64_t)sk.x * e1) % Q;
    printf("Signature 1 on \"%s\":\n", m1);
    printf("  k = %u (REUSED!), e1 = %u, s1 = %u\n\n", reused_k, e1, sig1.s);

    /* Signature 2 with SAME k */
    const char *m2 = "Second message";
    signature sig2;
    sig2.r = mod_exp(G, reused_k, P);  /* Same r since same k */
    uint32_t e2 = hash_message((const uint8_t *)m2, strlen(m2), sig2.r);
    sig2.s = (reused_k + (uint64_t)sk.x * e2) % Q;
    printf("Signature 2 on \"%s\":\n", m2);
    printf("  k = %u (REUSED!), e2 = %u, s2 = %u\n\n", reused_k, e2, sig2.s);

    /* ATTACK: Recover secret key */
    printf("--- Attacker's Recovery ---\n");
    printf("Attacker observes: r1 = r2 = %u (same r means same k)\n\n", sig1.r);

    printf("From signatures:\n");
    printf("  s1 = k + x*e1 (mod Q)\n");
    printf("  s2 = k + x*e2 (mod Q)\n\n");

    printf("Subtracting:\n");
    printf("  s1 - s2 = x*(e1 - e2) (mod Q)\n");
    printf("  %u - %u = x*(%u - %u) (mod %u)\n", sig1.s, sig2.s, e1, e2, Q);

    /* Compute s1 - s2 mod Q */
    int32_t s_diff = (int32_t)sig1.s - (int32_t)sig2.s;
    if (s_diff < 0) s_diff += Q;

    int32_t e_diff = (int32_t)e1 - (int32_t)e2;
    if (e_diff < 0) e_diff += Q;

    /* Compute modular inverse of e_diff */
    /* Using extended Euclidean algorithm would be proper, */
    /* but for small Q we can just search */
    uint32_t e_diff_inv = 0;
    for (uint32_t i = 1; i < Q; i++) {
        if (((uint64_t)e_diff * i) % Q == 1) {
            e_diff_inv = i;
            break;
        }
    }

    uint32_t recovered_x = ((uint64_t)s_diff * e_diff_inv) % Q;

    printf("  x = (s1 - s2) * (e1 - e2)^(-1)\n");
    printf("  x = %d * %u^(-1) = %d * %u = %u (mod %u)\n\n",
           s_diff, e_diff, s_diff, e_diff_inv, recovered_x, Q);

    printf("Recovered secret key: x = %u\n", recovered_x);
    printf("Actual secret key:    x = %u\n", secret_x);
    printf("Attack %s!\n", (recovered_x == secret_x) ? "SUCCEEDED" : "failed");

    printf("\n*** LESSON: Never reuse nonces in Schnorr/ECDSA signatures! ***\n");
    printf("*** This is why ML-DSA uses deterministic nonce derivation. ***\n");
}

/*
 * Main demonstration
 */
int main(void) {
    srand(time(NULL));

    printf("=== Digital Signature Security Concepts ===\n");
    printf("Educational demonstration using Schnorr-like signatures\n");
    printf("Parameters: P=%u, G=%u, Q=%u\n", P, G, Q);
    printf("WARNING: These parameters are NOT secure!\n");

    /* Demonstrate correctness */
    demo_correctness();

    /* Demonstrate EUF-CMA game */
    demo_eufcma();

    /* Demonstrate nonce reuse attack */
    demo_nonce_reuse_attack();

    return 0;
}
