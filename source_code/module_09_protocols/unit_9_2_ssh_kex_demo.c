/*
 * unit_9_2_ssh_kex_demo.c
 *
 * Demonstrates SSH hybrid post-quantum key exchange end-to-end:
 *
 *   1. KEX algorithm negotiation, the way OpenSSH does client-to-server.
 *      OpenSSH 10.0+ defaults to mlkem768x25519-sha256.
 *   2. A *toy* round-trip of the negotiated hybrid KEX in which the client
 *      and server independently derive the SAME shared secret K, exactly as
 *      mlkem768x25519-sha256 prescribes:
 *
 *          K = HASH( classical_shared || pq_shared )
 *
 *      Here the classical half is a toy finite-field Diffie-Hellman (standing
 *      in for X25519) and the PQ half is a toy ElGamal-style KEM (standing in
 *      for ML-KEM-768). Both halves are mathematically consistent, so the two
 *      sides recover identical secrets and the program asserts
 *      client_secret == server_secret, printing PASS/FAIL with the matching
 *      process exit code.
 *
 * Maps to: Handbook Unit 9.2 (SSH Post-Quantum Integration).
 *
 * Build:
 *   gcc -Wall -Wextra -Wshadow -O2 -std=c11 -o ssh_kex unit_9_2_ssh_kex_demo.c
 * Run:
 *   ./ssh_kex            # PASS on agreement (exit 0), FAIL otherwise (exit 1)
 *
 * Reproducible output:
 *   The default RNG seed is fixed so the teaching output is stable. Override
 *   it for experimentation with the PQC_DEMO_SEED environment variable:
 *       PQC_DEMO_SEED=42 ./ssh_kex
 *
 * ============================================================================
 *  PEDAGOGICAL TOY - NOT REAL CRYPTOGRAPHY
 * ============================================================================
 *  The DH group is tiny (a 31-bit prime), the "KEM" is textbook ElGamal, and
 *  the hash is a non-cryptographic mixer. None of this provides any security.
 *  Its ONLY purpose is to make the hybrid KEX round-trip concrete and
 *  verifiable. Real OpenSSH uses X25519 + ML-KEM-768 with SHA-256 and
 *  constant-time, validated implementations.
 * ============================================================================
 *
 * Self-contained: no external libraries.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

/* OpenSSH 10.0+ default KEX preference order (client side).
 * See: https://www.openssh.org/pq.html */
static const char *openssh_10_default_kex[] = {
    "mlkem768x25519-sha256",               /* ML-KEM + X25519 (OpenSSH 10.0 default) */
    "sntrup761x25519-sha512@openssh.com",  /* NTRU Prime + X25519 (older hybrid) */
    "curve25519-sha256",                   /* classical fallback */
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group14-sha256",
    NULL
};

/* Hypothetical server side: supports only hybrid PQ + one classical fallback. */
static const char *strict_pq_server_kex[] = {
    "mlkem768x25519-sha256",
    "sntrup761x25519-sha512@openssh.com",
    "curve25519-sha256",
    NULL
};

/* SSH KEX negotiation: client proposes list, server proposes list,
 * both pick the first match in the client's preference order. */
static const char *negotiate_kex(const char **client_prefs, const char **server_accepts) {
    for (int i = 0; client_prefs[i]; i++) {
        for (int j = 0; server_accepts[j]; j++) {
            if (strcmp(client_prefs[i], server_accepts[j]) == 0) {
                return client_prefs[i];
            }
        }
    }
    return NULL;
}

static int is_pq_hybrid(const char *kex_name) {
    return (strstr(kex_name, "mlkem") != NULL) ||
           (strstr(kex_name, "sntrup") != NULL);
}

/* ===========================================================================
 * Toy hybrid key exchange (the part that actually agrees end-to-end).
 *
 * Everything below is a deliberately tiny stand-in for X25519 + ML-KEM-768.
 * ===========================================================================
 */

/* Toy Diffie-Hellman group: P is the Mersenne prime 2^31-1, G a generator.
 * FAR too small for security; chosen so the modular exponentiation is easy to
 * follow and all intermediates fit in 64-bit values. */
#define DH_P  2147483647ULL   /* 2^31 - 1 */
#define DH_G  7ULL

#define SHARED_SECRET_SIZE 32 /* bytes of derived KEX secret */

#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/* ---------------------------------------------------------------------------
 * Reproducible RNG seam.
 *
 * Fixed default seed => reproducible teaching output; override with
 * PQC_DEMO_SEED. (srand(time(NULL)) would make output differ every run, which
 * is un-documentable and un-testable.)
 * ------------------------------------------------------------------------- */
static void seed_rng(void) {
    const char *demo_seed_env = getenv("PQC_DEMO_SEED");
    srand(demo_seed_env ? (unsigned)strtoul(demo_seed_env, NULL, 10) : 1234567u);
}

/* Non-cryptographic hash for educational use only (stands in for SHA-256). */
static void simple_hash(const uint8_t *input, size_t len, uint8_t *output) {
    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    for (size_t i = 0; i < len; i++) {
        state[i % 8] ^= input[i];
        state[i % 8] = ROL32(state[i % 8], 7);
        state[(i + 1) % 8] += state[i % 8];
    }
    for (int r = 0; r < 3; r++) {
        for (int i = 0; i < 8; i++) {
            state[i] ^= ROL32(state[(i + 1) % 8] + (uint32_t)len, 11);
            state[i] = ROL32(state[i], 5);
        }
    }
    for (int i = 0; i < 8; i++) {
        output[i*4+0] = (uint8_t)(state[i] & 0xff);
        output[i*4+1] = (uint8_t)((state[i] >> 8) & 0xff);
        output[i*4+2] = (uint8_t)((state[i] >> 16) & 0xff);
        output[i*4+3] = (uint8_t)((state[i] >> 24) & 0xff);
    }
}

/* Random private exponent in [1, P-2] (educational rand() — NOT a CSPRNG). */
static uint64_t random_exponent(void) {
    uint64_t r = ((uint64_t)(uint32_t)rand() << 32) ^ (uint64_t)(uint32_t)rand();
    r %= (DH_P - 2);
    return r + 1;
}

/* result = base^exp mod DH_P (square-and-multiply). base stays < 2^31 so
 * base*base < 2^62 fits in uint64_t. */
static uint64_t mod_pow(uint64_t base, uint64_t exp) {
    uint64_t result = 1;
    base %= DH_P;
    while (exp > 0) {
        if (exp & 1ULL) result = (result * base) % DH_P;
        exp >>= 1;
        base = (base * base) % DH_P;
    }
    return result;
}

/* Serialize a group element to 8 big-endian bytes (wire encoding). */
static void encode_u64(uint64_t v, uint8_t out[8]) {
    for (int i = 7; i >= 0; i--) { out[i] = (uint8_t)(v & 0xff); v >>= 8; }
}

/* --- Classical half: toy ephemeral Diffie-Hellman (stands in for X25519). */
typedef struct { uint64_t priv, pub; } dh_keyshare;

static void dh_keygen(dh_keyshare *ks) {
    ks->priv = random_exponent();
    ks->pub  = mod_pow(DH_G, ks->priv);            /* G^priv mod P */
}
static uint64_t dh_agree(uint64_t peer_pub, uint64_t my_priv) {
    return mod_pow(peer_pub, my_priv);             /* G^{ab} mod P */
}

/* --- PQ half: toy ElGamal-style KEM (stands in for ML-KEM-768).
 * KeyGen sk=x, pk=G^x;  Encaps ct=G^y, ss=H(pk^y)=H(G^{xy});
 * Decaps ss=H(ct^x)=H(G^{xy}).  Encaps and Decaps recover the same ss. */
typedef struct { uint64_t sk, pk; } kem_keypair;

static void kem_keygen(kem_keypair *kp) {
    kp->sk = random_exponent();
    kp->pk = mod_pow(DH_G, kp->sk);
}
static void kem_encaps(uint64_t pk, uint64_t *ct_out, uint8_t *ss_out) {
    uint64_t y = random_exponent();
    *ct_out = mod_pow(DH_G, y);                     /* ciphertext = G^y */
    uint8_t enc[8];
    encode_u64(mod_pow(pk, y), enc);                /* pk^y = G^{xy}    */
    simple_hash(enc, sizeof(enc), ss_out);
}
static void kem_decaps(uint64_t sk, uint64_t ct, uint8_t *ss_out) {
    uint8_t enc[8];
    encode_u64(mod_pow(ct, sk), enc);               /* ct^x = G^{xy}    */
    simple_hash(enc, sizeof(enc), ss_out);
}

/* Hybrid combiner per mlkem768x25519-sha256:
 * K = HASH( classical_shared || pq_shared ).  Both sides build the identical
 * input, so they derive the identical session key K. */
static void hybrid_combine(uint64_t classical_shared,
                           const uint8_t pq_shared[SHARED_SECRET_SIZE],
                           uint8_t *kex_secret_out) {
    uint8_t buf[8 + SHARED_SECRET_SIZE];
    encode_u64(classical_shared, buf);
    memcpy(buf + 8, pq_shared, SHARED_SECRET_SIZE);
    simple_hash(buf, sizeof(buf), kex_secret_out);
}

static void print_hex(const char *label, const uint8_t *buf, size_t len) {
    printf("  %-20s", label);
    for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
    printf("\n");
}

/*
 * Run the toy hybrid handshake for the negotiated mlkem768x25519-sha256.
 * Returns 1 if the client and server derived the same secret, else 0.
 */
static int run_hybrid_handshake(void) {
    printf("Toy hybrid KEX round-trip (mlkem768x25519-sha256)\n");
    printf("  *** PEDAGOGICAL TOY - NOT REAL CRYPTO ***\n\n");

    /* Client -> Server (SSH_MSG_KEX_ECDH_INIT, hybrid form):
     *   client sends X25519 public + ML-KEM public key. */
    dh_keyshare client_dh;
    kem_keypair client_kem;
    dh_keygen(&client_dh);
    kem_keygen(&client_kem);
    printf("[Client] sends X25519_pub=%" PRIu64 ", MLKEM_pk=%" PRIu64 "\n",
           client_dh.pub, client_kem.pk);

    /* Server -> Client (SSH_MSG_KEX_ECDH_REPLY, hybrid form):
     *   server makes its own X25519 share, encapsulates to the client's
     *   ML-KEM public key, and returns X25519_pub + KEM ciphertext. */
    dh_keyshare server_dh;
    dh_keygen(&server_dh);
    uint64_t kem_ct;
    uint8_t server_pq_ss[SHARED_SECRET_SIZE];
    kem_encaps(client_kem.pk, &kem_ct, server_pq_ss);
    uint64_t server_classical = dh_agree(client_dh.pub, server_dh.priv);
    printf("[Server] sends X25519_pub=%" PRIu64 ", KEM_ct=%" PRIu64 "\n\n",
           server_dh.pub, kem_ct);

    /* Server derives K = HASH(classical || pq). */
    uint8_t server_secret[SHARED_SECRET_SIZE];
    hybrid_combine(server_classical, server_pq_ss, server_secret);
    print_hex("server pq_ss", server_pq_ss, SHARED_SECRET_SIZE);
    print_hex("server K", server_secret, SHARED_SECRET_SIZE);

    /* Client derives the same halves: classical from the server's X25519 pub,
     * PQ by decapsulating the server's KEM ciphertext with its own KEM sk. */
    uint64_t client_classical = dh_agree(server_dh.pub, client_dh.priv);
    uint8_t client_pq_ss[SHARED_SECRET_SIZE];
    kem_decaps(client_kem.sk, kem_ct, client_pq_ss);
    uint8_t client_secret[SHARED_SECRET_SIZE];
    hybrid_combine(client_classical, client_pq_ss, client_secret);
    print_hex("client pq_ss", client_pq_ss, SHARED_SECRET_SIZE);
    print_hex("client K", client_secret, SHARED_SECRET_SIZE);
    printf("\n");

    int classical_match = (client_classical == server_classical);
    int pq_match  = (memcmp(client_pq_ss, server_pq_ss, SHARED_SECRET_SIZE) == 0);
    int key_match = (memcmp(client_secret, server_secret, SHARED_SECRET_SIZE) == 0);

    printf("  classical (X25519) shares agree : %s\n", classical_match ? "yes" : "NO");
    printf("  PQ (ML-KEM) secrets agree       : %s\n", pq_match  ? "yes" : "NO");
    printf("  hybrid session key K agrees     : %s\n", key_match ? "yes" : "NO");

    return classical_match && pq_match && key_match;
}

int main(void) {
    seed_rng();

    const char *chosen = negotiate_kex(openssh_10_default_kex, strict_pq_server_kex);

    printf("SSH KEX negotiation demo (OpenSSH 10.0+ behavior)\n");
    printf("=================================================\n\n");

    printf("Client preference (first few):\n");
    for (int i = 0; i < 3 && openssh_10_default_kex[i]; i++) {
        printf("  %d. %s\n", i + 1, openssh_10_default_kex[i]);
    }
    printf("  ...\n\n");

    printf("Server accepts:\n");
    for (int i = 0; strict_pq_server_kex[i]; i++) {
        printf("  %d. %s\n", i + 1, strict_pq_server_kex[i]);
    }
    printf("\n");

    if (!chosen) {
        printf("No common KEX algorithm — connection would fail.\n");
        printf("\nRESULT: FAIL - no shared KEX algorithm.\n");
        return EXIT_FAILURE;
    }

    printf("Negotiated: %s\n", chosen);
    printf("Hybrid PQ?  %s\n\n", is_pq_hybrid(chosen) ? "YES" : "NO");

    /* Carry the negotiated hybrid KEX through an actual (toy) round-trip so we
     * can verify both peers compute the same session key. */
    int agreed = run_hybrid_handshake();

    printf("\nNote: OpenSSH 10.2+ emits a warning banner to the user when the\n");
    printf("negotiated KEX is not hybrid-PQ. By 2028, classical-only KEX is\n");
    printf("expected to be disabled in the default SSH server configuration.\n\n");

    if (agreed) {
        printf("RESULT: PASS - client and server derived the same KEX secret.\n");
        return EXIT_SUCCESS;
    }
    printf("RESULT: FAIL - client and server KEX secrets differ.\n");
    return EXIT_FAILURE;
}
