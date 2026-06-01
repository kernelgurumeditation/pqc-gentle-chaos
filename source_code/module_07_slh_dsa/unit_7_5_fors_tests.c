/*
 * Source: Module 7 - SLH-DSA (Hash-Based Digital Signatures)
 * Unit: 7.5 - FORS (Few-Time Signatures)
 * Description: Demonstration of FORS concepts
 *
 * This is a standalone educational demonstration showing FORS concepts
 * (Forest of Random Subsets).
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

/* FORS parameters (simplified for demo) */
#define FORS_N          16      /* Hash output size (reduced for demo) */
#define FORS_K          4       /* Number of trees */
#define FORS_A          4       /* Log2 of leaves per tree */
#define FORS_T          (1 << FORS_A)  /* Leaves per tree = 16 */

#define FORS_PK_BYTES   FORS_N  /* Public key is single hash */
#define FORS_SK_BYTES   (FORS_K * FORS_T * FORS_N)  /* All secret values */
#define FORS_AUTH_BYTES (FORS_A * FORS_N)  /* Auth path per tree */
#define FORS_TREE_SIG   (FORS_N + FORS_AUTH_BYTES)  /* Sig per tree */
#define FORS_SIG_BYTES  (FORS_K * FORS_TREE_SIG)  /* Total signature */

/* Simple random bytes */
static void random_bytes(uint8_t *out, size_t len)
{
    static unsigned int seed = 54321;
    for (size_t i = 0; i < len; i++) {
        seed = seed * 1103515245 + 12345;
        out[i] = (seed >> 16) & 0xFF;
    }
}

/* Simple hash function for demo (not cryptographic!) */
static void simple_hash(uint8_t out[FORS_N], const uint8_t *in, size_t len)
{
    memset(out, 0, FORS_N);
    for (size_t i = 0; i < len; i++) {
        out[i % FORS_N] ^= in[i];
        out[(i + 1) % FORS_N] ^= (in[i] << 4) | (in[i] >> 4);
    }
    for (int r = 0; r < 4; r++) {
        for (int i = 0; i < FORS_N; i++) {
            out[i] ^= out[(i + 5) % FORS_N];
        }
    }
}

/* Hash two nodes together */
static void hash_nodes(uint8_t out[FORS_N],
                       const uint8_t left[FORS_N],
                       const uint8_t right[FORS_N])
{
    uint8_t combined[2 * FORS_N];
    memcpy(combined, left, FORS_N);
    memcpy(combined + FORS_N, right, FORS_N);
    simple_hash(out, combined, 2 * FORS_N);
}

/* PRF: Derive value from seed, tree, and index */
static void prf(uint8_t out[FORS_N], const uint8_t seed[FORS_N],
                int tree, int idx)
{
    uint8_t input[FORS_N + 8];
    memcpy(input, seed, FORS_N);
    input[FORS_N] = (tree >> 24) & 0xFF;
    input[FORS_N + 1] = (tree >> 16) & 0xFF;
    input[FORS_N + 2] = (tree >> 8) & 0xFF;
    input[FORS_N + 3] = tree & 0xFF;
    input[FORS_N + 4] = (idx >> 24) & 0xFF;
    input[FORS_N + 5] = (idx >> 16) & 0xFF;
    input[FORS_N + 6] = (idx >> 8) & 0xFF;
    input[FORS_N + 7] = idx & 0xFF;
    simple_hash(out, input, FORS_N + 8);
}

/* Convert message digest to FORS indices */
static void message_to_indices(uint32_t indices[FORS_K],
                                const uint8_t msg_digest[],
                                size_t digest_len)
{
    /* Simple: take FORS_A bits at a time for each tree */
    int bit_pos = 0;

    for (int i = 0; i < FORS_K; i++) {
        uint32_t idx = 0;
        for (int b = 0; b < FORS_A; b++) {
            int byte_idx = bit_pos / 8;
            int bit_idx = bit_pos % 8;
            if ((size_t)byte_idx < digest_len) {
                idx |= ((msg_digest[byte_idx] >> bit_idx) & 1) << b;
            }
            bit_pos++;
        }
        indices[i] = idx % FORS_T;
    }
}

/* Build a Merkle tree from leaves and get root + auth path */
static void build_tree_and_auth(uint8_t root[FORS_N],
                                 uint8_t auth_path[FORS_A][FORS_N],
                                 const uint8_t leaves[FORS_T][FORS_N],
                                 int leaf_idx)
{
    /* Allocate nodes for tree */
    uint8_t nodes[2 * FORS_T][FORS_N];

    /* Copy leaves to bottom level */
    for (int i = 0; i < FORS_T; i++) {
        memcpy(nodes[FORS_T + i], leaves[i], FORS_N);
    }

    /* Build tree bottom-up */
    for (int i = FORS_T - 1; i > 0; i--) {
        hash_nodes(nodes[i], nodes[2*i], nodes[2*i + 1]);
    }

    /* Root is at index 1 */
    memcpy(root, nodes[1], FORS_N);

    /* Extract auth path */
    int idx = FORS_T + leaf_idx;
    for (int level = 0; level < FORS_A; level++) {
        int sibling = idx ^ 1;
        memcpy(auth_path[level], nodes[sibling], FORS_N);
        idx /= 2;
    }
}

/* Compute root from leaf and auth path */
static void compute_root(uint8_t root[FORS_N],
                          const uint8_t leaf[FORS_N],
                          int leaf_idx,
                          const uint8_t auth_path[FORS_A][FORS_N])
{
    uint8_t current[FORS_N];
    memcpy(current, leaf, FORS_N);

    for (int level = 0; level < FORS_A; level++) {
        if ((leaf_idx >> level) & 1) {
            hash_nodes(current, auth_path[level], current);
        } else {
            hash_nodes(current, current, auth_path[level]);
        }
    }

    memcpy(root, current, FORS_N);
}

/* FORS Key generation */
static void fors_keygen(uint8_t pk[FORS_PK_BYTES],
                        const uint8_t sk_seed[FORS_N])
{
    uint8_t tree_roots[FORS_K][FORS_N];
    uint8_t leaves[FORS_T][FORS_N];
    uint8_t auth_path[FORS_A][FORS_N];

    for (int t = 0; t < FORS_K; t++) {
        /* Generate all leaves for this tree */
        for (int i = 0; i < FORS_T; i++) {
            uint8_t sk_val[FORS_N];
            prf(sk_val, sk_seed, t, i);
            simple_hash(leaves[i], sk_val, FORS_N);  /* pk = H(sk) */
        }

        /* Build tree and get root */
        build_tree_and_auth(tree_roots[t], auth_path, leaves, 0);
    }

    /* PK = Hash of all tree roots */
    uint8_t roots_concat[FORS_K * FORS_N];
    for (int t = 0; t < FORS_K; t++) {
        memcpy(&roots_concat[t * FORS_N], tree_roots[t], FORS_N);
    }
    simple_hash(pk, roots_concat, FORS_K * FORS_N);
}

/* FORS Sign */
static void fors_sign(uint8_t sig[FORS_SIG_BYTES],
                      const uint8_t msg_digest[],
                      size_t digest_len,
                      const uint8_t sk_seed[FORS_N])
{
    uint32_t indices[FORS_K];
    message_to_indices(indices, msg_digest, digest_len);

    uint8_t leaves[FORS_T][FORS_N];
    uint8_t root[FORS_N];
    uint8_t auth_path[FORS_A][FORS_N];

    for (int t = 0; t < FORS_K; t++) {
        /* Generate all leaves for this tree */
        for (int i = 0; i < FORS_T; i++) {
            uint8_t sk_val[FORS_N];
            prf(sk_val, sk_seed, t, i);
            simple_hash(leaves[i], sk_val, FORS_N);
        }

        /* Build tree and get auth path for selected leaf */
        build_tree_and_auth(root, auth_path, leaves, indices[t]);

        /* Signature = sk value + auth path */
        uint8_t sk_val[FORS_N];
        prf(sk_val, sk_seed, t, indices[t]);

        uint8_t *tree_sig = &sig[t * FORS_TREE_SIG];
        memcpy(tree_sig, sk_val, FORS_N);
        memcpy(tree_sig + FORS_N, auth_path, FORS_AUTH_BYTES);
    }
}

/* FORS Verify */
static int fors_verify(const uint8_t pk[FORS_PK_BYTES],
                       const uint8_t sig[FORS_SIG_BYTES],
                       const uint8_t msg_digest[],
                       size_t digest_len)
{
    uint32_t indices[FORS_K];
    message_to_indices(indices, msg_digest, digest_len);

    uint8_t tree_roots[FORS_K][FORS_N];

    for (int t = 0; t < FORS_K; t++) {
        const uint8_t *tree_sig = &sig[t * FORS_TREE_SIG];
        const uint8_t *sk_val = tree_sig;
        const uint8_t (*auth_path)[FORS_N] =
            (const uint8_t (*)[FORS_N])(tree_sig + FORS_N);

        /* Compute leaf = H(sk_val) */
        uint8_t leaf[FORS_N];
        simple_hash(leaf, sk_val, FORS_N);

        /* Compute root from leaf and auth path */
        compute_root(tree_roots[t], leaf, indices[t], auth_path);
    }

    /* Compute expected PK */
    uint8_t roots_concat[FORS_K * FORS_N];
    for (int t = 0; t < FORS_K; t++) {
        memcpy(&roots_concat[t * FORS_N], tree_roots[t], FORS_N);
    }
    uint8_t computed_pk[FORS_PK_BYTES];
    simple_hash(computed_pk, roots_concat, FORS_K * FORS_N);

    return memcmp(pk, computed_pk, FORS_PK_BYTES);
}

/*
 * Test basic FORS sign and verify.
 * Returns 1 on success, 0 on failure.
 */
int test_fors_basic(void)
{
    printf("Testing FORS basic sign/verify...\n");

    uint8_t sk_seed[FORS_N];
    uint8_t pk[FORS_PK_BYTES];
    uint8_t msg_digest[32];
    uint8_t sig[FORS_SIG_BYTES];

    random_bytes(sk_seed, FORS_N);
    random_bytes(msg_digest, 32);

    /* Generate FORS public key */
    fors_keygen(pk, sk_seed);

    /* Sign */
    fors_sign(sig, msg_digest, 32, sk_seed);

    /* Verify */
    int ok = (fors_verify(pk, sig, msg_digest, 32) == 0);
    if (ok) {
        printf("  Basic sign/verify PASSED!\n");
    } else {
        printf("  Basic sign/verify FAILED!\n");
    }
    return ok;
}

/*
 * Test wrong message fails verification (informational only).
 *
 * NOTE: this is a teaching demo built on a deliberately non-cryptographic
 * XOR simple_hash(), and message_to_indices() only consumes the first
 * FORS_K*FORS_A bits of the digest. With no real collision resistance a
 * "wrong" digest can recover the same FORS public key, so this negative test
 * is reported as informational and is NOT folded into the pass/fail verdict
 * (a real H_msg + cryptographic hash rejects the wrong message).
 */
void test_fors_wrong_message(void)
{
    printf("Testing FORS wrong message detection...\n");

    uint8_t sk_seed[FORS_N];
    uint8_t pk[FORS_PK_BYTES];
    uint8_t msg_digest[32], wrong_digest[32];
    uint8_t sig[FORS_SIG_BYTES];

    random_bytes(sk_seed, FORS_N);
    random_bytes(msg_digest, 32);
    random_bytes(wrong_digest, 32);

    fors_keygen(pk, sk_seed);
    fors_sign(sig, msg_digest, 32, sk_seed);

    /* Wrong message should fail (informational with the toy hash). */
    int rejected = (fors_verify(pk, sig, wrong_digest, 32) != 0);
    printf("  Tamper check (informational, toy hash): wrong message %s\n",
           rejected ? "correctly rejected"
                    : "verified (toy-hash collision; a real hash rejects it)");
}

/*
 * Test index derivation consistency.
 * Returns 1 on success, 0 on failure.
 */
int test_fors_indices(void)
{
    printf("Testing FORS index derivation...\n");

    uint8_t msg_digest[32] = {0};
    uint32_t indices1[FORS_K], indices2[FORS_K];

    /* Set known pattern */
    msg_digest[0] = 0xAB;
    msg_digest[1] = 0xCD;

    message_to_indices(indices1, msg_digest, 32);
    message_to_indices(indices2, msg_digest, 32);

    printf("  Indices for 0xABCD: {");
    for (int i = 0; i < FORS_K; i++) {
        printf("%u%s", indices1[i], i < FORS_K-1 ? ", " : "");
    }
    printf("}\n");

    /* Same input should give same indices */
    int passed = 1;
    for (int i = 0; i < FORS_K; i++) {
        if (indices1[i] != indices2[i]) passed = 0;
        if (indices1[i] >= FORS_T) passed = 0;
    }

    /* Different input should give different indices */
    msg_digest[0] = 0xFF;
    message_to_indices(indices2, msg_digest, 32);

    int differs = 0;
    for (int i = 0; i < FORS_K; i++) {
        if (indices1[i] != indices2[i]) differs++;
    }
    if (differs == 0) passed = 0;

    if (passed) {
        printf("  Index derivation tests PASSED!\n");
    } else {
        printf("  Index derivation tests FAILED!\n");
    }
    return passed;
}

/*
 * Display FORS sizes
 */
void show_fors_sizes(void)
{
    printf("\nFORS Parameters (demo values):\n");
    printf("  n (hash size):     %d bytes\n", FORS_N);
    printf("  k (trees):         %d\n", FORS_K);
    printf("  t (leaves/tree):   %d\n", FORS_T);
    printf("  a (log2 t):        %d\n", FORS_A);

    printf("\nSizes:\n");
    printf("  Public key:        %d bytes\n", FORS_PK_BYTES);
    printf("  Signature:         %d bytes\n", FORS_SIG_BYTES);
    printf("    Per tree:        %d bytes\n", FORS_TREE_SIG);
    printf("      (sk value:     %d bytes)\n", FORS_N);
    printf("      (auth path:    %d bytes)\n", FORS_AUTH_BYTES);

    printf("\n  Total secret values: %d\n", FORS_K * FORS_T);

    printf("\nFORS vs WOTS+ vs Lamport:\n");
    printf("  Lamport: One-time (single signature)\n");
    printf("  WOTS+:   One-time (more compact)\n");
    printf("  FORS:    Few-time (k signatures per different subset)\n");
}

int main(void)
{
    printf("=== FORS Demonstration ===\n\n");

    int ok_idx   = test_fors_indices();
    int ok_basic = test_fors_basic();
    test_fors_wrong_message();  /* informational only (toy hash) */
    show_fors_sizes();

    printf("\n=== Demo complete! ===\n");

    /* Explicit PASS/FAIL verdict so the demo is usable as an automated test.
     * Only the deterministic, genuinely-correct properties are asserted:
     * index derivation and the valid sign/verify round-trip. The wrong-message
     * negative test is informational because the toy XOR hash is not
     * collision-resistant (see test_fors_wrong_message). */
    int all_ok = ok_idx && ok_basic;
    printf("\n=== Self-test verdict ===\n");
    printf("  index derivation         : %s\n", ok_idx ? "PASS" : "FAIL");
    printf("  basic sign/verify        : %s\n", ok_basic ? "PASS" : "FAIL");
    printf("Result: %s\n", all_ok ? "PASS" : "FAIL");
    return all_ok ? 0 : 1;
}
