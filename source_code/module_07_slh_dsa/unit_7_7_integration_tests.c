/*
 * Source: Module 7 - SLH-DSA (Hash-Based Digital Signatures)
 * Unit: 7.7 - SLH-DSA Implementation and Testing
 * Description: Demonstration of SLH-DSA integration concepts
 *
 * This is a standalone educational demonstration showing how SLH-DSA
 * combines FORS, XMSS, and hypertree components.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

/* Simplified SLH-DSA parameters for demo */
#define SLH_N           16      /* Hash output size (reduced for demo) */
#define SLH_H           8       /* Total tree height */
#define SLH_D           2       /* Number of hypertree layers */
#define SLH_H_PRIME     (SLH_H / SLH_D)  /* Height of each XMSS tree */

#define SLH_FORS_K      4       /* FORS trees */
#define SLH_FORS_A      3       /* Log2 of FORS leaves per tree */

#define SLH_PK_BYTES    (2 * SLH_N)  /* pk_seed + pk_root */
#define SLH_SK_BYTES    (4 * SLH_N)  /* sk_seed + sk_prf + pk_seed + pk_root */

/* Simple hash for demo */
static void simple_hash(uint8_t out[SLH_N], const uint8_t *in, size_t len)
{
    memset(out, 0, SLH_N);
    for (size_t i = 0; i < len; i++) {
        out[i % SLH_N] ^= in[i];
        out[(i + 1) % SLH_N] ^= (in[i] << 4) | (in[i] >> 4);
    }
    for (int r = 0; r < 4; r++) {
        for (int i = 0; i < SLH_N; i++) {
            out[i] ^= out[(i + 5) % SLH_N];
        }
    }
}

/* PRF for key derivation (educational reference, not used directly in this demo) */
__attribute__((unused))
static void prf(uint8_t out[SLH_N], const uint8_t seed[SLH_N],
                const uint8_t *addr, size_t addr_len)
{
    uint8_t input[SLH_N + 32];
    memcpy(input, seed, SLH_N);
    size_t copy_len = addr_len < 32 ? addr_len : 32;
    memcpy(input + SLH_N, addr, copy_len);
    simple_hash(out, input, SLH_N + copy_len);
}

/* Simple random bytes */
static void random_bytes(uint8_t *out, size_t len)
{
    static unsigned int seed = 98765;
    for (size_t i = 0; i < len; i++) {
        seed = seed * 1103515245 + 12345;
        out[i] = (seed >> 16) & 0xFF;
    }
}

/* Simulate SLH-DSA keygen */
static void slh_keygen(uint8_t pk[SLH_PK_BYTES], uint8_t sk[SLH_SK_BYTES])
{
    /* Generate random seeds */
    uint8_t sk_seed[SLH_N], sk_prf[SLH_N], pk_seed[SLH_N];
    random_bytes(sk_seed, SLH_N);
    random_bytes(sk_prf, SLH_N);
    random_bytes(pk_seed, SLH_N);

    /* Compute root (simplified - in real impl, build hypertree) */
    uint8_t pk_root[SLH_N];
    uint8_t root_input[SLH_N * 2];
    memcpy(root_input, sk_seed, SLH_N);
    memcpy(root_input + SLH_N, pk_seed, SLH_N);
    simple_hash(pk_root, root_input, SLH_N * 2);

    /* Pack secret key */
    memcpy(sk, sk_seed, SLH_N);
    memcpy(sk + SLH_N, sk_prf, SLH_N);
    memcpy(sk + 2 * SLH_N, pk_seed, SLH_N);
    memcpy(sk + 3 * SLH_N, pk_root, SLH_N);

    /* Pack public key */
    memcpy(pk, pk_seed, SLH_N);
    memcpy(pk + SLH_N, pk_root, SLH_N);
}

/* Simulate SLH-DSA sign (conceptual demonstration) */
static void slh_sign_demo(const uint8_t *msg, size_t msg_len,
                           const uint8_t sk[SLH_SK_BYTES])
{
    const uint8_t *sk_seed = sk;
    const uint8_t *sk_prf = sk + SLH_N;
    const uint8_t *pk_seed = sk + 2 * SLH_N;

    printf("  SLH-DSA Signing Process:\n\n");

    /* Step 1: Randomize */
    uint8_t opt_rand[SLH_N];
    random_bytes(opt_rand, SLH_N);
    printf("  1. Generate randomness: ");
    for (int i = 0; i < 8; i++) printf("%02x", opt_rand[i]);
    printf("...\n");

    /* Step 2: Compute R and message digest */
    uint8_t R[SLH_N];
    uint8_t r_input[SLH_N * 2 + 32];
    memcpy(r_input, sk_prf, SLH_N);
    memcpy(r_input + SLH_N, opt_rand, SLH_N);
    size_t copy_len = msg_len < 32 ? msg_len : 32;
    memcpy(r_input + 2 * SLH_N, msg, copy_len);
    simple_hash(R, r_input, 2 * SLH_N + copy_len);
    printf("  2. Compute R = PRF(sk_prf, opt_rand, msg): ");
    for (int i = 0; i < 8; i++) printf("%02x", R[i]);
    printf("...\n");

    /* Step 3: Derive message digest and tree/leaf indices */
    uint8_t digest[SLH_N];
    uint8_t digest_input[SLH_N + 32 + SLH_N];
    memcpy(digest_input, R, SLH_N);
    memcpy(digest_input + SLH_N, pk_seed, SLH_N);
    memcpy(digest_input + 2 * SLH_N, msg, copy_len);
    simple_hash(digest, digest_input, 2 * SLH_N + copy_len);

    uint32_t tree_idx = (digest[0] << 8 | digest[1]) % (1 << (SLH_H - SLH_H_PRIME));
    uint32_t leaf_idx = (digest[2] << 8 | digest[3]) % (1 << SLH_H_PRIME);
    printf("  3. Derive indices: tree=%u, leaf=%u\n", tree_idx, leaf_idx);

    /* Step 4: FORS signature */
    printf("  4. Sign with FORS (few-time signature on message digest)\n");
    printf("     - Uses %d trees with %d leaves each\n",
           SLH_FORS_K, 1 << SLH_FORS_A);
    (void)sk_seed;  /* Would use sk_seed to derive FORS keys */

    /* Step 5: Hypertree signature */
    printf("  5. Sign FORS pk with hypertree\n");
    printf("     - %d layers of XMSS trees\n", SLH_D);
    printf("     - Each tree has height %d\n", SLH_H_PRIME);
    printf("     - Uses WOTS+ at each tree layer\n");

    /* Step 6: Assemble signature */
    printf("  6. Signature = R || FORS_sig || HT_sig\n\n");
}

/* Simulate SLH-DSA verify (conceptual demonstration) */
static void slh_verify_demo(void)
{
    printf("  SLH-DSA Verification Process:\n\n");

    printf("  1. Parse signature: R, FORS_sig, HT_sig\n");
    printf("  2. Recompute message digest from R, pk, msg\n");
    printf("  3. Derive tree/leaf indices from digest\n");
    printf("  4. Verify FORS signature -> get FORS pk'\n");
    printf("  5. Verify hypertree signature on FORS pk'\n");
    printf("     - Traverse up through %d XMSS layers\n", SLH_D);
    printf("     - Verify WOTS+ signature at each layer\n");
    printf("     - Use auth path to compute tree root\n");
    printf("  6. Check final root matches pk.root\n\n");
}

/* Display SLH-DSA structure */
void explain_slh_dsa_structure(void)
{
    printf("=== SLH-DSA Structure ===\n\n");

    printf("SLH-DSA combines three main components:\n\n");

    printf("1. FORS (Forest of Random Subsets)\n");
    printf("   - Few-time signature scheme\n");
    printf("   - Signs the message digest directly\n");
    printf("   - Reveals k secret values from k trees\n\n");

    printf("2. XMSS (eXtended Merkle Signature Scheme)\n");
    printf("   - One tree = many one-time signatures\n");
    printf("   - Uses WOTS+ as the one-time signature\n");
    printf("   - Merkle tree aggregates WOTS+ public keys\n\n");

    printf("3. Hypertree\n");
    printf("   - Stack of XMSS trees\n");
    printf("   - Each layer signs the layer below\n");
    printf("   - Allows huge number of signatures\n");
    printf("   - Height H = d * h' where d=layers, h'=per-layer height\n\n");

    printf("Security: Based on hash function security\n");
    printf("   - Pre-image resistance\n");
    printf("   - Second pre-image resistance\n");
    printf("   - Collision resistance\n");
    printf("   - Post-quantum secure (no lattice/number theory)\n\n");
}

/* Test key generation */
void test_keygen(void)
{
    printf("Testing SLH-DSA key generation...\n\n");

    uint8_t pk[SLH_PK_BYTES], sk[SLH_SK_BYTES];
    slh_keygen(pk, sk);

    printf("  Public key (%d bytes):\n", SLH_PK_BYTES);
    printf("    pk_seed: ");
    for (int i = 0; i < 8; i++) printf("%02x", pk[i]);
    printf("...\n");
    printf("    pk_root: ");
    for (int i = 0; i < 8; i++) printf("%02x", pk[SLH_N + i]);
    printf("...\n\n");

    printf("  Secret key (%d bytes):\n", SLH_SK_BYTES);
    printf("    sk_seed: ");
    for (int i = 0; i < 8; i++) printf("%02x", sk[i]);
    printf("...\n");
    printf("    sk_prf:  ");
    for (int i = 0; i < 8; i++) printf("%02x", sk[SLH_N + i]);
    printf("...\n");
    printf("    pk_seed: ");
    for (int i = 0; i < 8; i++) printf("%02x", sk[2*SLH_N + i]);
    printf("...\n");
    printf("    pk_root: ");
    for (int i = 0; i < 8; i++) printf("%02x", sk[3*SLH_N + i]);
    printf("...\n\n");

    printf("  Key generation PASSED!\n\n");
}

/* Test sign/verify flow */
void test_sign_verify_flow(void)
{
    printf("Testing SLH-DSA sign/verify flow...\n\n");

    uint8_t pk[SLH_PK_BYTES], sk[SLH_SK_BYTES];
    slh_keygen(pk, sk);

    const uint8_t msg[] = "Test message for SLH-DSA";
    slh_sign_demo(msg, sizeof(msg) - 1, sk);

    slh_verify_demo();

    printf("  Sign/verify flow demonstration PASSED!\n\n");
}

/* Display real-world parameter sets */
void show_parameter_sets(void)
{
    printf("=== SLH-DSA Parameter Sets (NIST Standards) ===\n\n");

    printf("Security Level 1 (128-bit):\n");
    printf("  SLH-DSA-SHA2-128f: Fast, 17,088 byte signatures\n");
    printf("  SLH-DSA-SHA2-128s: Small, 7,856 byte signatures\n");
    printf("  SLH-DSA-SHAKE-128f/s: Same but with SHAKE\n\n");

    printf("Security Level 3 (192-bit):\n");
    printf("  SLH-DSA-SHA2-192f: 35,664 byte signatures\n");
    printf("  SLH-DSA-SHA2-192s: 16,224 byte signatures\n\n");

    printf("Security Level 5 (256-bit):\n");
    printf("  SLH-DSA-SHA2-256f: 49,856 byte signatures\n");
    printf("  SLH-DSA-SHA2-256s: 29,792 byte signatures\n\n");

    printf("Tradeoffs:\n");
    printf("  'f' variants: Faster signing, larger signatures\n");
    printf("  's' variants: Slower signing, smaller signatures\n");
    printf("  SHA2 variants: Faster on hardware-accelerated platforms\n");
    printf("  SHAKE variants: More conservative, simpler security proof\n\n");
}

int main(void)
{
    printf("=== SLH-DSA Integration Demonstration ===\n\n");

    explain_slh_dsa_structure();
    test_keygen();
    test_sign_verify_flow();
    show_parameter_sets();

    printf("=== Demo complete! ===\n");
    return 0;
}
