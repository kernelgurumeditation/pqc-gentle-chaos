/*
 * Source: Module 7 - SLH-DSA (Hash-Based Digital Signatures)
 * Unit: 7.3 - WOTS+ (Winternitz One-Time Signature Plus)
 * Description: Demonstrate WOTS+ key recovery attack from two signatures
 *
 * This shows why WOTS+ keys must NEVER be reused!
 * This is a standalone educational demonstration.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

/* Simplified WOTS+ parameters for demo */
#define WOTS_N       16        /* Hash output size (reduced for demo) */
#define WOTS_W       16        /* Winternitz parameter */
#define WOTS_LOG_W   4         /* log2(w) */
#define WOTS_LEN1    4         /* Message chunks (reduced for demo) */
#define WOTS_LEN2    2         /* Checksum chunks */
#define WOTS_LEN     (WOTS_LEN1 + WOTS_LEN2)

/* Simple hash for demo */
static void simple_hash(uint8_t out[WOTS_N], const uint8_t *in, size_t len)
{
    memset(out, 0, WOTS_N);
    for (size_t i = 0; i < len; i++) {
        out[i % WOTS_N] ^= in[i];
        out[(i + 1) % WOTS_N] ^= (in[i] << 4) | (in[i] >> 4);
    }
    for (int r = 0; r < 4; r++) {
        for (int i = 0; i < WOTS_N; i++) {
            out[i] ^= out[(i + 5) % WOTS_N];
        }
    }
}

/* Chain function: Apply hash from position start for steps iterations */
static void chain(uint8_t out[WOTS_N], const uint8_t in[WOTS_N],
                  int start, int steps, const uint8_t pub_seed[WOTS_N])
{
    uint8_t temp[WOTS_N * 2];

    memcpy(out, in, WOTS_N);
    for (int i = start; i < start + steps; i++) {
        memcpy(temp, pub_seed, WOTS_N);
        memcpy(temp + WOTS_N, out, WOTS_N);
        temp[0] ^= (i & 0xFF);
        simple_hash(out, temp, WOTS_N * 2);
    }
}

/* PRF: Derive value from seed and index */
static void prf(uint8_t out[WOTS_N], const uint8_t seed[WOTS_N], int idx)
{
    uint8_t input[WOTS_N + 4];
    memcpy(input, seed, WOTS_N);
    input[WOTS_N] = (idx >> 24) & 0xFF;
    input[WOTS_N + 1] = (idx >> 16) & 0xFF;
    input[WOTS_N + 2] = (idx >> 8) & 0xFF;
    input[WOTS_N + 3] = idx & 0xFF;
    simple_hash(out, input, WOTS_N + 4);
}

/* Convert message to base-w indices (educational reference, not used in this demo) */
__attribute__((unused))
static void msg_to_base_w(uint32_t *out, const uint8_t *msg, int out_len)
{
    int bits = 0;
    uint32_t total = 0;
    int in_idx = 0;

    for (int i = 0; i < out_len; i++) {
        while (bits < WOTS_LOG_W) {
            total = (total << 8) | msg[in_idx++];
            bits += 8;
        }
        bits -= WOTS_LOG_W;
        out[i] = (total >> bits) & (WOTS_W - 1);
    }
}

/* Compute checksum (educational reference, not used in this demo) */
__attribute__((unused))
static uint32_t compute_checksum(const uint32_t *chunks, int len)
{
    uint32_t sum = 0;
    for (int i = 0; i < len; i++) {
        sum += (WOTS_W - 1) - chunks[i];
    }
    return sum;
}

void demonstrate_key_reuse_attack(void)
{
    uint8_t sk_seed[WOTS_N], pub_seed[WOTS_N];

    printf("=== WOTS+ Key Reuse Attack Demo ===\n\n");

    /* Initialize seeds */
    memset(sk_seed, 0x42, WOTS_N);
    memset(pub_seed, 0xAB, WOTS_N);

    /* Generate secret chain starting values */
    uint8_t sk_chains[WOTS_LEN][WOTS_N];
    for (int i = 0; i < WOTS_LEN; i++) {
        prf(sk_chains[i], sk_seed, i);
    }

    printf("Setup: WOTS+ key with %d chains, each of length %d\n\n", WOTS_LEN, WOTS_W);

    /* Message 1: simulated base-w representation */
    uint32_t msg1_chunks[WOTS_LEN] = {3, 7, 2, 5, 8, 4};  /* Chain positions */
    printf("Message 1 chain positions: {");
    for (int i = 0; i < WOTS_LEN; i++) {
        printf("%u%s", msg1_chunks[i], i < WOTS_LEN-1 ? ", " : "");
    }
    printf("}\n");

    /* Message 2: different base-w representation */
    uint32_t msg2_chunks[WOTS_LEN] = {7, 3, 9, 1, 6, 10};
    printf("Message 2 chain positions: {");
    for (int i = 0; i < WOTS_LEN; i++) {
        printf("%u%s", msg2_chunks[i], i < WOTS_LEN-1 ? ", " : "");
    }
    printf("}\n\n");

    /* Generate "signatures" (chain values at each position) */
    uint8_t sig1[WOTS_LEN][WOTS_N];
    uint8_t sig2[WOTS_LEN][WOTS_N];

    printf("Generating signature 1 (DANGEROUS - first use of key)...\n");
    for (int i = 0; i < WOTS_LEN; i++) {
        chain(sig1[i], sk_chains[i], 0, msg1_chunks[i], pub_seed);
    }

    printf("Generating signature 2 (DANGEROUS - key reuse!)...\n\n");
    for (int i = 0; i < WOTS_LEN; i++) {
        chain(sig2[i], sk_chains[i], 0, msg2_chunks[i], pub_seed);
    }

    /* Now demonstrate the attack */
    printf("=== ATTACK: Forging a Third Signature ===\n\n");

    /* Target message with positions between the known ones */
    uint32_t target_chunks[WOTS_LEN] = {5, 5, 8, 3, 7, 7};
    printf("Target message positions: {");
    for (int i = 0; i < WOTS_LEN; i++) {
        printf("%u%s", target_chunks[i], i < WOTS_LEN-1 ? ", " : "");
    }
    printf("}\n\n");

    printf("Chain-by-chain forgery analysis:\n");

    uint8_t forged_sig[WOTS_LEN][WOTS_N];
    int can_forge = 1;

    for (int i = 0; i < WOTS_LEN; i++) {
        uint32_t t = target_chunks[i];
        uint32_t p1 = msg1_chunks[i];
        uint32_t p2 = msg2_chunks[i];

        printf("  Chain %d: need position %u, have positions %u and %u\n",
               i, t, p1, p2);

        if (t >= p1 && t >= p2) {
            /* Can compute from the lower signature */
            if (p1 <= p2) {
                printf("    -> Forge from sig1: chain forward %u steps\n", t - p1);
                chain(forged_sig[i], sig1[i], p1, t - p1, pub_seed);
            } else {
                printf("    -> Forge from sig2: chain forward %u steps\n", t - p2);
                chain(forged_sig[i], sig2[i], p2, t - p2, pub_seed);
            }
        } else if (t >= p1) {
            printf("    -> Forge from sig1: chain forward %u steps\n", t - p1);
            chain(forged_sig[i], sig1[i], p1, t - p1, pub_seed);
        } else if (t >= p2) {
            printf("    -> Forge from sig2: chain forward %u steps\n", t - p2);
            chain(forged_sig[i], sig2[i], p2, t - p2, pub_seed);
        } else {
            printf("    -> BLOCKED: need position %u but lowest known is %u\n",
                   t, (p1 < p2) ? p1 : p2);
            can_forge = 0;
        }
    }

    printf("\n=== Attack Result ===\n");
    if (can_forge) {
        printf("FORGERY SUCCESSFUL!\n");
        printf("Attacker created valid signature for new message.\n");
    } else {
        printf("Forgery blocked for THIS message.\n");
        printf("But attacker can still forge many other messages.\n");
    }

    printf("\n=== Security Analysis ===\n\n");
    printf("Key insight from the attack:\n");
    printf("  - Signature reveals chain value at position m_i\n");
    printf("  - Attacker can hash FORWARD (increase position)\n");
    printf("  - Attacker CANNOT hash backward (would need preimage)\n\n");

    printf("With ONE signature:\n");
    printf("  - For each chain, attacker knows position m_i\n");
    printf("  - Can forge any message where m'_i >= m_i for all i\n\n");

    printf("With TWO signatures on different messages:\n");
    printf("  - For each chain, attacker knows min(m1_i, m2_i)\n");
    printf("  - Forgery space grows significantly\n\n");

    printf("With multiple signatures:\n");
    printf("  - Eventually know position 0 for each chain\n");
    printf("  - Complete key recovery: can forge ANY message!\n\n");

    printf("Conclusion: WOTS+ is ONE-TIME ONLY!\n");
    printf("This is why SLH-DSA uses a hypertree of WOTS+ keys,\n");
    printf("each used exactly once to sign the layer below.\n");
}

int main(void)
{
    demonstrate_key_reuse_attack();
    return 0;
}
