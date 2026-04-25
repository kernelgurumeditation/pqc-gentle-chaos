/*
 * Source: Module 7 - SLH-DSA (Hash-Based Digital Signatures)
 * Unit: 7.2 - Merkle Trees and One-Time Signatures
 * Description: Demonstration of Merkle tree concepts
 *
 * This is a standalone educational demonstration showing Merkle tree
 * construction and authentication path concepts.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#define HASH_BYTES 32
#define MAX_HEIGHT 10

/* Simple hash function for demonstration (not cryptographic!) */
static void simple_hash(uint8_t out[HASH_BYTES], const uint8_t *in, size_t len)
{
    /* Simple XOR-based hash for demo only */
    memset(out, 0, HASH_BYTES);
    for (size_t i = 0; i < len; i++) {
        out[i % HASH_BYTES] ^= in[i];
        out[(i + 1) % HASH_BYTES] ^= (in[i] << 4) | (in[i] >> 4);
    }
    /* Mix */
    for (int r = 0; r < 4; r++) {
        for (int i = 0; i < HASH_BYTES; i++) {
            out[i] ^= out[(i + 7) % HASH_BYTES];
        }
    }
}

/* Hash two nodes together */
static void hash_nodes(uint8_t out[HASH_BYTES],
                       const uint8_t left[HASH_BYTES],
                       const uint8_t right[HASH_BYTES])
{
    uint8_t combined[2 * HASH_BYTES];
    memcpy(combined, left, HASH_BYTES);
    memcpy(combined + HASH_BYTES, right, HASH_BYTES);
    simple_hash(out, combined, 2 * HASH_BYTES);
}

/* Merkle tree structure */
typedef struct {
    uint32_t height;
    uint32_t num_leaves;
    uint8_t **nodes;  /* Array of node hashes at each level */
} merkle_tree_t;

/* Initialize tree */
static int merkle_tree_init(merkle_tree_t *tree, uint32_t height)
{
    tree->height = height;
    tree->num_leaves = 1u << height;
    tree->nodes = malloc((height + 1) * sizeof(uint8_t *));
    if (!tree->nodes) {
        fprintf(stderr, "Memory allocation failed for tree nodes array\n");
        return -1;
    }

    for (uint32_t level = 0; level <= height; level++) {
        uint32_t nodes_at_level = 1u << (height - level);
        tree->nodes[level] = calloc(nodes_at_level, HASH_BYTES);
        if (!tree->nodes[level]) {
            fprintf(stderr, "Memory allocation failed for level %u\n", level);
            /* Free previously allocated levels */
            for (uint32_t j = 0; j < level; j++) {
                free(tree->nodes[j]);
            }
            free(tree->nodes);
            tree->nodes = NULL;
            return -1;
        }
    }
    return 0;
}

/* Set leaf value */
static void merkle_tree_set_leaf(merkle_tree_t *tree, uint32_t index,
                                  const uint8_t *data, size_t len)
{
    simple_hash(&tree->nodes[0][index * HASH_BYTES], data, len);
}

/* Build tree from leaves */
static void merkle_tree_build(merkle_tree_t *tree)
{
    for (uint32_t level = 0; level < tree->height; level++) {
        uint32_t nodes_at_level = 1u << (tree->height - level);
        for (uint32_t i = 0; i < nodes_at_level; i += 2) {
            hash_nodes(&tree->nodes[level + 1][(i/2) * HASH_BYTES],
                      &tree->nodes[level][i * HASH_BYTES],
                      &tree->nodes[level][(i + 1) * HASH_BYTES]);
        }
    }
}

/* Get root */
static uint8_t *merkle_tree_root(merkle_tree_t *tree)
{
    return tree->nodes[tree->height];
}

/* Get authentication path for leaf at index */
static void merkle_tree_auth_path(merkle_tree_t *tree, uint32_t index,
                                   uint8_t path[][HASH_BYTES])
{
    for (uint32_t level = 0; level < tree->height; level++) {
        uint32_t sibling_idx = index ^ 1;  /* Flip lowest bit */
        memcpy(path[level], &tree->nodes[level][sibling_idx * HASH_BYTES],
               HASH_BYTES);
        index >>= 1;  /* Move to parent */
    }
}

/* Verify authentication path */
static int merkle_verify_path(const uint8_t root[HASH_BYTES], uint32_t index,
                               const uint8_t leaf[HASH_BYTES],
                               uint8_t path[][HASH_BYTES], uint32_t height)
{
    uint8_t current[HASH_BYTES];
    memcpy(current, leaf, HASH_BYTES);

    for (uint32_t level = 0; level < height; level++) {
        uint8_t combined[2 * HASH_BYTES];
        if (index & 1) {
            /* Current is right child */
            memcpy(combined, path[level], HASH_BYTES);
            memcpy(combined + HASH_BYTES, current, HASH_BYTES);
        } else {
            /* Current is left child */
            memcpy(combined, current, HASH_BYTES);
            memcpy(combined + HASH_BYTES, path[level], HASH_BYTES);
        }
        simple_hash(current, combined, 2 * HASH_BYTES);
        index >>= 1;
    }

    return memcmp(current, root, HASH_BYTES);
}

/* Free tree */
static void merkle_tree_free(merkle_tree_t *tree)
{
    for (uint32_t level = 0; level <= tree->height; level++) {
        free(tree->nodes[level]);
    }
    free(tree->nodes);
}

/* Print hash in hex (first 8 bytes) */
static void print_hash(const uint8_t *hash)
{
    for (int i = 0; i < 8; i++) {
        printf("%02x", hash[i]);
    }
    printf("...");
}

/*
 * Test basic Merkle tree construction and authentication
 */
void test_merkle_tree(void)
{
    printf("Testing Merkle tree construction...\n");

    merkle_tree_t tree;
    if (merkle_tree_init(&tree, 3) != 0) {  /* Height 3 = 8 leaves */
        printf("  FAILED: Could not initialize tree\n");
        return;
    }

    /* Set leaves with dummy data */
    uint8_t leaf_data[HASH_BYTES];
    for (uint32_t i = 0; i < 8; i++) {
        memset(leaf_data, i, HASH_BYTES);
        merkle_tree_set_leaf(&tree, i, leaf_data, HASH_BYTES);
    }

    /* Build tree */
    merkle_tree_build(&tree);

    printf("  Root: ");
    print_hash(merkle_tree_root(&tree));
    printf("\n");

    /* Test authentication paths for each leaf */
    uint8_t auth_path[MAX_HEIGHT][HASH_BYTES];
    int passed = 1;

    for (uint32_t i = 0; i < 8; i++) {
        merkle_tree_auth_path(&tree, i, auth_path);

        /* Recompute leaf hash */
        uint8_t leaf_hash[HASH_BYTES];
        memset(leaf_data, i, HASH_BYTES);
        simple_hash(leaf_hash, leaf_data, HASH_BYTES);

        /* Verify path */
        int result = merkle_verify_path(merkle_tree_root(&tree), i,
                                         leaf_hash, auth_path, 3);
        if (result != 0) {
            printf("  FAILED: Leaf %u path verification failed\n", i);
            passed = 0;
        }
    }

    /* Test that wrong leaf doesn't verify */
    merkle_tree_auth_path(&tree, 0, auth_path);

    uint8_t wrong_leaf[HASH_BYTES];
    memset(wrong_leaf, 0xFF, HASH_BYTES);  /* Wrong data */

    int result = merkle_verify_path(merkle_tree_root(&tree), 0,
                                     wrong_leaf, auth_path, 3);
    if (result == 0) {
        printf("  FAILED: Wrong leaf should not verify\n");
        passed = 0;
    }

    merkle_tree_free(&tree);

    if (passed) {
        printf("  Merkle tree tests PASSED!\n");
    }
}

/*
 * Test authentication path bit manipulation
 */
void test_auth_path_indices(void)
{
    printf("Testing authentication path index computation...\n");

    merkle_tree_t tree;
    if (merkle_tree_init(&tree, 4) != 0) {  /* Height 4 = 16 leaves */
        printf("  FAILED: Could not initialize tree\n");
        return;
    }

    /* Fill with identifiable data */
    for (uint32_t i = 0; i < 16; i++) {
        uint8_t data[HASH_BYTES] = {0};
        data[0] = i;
        merkle_tree_set_leaf(&tree, i, data, HASH_BYTES);
    }
    merkle_tree_build(&tree);

    /* Test index 5 (binary 0101) */
    printf("  Testing leaf 5 (binary 0101):\n");
    printf("    Level 0: sibling is 4 (0100)\n");
    printf("    Level 1: sibling covers leaves 6-7\n");
    printf("    Level 2: sibling covers leaves 0-3\n");
    printf("    Level 3: sibling covers leaves 8-15\n");

    uint8_t auth_path[MAX_HEIGHT][HASH_BYTES];
    merkle_tree_auth_path(&tree, 5, auth_path);

    /* Verify the path is correct by recomputing root */
    uint8_t leaf_data[HASH_BYTES] = {0};
    leaf_data[0] = 5;
    uint8_t leaf_hash[HASH_BYTES];
    simple_hash(leaf_hash, leaf_data, HASH_BYTES);

    int result = merkle_verify_path(merkle_tree_root(&tree), 5,
                                     leaf_hash, auth_path, 4);
    if (result == 0) {
        printf("  Authentication path index tests PASSED!\n");
    } else {
        printf("  FAILED: Path verification failed\n");
    }

    merkle_tree_free(&tree);
}

/*
 * Demonstrate one-time signature concept
 */
void demo_ots_concept(void)
{
    printf("\nDemonstrating OTS + Merkle concept...\n");

    printf("  In a real MSS (Merkle Signature Scheme):\n");
    printf("    1. Generate N OTS key pairs\n");
    printf("    2. Build Merkle tree from OTS public keys\n");
    printf("    3. Public key = Merkle root\n");
    printf("    4. To sign: use next unused OTS key + auth path\n");
    printf("    5. To verify: verify OTS sig, recompute path to root\n");
    printf("\n");
    printf("  Key insight: Each OTS key can only be used ONCE\n");
    printf("  The Merkle tree allows compact verification of many OTS keys\n");
    printf("\n");
    printf("  Tree of height h allows 2^h signatures\n");
    printf("    h=20 -> ~1 million signatures\n");
    printf("    h=10 -> 1024 signatures\n");
}

int main(void)
{
    printf("=== Merkle Signature Scheme Demonstration ===\n\n");

    test_merkle_tree();
    test_auth_path_indices();
    demo_ots_concept();

    printf("\n=== Demo complete! ===\n");
    return 0;
}
