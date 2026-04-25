#include <openssl/evp.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#define HASH_LEN 32
#define TREE_HEIGHT 4
#define NUM_LEAVES (1 << TREE_HEIGHT)

typedef struct {
    uint8_t leaves[NUM_LEAVES][HASH_LEN];   // Leaf hashes (WOTS public keys)
    uint8_t nodes[2 * NUM_LEAVES][HASH_LEN]; // All tree nodes
    uint8_t root[HASH_LEN];
} merkle_tree;

// Hash two nodes together
void hash_nodes(uint8_t out[HASH_LEN],
                const uint8_t left[HASH_LEN],
                const uint8_t right[HASH_LEN]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, left, HASH_LEN);
    EVP_DigestUpdate(ctx, right, HASH_LEN);
    EVP_DigestFinal_ex(ctx, out, NULL);
    EVP_MD_CTX_free(ctx);
}

// Build tree from leaves
void build_tree(merkle_tree *tree) {
    // Copy leaves to bottom level of nodes array
    int offset = NUM_LEAVES;
    for (int i = 0; i < NUM_LEAVES; i++) {
        memcpy(tree->nodes[offset + i], tree->leaves[i], HASH_LEN);
    }

    // Build internal nodes
    for (int level = TREE_HEIGHT - 1; level >= 0; level--) {
        int level_offset = 1 << level;
        int child_offset = 1 << (level + 1);
        for (int i = 0; i < (1 << level); i++) {
            hash_nodes(tree->nodes[level_offset + i],
                       tree->nodes[child_offset + 2*i],
                       tree->nodes[child_offset + 2*i + 1]);
        }
    }

    // Root is at index 1
    memcpy(tree->root, tree->nodes[1], HASH_LEN);
}

// Get authentication path for leaf
void get_auth_path(const merkle_tree *tree, int leaf_idx,
                   uint8_t path[TREE_HEIGHT][HASH_LEN]) {
    int idx = NUM_LEAVES + leaf_idx;
    for (int level = 0; level < TREE_HEIGHT; level++) {
        int sibling = idx ^ 1;  // XOR flips last bit to get sibling
        memcpy(path[level], tree->nodes[sibling], HASH_LEN);
        idx /= 2;
    }
}

// Verify authentication path
int verify_auth_path(const uint8_t root[HASH_LEN],
                     const uint8_t leaf[HASH_LEN],
                     int leaf_idx,
                     const uint8_t path[TREE_HEIGHT][HASH_LEN]) {
    uint8_t current[HASH_LEN];
    memcpy(current, leaf, HASH_LEN);

    for (int level = 0; level < TREE_HEIGHT; level++) {
        uint8_t next[HASH_LEN];
        if ((leaf_idx >> level) & 1) {
            // Current is right child
            hash_nodes(next, path[level], current);
        } else {
            // Current is left child
            hash_nodes(next, current, path[level]);
        }
        memcpy(current, next, HASH_LEN);
    }

    return memcmp(current, root, HASH_LEN) == 0;
}

int main(void) {
    merkle_tree tree;

    // Initialize leaves with random data (would be WOTS public keys)
    printf("Initializing %d leaves...\n", NUM_LEAVES);
    for (int i = 0; i < NUM_LEAVES; i++) {
        uint8_t data[4] = {i, i+1, i+2, i+3};
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
        EVP_DigestUpdate(ctx, data, 4);
        EVP_DigestFinal_ex(ctx, tree.leaves[i], NULL);
        EVP_MD_CTX_free(ctx);
    }

    // Build tree
    build_tree(&tree);
    printf("Tree built. Root: ");
    for (int i = 0; i < 8; i++) printf("%02x", tree.root[i]);
    printf("...\n");

    // Test authentication path for leaf 5
    int test_leaf = 5;
    uint8_t auth_path[TREE_HEIGHT][HASH_LEN];
    get_auth_path(&tree, test_leaf, auth_path);

    printf("Testing auth path for leaf %d...\n", test_leaf);
    int valid = verify_auth_path(tree.root, tree.leaves[test_leaf],
                                  test_leaf, auth_path);
    printf("Verification: %s\n", valid ? "PASS" : "FAIL");

    // Test with wrong leaf
    printf("Testing with wrong leaf...\n");
    valid = verify_auth_path(tree.root, tree.leaves[0],  // Wrong leaf!
                              test_leaf, auth_path);
    printf("Wrong leaf verification: %s\n",
           valid ? "PASS (BAD!)" : "FAIL (expected)");

    return 0;
}
