#include <openssl/sha.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#define LAMPORT_N 256    // For SHA-256
#define HASH_LEN 32

typedef struct {
    uint8_t sk[2][LAMPORT_N][HASH_LEN];
    uint8_t pk[2][LAMPORT_N][HASH_LEN];
} lamport_keypair;

void lamport_keygen(lamport_keypair *kp) {
    for (int b = 0; b < 2; b++) {
        for (int i = 0; i < LAMPORT_N; i++) {
            // Generate random secret
            RAND_bytes(kp->sk[b][i], HASH_LEN);
            // Compute public key (hash of secret)
            SHA256(kp->sk[b][i], HASH_LEN, kp->pk[b][i]);
        }
    }
}

void lamport_sign(const lamport_keypair *kp,
                  const uint8_t msg_hash[HASH_LEN],
                  uint8_t sig[LAMPORT_N][HASH_LEN]) {
    for (int i = 0; i < LAMPORT_N; i++) {
        int bit = (msg_hash[i / 8] >> (7 - (i % 8))) & 1;
        memcpy(sig[i], kp->sk[bit][i], HASH_LEN);
    }
}

int lamport_verify(const lamport_keypair *kp,
                   const uint8_t msg_hash[HASH_LEN],
                   const uint8_t sig[LAMPORT_N][HASH_LEN]) {
    uint8_t computed[HASH_LEN];
    for (int i = 0; i < LAMPORT_N; i++) {
        int bit = (msg_hash[i / 8] >> (7 - (i % 8))) & 1;
        SHA256(sig[i], HASH_LEN, computed);
        if (memcmp(computed, kp->pk[bit][i], HASH_LEN) != 0) {
            return 0;  // Verification failed
        }
    }
    return 1;  // Success
}

int main(void) {
    lamport_keypair kp;
    uint8_t msg[] = "Hello, Lamport signatures!";
    uint8_t msg_hash[HASH_LEN];
    uint8_t signature[LAMPORT_N][HASH_LEN];

    printf("Generating Lamport keypair...\n");
    lamport_keygen(&kp);

    printf("Key sizes:\n");
    printf("  Secret key: %zu bytes\n", sizeof(kp.sk));
    printf("  Public key: %zu bytes\n", sizeof(kp.pk));

    // Hash the message
    SHA256(msg, strlen((char*)msg), msg_hash);

    // Sign
    lamport_sign(&kp, msg_hash, signature);
    printf("Signature size: %zu bytes\n", sizeof(signature));

    // Verify
    int valid = lamport_verify(&kp, msg_hash, signature);
    printf("Verification: %s\n", valid ? "PASS" : "FAIL");

    // Try to verify with wrong message
    msg[0] ^= 1;  // Flip a bit
    SHA256(msg, strlen((char*)msg), msg_hash);
    valid = lamport_verify(&kp, msg_hash, signature);
    printf("Wrong message verification: %s\n", valid ? "PASS (BAD!)" : "FAIL (expected)");

    return 0;
}
