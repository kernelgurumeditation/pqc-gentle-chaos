/*
 * Source: Module 7 - SLH-DSA (Hash-Based Digital Signatures)
 * Unit: 7.1 - Hash-Based Signature Foundations
 * Description: Lamport One-Time Signature Implementation
 *
 * Educational demonstration of hash-based signature fundamentals
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* Use 256-bit hash and message digest */
#define HASH_BYTES 32
#define MSG_BITS 256
#define SK_PAIRS (MSG_BITS * 2)  /* 2 values per bit */

/* Simple SHA-256 simulation (use real implementation in production) */
void sha256(uint8_t out[32], const uint8_t *in, size_t inlen) {
    /* Placeholder - use actual SHA-256 */
    uint32_t state = 0x6a09e667;
    for (size_t i = 0; i < inlen; i++) {
        state ^= (uint32_t)in[i] << ((i % 4) * 8);
        state = state * 1103515245 + 12345;
    }
    for (int i = 0; i < 32; i++) {
        state = state * 1103515245 + 12345;
        out[i] = (state >> 16) & 0xFF;
    }
}

/* Lamport key structures */
typedef struct {
    uint8_t sk0[MSG_BITS][HASH_BYTES];  /* Secret keys for bit=0 */
    uint8_t sk1[MSG_BITS][HASH_BYTES];  /* Secret keys for bit=1 */
} lamport_sk;

typedef struct {
    uint8_t pk0[MSG_BITS][HASH_BYTES];  /* Public keys for bit=0 */
    uint8_t pk1[MSG_BITS][HASH_BYTES];  /* Public keys for bit=1 */
} lamport_pk;

typedef struct {
    uint8_t sig[MSG_BITS][HASH_BYTES];  /* Revealed secret keys */
} lamport_sig;

/* Generate random bytes (use secure RNG in production) */
void random_bytes(uint8_t *out, size_t len) {
    for (size_t i = 0; i < len; i++) {
        out[i] = rand() & 0xFF;
    }
}

/* Key generation */
void lamport_keygen(lamport_pk *pk, lamport_sk *sk) {
    printf("Generating Lamport key pair...\n");

    for (int i = 0; i < MSG_BITS; i++) {
        /* Generate random secret keys */
        random_bytes(sk->sk0[i], HASH_BYTES);
        random_bytes(sk->sk1[i], HASH_BYTES);

        /* Compute public keys as hashes */
        sha256(pk->pk0[i], sk->sk0[i], HASH_BYTES);
        sha256(pk->pk1[i], sk->sk1[i], HASH_BYTES);
    }

    printf("  Secret key size: %zu bytes\n", sizeof(lamport_sk));
    printf("  Public key size: %zu bytes\n", sizeof(lamport_pk));
}

/* Get bit i from byte array */
int get_bit(const uint8_t *data, int i) {
    return (data[i / 8] >> (7 - (i % 8))) & 1;
}

/* Signing */
void lamport_sign(lamport_sig *sig, const uint8_t *msg, size_t msglen,
                  const lamport_sk *sk) {
    uint8_t digest[HASH_BYTES];

    /* Hash the message */
    sha256(digest, msg, msglen);

    printf("Signing message (digest bits shown)...\n");
    printf("  First 16 bits: ");
    for (int i = 0; i < 16; i++) {
        printf("%d", get_bit(digest, i));
    }
    printf("...\n");

    /* For each bit in digest, reveal corresponding secret key */
    for (int i = 0; i < MSG_BITS; i++) {
        int bit = get_bit(digest, i);
        if (bit == 0) {
            memcpy(sig->sig[i], sk->sk0[i], HASH_BYTES);
        } else {
            memcpy(sig->sig[i], sk->sk1[i], HASH_BYTES);
        }
    }

    printf("  Signature size: %zu bytes\n", sizeof(lamport_sig));
}

/* Verification */
int lamport_verify(const lamport_pk *pk, const uint8_t *msg, size_t msglen,
                   const lamport_sig *sig) {
    uint8_t digest[HASH_BYTES];
    uint8_t computed_hash[HASH_BYTES];

    /* Hash the message */
    sha256(digest, msg, msglen);

    printf("Verifying signature...\n");

    /* Check each revealed key against public key */
    for (int i = 0; i < MSG_BITS; i++) {
        int bit = get_bit(digest, i);

        /* Hash the revealed secret key */
        sha256(computed_hash, sig->sig[i], HASH_BYTES);

        /* Compare with appropriate public key */
        const uint8_t *expected = (bit == 0) ? pk->pk0[i] : pk->pk1[i];

        if (memcmp(computed_hash, expected, HASH_BYTES) != 0) {
            printf("  Verification FAILED at bit %d\n", i);
            return -1;
        }
    }

    printf("  All %d bits verified successfully\n", MSG_BITS);
    return 0;
}

/* Demonstrate one-time property violation */
void demonstrate_one_time_vulnerability(void) {
    lamport_pk pk;
    lamport_sk sk;
    lamport_sig sig1, sig2;

    printf("\n=== One-Time Vulnerability Demonstration ===\n\n");

    lamport_keygen(&pk, &sk);

    /* Sign two different messages */
    const char *msg1 = "First message";
    const char *msg2 = "Second message";

    printf("\nSigning first message: \"%s\"\n", msg1);
    lamport_sign(&sig1, (uint8_t *)msg1, strlen(msg1), &sk);

    printf("\nSigning second message: \"%s\"\n", msg2);
    lamport_sign(&sig2, (uint8_t *)msg2, strlen(msg2), &sk);

    /* Analyze what was revealed */
    uint8_t digest1[HASH_BYTES], digest2[HASH_BYTES];
    sha256(digest1, (uint8_t *)msg1, strlen(msg1));
    sha256(digest2, (uint8_t *)msg2, strlen(msg2));

    int both_revealed = 0;
    for (int i = 0; i < MSG_BITS; i++) {
        int bit1 = get_bit(digest1, i);
        int bit2 = get_bit(digest2, i);

        if (bit1 != bit2) {
            both_revealed++;
        }
    }

    printf("\n=== Security Analysis ===\n");
    printf("Bits where messages differ: %d / %d\n", both_revealed, MSG_BITS);
    printf("For these bits, BOTH sk0 and sk1 are now revealed!\n");
    printf("Attacker can forge signatures for 2^%d different messages\n", both_revealed);
    printf("\nThis is why Lamport signatures are ONE-TIME ONLY!\n");
}

/* Size comparison with other schemes */
void print_size_comparison(void) {
    printf("\n=== Signature Scheme Size Comparison ===\n\n");
    printf("%-20s %12s %12s %12s\n", "Scheme", "Public Key", "Secret Key", "Signature");
    printf("%-20s %12s %12s %12s\n", "------", "----------", "----------", "---------");
    printf("%-20s %12zu %12zu %12zu\n", "Lamport (256-bit)",
           sizeof(lamport_pk), sizeof(lamport_sk), sizeof(lamport_sig));
    printf("%-20s %12d %12d %12d\n", "ECDSA P-256", 64, 32, 64);
    printf("%-20s %12d %12d %12d\n", "ML-DSA-65", 1952, 4032, 3309);
    printf("%-20s %12d %12d %12d\n", "SLH-DSA-128f", 32, 64, 17088);
    printf("%-20s %12d %12d %12d\n", "SLH-DSA-128s", 32, 64, 7856);
}

int main(void) {
    printf("Lamport One-Time Signature Demonstration\n");
    printf("=========================================\n\n");

    srand(12345);  /* Reproducible for demo */

    /* Basic sign/verify */
    lamport_pk pk;
    lamport_sk sk;
    lamport_sig sig;

    lamport_keygen(&pk, &sk);

    const char *message = "Hello, hash-based signatures!";
    printf("\nMessage: \"%s\"\n\n", message);

    lamport_sign(&sig, (uint8_t *)message, strlen(message), &sk);

    int result = lamport_verify(&pk, (uint8_t *)message, strlen(message), &sig);
    printf("\nVerification result: %s\n", result == 0 ? "VALID" : "INVALID");

    /* Test with wrong message */
    printf("\nTesting with wrong message...\n");
    const char *wrong = "Wrong message";
    result = lamport_verify(&pk, (uint8_t *)wrong, strlen(wrong), &sig);
    printf("Wrong message result: %s (expected INVALID)\n",
           result == 0 ? "VALID" : "INVALID");

    /* Demonstrate vulnerability */
    demonstrate_one_time_vulnerability();

    /* Size comparison */
    print_size_comparison();

    return 0;
}
