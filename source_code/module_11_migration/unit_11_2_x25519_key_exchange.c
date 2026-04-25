#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>

void print_hex(const char *label, const unsigned char *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
}

int main(void) {
    // Alice generates keypair
    EVP_PKEY_CTX *alice_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY_keygen_init(alice_ctx);
    EVP_PKEY *alice_key = NULL;
    EVP_PKEY_keygen(alice_ctx, &alice_key);

    // Bob generates keypair
    EVP_PKEY_CTX *bob_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY_keygen_init(bob_ctx);
    EVP_PKEY *bob_key = NULL;
    EVP_PKEY_keygen(bob_ctx, &bob_key);

    // Extract public keys
    unsigned char alice_pub[32], bob_pub[32];
    size_t len = 32;
    EVP_PKEY_get_raw_public_key(alice_key, alice_pub, &len);
    EVP_PKEY_get_raw_public_key(bob_key, bob_pub, &len);

    print_hex("Alice public", alice_pub, 32);
    print_hex("Bob public  ", bob_pub, 32);

    // Alice computes shared secret using Bob's public key
    EVP_PKEY_CTX *alice_derive = EVP_PKEY_CTX_new(alice_key, NULL);
    EVP_PKEY_derive_init(alice_derive);
    EVP_PKEY_derive_set_peer(alice_derive, bob_key);
    unsigned char alice_shared[32];
    size_t alice_shared_len = 32;
    EVP_PKEY_derive(alice_derive, alice_shared, &alice_shared_len);

    // Bob computes shared secret using Alice's public key
    EVP_PKEY_CTX *bob_derive = EVP_PKEY_CTX_new(bob_key, NULL);
    EVP_PKEY_derive_init(bob_derive);
    EVP_PKEY_derive_set_peer(bob_derive, alice_key);
    unsigned char bob_shared[32];
    size_t bob_shared_len = 32;
    EVP_PKEY_derive(bob_derive, bob_shared, &bob_shared_len);

    print_hex("Alice shared", alice_shared, 32);
    print_hex("Bob shared  ", bob_shared, 32);

    // Verify they match
    if (memcmp(alice_shared, bob_shared, 32) == 0) {
        printf("\nKey exchange successful!\n");
    }

    // Cleanup
    EVP_PKEY_CTX_free(alice_ctx);
    EVP_PKEY_CTX_free(bob_ctx);
    EVP_PKEY_CTX_free(alice_derive);
    EVP_PKEY_CTX_free(bob_derive);
    EVP_PKEY_free(alice_key);
    EVP_PKEY_free(bob_key);

    return 0;
}
