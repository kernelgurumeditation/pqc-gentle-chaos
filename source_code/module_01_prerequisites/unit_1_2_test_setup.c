/* Unit 1.2.5: Verify PQC development environment
 * Requires: liboqs, OpenSSL 3.x
 * Build: gcc -o unit_1_2_test_setup unit_1_2_test_setup.c -loqs -lssl -lcrypto
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <oqs/oqs.h>

int test_openssl_shake(void) {
    printf("Testing OpenSSL SHAKE256... ");

    unsigned char input[] = "test";
    unsigned char output[32];

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;

    if (EVP_DigestInit_ex(ctx, EVP_shake256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }
    EVP_DigestUpdate(ctx, input, strlen((char*)input));
    EVP_DigestFinalXOF(ctx, output, sizeof(output));
    EVP_MD_CTX_free(ctx);

    printf("OK\n");
    return 1;
}

int test_liboqs_kem(void) {
    printf("Testing liboqs ML-KEM-768... ");

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (kem == NULL) {
        printf("FAILED (algorithm not available)\n");
        return 0;
    }

    uint8_t *pk = malloc(kem->length_public_key);
    uint8_t *sk = malloc(kem->length_secret_key);
    uint8_t *ct = malloc(kem->length_ciphertext);
    uint8_t *ss_enc = malloc(kem->length_shared_secret);
    uint8_t *ss_dec = malloc(kem->length_shared_secret);

    OQS_KEM_keypair(kem, pk, sk);
    OQS_KEM_encaps(kem, ct, ss_enc, pk);
    OQS_KEM_decaps(kem, ss_dec, ct, sk);

    int success = (memcmp(ss_enc, ss_dec, kem->length_shared_secret) == 0);

    OQS_MEM_secure_free(sk, kem->length_secret_key);
    OQS_MEM_secure_free(ss_enc, kem->length_shared_secret);
    OQS_MEM_secure_free(ss_dec, kem->length_shared_secret);
    free(pk);
    free(ct);
    OQS_KEM_free(kem);

    printf("%s\n", success ? "OK" : "FAILED");
    return success;
}

int test_liboqs_sig(void) {
    printf("Testing liboqs ML-DSA-65... ");

    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (sig == NULL) {
        printf("FAILED (algorithm not available)\n");
        return 0;
    }

    uint8_t *pk = malloc(sig->length_public_key);
    uint8_t *sk = malloc(sig->length_secret_key);
    uint8_t *signature = malloc(sig->length_signature);
    size_t sig_len;

    const uint8_t message[] = "Hello, Post-Quantum World!";

    OQS_SIG_keypair(sig, pk, sk);
    OQS_SIG_sign(sig, signature, &sig_len, message, sizeof(message) - 1, sk);
    int valid = (OQS_SIG_verify(sig, message, sizeof(message) - 1,
                                signature, sig_len, pk) == OQS_SUCCESS);

    OQS_MEM_secure_free(sk, sig->length_secret_key);
    free(pk);
    free(signature);
    OQS_SIG_free(sig);

    printf("%s\n", valid ? "OK" : "FAILED");
    return valid;
}

int main(void) {
    printf("=== PQC Development Environment Test ===\n\n");

    printf("OpenSSL version: %s\n", OpenSSL_version(OPENSSL_VERSION));
    printf("liboqs version: %s\n\n", OQS_VERSION_TEXT);

    int all_pass = 1;
    all_pass &= test_openssl_shake();
    all_pass &= test_liboqs_kem();
    all_pass &= test_liboqs_sig();

    printf("\n=== %s ===\n", all_pass ? "ALL TESTS PASSED" : "SOME TESTS FAILED");

    return all_pass ? 0 : 1;
}
