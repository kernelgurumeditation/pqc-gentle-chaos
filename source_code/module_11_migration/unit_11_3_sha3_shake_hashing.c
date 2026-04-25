#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void sha3_256_example(const unsigned char *input, size_t input_len) {
    unsigned char hash[32];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    EVP_DigestInit_ex(ctx, EVP_sha3_256(), NULL);
    EVP_DigestUpdate(ctx, input, input_len);
    unsigned int hash_len;
    EVP_DigestFinal_ex(ctx, hash, &hash_len);

    printf("SHA3-256: ");
    for (int i = 0; i < 32; i++) printf("%02x", hash[i]);
    printf("\n");

    EVP_MD_CTX_free(ctx);
}

void shake256_example(const unsigned char *input, size_t input_len,
                      size_t output_len) {
    unsigned char *output = malloc(output_len);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    EVP_DigestInit_ex(ctx, EVP_shake256(), NULL);
    EVP_DigestUpdate(ctx, input, input_len);
    EVP_DigestFinalXOF(ctx, output, output_len);

    printf("SHAKE256 (%zu bytes): ", output_len);
    for (size_t i = 0; i < (output_len < 32 ? output_len : 32); i++) {
        printf("%02x", output[i]);
    }
    if (output_len > 32) printf("...");
    printf("\n");

    free(output);
    EVP_MD_CTX_free(ctx);
}

int main(void) {
    const unsigned char msg[] = "Hello, PQC!";

    printf("Input: \"%s\"\n\n", msg);

    sha3_256_example(msg, strlen((char*)msg));
    shake256_example(msg, strlen((char*)msg), 32);
    shake256_example(msg, strlen((char*)msg), 64);
    shake256_example(msg, strlen((char*)msg), 128);

    return 0;
}
