/*
 * unit_10_4_bike_demo.c
 *
 * BIKE (Bit Flipping Key Encapsulation) KEM demo via liboqs.
 * BIKE is a code-based KEM not selected by NIST for standardization but
 * maintained in liboqs as a research candidate. Provided here for
 * algorithm diversity experimentation.
 *
 * Maps to: Handbook Unit 10.1 (emerging algorithms).
 *
 * Build:
 *   gcc -Wall -Wextra -Wshadow -O2 -std=c11 -DHAVE_LIBOQS -o bike_demo unit_10_4_bike_demo.c -loqs
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef HAVE_LIBOQS
#include <oqs/oqs.h>

static int demo_bike(const char *variant) {
    OQS_KEM *kem = OQS_KEM_new(variant);
    if (!kem) {
        fprintf(stderr, "BIKE variant %s not available.\n", variant);
        return 1;
    }

    printf("Algorithm:      %s\n", kem->method_name);
    printf("Public key:     %zu bytes\n", kem->length_public_key);
    printf("Secret key:     %zu bytes\n", kem->length_secret_key);
    printf("Ciphertext:     %zu bytes\n", kem->length_ciphertext);
    printf("Shared secret:  %zu bytes\n", kem->length_shared_secret);

    uint8_t *pk = malloc(kem->length_public_key);
    uint8_t *sk = malloc(kem->length_secret_key);
    uint8_t *ct = malloc(kem->length_ciphertext);
    uint8_t *ss_enc = malloc(kem->length_shared_secret);
    uint8_t *ss_dec = malloc(kem->length_shared_secret);

    if (!pk || !sk || !ct || !ss_enc || !ss_dec) goto cleanup;
    if (OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS) goto cleanup;
    if (OQS_KEM_encaps(kem, ct, ss_enc, pk) != OQS_SUCCESS) goto cleanup;
    if (OQS_KEM_decaps(kem, ss_dec, ct, sk) != OQS_SUCCESS) goto cleanup;

    int ok = (memcmp(ss_enc, ss_dec, kem->length_shared_secret) == 0);
    printf("Match:          %s\n", ok ? "YES" : "NO");

cleanup:
    if (sk) OQS_MEM_cleanse(sk, kem->length_secret_key);
    free(pk); free(sk); free(ct); free(ss_enc); free(ss_dec);
    OQS_KEM_free(kem);
    return 0;
}

int main(void) {
    printf("BIKE KEM demo via liboqs\n");
    printf("(Research candidate, not a NIST standard)\n\n");

    demo_bike(OQS_KEM_alg_bike_l1);
    printf("\n---\n\n");
    demo_bike(OQS_KEM_alg_bike_l3);
    printf("\n---\n\n");
    demo_bike(OQS_KEM_alg_bike_l5);

    return 0;
}

#else

int main(void) {
    printf("BIKE KEM demo — requires liboqs with BIKE enabled.\n");
    printf("\n");
    printf("BIKE parameter sets (per liboqs support matrix):\n");
    printf("  BIKE-L1 (Level 1):  pk=1541, sk=5223, ct=1573\n");
    printf("  BIKE-L3 (Level 3):  pk=3083, sk=10105, ct=3115\n");
    printf("  BIKE-L5 (Level 5):  pk=5122, sk=16494, ct=5154\n");
    printf("\n");
    printf("Note: BIKE was not selected by NIST. Its inclusion is for\n");
    printf("research and algorithm-diversity comparison only.\n");
    return 0;
}

#endif
