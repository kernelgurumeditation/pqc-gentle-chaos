/*
 * unit_9_5_hybrid_code_signing.c
 *
 * Skeleton for cosign-style code signing with ML-DSA via a KMS-backed
 * key. Illustrates the architectural pattern; real deployments use the
 * sigstore/cosign binary or a vendor SDK rather than hand-written C.
 *
 * Maps to: Handbook Unit 9.5 (Code Signing and PKI Integration).
 *
 * Build:
 *   gcc -Wall -Wextra -Wshadow -O2 -std=c11 -o code_sign unit_9_5_hybrid_code_signing.c
 *
 * Self-contained: no external libraries. In real deployment you would
 * link against your KMS vendor's SDK (aws-sdk-c, google-cloud-cpp, etc.)
 * or invoke the `cosign` CLI from your build system.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Simulate a signed artifact record. In reality this is a Sigstore
 * Rekor transparency-log entry or an in-toto attestation. */
typedef struct {
    const char *artifact_digest;    /* e.g., "sha256:abc123..." */
    const char *signing_key_ref;    /* e.g., "awskms:///alias/pqc-mldsa65" */
    const char *sig_algorithm;      /* "ML-DSA-65" */
    size_t     sig_length;          /* 3309 bytes for ML-DSA-65 */
} signed_artifact_t;

/* Print the CosignAttestation-shaped output that a real cosign invocation
 * would produce when signing with a KMS key. */
static void print_attestation(const signed_artifact_t *a) {
    printf("Signed artifact attestation (Sigstore-style):\n");
    printf("  Artifact:    %s\n", a->artifact_digest);
    printf("  Key ref:     %s\n", a->signing_key_ref);
    printf("  Sig alg:     %s\n", a->sig_algorithm);
    printf("  Sig length:  %zu bytes\n", a->sig_length);
    printf("\nReal cosign invocation:\n");
    printf("  cosign sign --key %s <image-ref>\n", a->signing_key_ref);
    printf("  cosign verify --key %s <image-ref>\n", a->signing_key_ref);
    printf("\nPolicy enforcement example (Kyverno):\n");
    printf("  spec:\n");
    printf("    verifyImages:\n");
    printf("      - imageReferences: [ \"*\" ]\n");
    printf("        attestors:\n");
    printf("          - entries:\n");
    printf("              - keyless:\n");
    printf("                  subject: \"https://my-ci/*\"\n");
    printf("                  issuer:  \"https://my-oidc-issuer/\"\n");
    printf("                  signatureAlgorithm: %s\n", a->sig_algorithm);
}

int main(int argc, char **argv) {
    const char *key_ref = argc > 1 ? argv[1] : "awskms:///alias/pqc-mldsa65";
    const char *artifact = argc > 2 ? argv[2]
                                    : "sha256:0000000000000000000000000000000000000000000000000000000000000000";

    signed_artifact_t a = {
        .artifact_digest = artifact,
        .signing_key_ref = key_ref,
        .sig_algorithm   = "ML-DSA-65",
        .sig_length      = 3309,
    };

    print_attestation(&a);

    printf("\nNote: For long-lived bootloader and firmware signing, prefer\n");
    printf("LMS/XMSS (stateful, SP 800-208) over ML-DSA. See Unit 7.2 and\n");
    printf("Unit 11.9.7 Scenario C for algorithm selection guidance.\n");

    return 0;
}
