/*
 * unit_9_4_ipsec_ike_mlkem.c
 *
 * IKEv2 post-quantum key exchange stub: demonstrates the transform
 * configuration that requests ML-KEM hybrid additional key exchange
 * (draft-ietf-ipsecme-ikev2-mlkem).
 *
 * Maps to: Handbook Unit 9.4 (VPN and IPsec Integration).
 *
 * This file is a configuration-snippet demonstration, not a full IKE
 * implementation (which would be tens of thousands of lines — use
 * strongSwan or libreswan instead).
 *
 * Build:
 *   gcc -Wall -Wextra -Wshadow -O2 -std=c11 -o ipsec_demo unit_9_4_ipsec_ike_mlkem.c
 */

#include <stdio.h>
#include <string.h>

/* IKEv2 transform types (per RFC 7296 and draft-ietf-ipsecme-ikev2-mlkem). */
enum ike_transform_type {
    IKE_T_ENCR         = 1,   /* Encryption */
    IKE_T_PRF          = 2,   /* Pseudorandom Function */
    IKE_T_INTEG        = 3,   /* Integrity */
    IKE_T_DH           = 4,   /* Diffie-Hellman group (classical) */
    IKE_T_ESN          = 5,   /* Extended Sequence Numbers */
    IKE_T_ADDKE1       = 6,   /* Additional KE round 1 (PQ) — new per draft */
    IKE_T_ADDKE2       = 7,   /* Additional KE round 2 (PQ) — new per draft */
};

/* Hybrid PQ key exchange group numbers (IANA-allocated per draft). */
enum ike_group {
    IKE_GROUP_X25519          = 31,    /* Classical X25519 */
    IKE_GROUP_SECP256R1       = 19,    /* Classical P-256 */
    IKE_GROUP_MLKEM512        = 35,    /* per draft-ietf-ipsecme-ikev2-mlkem */
    IKE_GROUP_MLKEM768        = 36,
    IKE_GROUP_MLKEM1024       = 37,
};

/* Print a human-readable transform proposal matching what strongSwan
 * would negotiate when configured for hybrid PQ. */
static void print_proposal(const char *label,
                           int classical_group, int pq_group,
                           const char *encr, const char *prf,
                           const char *integ) {
    printf("Proposal: %s\n", label);
    printf("  ENCR:     %s\n", encr);
    printf("  PRF:      %s\n", prf);
    printf("  INTEG:    %s\n", integ);
    printf("  DH:       group %d (classical)\n", classical_group);
    if (pq_group) {
        printf("  ADDKE1:   group %d (ML-KEM) -- hybrid PQ exchange\n", pq_group);
    }
    printf("\n");
}

int main(void) {
    printf("IKEv2 hybrid PQ transform proposals\n");
    printf("(draft-ietf-ipsecme-ikev2-mlkem)\n\n");

    print_proposal("Hybrid ML-KEM-768 + X25519",
                   IKE_GROUP_X25519, IKE_GROUP_MLKEM768,
                   "AES_GCM_16 (256)", "HMAC_SHA2_256", "HMAC_SHA2_256_128");

    print_proposal("Hybrid ML-KEM-1024 + P-384 (CNSA 2.0-compatible)",
                   29 /* secp384r1 */, IKE_GROUP_MLKEM1024,
                   "AES_GCM_16 (256)", "HMAC_SHA2_384", "HMAC_SHA2_384_192");

    print_proposal("Classical-only (fallback)",
                   IKE_GROUP_X25519, 0,
                   "AES_GCM_16 (128)", "HMAC_SHA2_256", "HMAC_SHA2_256_128");

    printf("strongSwan 6.0+ / Libreswan 5.2+ support ADDKE1 with ML-KEM.\n");
    printf("Cloudflare deployed this in production (March 2026), interop-tested\n");
    printf("with strongSwan at the IETF 118 hackathon.\n");

    return 0;
}
