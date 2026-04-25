/*
 * unit_9_1_tls13_cert_chain.c
 *
 * TLS 1.3 certificate chain handling with post-quantum signatures.
 * Demonstrates parsing a chain of composite or pure PQ certificates
 * from PEM and querying their signature algorithms.
 *
 * Maps to: Handbook Unit 9.1 (TLS 1.3 cert chain under PQC).
 *
 * Build:
 *   gcc -Wall -Wextra -O2 -std=c11 -o cert_chain unit_9_1_tls13_cert_chain.c -lssl -lcrypto
 *
 * Requires: OpenSSL 3.5.0+ with composite/ML-DSA support.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_OPENSSL
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

static void describe_cert(X509 *cert, int index) {
    char subj[256] = {0};
    char issuer[256] = {0};
    X509_NAME_oneline(X509_get_subject_name(cert), subj, sizeof(subj));
    X509_NAME_oneline(X509_get_issuer_name(cert), issuer, sizeof(issuer));

    int nid = X509_get_signature_nid(cert);
    const char *sig_alg = OBJ_nid2ln(nid);

    EVP_PKEY *pkey = X509_get0_pubkey(cert);
    const char *key_alg = pkey ? EVP_PKEY_get0_type_name(pkey) : "(unknown)";
    int key_bits = pkey ? EVP_PKEY_get_bits(pkey) : 0;

    printf("  Cert %d\n", index);
    printf("    Subject:        %s\n", subj);
    printf("    Issuer:         %s\n", issuer);
    printf("    Signature alg:  %s\n", sig_alg ? sig_alg : "(unknown)");
    printf("    Key alg:        %s (%d bits)\n", key_alg, key_bits);

    if (sig_alg && (strstr(sig_alg, "ML-DSA") || strstr(sig_alg, "mldsa") ||
                    strstr(sig_alg, "composite"))) {
        printf("    --> Post-quantum or hybrid signature detected\n");
    } else {
        printf("    --> Classical signature (quantum-vulnerable)\n");
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s chain.pem\n", argv[0]);
        return 1;
    }

    BIO *in = BIO_new_file(argv[1], "r");
    if (!in) {
        fprintf(stderr, "Cannot open %s\n", argv[1]);
        return 1;
    }

    printf("Certificate chain: %s\n", argv[1]);

    X509 *cert;
    int count = 0;
    while ((cert = PEM_read_bio_X509(in, NULL, NULL, NULL)) != NULL) {
        describe_cert(cert, ++count);
        X509_free(cert);
    }
    BIO_free(in);

    if (count == 0) {
        fprintf(stderr, "No certificates found in %s.\n", argv[1]);
        return 1;
    }
    printf("\nTotal certificates in chain: %d\n", count);
    return 0;
}

#else
int main(void) {
    printf("Requires OpenSSL 3.5+; build with -DHAVE_OPENSSL -lssl -lcrypto\n");
    return 0;
}
#endif
