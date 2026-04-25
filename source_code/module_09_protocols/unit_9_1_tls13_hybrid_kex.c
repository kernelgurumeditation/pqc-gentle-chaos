/*
 * unit_9_1_tls13_hybrid_kex.c
 *
 * Hybrid post-quantum TLS 1.3 key exchange using OpenSSL 3.5+.
 * Demonstrates X25519MLKEM768 hybrid group negotiation for a simple
 * client/server pair. Uses native OpenSSL 3.5+ PQ primitives; no
 * oqs-provider required.
 *
 * Maps to: Handbook Unit 9.1 (TLS 1.3 Post-Quantum Integration).
 *
 * Build:
 *   gcc -Wall -Wextra -O2 -std=c11 -o tls13_hybrid unit_9_1_tls13_hybrid_kex.c -lssl -lcrypto
 *
 * Requires: OpenSSL 3.5.0+ (SecP256r1MLKEM768 / X25519MLKEM768 support).
 *
 * Educational: this is a minimal demonstration. Production TLS servers
 * should use a library-provided TLS implementation rather than hand-rolled
 * BIO glue.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

/* Configure a TLS 1.3 SSL_CTX to prefer hybrid PQ key exchange. */
static SSL_CTX *make_hybrid_ctx(int is_server) {
    SSL_CTX *ctx = SSL_CTX_new(is_server ? TLS_server_method() : TLS_client_method());
    if (!ctx) return NULL;

    /* Force TLS 1.3 only; hybrid PQ groups are TLS 1.3 features. */
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    /* Request hybrid groups in preference order. OpenSSL 3.5+ recognizes:
     *   X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024.
     * If peer doesn't support any hybrid, fall back to classical X25519. */
    if (SSL_CTX_set1_groups_list(ctx,
            "X25519MLKEM768:SecP256r1MLKEM768:X25519:P-256") != 1) {
        fprintf(stderr, "Hybrid group list not accepted — is OpenSSL >= 3.5.0?\n");
        SSL_CTX_free(ctx);
        return NULL;
    }

    return ctx;
}

/* Print the negotiated key exchange group after a successful handshake. */
static void report_negotiation(SSL *ssl) {
    const char *group_name = SSL_get0_group_name(ssl);
    const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);

    printf("TLS version:    %s\n", SSL_get_version(ssl));
    printf("Cipher suite:   %s\n", cipher ? SSL_CIPHER_get_name(cipher) : "(unknown)");
    printf("Key exchange:   %s\n", group_name ? group_name : "(unknown)");

    if (group_name && (strstr(group_name, "MLKEM") || strstr(group_name, "ML-KEM"))) {
        printf("  -> Hybrid post-quantum key exchange: YES\n");
    } else {
        printf("  -> Hybrid post-quantum key exchange: NO (classical only)\n");
    }
}

int main(int argc, char **argv) {
    /* In a real program you'd accept on a socket, handshake, etc.
     * This stub just verifies that the SSL_CTX can be created with
     * hybrid groups — a smoke test for the underlying library. */
    (void)argc;
    (void)argv;

    SSL_CTX *client = make_hybrid_ctx(0);
    SSL_CTX *server = make_hybrid_ctx(1);

    if (!client || !server) {
        fprintf(stderr, "Failed to build hybrid TLS contexts.\n");
        return 1;
    }

    printf("OpenSSL version: %s\n", OpenSSL_version(OPENSSL_VERSION));
    printf("Hybrid TLS 1.3 contexts created with group list:\n");
    printf("  X25519MLKEM768:SecP256r1MLKEM768:X25519:P-256\n");
    printf("\nTo test interop: run as server, connect from curl/openssl s_client\n");
    printf("with -groups X25519MLKEM768 and inspect the negotiated group.\n");

    /* Skeleton: wire up a BIO pair, call SSL_accept/SSL_connect, then
     * report_negotiation() on the resulting SSL. Omitted here to keep
     * the example focused on the hybrid group API. */

    SSL_CTX_free(client);
    SSL_CTX_free(server);
    return 0;
}

#else /* HAVE_OPENSSL not defined */

int main(void) {
    printf("This demo requires OpenSSL >= 3.5.0.\n");
    printf("Build with: gcc -DHAVE_OPENSSL -lssl -lcrypto\n");
    return 0;
}

#endif
