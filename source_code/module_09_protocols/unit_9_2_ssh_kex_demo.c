/*
 * unit_9_2_ssh_kex_demo.c
 *
 * Demonstrates parsing and selecting SSH hybrid post-quantum key exchange
 * algorithm lists. OpenSSH 10.0+ defaults to mlkem768x25519-sha256.
 *
 * Maps to: Handbook Unit 9.2 (SSH Post-Quantum Integration).
 *
 * Build:
 *   gcc -Wall -Wextra -Wshadow -O2 -std=c11 -o ssh_kex unit_9_2_ssh_kex_demo.c
 *
 * Self-contained: no external libraries. Simulates KEX algorithm
 * negotiation the way OpenSSH does client-to-server.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* OpenSSH 10.0+ default KEX preference order (client side).
 * See: https://www.openssh.org/pq.html */
static const char *openssh_10_default_kex[] = {
    "sntrup761x25519-sha512@openssh.com",  /* NTRU Prime + X25519 (legacy default) */
    "mlkem768x25519-sha256",               /* ML-KEM + X25519 (OpenSSH 10.0 new default) */
    "curve25519-sha256",                   /* classical fallback */
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group14-sha256",
    NULL
};

/* Hypothetical server side: supports only hybrid PQ + one classical fallback. */
static const char *strict_pq_server_kex[] = {
    "mlkem768x25519-sha256",
    "sntrup761x25519-sha512@openssh.com",
    "curve25519-sha256",
    NULL
};

/* SSH KEX negotiation: client proposes list, server proposes list,
 * both pick the first match in the client's preference order. */
static const char *negotiate_kex(const char **client_prefs, const char **server_accepts) {
    for (int i = 0; client_prefs[i]; i++) {
        for (int j = 0; server_accepts[j]; j++) {
            if (strcmp(client_prefs[i], server_accepts[j]) == 0) {
                return client_prefs[i];
            }
        }
    }
    return NULL;
}

static int is_pq_hybrid(const char *kex_name) {
    return (strstr(kex_name, "mlkem") != NULL) ||
           (strstr(kex_name, "sntrup") != NULL);
}

int main(void) {
    const char *chosen = negotiate_kex(openssh_10_default_kex, strict_pq_server_kex);

    printf("SSH KEX negotiation demo (OpenSSH 10.0+ behavior)\n");
    printf("=================================================\n\n");

    printf("Client preference (first few):\n");
    for (int i = 0; i < 3 && openssh_10_default_kex[i]; i++) {
        printf("  %d. %s\n", i + 1, openssh_10_default_kex[i]);
    }
    printf("  ...\n\n");

    printf("Server accepts:\n");
    for (int i = 0; strict_pq_server_kex[i]; i++) {
        printf("  %d. %s\n", i + 1, strict_pq_server_kex[i]);
    }
    printf("\n");

    if (chosen) {
        printf("Negotiated: %s\n", chosen);
        printf("Hybrid PQ?  %s\n", is_pq_hybrid(chosen) ? "YES" : "NO");
    } else {
        printf("No common KEX algorithm — connection would fail.\n");
    }

    printf("\nNote: OpenSSH 10.2+ emits a warning banner to the user when the\n");
    printf("negotiated KEX is not hybrid-PQ. By 2028, classical-only KEX is\n");
    printf("expected to be disabled in the default SSH server configuration.\n");

    return 0;
}
