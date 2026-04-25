# Module 9: Protocol Integration — Source Code

Companion code for Handbook Module 9: TLS, SSH, S/MIME, IPsec, and code signing under PQC.

## Files

| File | Purpose | External deps |
|------|---------|---------------|
| `unit_9_1_tls13_hybrid_kex.c` | OpenSSL 3.5+ hybrid TLS 1.3 (X25519MLKEM768) context setup | OpenSSL ≥ 3.5 |
| `unit_9_1_tls13_cert_chain.c` | PEM certificate chain parser with PQ signature detection | OpenSSL ≥ 3.5 |
| `unit_9_2_ssh_kex_demo.c` | Standalone SSH KEX negotiation simulator (OpenSSH 10.0+ defaults) | none |
| `unit_9_3_smime_hybrid.c` | CMS S/MIME hybrid envelope encryption skeleton (RFC 9629 KEMRecipientInfo) | OpenSSL ≥ 3.6 |
| `unit_9_4_ipsec_ike_mlkem.c` | IKEv2 transform proposal showcase for hybrid ML-KEM (draft-ietf-ipsecme-ikev2-mlkem) | none |
| `unit_9_5_hybrid_code_signing.c` | Cosign-style code signing attestation with KMS-backed ML-DSA | none |

## Build

```bash
# Self-contained demos (no external libs needed)
make self-contained
make test

# With OpenSSL 3.5+ (installed system-wide or in /usr/local/openssl3)
make openssl
```

## Status Notes

- **OpenSSL 3.5+ required** for TLS and cert examples. Ubuntu 24.04 LTS ships OpenSSL 3.0; you need to build 3.5+ from source or use a distribution that includes it (Ubuntu 26.04 LTS, RHEL 10.1, Fedora 42+).
- **OpenSSL 3.6+ required** for `unit_9_3_smime_hybrid.c` because CMS KEMRecipientInfo (RFC 9629) landed in 3.6.
- **Self-contained demos** use only standard C library — useful for readers without an OpenSSL 3.5 installation.
- These are educational skeletons. For production TLS/SSH/S-MIME use mature implementations (Nginx, OpenSSH, Thunderbird's NSS bindings).

## Cross-references

- Handbook Unit 9.1–9.5: theory and design
- Module 8: hybrid cryptography primitives (X-Wing construction)
- Module 11.9: cloud KMS integration for PQ signing keys
- Module 11.10: CVE registry (relevant to TLS deployments)
