/* composite_keys.h - Composite key/cert format declarations
 *
 * Educational header for composite_keys.c — declares the ASN.1 buffer
 * helpers, composite-key types, and X.509-flavored cert types used by
 * the demo encoder. NOT a production ASN.1 library.
 *
 * Composite signature/encryption is the LAMPS-WG approach to migrating
 * X.509 to PQC: a single SubjectPublicKeyInfo carries BOTH a classical
 * key (Ed25519, ECDSA-P256) AND a PQC key (ML-DSA-65) so that the
 * certificate validates only if BOTH algorithms verify. See
 * draft-ietf-lamps-pq-composite-sigs-16 for the live spec.
 */

#ifndef COMPOSITE_KEYS_H
#define COMPOSITE_KEYS_H

#include <stddef.h>
#include <stdint.h>

/* -------- Return codes -------- */
#define COMPOSITE_OK                    0
#define COMPOSITE_ERR_INVALID_INPUT    -1
#define COMPOSITE_ERR_BUFFER_TOO_SMALL -2
#define COMPOSITE_ERR_ENCODE_FAILED    -3
#define COMPOSITE_ERR_DECODE_FAILED    -4
#define COMPOSITE_ERR_INVALID_ASN      -5
#define COMPOSITE_ERR_INVALID_ASN1     COMPOSITE_ERR_INVALID_ASN  /* alias used by some sources */
#define COMPOSITE_ERR_UNSUPPORTED_ALG  -6

/* -------- Sizing constants -------- */
#define MAX_SPKI_SIZE     4096
#define MAX_PKCS          8192
#define MAX_PKCS8_SIZE    8192
#define MAX_CERT_SIZE     16384

/* Component algorithm sizes (bytes) */
#define ED25519_PK_SIZE     32
#define ED25519_SK_SIZE     64
#define MLDSA65_PK_SIZE   1952
#define MLDSA65_SK_SIZE   4032
#define MLDSA65_SIG_SIZE  3309   /* FIPS 204 ML-DSA-65 signature */

/* -------- ASN.1 universal tags -------- */
#define ASN1_INTEGER          0x02
#define ASN1_BIT_STRING       0x03
#define ASN1_OCTET_STRING     0x04
#define ASN1_NULL             0x05
#define ASN1_OID              0x06
#define ASN1_UTF8_STRING      0x0c
#define ASN1_PRINTABLE_STRING 0x13
#define ASN1_UTC_TIME         0x17
#define ASN1_SEQUENCE         0x30
#define ASN1_SET              0x31
#define ASN1_CONTEXT_0        0xa0
#define ASN1_CONTEXT_1        0xa1
#define ASN1_CONTEXT_3        0xa3

/* -------- Algorithm identifiers -------- */
typedef enum {
    ALG_NONE = 0,
    ALG_ED25519,
    ALG_ECDSA_P256,
    ALG_ECDSA_P384,
    ALG_ML_DSA_65,
    ALG_COMPOSITE_MLDSA65_ED25519
} algorithm_id_t;

/* -------- ASN.1 buffer (growable byte vector with read cursor) -------- */
typedef struct {
    uint8_t *data;
    size_t   len;       /* Bytes written */
    size_t   capacity;  /* Allocated bytes */
    size_t   pos;       /* Read cursor for decode functions */
} asn1_buffer_t;

/* -------- SubjectPublicKeyInfo -------- */
typedef struct {
    algorithm_id_t algorithm;
    const uint8_t *public_key;       /* Pointer to caller-owned buffer */
    size_t         public_key_len;
} spki_t;

/* -------- Composite keypair (classical inline arrays + PQC heap) -------- */
typedef struct {
    algorithm_id_t classical_alg;
    uint8_t        classical_pk[64];
    size_t         classical_pk_len;
    uint8_t        classical_sk[128];
    size_t         classical_sk_len;

    algorithm_id_t pqc_alg;
    uint8_t       *pqc_pk;            /* malloc'd, pqc_pk_len bytes */
    size_t         pqc_pk_len;
    uint8_t       *pqc_sk;            /* malloc'd, pqc_sk_len bytes */
    size_t         pqc_sk_len;
} composite_keypair_t;

/* -------- X.509 Name attribute (simplified to CN-only) -------- */
typedef struct {
    const char *value;
} x509_name_attr_t;

/* -------- TBSCertificate (simplified) -------- */
typedef struct {
    int               version;          /* 0 = v1, 1 = v2, 2 = v3 */
    const uint8_t    *serial_number;
    size_t            serial_len;
    algorithm_id_t    signature_alg;
    x509_name_attr_t  issuer[1];        /* Single CN */
    x509_name_attr_t  subject[1];       /* Single CN */
    spki_t            subject_pki;
} tbs_certificate_t;

/* -------- Certificate (TBS + signature) -------- */
typedef struct {
    const uint8_t *tbs_der;             /* Pre-encoded TBSCertificate DER */
    size_t         tbs_der_len;
    algorithm_id_t signature_alg;
    const uint8_t *signature;
    size_t         signature_len;
} certificate_t;

/* -------- ASN.1 buffer ops -------- */
int  asn1_buffer_init(asn1_buffer_t *buf, size_t capacity);
void asn1_buffer_free(asn1_buffer_t *buf);
void asn1_buffer_reset(asn1_buffer_t *buf);

/* -------- ASN.1 encode -------- */
int asn1_encode_length(asn1_buffer_t *buf, size_t length);
int asn1_encode_tag_length(asn1_buffer_t *buf, uint8_t tag, size_t length);
int asn1_encode_integer(asn1_buffer_t *buf, const uint8_t *value, size_t len);
int asn1_encode_octet_string(asn1_buffer_t *buf, const uint8_t *data, size_t len);
int asn1_encode_bit_string(asn1_buffer_t *buf, const uint8_t *data, size_t len);
int asn1_encode_oid(asn1_buffer_t *buf, const uint8_t *oid, size_t oid_len);
int asn1_encode_null(asn1_buffer_t *buf);
int asn1_encode_sequence(asn1_buffer_t *buf, const uint8_t *content, size_t len);

/* -------- ASN.1 decode -------- */
int asn1_decode_tag(asn1_buffer_t *buf, uint8_t *tag);
int asn1_decode_length(asn1_buffer_t *buf, size_t *length);
int asn1_decode_tag_length(asn1_buffer_t *buf, uint8_t expected_tag, size_t *length);
int asn1_decode_integer(asn1_buffer_t *buf, uint8_t *value, size_t *len, size_t max_len);
int asn1_decode_octet_string(asn1_buffer_t *buf, uint8_t *data, size_t *len, size_t max_len);
int asn1_decode_bit_string(asn1_buffer_t *buf, uint8_t *data, size_t *len, size_t max_len);
int asn1_decode_oid(asn1_buffer_t *buf, uint8_t *oid, size_t *len, size_t max_len);

/* -------- Algorithm/SPKI -------- */
int get_algorithm_oid(algorithm_id_t alg, const uint8_t **oid, size_t *oid_len);
int encode_algorithm_identifier(asn1_buffer_t *buf, algorithm_id_t alg);
int encode_spki(asn1_buffer_t *buf, const spki_t *spki);
int encode_composite_spki(asn1_buffer_t *buf, const composite_keypair_t *keypair);
int encode_pkcs8_private_key(asn1_buffer_t *buf, const composite_keypair_t *keypair);

/* -------- X.509 cert -------- */
int encode_tbs_certificate(asn1_buffer_t *buf, const tbs_certificate_t *tbs);
int encode_certificate(asn1_buffer_t *buf, const certificate_t *cert);

/* -------- Composite keypair lifecycle -------- */
int  composite_keypair_init(composite_keypair_t *keypair,
                            algorithm_id_t classical, algorithm_id_t pqc);
void composite_keypair_free(composite_keypair_t *keypair);

/* -------- PEM -------- */
int der_to_pem(const uint8_t *der, size_t der_len,
               const char *label, char *pem, size_t *pem_len);

/* -------- Demo helpers -------- */
int  create_test_composite_keypair(composite_keypair_t *keypair);
void demo_composite_encoding(void);

#endif /* COMPOSITE_KEYS_H */
