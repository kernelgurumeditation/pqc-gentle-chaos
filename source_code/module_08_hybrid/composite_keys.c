/* composite_keys.c - Composite key format implementation */

#define _POSIX_C_SOURCE 200809L
#include "composite_keys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Base64 encoding table */
static const char base64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* OID definitions */
static const uint8_t oid_ed25519[] = {0x2b, 0x65, 0x70};
static const uint8_t oid_ml_dsa_65[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12};
static const uint8_t oid_ecdsa_p256[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01};
static const uint8_t oid_ecdsa_p384[] = {0x2b, 0x81, 0x04, 0x00, 0x22};
static const uint8_t oid_composite_mldsa65_ed25519[] = {
    0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x53, 0x50, 0x08, 0x01, 0x02
};

/* Common Name OID: 2.5.4.3 */
static const uint8_t oid_common_name[] = {0x55, 0x04, 0x03};

/* Subject Key Identifier OID: 2.5.29.14 */
static const uint8_t oid_subject_key_id[] = {0x55, 0x1d, 0x0e};

/* Basic Constraints OID: 2.5.29.19 */
static const uint8_t oid_basic_constraints[] = {0x55, 0x1d, 0x13};

/* Key Usage OID: 2.5.29.15 */
static const uint8_t oid_key_usage[] = {0x55, 0x1d, 0x0f};

/*
 * ASN.1 Buffer Management
 */

int asn1_buffer_init(asn1_buffer_t *buf, size_t capacity) {
    if (!buf) {
        return COMPOSITE_ERR_INVALID_INPUT;
    }

    buf->data = malloc(capacity);
    if (!buf->data) {
        return COMPOSITE_ERR_BUFFER_TOO_SMALL;
    }

    buf->len = 0;
    buf->capacity = capacity;
    buf->pos = 0;

    return COMPOSITE_OK;
}

void asn1_buffer_free(asn1_buffer_t *buf) {
    if (buf && buf->data) {
        /* Securely clear sensitive data */
        memset(buf->data, 0, buf->capacity);
        free(buf->data);
        buf->data = NULL;
        buf->len = 0;
        buf->capacity = 0;
        buf->pos = 0;
    }
}

void asn1_buffer_reset(asn1_buffer_t *buf) {
    if (buf) {
        buf->len = 0;
        buf->pos = 0;
    }
}

/*
 * ASN.1 Encoding Functions
 */

/* Encode length in DER format */
int asn1_encode_length(asn1_buffer_t *buf, size_t length) {
    if (!buf || !buf->data) {
        return COMPOSITE_ERR_INVALID_INPUT;
    }

    if (length < 128) {
        /* Short form: single byte */
        if (buf->len + 1 > buf->capacity) {
            return COMPOSITE_ERR_BUFFER_TOO_SMALL;
        }
        buf->data[buf->len++] = (uint8_t)length;
    } else if (length < 256) {
        /* Long form: 0x81 followed by one byte */
        if (buf->len + 2 > buf->capacity) {
            return COMPOSITE_ERR_BUFFER_TOO_SMALL;
        }
        buf->data[buf->len++] = 0x81;
        buf->data[buf->len++] = (uint8_t)length;
    } else if (length < 65536) {
        /* Long form: 0x82 followed by two bytes */
        if (buf->len + 3 > buf->capacity) {
            return COMPOSITE_ERR_BUFFER_TOO_SMALL;
        }
        buf->data[buf->len++] = 0x82;
        buf->data[buf->len++] = (uint8_t)(length >> 8);
        buf->data[buf->len++] = (uint8_t)(length & 0xFF);
    } else if (length < 16777216) {
        /* Long form: 0x83 followed by three bytes */
        if (buf->len + 4 > buf->capacity) {
            return COMPOSITE_ERR_BUFFER_TOO_SMALL;
        }
        buf->data[buf->len++] = 0x83;
        buf->data[buf->len++] = (uint8_t)(length >> 16);
        buf->data[buf->len++] = (uint8_t)((length >> 8) & 0xFF);
        buf->data[buf->len++] = (uint8_t)(length & 0xFF);
    } else {
        return COMPOSITE_ERR_ENCODE_FAILED;
    }

    return COMPOSITE_OK;
}

/* Get encoded length size */
static size_t get_length_size(size_t length) {
    if (length < 128) return 1;
    if (length < 256) return 2;
    if (length < 65536) return 3;
    if (length < 16777216) return 4;
    return 5;
}

/* Encode tag and length */
int asn1_encode_tag_length(asn1_buffer_t *buf, uint8_t tag, size_t length) {
    if (!buf || !buf->data) {
        return COMPOSITE_ERR_INVALID_INPUT;
    }

    if (buf->len + 1 > buf->capacity) {
        return COMPOSITE_ERR_BUFFER_TOO_SMALL;
    }

    buf->data[buf->len++] = tag;
    return asn1_encode_length(buf, length);
}

/* Encode INTEGER */
int asn1_encode_integer(asn1_buffer_t *buf, const uint8_t *value, size_t len) {
    if (!buf || !buf->data || !value || len == 0) {
        return COMPOSITE_ERR_INVALID_INPUT;
    }

    /* Skip leading zeros, but keep at least one byte */
    while (len > 1 && value[0] == 0) {
        value++;
        len--;
    }

    /* Add padding byte if high bit is set (to ensure positive) */
    int needs_padding = (value[0] & 0x80) != 0;
    size_t encoded_len = len + (needs_padding ? 1 : 0);

    int ret = asn1_encode_tag_length(buf, ASN1_INTEGER, encoded_len);
    if (ret != COMPOSITE_OK) {
        return ret;
    }

    if (buf->len + encoded_len > buf->capacity) {
        return COMPOSITE_ERR_BUFFER_TOO_SMALL;
    }

    if (needs_padding) {
        buf->data[buf->len++] = 0x00;
    }

    memcpy(buf->data + buf->len, value, len);
    buf->len += len;

    return COMPOSITE_OK;
}

/* Encode OCTET STRING */
int asn1_encode_octet_string(asn1_buffer_t *buf, const uint8_t *data, size_t len) {
    if (!buf || !buf->data || (!data && len > 0)) {
        return COMPOSITE_ERR_INVALID_INPUT;
    }

    int ret = asn1_encode_tag_length(buf, ASN1_OCTET_STRING, len);
    if (ret != COMPOSITE_OK) {
        return ret;
    }

    if (len > 0) {
        if (buf->len + len > buf->capacity) {
            return COMPOSITE_ERR_BUFFER_TOO_SMALL;
        }
        memcpy(buf->data + buf->len, data, len);
        buf->len += len;
    }

    return COMPOSITE_OK;
}

/* Encode BIT STRING */
int asn1_encode_bit_string(asn1_buffer_t *buf, const uint8_t *data, size_t len) {
    if (!buf || !buf->data || (!data && len > 0)) {
        return COMPOSITE_ERR_INVALID_INPUT;
    }

    /* BIT STRING has unused bits count as first byte (usually 0) */
    int ret = asn1_encode_tag_length(buf, ASN1_BIT_STRING, len + 1);
    if (ret != COMPOSITE_OK) {
        return ret;
    }

    if (buf->len + len + 1 > buf->capacity) {
        return COMPOSITE_ERR_BUFFER_TOO_SMALL;
    }

    buf->data[buf->len++] = 0x00;  /* No unused bits */

    if (len > 0) {
        memcpy(buf->data + buf->len, data, len);
        buf->len += len;
    }

    return COMPOSITE_OK;
}

/* Encode OID */
int asn1_encode_oid(asn1_buffer_t *buf, const uint8_t *oid, size_t oid_len) {
    if (!buf || !buf->data || !oid || oid_len == 0) {
        return COMPOSITE_ERR_INVALID_INPUT;
    }

    int ret = asn1_encode_tag_length(buf, ASN1_OID, oid_len);
    if (ret != COMPOSITE_OK) {
        return ret;
    }

    if (buf->len + oid_len > buf->capacity) {
        return COMPOSITE_ERR_BUFFER_TOO_SMALL;
    }

    memcpy(buf->data + buf->len, oid, oid_len);
    buf->len += oid_len;

    return COMPOSITE_OK;
}

/* Encode NULL */
int asn1_encode_null(asn1_buffer_t *buf) {
    if (!buf || !buf->data) {
        return COMPOSITE_ERR_INVALID_INPUT;
    }

    if (buf->len + 2 > buf->capacity) {
        return COMPOSITE_ERR_BUFFER_TOO_SMALL;
    }

    buf->data[buf->len++] = ASN1_NULL;
    buf->data[buf->len++] = 0x00;

    return COMPOSITE_OK;
}

/* Encode SEQUENCE (wrap existing content) */
int asn1_encode_sequence(asn1_buffer_t *buf, const uint8_t *content, size_t len) {
    if (!buf || !buf->data || (!content && len > 0)) {
        return COMPOSITE_ERR_INVALID_INPUT;
    }

    int ret = asn1_encode_tag_length(buf, ASN1_SEQUENCE, len);
    if (ret != COMPOSITE_OK) {
        return ret;
    }

    if (len > 0) {
        if (buf->len + len > buf->capacity) {
            return COMPOSITE_ERR_BUFFER_TOO_SMALL;
        }
        memcpy(buf->data + buf->len, content, len);
        buf->len += len;
    }

    return COMPOSITE_OK;
}

/*
 * ASN.1 Decoding Functions
 */

/* Decode tag */
int asn1_decode_tag(asn1_buffer_t *buf, uint8_t *tag) {
    if (!buf || !buf->data || !tag) {
        return COMPOSITE_ERR_INVALID_INPUT;
    }

    if (buf->pos >= buf->len) {
        return COMPOSITE_ERR_DECODE_FAILED;
    }

    *tag = buf->data[buf->pos++];
    return COMPOSITE_OK;
}

/* Decode length */
int asn1_decode_length(asn1_buffer_t *buf, size_t *length) {
    if (!buf || !buf->data || !length) {
        return COMPOSITE_ERR_INVALID_INPUT;
    }

    if (buf->pos >= buf->len) {
        return COMPOSITE_ERR_DECODE_FAILED;
    }

    uint8_t first = buf->data[buf->pos++];

    if (first < 128) {
        /* Short form */
        *length = first;
    } else {
        /* Long form */
        int num_bytes = first & 0x7F;
        if (num_bytes > 4 || buf->pos + num_bytes > buf->len) {
            return COMPOSITE_ERR_DECODE_FAILED;
        }

        *length = 0;
        for (int i = 0; i < num_bytes; i++) {
            *length = (*length << 8) | buf->data[buf->pos++];
        }
    }

    return COMPOSITE_OK;
}

/* Decode tag and length, verify expected tag */
int asn1_decode_tag_length(asn1_buffer_t *buf, uint8_t expected_tag, size_t *length) {
    uint8_t tag;
    int ret = asn1_decode_tag(buf, &tag);
    if (ret != COMPOSITE_OK) {
        return ret;
    }

    if (tag != expected_tag) {
        return COMPOSITE_ERR_INVALID_ASN1;
    }

    return asn1_decode_length(buf, length);
}

/* Decode INTEGER */
int asn1_decode_integer(asn1_buffer_t *buf, uint8_t *value, size_t *len, size_t max_len) {
    if (!buf || !value || !len) {
        return COMPOSITE_ERR_INVALID_INPUT;
    }

    size_t int_len;
    int ret = asn1_decode_tag_length(buf, ASN1_INTEGER, &int_len);
    if (ret != COMPOSITE_OK) {
        return ret;
    }

    if (buf->pos + int_len > buf->len) {
        return COMPOSITE_ERR_DECODE_FAILED;
    }

    /* Skip leading zero padding */
    const uint8_t *int_data = buf->data + buf->pos;
    if (int_len > 1 && int_data[0] == 0x00) {
        int_data++;
        int_len--;
    }

    if (int_len > max_len) {
        return COMPOSITE_ERR_BUFFER_TOO_SMALL;
    }

    memcpy(value, int_data, int_len);
    *len = int_len;
    buf->pos += (buf->data + buf->pos == int_data) ? int_len : int_len + 1;

    return COMPOSITE_OK;
}

/* Decode OCTET STRING */
int asn1_decode_octet_string(asn1_buffer_t *buf, uint8_t *data, size_t *len, size_t max_len) {
    if (!buf || !data || !len) {
        return COMPOSITE_ERR_INVALID_INPUT;
    }

    size_t os_len;
    int ret = asn1_decode_tag_length(buf, ASN1_OCTET_STRING, &os_len);
    if (ret != COMPOSITE_OK) {
        return ret;
    }

    if (os_len > max_len || buf->pos + os_len > buf->len) {
        return COMPOSITE_ERR_BUFFER_TOO_SMALL;
    }

    memcpy(data, buf->data + buf->pos, os_len);
    *len = os_len;
    buf->pos += os_len;

    return COMPOSITE_OK;
}

/* Decode BIT STRING */
int asn1_decode_bit_string(asn1_buffer_t *buf, uint8_t *data, size_t *len, size_t max_len) {
    if (!buf || !data || !len) {
        return COMPOSITE_ERR_INVALID_INPUT;
    }

    size_t bs_len;
    int ret = asn1_decode_tag_length(buf, ASN1_BIT_STRING, &bs_len);
    if (ret != COMPOSITE_OK) {
        return ret;
    }

    if (bs_len < 1 || buf->pos + bs_len > buf->len) {
        return COMPOSITE_ERR_DECODE_FAILED;
    }

    /* First byte is unused bits count */
    uint8_t unused_bits = buf->data[buf->pos++];
    bs_len--;

    if (bs_len > max_len) {
        return COMPOSITE_ERR_BUFFER_TOO_SMALL;
    }

    memcpy(data, buf->data + buf->pos, bs_len);
    *len = bs_len;
    buf->pos += bs_len;

    (void)unused_bits;  /* Could be used for partial byte handling */

    return COMPOSITE_OK;
}

/* Decode OID */
int asn1_decode_oid(asn1_buffer_t *buf, uint8_t *oid, size_t *len, size_t max_len) {
    if (!buf || !oid || !len) {
        return COMPOSITE_ERR_INVALID_INPUT;
    }

    size_t oid_len;
    int ret = asn1_decode_tag_length(buf, ASN1_OID, &oid_len);
    if (ret != COMPOSITE_OK) {
        return ret;
    }

    if (oid_len > max_len || buf->pos + oid_len > buf->len) {
        return COMPOSITE_ERR_BUFFER_TOO_SMALL;
    }

    memcpy(oid, buf->data + buf->pos, oid_len);
    *len = oid_len;
    buf->pos += oid_len;

    return COMPOSITE_OK;
}

/*
 * Algorithm Identifier Functions
 */

int get_algorithm_oid(algorithm_id_t alg, const uint8_t **oid, size_t *oid_len) {
    switch (alg) {
        case ALG_ED25519:
            *oid = oid_ed25519;
            *oid_len = sizeof(oid_ed25519);
            break;
        case ALG_ML_DSA_65:
            *oid = oid_ml_dsa_65;
            *oid_len = sizeof(oid_ml_dsa_65);
            break;
        case ALG_ECDSA_P256:
            *oid = oid_ecdsa_p256;
            *oid_len = sizeof(oid_ecdsa_p256);
            break;
        case ALG_ECDSA_P384:
            *oid = oid_ecdsa_p384;
            *oid_len = sizeof(oid_ecdsa_p384);
            break;
        case ALG_COMPOSITE_MLDSA65_ED25519:
            *oid = oid_composite_mldsa65_ed25519;
            *oid_len = sizeof(oid_composite_mldsa65_ed25519);
            break;
        default:
            return COMPOSITE_ERR_UNSUPPORTED_ALG;
    }
    return COMPOSITE_OK;
}

/* Encode AlgorithmIdentifier */
int encode_algorithm_identifier(asn1_buffer_t *buf, algorithm_id_t alg) {
    const uint8_t *oid;
    size_t oid_len;

    int ret = get_algorithm_oid(alg, &oid, &oid_len);
    if (ret != COMPOSITE_OK) {
        return ret;
    }

    /* Build inner content first */
    asn1_buffer_t inner;
    ret = asn1_buffer_init(&inner, 64);
    if (ret != COMPOSITE_OK) {
        return ret;
    }

    ret = asn1_encode_oid(&inner, oid, oid_len);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&inner);
        return ret;
    }

    /* Ed25519 has no parameters; others may have NULL or specific params */
    if (alg != ALG_ED25519 && alg != ALG_COMPOSITE_MLDSA65_ED25519) {
        ret = asn1_encode_null(&inner);
        if (ret != COMPOSITE_OK) {
            asn1_buffer_free(&inner);
            return ret;
        }
    }

    /* Wrap in SEQUENCE */
    ret = asn1_encode_sequence(buf, inner.data, inner.len);
    asn1_buffer_free(&inner);

    return ret;
}

/*
 * SubjectPublicKeyInfo Functions
 */

/* Encode simple (non-composite) SPKI */
int encode_spki(asn1_buffer_t *buf, const spki_t *spki) {
    if (!buf || !spki) {
        return COMPOSITE_ERR_INVALID_INPUT;
    }

    asn1_buffer_t inner;
    int ret = asn1_buffer_init(&inner, MAX_SPKI_SIZE);
    if (ret != COMPOSITE_OK) {
        return ret;
    }

    /* Algorithm identifier */
    ret = encode_algorithm_identifier(&inner, spki->algorithm);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&inner);
        return ret;
    }

    /* Subject public key as BIT STRING */
    ret = asn1_encode_bit_string(&inner, spki->public_key, spki->public_key_len);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&inner);
        return ret;
    }

    /* Wrap in SEQUENCE */
    ret = asn1_encode_sequence(buf, inner.data, inner.len);
    asn1_buffer_free(&inner);

    return ret;
}

/* Encode composite SPKI */
int encode_composite_spki(asn1_buffer_t *buf, const composite_keypair_t *keypair) {
    if (!buf || !keypair) {
        return COMPOSITE_ERR_INVALID_INPUT;
    }

    asn1_buffer_t inner, pk_seq;
    int ret;

    ret = asn1_buffer_init(&inner, MAX_SPKI_SIZE);
    if (ret != COMPOSITE_OK) {
        return ret;
    }

    ret = asn1_buffer_init(&pk_seq, MAX_SPKI_SIZE);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&inner);
        return ret;
    }

    /* Build CompositePublicKey SEQUENCE */
    /* First component: classical SPKI */
    spki_t classical_spki = {
        .algorithm = keypair->classical_alg,
        .public_key_len = keypair->classical_pk_len
    };
    memcpy((uint8_t *)classical_spki.public_key, keypair->classical_pk,
           keypair->classical_pk_len);

    asn1_buffer_t classical_buf;
    ret = asn1_buffer_init(&classical_buf, 256);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&inner);
        asn1_buffer_free(&pk_seq);
        return ret;
    }

    ret = encode_spki(&classical_buf, &classical_spki);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&inner);
        asn1_buffer_free(&pk_seq);
        asn1_buffer_free(&classical_buf);
        return ret;
    }

    /* Copy classical SPKI to pk_seq */
    if (pk_seq.len + classical_buf.len > pk_seq.capacity) {
        asn1_buffer_free(&inner);
        asn1_buffer_free(&pk_seq);
        asn1_buffer_free(&classical_buf);
        return COMPOSITE_ERR_BUFFER_TOO_SMALL;
    }
    memcpy(pk_seq.data + pk_seq.len, classical_buf.data, classical_buf.len);
    pk_seq.len += classical_buf.len;
    asn1_buffer_free(&classical_buf);

    /* Second component: PQC SPKI */
    spki_t pqc_spki = {
        .algorithm = keypair->pqc_alg,
        .public_key = keypair->pqc_pk,
        .public_key_len = keypair->pqc_pk_len
    };

    asn1_buffer_t pqc_buf;
    ret = asn1_buffer_init(&pqc_buf, 4096);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&inner);
        asn1_buffer_free(&pk_seq);
        return ret;
    }

    ret = encode_spki(&pqc_buf, &pqc_spki);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&inner);
        asn1_buffer_free(&pk_seq);
        asn1_buffer_free(&pqc_buf);
        return ret;
    }

    /* Copy PQC SPKI to pk_seq */
    if (pk_seq.len + pqc_buf.len > pk_seq.capacity) {
        asn1_buffer_free(&inner);
        asn1_buffer_free(&pk_seq);
        asn1_buffer_free(&pqc_buf);
        return COMPOSITE_ERR_BUFFER_TOO_SMALL;
    }
    memcpy(pk_seq.data + pk_seq.len, pqc_buf.data, pqc_buf.len);
    pk_seq.len += pqc_buf.len;
    asn1_buffer_free(&pqc_buf);

    /* Wrap public keys in SEQUENCE for CompositePublicKey */
    asn1_buffer_t composite_pk;
    ret = asn1_buffer_init(&composite_pk, MAX_SPKI_SIZE);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&inner);
        asn1_buffer_free(&pk_seq);
        return ret;
    }

    ret = asn1_encode_sequence(&composite_pk, pk_seq.data, pk_seq.len);
    asn1_buffer_free(&pk_seq);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&inner);
        asn1_buffer_free(&composite_pk);
        return ret;
    }

    /* Build outer SPKI */
    /* Algorithm identifier for composite */
    const uint8_t *oid;
    size_t oid_len;

    /* Determine composite OID based on algorithms */
    if (keypair->classical_alg == ALG_ED25519 && keypair->pqc_alg == ALG_ML_DSA_65) {
        oid = oid_composite_mldsa65_ed25519;
        oid_len = sizeof(oid_composite_mldsa65_ed25519);
    } else {
        asn1_buffer_free(&inner);
        asn1_buffer_free(&composite_pk);
        return COMPOSITE_ERR_UNSUPPORTED_ALG;
    }

    /* Build AlgorithmIdentifier for composite */
    asn1_buffer_t alg_id;
    ret = asn1_buffer_init(&alg_id, 64);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&inner);
        asn1_buffer_free(&composite_pk);
        return ret;
    }

    ret = asn1_encode_oid(&alg_id, oid, oid_len);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&inner);
        asn1_buffer_free(&composite_pk);
        asn1_buffer_free(&alg_id);
        return ret;
    }

    /* Wrap AlgorithmIdentifier in SEQUENCE */
    asn1_buffer_t alg_seq;
    ret = asn1_buffer_init(&alg_seq, 64);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&inner);
        asn1_buffer_free(&composite_pk);
        asn1_buffer_free(&alg_id);
        return ret;
    }

    ret = asn1_encode_sequence(&alg_seq, alg_id.data, alg_id.len);
    asn1_buffer_free(&alg_id);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&inner);
        asn1_buffer_free(&composite_pk);
        asn1_buffer_free(&alg_seq);
        return ret;
    }

    /* Copy algorithm identifier to inner */
    if (inner.len + alg_seq.len > inner.capacity) {
        asn1_buffer_free(&inner);
        asn1_buffer_free(&composite_pk);
        asn1_buffer_free(&alg_seq);
        return COMPOSITE_ERR_BUFFER_TOO_SMALL;
    }
    memcpy(inner.data + inner.len, alg_seq.data, alg_seq.len);
    inner.len += alg_seq.len;
    asn1_buffer_free(&alg_seq);

    /* Add public key as BIT STRING */
    ret = asn1_encode_bit_string(&inner, composite_pk.data, composite_pk.len);
    asn1_buffer_free(&composite_pk);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&inner);
        return ret;
    }

    /* Final SEQUENCE wrapper */
    ret = asn1_encode_sequence(buf, inner.data, inner.len);
    asn1_buffer_free(&inner);

    return ret;
}

/*
 * PKCS#8 Private Key Functions
 */

int encode_pkcs8_private_key(asn1_buffer_t *buf, const composite_keypair_t *keypair) {
    if (!buf || !keypair) {
        return COMPOSITE_ERR_INVALID_INPUT;
    }

    asn1_buffer_t inner;
    int ret = asn1_buffer_init(&inner, MAX_PKCS8_SIZE);
    if (ret != COMPOSITE_OK) {
        return ret;
    }

    /* Version: INTEGER 0 for v1, 1 for v2 (with public key) */
    uint8_t version = 1;  /* v2 to include public key */
    ret = asn1_encode_integer(&inner, &version, 1);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&inner);
        return ret;
    }

    /* Algorithm identifier */
    const uint8_t *oid;
    size_t oid_len;

    if (keypair->classical_alg == ALG_ED25519 && keypair->pqc_alg == ALG_ML_DSA_65) {
        oid = oid_composite_mldsa65_ed25519;
        oid_len = sizeof(oid_composite_mldsa65_ed25519);
    } else {
        asn1_buffer_free(&inner);
        return COMPOSITE_ERR_UNSUPPORTED_ALG;
    }

    asn1_buffer_t alg_id;
    ret = asn1_buffer_init(&alg_id, 64);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&inner);
        return ret;
    }

    ret = asn1_encode_oid(&alg_id, oid, oid_len);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&inner);
        asn1_buffer_free(&alg_id);
        return ret;
    }

    asn1_buffer_t alg_seq;
    ret = asn1_buffer_init(&alg_seq, 64);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&inner);
        asn1_buffer_free(&alg_id);
        return ret;
    }

    ret = asn1_encode_sequence(&alg_seq, alg_id.data, alg_id.len);
    asn1_buffer_free(&alg_id);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&inner);
        asn1_buffer_free(&alg_seq);
        return ret;
    }

    /* Copy algorithm identifier */
    if (inner.len + alg_seq.len > inner.capacity) {
        asn1_buffer_free(&inner);
        asn1_buffer_free(&alg_seq);
        return COMPOSITE_ERR_BUFFER_TOO_SMALL;
    }
    memcpy(inner.data + inner.len, alg_seq.data, alg_seq.len);
    inner.len += alg_seq.len;
    asn1_buffer_free(&alg_seq);

    /* Build CompositePrivateKey */
    asn1_buffer_t priv_seq;
    ret = asn1_buffer_init(&priv_seq, MAX_PKCS8_SIZE);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&inner);
        return ret;
    }

    /* Classical private key wrapped in OCTET STRING */
    ret = asn1_encode_octet_string(&priv_seq, keypair->classical_sk,
                                    keypair->classical_sk_len);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&inner);
        asn1_buffer_free(&priv_seq);
        return ret;
    }

    /* PQC private key wrapped in OCTET STRING */
    ret = asn1_encode_octet_string(&priv_seq, keypair->pqc_sk, keypair->pqc_sk_len);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&inner);
        asn1_buffer_free(&priv_seq);
        return ret;
    }

    /* Wrap in SEQUENCE */
    asn1_buffer_t composite_priv;
    ret = asn1_buffer_init(&composite_priv, MAX_PKCS8_SIZE);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&inner);
        asn1_buffer_free(&priv_seq);
        return ret;
    }

    ret = asn1_encode_sequence(&composite_priv, priv_seq.data, priv_seq.len);
    asn1_buffer_free(&priv_seq);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&inner);
        asn1_buffer_free(&composite_priv);
        return ret;
    }

    /* Wrap CompositePrivateKey in OCTET STRING */
    ret = asn1_encode_octet_string(&inner, composite_priv.data, composite_priv.len);
    asn1_buffer_free(&composite_priv);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&inner);
        return ret;
    }

    /* Optional: Add public key with context tag [1] */
    asn1_buffer_t pub_buf;
    ret = asn1_buffer_init(&pub_buf, MAX_SPKI_SIZE);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&inner);
        return ret;
    }

    ret = encode_composite_spki(&pub_buf, keypair);
    if (ret == COMPOSITE_OK) {
        /* Add with context tag [1] IMPLICIT BIT STRING */
        size_t pub_tag_len = 1 + get_length_size(pub_buf.len + 1) + 1 + pub_buf.len;
        if (inner.len + pub_tag_len <= inner.capacity) {
            inner.data[inner.len++] = ASN1_CONTEXT_1;  /* [1] */
            asn1_encode_length(&inner, pub_buf.len + 1);
            inner.data[inner.len++] = 0x00;  /* Unused bits */
            memcpy(inner.data + inner.len, pub_buf.data, pub_buf.len);
            inner.len += pub_buf.len;
        }
    }
    asn1_buffer_free(&pub_buf);

    /* Final SEQUENCE wrapper */
    ret = asn1_encode_sequence(buf, inner.data, inner.len);
    asn1_buffer_free(&inner);

    return ret;
}

/*
 * X.509 Certificate Functions
 */

/* Encode X.509 Name (simplified - just Common Name) */
static int encode_name(asn1_buffer_t *buf, const char *common_name) {
    asn1_buffer_t rdn, atv, inner;
    int ret;

    ret = asn1_buffer_init(&inner, 256);
    if (ret != COMPOSITE_OK) return ret;

    ret = asn1_buffer_init(&atv, 128);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&inner);
        return ret;
    }

    /* OID for Common Name */
    ret = asn1_encode_oid(&atv, oid_common_name, sizeof(oid_common_name));
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&inner);
        asn1_buffer_free(&atv);
        return ret;
    }

    /* UTF8String for value */
    size_t cn_len = strlen(common_name);
    ret = asn1_encode_tag_length(&atv, ASN1_UTF8_STRING, cn_len);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&inner);
        asn1_buffer_free(&atv);
        return ret;
    }

    if (atv.len + cn_len > atv.capacity) {
        asn1_buffer_free(&inner);
        asn1_buffer_free(&atv);
        return COMPOSITE_ERR_BUFFER_TOO_SMALL;
    }
    memcpy(atv.data + atv.len, common_name, cn_len);
    atv.len += cn_len;

    /* Wrap in SEQUENCE for AttributeTypeAndValue */
    ret = asn1_buffer_init(&rdn, 256);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&inner);
        asn1_buffer_free(&atv);
        return ret;
    }

    ret = asn1_encode_sequence(&rdn, atv.data, atv.len);
    asn1_buffer_free(&atv);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&inner);
        asn1_buffer_free(&rdn);
        return ret;
    }

    /* Wrap in SET for RelativeDistinguishedName */
    ret = asn1_encode_tag_length(&inner, ASN1_SET, rdn.len);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&inner);
        asn1_buffer_free(&rdn);
        return ret;
    }

    if (inner.len + rdn.len > inner.capacity) {
        asn1_buffer_free(&inner);
        asn1_buffer_free(&rdn);
        return COMPOSITE_ERR_BUFFER_TOO_SMALL;
    }
    memcpy(inner.data + inner.len, rdn.data, rdn.len);
    inner.len += rdn.len;
    asn1_buffer_free(&rdn);

    /* Wrap in SEQUENCE for Name */
    ret = asn1_encode_sequence(buf, inner.data, inner.len);
    asn1_buffer_free(&inner);

    return ret;
}

/* Encode Validity */
static int encode_validity(asn1_buffer_t *buf, int validity_days) {
    asn1_buffer_t inner;
    int ret;

    ret = asn1_buffer_init(&inner, 64);
    if (ret != COMPOSITE_OK) return ret;

    time_t now = time(NULL);
    struct tm *tm_now = gmtime(&now);

    /* notBefore - UTC Time */
    char time_str[16];
    strftime(time_str, sizeof(time_str), "%y%m%d%H%M%SZ", tm_now);
    size_t time_len = strlen(time_str);

    ret = asn1_encode_tag_length(&inner, ASN1_UTC_TIME, time_len);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&inner);
        return ret;
    }
    memcpy(inner.data + inner.len, time_str, time_len);
    inner.len += time_len;

    /* notAfter - UTC Time */
    time_t future = now + (validity_days * 24 * 60 * 60);
    struct tm *tm_future = gmtime(&future);
    strftime(time_str, sizeof(time_str), "%y%m%d%H%M%SZ", tm_future);

    ret = asn1_encode_tag_length(&inner, ASN1_UTC_TIME, time_len);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&inner);
        return ret;
    }
    memcpy(inner.data + inner.len, time_str, time_len);
    inner.len += time_len;

    /* Wrap in SEQUENCE */
    ret = asn1_encode_sequence(buf, inner.data, inner.len);
    asn1_buffer_free(&inner);

    return ret;
}

/* Encode basic extensions for self-signed CA certificate */
static int encode_extensions(asn1_buffer_t *buf) {
    asn1_buffer_t exts, ext, inner;
    int ret;

    ret = asn1_buffer_init(&exts, 512);
    if (ret != COMPOSITE_OK) return ret;

    ret = asn1_buffer_init(&ext, 128);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&exts);
        return ret;
    }

    /* Basic Constraints: CA=TRUE */
    ret = asn1_buffer_init(&inner, 64);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&exts);
        asn1_buffer_free(&ext);
        return ret;
    }

    /* Extension OID */
    ret = asn1_encode_oid(&ext, oid_basic_constraints, sizeof(oid_basic_constraints));
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&exts);
        asn1_buffer_free(&ext);
        asn1_buffer_free(&inner);
        return ret;
    }

    /* Critical = TRUE */
    uint8_t bool_true[] = {0x01, 0x01, 0xFF};
    if (ext.len + sizeof(bool_true) > ext.capacity) {
        asn1_buffer_free(&exts);
        asn1_buffer_free(&ext);
        asn1_buffer_free(&inner);
        return COMPOSITE_ERR_BUFFER_TOO_SMALL;
    }
    memcpy(ext.data + ext.len, bool_true, sizeof(bool_true));
    ext.len += sizeof(bool_true);

    /* Extension value: SEQUENCE { BOOLEAN TRUE } */
    uint8_t bc_value[] = {0x30, 0x03, 0x01, 0x01, 0xFF};
    ret = asn1_encode_octet_string(&ext, bc_value, sizeof(bc_value));
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&exts);
        asn1_buffer_free(&ext);
        asn1_buffer_free(&inner);
        return ret;
    }

    /* Wrap extension in SEQUENCE */
    ret = asn1_encode_sequence(&exts, ext.data, ext.len);
    asn1_buffer_free(&ext);
    asn1_buffer_free(&inner);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&exts);
        return ret;
    }

    /* Wrap all extensions in SEQUENCE */
    asn1_buffer_t ext_seq;
    ret = asn1_buffer_init(&ext_seq, 512);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&exts);
        return ret;
    }

    ret = asn1_encode_sequence(&ext_seq, exts.data, exts.len);
    asn1_buffer_free(&exts);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&ext_seq);
        return ret;
    }

    /* Add context tag [3] for extensions */
    ret = asn1_encode_tag_length(buf, ASN1_CONTEXT_3, ext_seq.len);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&ext_seq);
        return ret;
    }

    if (buf->len + ext_seq.len > buf->capacity) {
        asn1_buffer_free(&ext_seq);
        return COMPOSITE_ERR_BUFFER_TOO_SMALL;
    }
    memcpy(buf->data + buf->len, ext_seq.data, ext_seq.len);
    buf->len += ext_seq.len;
    asn1_buffer_free(&ext_seq);

    return COMPOSITE_OK;
}

/* Encode TBSCertificate */
int encode_tbs_certificate(asn1_buffer_t *buf, const tbs_certificate_t *tbs) {
    asn1_buffer_t inner;
    int ret;

    ret = asn1_buffer_init(&inner, MAX_CERT_SIZE);
    if (ret != COMPOSITE_OK) return ret;

    /* Version [0] EXPLICIT INTEGER */
    uint8_t version = (uint8_t)tbs->version;
    asn1_buffer_t ver_buf;
    ret = asn1_buffer_init(&ver_buf, 8);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&inner);
        return ret;
    }

    ret = asn1_encode_integer(&ver_buf, &version, 1);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&inner);
        asn1_buffer_free(&ver_buf);
        return ret;
    }

    ret = asn1_encode_tag_length(&inner, ASN1_CONTEXT_0, ver_buf.len);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&inner);
        asn1_buffer_free(&ver_buf);
        return ret;
    }
    memcpy(inner.data + inner.len, ver_buf.data, ver_buf.len);
    inner.len += ver_buf.len;
    asn1_buffer_free(&ver_buf);

    /* Serial Number */
    ret = asn1_encode_integer(&inner, tbs->serial_number, tbs->serial_len);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&inner);
        return ret;
    }

    /* Signature Algorithm */
    ret = encode_algorithm_identifier(&inner, tbs->signature_alg);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&inner);
        return ret;
    }

    /* Issuer Name */
    ret = encode_name(&inner, tbs->issuer[0].value);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&inner);
        return ret;
    }

    /* Validity */
    ret = encode_validity(&inner, 365);  /* Default 1 year */
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&inner);
        return ret;
    }

    /* Subject Name */
    ret = encode_name(&inner, tbs->subject[0].value);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&inner);
        return ret;
    }

    /* Subject Public Key Info */
    asn1_buffer_t spki_buf;
    ret = asn1_buffer_init(&spki_buf, MAX_SPKI_SIZE);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&inner);
        return ret;
    }

    ret = encode_spki(&spki_buf, &tbs->subject_pki);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&inner);
        asn1_buffer_free(&spki_buf);
        return ret;
    }

    if (inner.len + spki_buf.len > inner.capacity) {
        asn1_buffer_free(&inner);
        asn1_buffer_free(&spki_buf);
        return COMPOSITE_ERR_BUFFER_TOO_SMALL;
    }
    memcpy(inner.data + inner.len, spki_buf.data, spki_buf.len);
    inner.len += spki_buf.len;
    asn1_buffer_free(&spki_buf);

    /* Extensions */
    if (tbs->version >= 2) {
        ret = encode_extensions(&inner);
        if (ret != COMPOSITE_OK) {
            asn1_buffer_free(&inner);
            return ret;
        }
    }

    /* Wrap in SEQUENCE */
    ret = asn1_encode_sequence(buf, inner.data, inner.len);
    asn1_buffer_free(&inner);

    return ret;
}

/* Encode complete certificate */
int encode_certificate(asn1_buffer_t *buf, const certificate_t *cert) {
    asn1_buffer_t inner;
    int ret;

    ret = asn1_buffer_init(&inner, MAX_CERT_SIZE);
    if (ret != COMPOSITE_OK) return ret;

    /* TBSCertificate (already encoded) */
    if (inner.len + cert->tbs_der_len > inner.capacity) {
        asn1_buffer_free(&inner);
        return COMPOSITE_ERR_BUFFER_TOO_SMALL;
    }
    memcpy(inner.data + inner.len, cert->tbs_der, cert->tbs_der_len);
    inner.len += cert->tbs_der_len;

    /* Signature Algorithm */
    ret = encode_algorithm_identifier(&inner, cert->signature_alg);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&inner);
        return ret;
    }

    /* Signature Value */
    ret = asn1_encode_bit_string(&inner, cert->signature, cert->signature_len);
    if (ret != COMPOSITE_OK) {
        asn1_buffer_free(&inner);
        return ret;
    }

    /* Wrap in SEQUENCE */
    ret = asn1_encode_sequence(buf, inner.data, inner.len);
    asn1_buffer_free(&inner);

    return ret;
}

/*
 * Composite Key Management
 */

int composite_keypair_init(composite_keypair_t *keypair,
                           algorithm_id_t classical, algorithm_id_t pqc) {
    if (!keypair) {
        return COMPOSITE_ERR_INVALID_INPUT;
    }

    memset(keypair, 0, sizeof(*keypair));
    keypair->classical_alg = classical;
    keypair->pqc_alg = pqc;

    /* Allocate PQC key buffers based on algorithm */
    switch (pqc) {
        case ALG_ML_DSA_65:
            keypair->pqc_pk = malloc(MLDSA65_PK_SIZE);
            keypair->pqc_sk = malloc(MLDSA65_SK_SIZE);
            if (!keypair->pqc_pk || !keypair->pqc_sk) {
                free(keypair->pqc_pk);
                free(keypair->pqc_sk);
                return COMPOSITE_ERR_BUFFER_TOO_SMALL;
            }
            keypair->pqc_pk_len = MLDSA65_PK_SIZE;
            keypair->pqc_sk_len = MLDSA65_SK_SIZE;
            break;
        default:
            return COMPOSITE_ERR_UNSUPPORTED_ALG;
    }

    /* Set classical key sizes */
    switch (classical) {
        case ALG_ED25519:
            keypair->classical_pk_len = ED25519_PK_SIZE;
            keypair->classical_sk_len = ED25519_SK_SIZE;
            break;
        default:
            free(keypair->pqc_pk);
            free(keypair->pqc_sk);
            return COMPOSITE_ERR_UNSUPPORTED_ALG;
    }

    return COMPOSITE_OK;
}

void composite_keypair_free(composite_keypair_t *keypair) {
    if (keypair) {
        /* Securely clear sensitive data */
        memset(keypair->classical_sk, 0, sizeof(keypair->classical_sk));
        if (keypair->pqc_sk) {
            memset(keypair->pqc_sk, 0, keypair->pqc_sk_len);
            free(keypair->pqc_sk);
        }
        if (keypair->pqc_pk) {
            free(keypair->pqc_pk);
        }
        memset(keypair, 0, sizeof(*keypair));
    }
}

/*
 * PEM Encoding/Decoding
 */

int der_to_pem(const uint8_t *der, size_t der_len,
               const char *label, char *pem, size_t *pem_len) {
    if (!der || !label || !pem || !pem_len) {
        return COMPOSITE_ERR_INVALID_INPUT;
    }

    /* Calculate required PEM size */
    size_t b64_len = ((der_len + 2) / 3) * 4;
    size_t line_breaks = (b64_len + 63) / 64;
    size_t header_len = strlen("-----BEGIN -----\n") + strlen(label);
    size_t footer_len = strlen("-----END -----\n") + strlen(label);
    size_t total_len = header_len + b64_len + line_breaks + footer_len + 1;

    if (*pem_len < total_len) {
        *pem_len = total_len;
        return COMPOSITE_ERR_BUFFER_TOO_SMALL;
    }

    /* Write header */
    int pos = snprintf(pem, *pem_len, "-----BEGIN %s-----\n", label);

    /* Base64 encode with line breaks */
    size_t line_pos = 0;
    for (size_t i = 0; i < der_len; i += 3) {
        uint32_t n = ((uint32_t)der[i] << 16);
        if (i + 1 < der_len) n |= ((uint32_t)der[i + 1] << 8);
        if (i + 2 < der_len) n |= der[i + 2];

        pem[pos++] = base64_table[(n >> 18) & 0x3F];
        pem[pos++] = base64_table[(n >> 12) & 0x3F];
        pem[pos++] = (i + 1 < der_len) ? base64_table[(n >> 6) & 0x3F] : '=';
        pem[pos++] = (i + 2 < der_len) ? base64_table[n & 0x3F] : '=';

        line_pos += 4;
        if (line_pos >= 64) {
            pem[pos++] = '\n';
            line_pos = 0;
        }
    }

    if (line_pos > 0) {
        pem[pos++] = '\n';
    }

    /* Write footer */
    pos += snprintf(pem + pos, *pem_len - pos, "-----END %s-----\n", label);

    *pem_len = pos;
    pem[pos] = '\0';

    return COMPOSITE_OK;
}

/*
 * Test/Example Functions
 */

/* Create test composite keypair with dummy data */
int create_test_composite_keypair(composite_keypair_t *keypair) {
    int ret = composite_keypair_init(keypair, ALG_ED25519, ALG_ML_DSA_65);
    if (ret != COMPOSITE_OK) {
        return ret;
    }

    /* Fill with deterministic test data (NOT for production!) */
    for (size_t i = 0; i < keypair->classical_pk_len; i++) {
        keypair->classical_pk[i] = (uint8_t)(i & 0xFF);
    }
    for (size_t i = 0; i < keypair->classical_sk_len; i++) {
        keypair->classical_sk[i] = (uint8_t)((i + 0x80) & 0xFF);
    }
    for (size_t i = 0; i < keypair->pqc_pk_len; i++) {
        keypair->pqc_pk[i] = (uint8_t)((i * 3) & 0xFF);
    }
    for (size_t i = 0; i < keypair->pqc_sk_len; i++) {
        keypair->pqc_sk[i] = (uint8_t)((i * 5 + 0x40) & 0xFF);
    }

    return COMPOSITE_OK;
}

/* Demonstration: encode composite keys */
void demo_composite_encoding(void) {
    composite_keypair_t keypair;
    asn1_buffer_t buf;
    char pem[16384];
    size_t pem_len;

    printf("=== Composite Key Encoding Demo ===\n\n");

    /* Create test keypair */
    if (create_test_composite_keypair(&keypair) != COMPOSITE_OK) {
        printf("Failed to create keypair\n");
        return;
    }

    /* Encode SPKI */
    if (asn1_buffer_init(&buf, MAX_SPKI_SIZE) != COMPOSITE_OK) {
        composite_keypair_free(&keypair);
        return;
    }

    if (encode_composite_spki(&buf, &keypair) == COMPOSITE_OK) {
        printf("Composite SPKI encoded: %zu bytes\n", buf.len);

        pem_len = sizeof(pem);
        if (der_to_pem(buf.data, buf.len, "PUBLIC KEY", pem, &pem_len) == COMPOSITE_OK) {
            printf("\n%s\n", pem);
        }
    }
    asn1_buffer_free(&buf);

    /* Encode PKCS#8 */
    if (asn1_buffer_init(&buf, MAX_PKCS8_SIZE) != COMPOSITE_OK) {
        composite_keypair_free(&keypair);
        return;
    }

    if (encode_pkcs8_private_key(&buf, &keypair) == COMPOSITE_OK) {
        printf("PKCS#8 private key encoded: %zu bytes\n", buf.len);

        pem_len = sizeof(pem);
        if (der_to_pem(buf.data, buf.len, "PRIVATE KEY", pem, &pem_len) == COMPOSITE_OK) {
            printf("\n%s\n", pem);
        }
    }
    asn1_buffer_free(&buf);

    composite_keypair_free(&keypair);
}
