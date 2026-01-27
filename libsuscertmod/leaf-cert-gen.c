#include "leaf-cert.h"
#include "certmod.h"
#include "key-desc.h"
#include "certs/certs.h"
#include "keymaster-types.h"
#include <suscertsign.h>
#include <core/log.h>
#include <core/util.h>
#include <core/vector.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <openssl/obj_mac.h>
#include <stdlib.h>
#include <string.h>

#define MODULE_NAME "leaf-cert"

static ASN1_TIME *get_notbefore(const struct KM_KeyDescription_v3 *desc);
static ASN1_TIME *get_notafter(const struct KM_KeyDescription_v3 *desc,
        enum sus_cert_chain_variant signing_key_variant);

static u8 get_keyusage_bits(const struct KM_KeyDescription_v3 *desc);

static VECTOR(u8) construct_x509_der(
        const unsigned char *tbs_der, unsigned long tbs_der_len,
        const unsigned char *sig_alg, unsigned long sig_alg_len,
        unsigned char *sig, unsigned long sig_len
);

static unsigned long get_bitstr_tl_length(unsigned long content_len);
static void encode_bitstr_tl(unsigned char **p, unsigned long content_len);

i32 leaf_cert_gen(VECTOR(u8) *out,
        enum sus_cert_chain_variant signing_key_variant,
        EVP_PKEY *subj_pubkey,
        const struct KM_KeyDescription_v3 *km_desc
)
{
    if ((signing_key_variant != SUS_CERT_CHAIN_EC &&
        signing_key_variant != SUS_CERT_CHAIN_RSA) ||
        (subj_pubkey == NULL) ||
        (km_desc == NULL))
    {
        s_log_error("Invalid parameters!");
        return -1;
    }

    if (out != NULL) *out = NULL;

    /* See:
     * https://source.android.com/docs/security/features/keystore/attestation#certificate-sequence
     */

    X509 *x509 = NULL;
    ASN1_OCTET_STRING *key_desc_str = NULL;

    ASN1_INTEGER *serial = NULL;
    X509_ALGOR *tbs_sig_alg = NULL;
    X509_NAME *issuer = NULL, *subject = NULL;
    ASN1_TIME *not_before = NULL, *not_after = NULL;

    u8 key_usage_bits = 0;
    ASN1_BIT_STRING *key_usage_val = NULL;
    X509_EXTENSION *key_usage_ext = NULL;

    ASN1_OBJECT *km_ext_obj = NULL;
    X509_EXTENSION *km_ext = NULL;

    unsigned char *tbs_der = NULL;
    long tbs_der_len = 0;

    X509_ALGOR *sig_alg = NULL;
    unsigned char *sig_alg_der = NULL;
    long sig_alg_len = 0;

    unsigned char *sig = NULL;
    unsigned long sig_len = 0;

    VECTOR(u8) ret = NULL;

    key_desc_str = key_desc_repack(km_desc);
    if (key_desc_str == NULL) {
        s_log_error("Failed to repack the key description");
        return 1;
    }

    x509 = X509_new();
    if (x509 == NULL)
        goto_error("Couldn't allocate the X509 cert structure");

    /* Version must be 3 */
    if (X509_set_version(x509, X509_VERSION_3) == 0)
        goto_error("Couldn't set the X509 version to 3");

    /* All Android Attestation certs must have serial `1` */
    serial = ASN1_INTEGER_new();
    if (serial == NULL)
        goto_error("Couldn't allocate the ASN.1 INTEGER for the X509 serial");

    if (ASN1_INTEGER_set_int64(serial, 1) == 0)
        goto_error("Couldn't set the value of the X509 serial ASN.1 INTEGER");

    if (X509_set_serialNumber(x509, serial) == 0)
        goto_error("Couldn't set the X509 serial number");

    ASN1_INTEGER_free(serial);
    serial = NULL;

    /* Set the appropriate signature algorithm */
    const i32 sig_nid = signing_key_variant == SUS_CERT_CHAIN_RSA ?
        NID_sha256WithRSAEncryption : NID_ecdsa_with_SHA256;

    /* openssl unfortunately doesn't provide us
     * with a way to do this cleanly :( */
    tbs_sig_alg = ((X509_ALGOR *)X509_get0_tbs_sigalg(x509));
    if (X509_ALGOR_set0(tbs_sig_alg, OBJ_nid2obj(sig_nid),
                V_ASN1_NULL, NULL) == 0)
        goto_error("Couldn't set the TBS signature algorithm");

    tbs_sig_alg = NULL;

    /* Set the issuer to whatever is in the top-most cert */
    issuer = X509_NAME_new();
    if (issuer == NULL)
        goto_error("Couldn't allocate an X509_NAME for the issuer");

    /* add the standard "TEE" issuer */
    if (X509_NAME_add_entry_by_NID(issuer, NID_title, V_ASN1_UTF8STRING,
                (const unsigned char *)"TEE", -1, -1, 0) == 0)
        goto_error("Couldn't add the issuer name entry");

    /* add the issuer's (top-most cert's) serial number */
    const unsigned char *const issuer_serial_str =
        signing_key_variant == SUS_CERT_CHAIN_RSA ?
            (const unsigned char *)cert_chain_rsa_top_issuer_serial :
            (const unsigned char *)cert_chain_ec_top_issuer_serial;

    if (X509_NAME_add_entry_by_NID(issuer, NID_serialNumber,
                V_ASN1_PRINTABLESTRING, issuer_serial_str, -1, -1, 0) == 0)
        goto_error("Couldn't add the issuer serial entry");

    /* append the whole issuer sequence to the cert */
    if (X509_set_issuer_name(x509, issuer) == 0)
        goto_error("Couldn't set the X509 issuer");

    X509_NAME_free(issuer);
    issuer = NULL;

    /* Set the cert validity */
    not_before = get_notbefore(km_desc);
    if (not_before == NULL)
        goto_error("Couldn't determine the correct value for `notBefore`");

    if (X509_set1_notBefore(x509, not_before) == 0)
        goto_error("Couldn't set the X509 `notBefore` field");

    ASN1_TIME_free(not_before);
    not_before = NULL;

    not_after = get_notafter(km_desc, signing_key_variant);
    if (not_after == NULL)
        goto_error("Couldn't determine the correct value for `notAfter`");

    if (X509_set1_notAfter(x509, not_after) == 0)
        goto_error("Couldn't set the X509 'notAfter' field");

    ASN1_TIME_free(not_after);
    not_after = NULL;


    /* Set the subject CN to "Android Keystore Key", as required by the spec */
    subject = X509_NAME_new();
    if (subject == NULL)
        goto_error("Couldn't allocate an X509_NAME for the subject");

    if (X509_NAME_add_entry_by_NID(subject, NID_commonName, V_ASN1_UTF8STRING,
                (const unsigned char *)"Android Keystore Key", -1, -1, 0) == 0)
        goto_error("Couldn't set the subject common-name field");

    if (X509_set_subject_name(x509, subject) == 0)
        goto_error("Couldn't set the X509 subject");

    /* Set the subjectPublicKeyInfo (the attested public key) */
    if (X509_set_pubkey(x509, subj_pubkey) == 0)
        goto_error("Couldn't set the subject public key");

    /* Set `keyUsage` = `digitalSignature` if the key has
     * `KM_PURPOSE_SIGN` or `KM_PURPOSE_VERIFY` */
    key_usage_bits = get_keyusage_bits(km_desc);

    key_usage_val = ASN1_BIT_STRING_new();
    if (key_usage_val == NULL)
        goto_error("Couldn't allocate a new ASN.1 BIT STRING");

    if (ASN1_BIT_STRING_set(key_usage_val, &key_usage_bits, 1) == 0)
        goto_error("Couldn't set the value of an ASN.1 BIT STRING");

    key_usage_ext = X509_EXTENSION_create_by_NID(NULL, NID_key_usage,
            false, key_usage_val);
    if (key_usage_ext == NULL)
        goto_error("Couldn't allocate the Key Usage X509 extension");
    key_usage_val = NULL;

    if (X509_add_ext(x509, key_usage_ext, -1) == 0)
        goto_error("Couldn't add the X509 Key Usage extension to the cert");

    X509_EXTENSION_free(key_usage_ext);
    key_usage_ext = NULL;


    /* Set the android attestation extension */
    km_ext_obj = OBJ_txt2obj(KM_kAttestionRecordOid, 1);
    if (km_ext_obj == NULL)
        goto_error("Couldn't create the KM Attestation Record OID");

    km_ext = X509_EXTENSION_create_by_OBJ(NULL, km_ext_obj, false,
            key_desc_str);
    if (km_ext == NULL)
        goto_error("Couldn't create the Android Attestation Extension");
    key_desc_str = NULL;

    ASN1_OBJECT_free(km_ext_obj);
    km_ext_obj = NULL;

    if (X509_add_ext(x509, km_ext, -1) == 0)
        goto_error("Couldn't add the Android Attestation Extension "
                "to the cert");
    X509_EXTENSION_free(km_ext);
    km_ext = NULL;

    /** Construct the outer X509 certificate sequence **/

    /* Serialize the TBS part of the cert */
    tbs_der_len = i2d_re_X509_tbs(x509, &tbs_der);
    if (tbs_der_len <= 0)
        goto_error("Couldn't serialize the X509 To-Be-Signed certificate");

    X509_free(x509);
    x509 = NULL;

    /* Create the signature algorithm sequence */
    sig_alg = X509_ALGOR_new();
    if (sig_alg == NULL)
        goto_error("Couldn't allocate a new X509 ALGOR structure");

    if (X509_ALGOR_set0(sig_alg, OBJ_nid2obj(sig_nid), V_ASN1_NULL, NULL) == 0)
        goto_error("Couldn't set the outer signature algorithm");

    sig_alg_len = i2d_X509_ALGOR(sig_alg, &sig_alg_der);
    if (sig_alg_len <= 0)
        goto_error("Couldn't serialize the X509 signature algorithm sequence");

    X509_ALGOR_free(sig_alg);
    sig_alg = NULL;

    /* Generate the signature (over TBS) */
    const int ec_or_rsa = signing_key_variant == SUS_CERT_CHAIN_RSA ?
            SUS_CERT_SIGN_RSA : SUS_CERT_SIGN_EC;
    if (sus_cert_sign(tbs_der, tbs_der_len, &sig, &sig_len, ec_or_rsa))
        goto_error("Couldn't to sign the X509 cert");


    /* Finally, glue everything together */
    ret = construct_x509_der(tbs_der, tbs_der_len,
            sig_alg_der, sig_alg_len, sig, sig_len);
    if (ret == NULL)
        goto_error("Couldn't construct the final X509 certificate sequence");

    *out = ret;
    return 0;

err:
    /* `ret` need not be freed under any circumstances */

    if (sig != NULL) {
        free(sig);
        sig = NULL;
    }
    if (sig_alg != NULL) {
        X509_ALGOR_free(sig_alg);
        sig_alg = NULL;
    }
    if (sig_alg_der != NULL) {
        OPENSSL_free(sig_alg_der);
        sig_alg_der = NULL;
    }
    if (tbs_der != NULL) {
        free(tbs_der);
        tbs_der = NULL;
    }

    if (km_ext != NULL) {
        X509_EXTENSION_free(km_ext);
        km_ext = NULL;
    }
    if (km_ext_obj != NULL) {
        ASN1_OBJECT_free(km_ext_obj);
        km_ext_obj = NULL;
    }
    if (key_usage_ext != NULL) {
        X509_EXTENSION_free(key_usage_ext);
        key_usage_ext = NULL;
    }
    if (key_usage_val != NULL) {
        ASN1_BIT_STRING_free(key_usage_val);
        key_usage_val = NULL;
    }
    if (subject != NULL) {
        X509_NAME_free(subject);
        subject = NULL;
    }
    if (not_after != NULL) {
        ASN1_TIME_free(not_after);
        not_after = NULL;
    }
    if (not_before != NULL) {
        ASN1_TIME_free(not_before);
        not_before = NULL;
    }
    if (issuer != NULL) {
        X509_NAME_free(issuer);
        issuer = NULL;
    }
    if (serial != NULL) {
        ASN1_INTEGER_free(serial);
        serial = NULL;
    }
    if (key_desc_str != NULL) {
        ASN1_OCTET_STRING_free(key_desc_str);
        key_desc_str = NULL;
    }
    if (x509 != NULL) {
        X509_free(x509);
        x509 = NULL;
    }

    s_log_error("Failed to generate the X509 cert");
    return -1;
}

static ASN1_TIME *get_notbefore(const struct KM_KeyDescription_v3 *desc)
{
    ASN1_TIME *ret = NULL;

    ret = ASN1_TIME_new();
    if (ret == NULL) {
        s_log_error("Failed to allocate a new ASN.1 TIME object!");
        return NULL;
    }

    /* hw activeDateTime -> sw activeDateTime ->
     * hw creationDateTime -> sw creationDateTime */

    time_t time = 0;
    if (desc->hardwareEnforced.__activeDateTime_present) {
        time = desc->hardwareEnforced.activeDateTime / 1000;
    } else if (desc->softwareEnforced.__activeDateTime_present) {
        time = desc->softwareEnforced.activeDateTime / 1000;
    } else if (desc->hardwareEnforced.__creationDateTime_present) {
        time = desc->hardwareEnforced.creationDateTime / 1000;
    } else if (desc->softwareEnforced.__creationDateTime_present) {
        time = desc->softwareEnforced.creationDateTime / 1000;
    } else {
        s_log_warn("No activeDateTime or creationDateTime in key description; "
                "setting `notBefore` to 0 (Jan 1 1970)");
        time = 0;
    }

    if (ASN1_TIME_set(ret, time) == 0) {
        s_log_error("Couldn't set the value of an ASN.1 TIME object!");
        ASN1_TIME_free(ret);
        return NULL;
    }

    return ret;
}

static ASN1_TIME *get_notafter(const struct KM_KeyDescription_v3 *desc,
        enum sus_cert_chain_variant signing_key_variant)
{
    ASN1_TIME *ret = NULL;

    ret = ASN1_TIME_new();
    if (ret == NULL) {
        s_log_error("Failed to allocate a new ASN.1 TIME object!");
        return NULL;
    }

    /* hw usageExpireDateTime -> sw usageExpireDateTime ->
     * top-most attestation cert notAfter */

    time_t time = 0;
    if (desc->hardwareEnforced.__usageExpireDateTime_present) {
        time = desc->hardwareEnforced.usageExpireDateTime / 1000;
    } else if (desc->softwareEnforced.__usageExpireDateTime_present) {
        time = desc->softwareEnforced.usageExpireDateTime / 1000;
    } else {
        s_log_warn("No usageExpireDateTime present in key description; "
                "setting `notAfter` to the expiration date of the "
                "attestation batch key certificate");
        time = signing_key_variant == SUS_CERT_CHAIN_RSA ?
            cert_chain_rsa_not_after :
            cert_chain_ec_not_after;
    }

    if (ASN1_TIME_set(ret, time) == 0) {
        s_log_error("Couldn't set the value of an ASN.1 TIME object!");
        ASN1_TIME_free(ret);
        return NULL;
    }

    return ret;
}

static u8 get_keyusage_bits(const struct KM_KeyDescription_v3 *desc)
{
    VECTOR(enum KM_KeyPurpose) hw_purpose = desc->hardwareEnforced.purpose;
    VECTOR(enum KM_KeyPurpose) sw_purpose = desc->softwareEnforced.purpose;

    for (u32 i = 0; i < vector_size(hw_purpose); i++) {
        if (hw_purpose[i] == KM_PURPOSE_SIGN ||
                hw_purpose[i] == KM_PURPOSE_VERIFY)
        {
            return 0x80; /* KU_DIGITAL_SIGNATURE */
        }
    }

    for (u32 i = 0; i < vector_size(sw_purpose); i++) {
        if (sw_purpose[i] == KM_PURPOSE_SIGN ||
                sw_purpose[i] == KM_PURPOSE_VERIFY)
        {
            return 0x80; /* KU_DIGITAL_SIGNATURE */
        }
    }

    return 0x0;
}

static VECTOR(u8) construct_x509_der(
        const unsigned char *tbs_der, unsigned long tbs_der_len,
        const unsigned char *sig_alg, unsigned long sig_alg_len,
        unsigned char *sig, unsigned long sig_len
)
{
    long sig_str_len = 0;
    VECTOR(u8) ret = NULL;
    unsigned char *p = NULL;

    /* First wrap the signature in a BIT_STRING */

    sig_str_len = get_bitstr_tl_length(sig_len) + sig_len;
    if (sig_str_len <= 3)
        goto_error("Invalid size of signature bit string: %d", sig_str_len);

    /* Allocate buffer */
    const u64 inner_length = tbs_der_len + sig_alg_len + sig_str_len;
    const u64 outer_length =
        ASN1_object_size(true, inner_length, V_ASN1_SEQUENCE);

    ret = vector_new(u8);
    vector_resize(&ret, outer_length);

    /* Put the raw bytes */

    p = ret;

    ASN1_put_object(&p, true, inner_length, V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL);

    memcpy(p, tbs_der, tbs_der_len);
    p += tbs_der_len;

    memcpy(p, sig_alg, sig_alg_len);
    p += sig_alg_len;

    encode_bitstr_tl(&p, sig_len);
    memcpy(p, sig, sig_len);
    p += sig_len;

    u8 *const end = ret + outer_length;
    if (p != end) {
        goto_error("Wrote an incorrect amount of bytes (p: %p, end: %p)",
                p, end);
    }

    return ret;

err:
    if (ret != NULL)
        vector_destroy(&ret);

    return NULL;
}

static unsigned long get_bitstr_tl_length(unsigned long content_len)
{
    content_len++; /* count the unused bits field */

    if (content_len <= 127)
        return 3; /* TAG | LENGTH | UNUSED BITS */

    u8 lensz = 0;
    do {
        lensz++;
        content_len >>= 8;
    } while (content_len != 0);

    return 2 + lensz + 1; /* TAG | LENSZ | <LEN> | UNUSED BITS */
}

static void encode_bitstr_tl(unsigned char **p, unsigned long content_len)
{
    /* TAG */
    **p = (u8)V_ASN1_BIT_STRING;
    (*p)++;

    /* LENGTH */
    content_len++; /* count the unused bits field */

    if (content_len <= 127) {
        /* Short-form length */
        **p = (u8)(content_len & 0x7f);
        (*p)++;
    } else {
        /* Long-form length */
        u8 lensz = 0;
        unsigned long len = content_len;
        do {
            lensz++;
            len >>= 8;
        } while (len != 0);

        /* LENGTH SIZE */
        **p = 0x80 | lensz;
        (*p)++;

        /* LENGTH (Big endian) */
        for (int i = lensz - 1; i >= 0; i--) {
            (*p)[1 + (lensz - 1 - i)] = (lensz >> (8*i)) & 0xFF;
        }
        *p += lensz;
    }

    /* UNUSED BITS (must always be 0 for X.509 signatures) */
    **p = 0x00;
    (*p)++;
}
