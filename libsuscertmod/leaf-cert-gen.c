#define OPENSSL_API_COMPAT 0x10002000L
#include "leaf-cert.h"
#include "keybox.h"
#include "certmod.h"
#include "key-desc.h"
#include "certsign.h"
#include <libsuskmhal/keymaster-types-c.h>
#include <core/log.h>
#include <core/util.h>
#include <core/vector.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <openssl/obj_mac.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <stdlib.h>
#include <string.h>

#define MODULE_NAME "leaf-cert"

static i32 set_serial(X509 *x509, i64 val);
static i32 set_tbs_signature_algorithm(X509 *x509,
        enum sus_key_variant signing_key_variant);

static i32 set_notbefore(X509 *x509, const struct KM_KeyDescription_v3 *desc);
static i32 set_notafter(X509 *x509, const struct KM_KeyDescription_v3 *desc,
        i64 issuer_not_after);
static i32 set_issuer_from_keybox(X509 *x509, i64 *out_issuer_not_after,
        enum sus_key_variant signing_key_variant);
static i32 set_issuer(X509 *x509,
        const VECTOR(u8) title, const VECTOR(u8) serial);
static i32 set_subject(X509 *x509, const u8 *common_name_str);

static i32 set_keyusage(X509 *x509, const struct KM_KeyDescription_v3 *desc);
static i32 set_attestation_extension(X509 *x509,
        const struct KM_KeyDescription_v3 *desc);

static i32 construct_tbs_der(const struct KM_KeyDescription_v3 *km_desc,
        enum sus_key_variant signing_key_variant, EVP_PKEY *subj_pubkey,
        VECTOR(u8) *out_der);

static i32 set_x509_signature_algorithm(VECTOR(u8) *out_der,
        enum sus_key_variant signing_key_variant);

static VECTOR(u8) construct_x509_der(const VECTOR(u8) tbs,
        const VECTOR(u8) sig_alg, const VECTOR(u8) sig);

static unsigned long get_bitstr_tl_length(unsigned long content_len);
static void encode_der_sig_bitstr_tl(unsigned char **p, unsigned long content_len);


i32 leaf_cert_gen(VECTOR(u8) *out,
        enum sus_key_variant signing_key_variant,
        EVP_PKEY *subj_pubkey,
        const struct KM_KeyDescription_v3 *km_desc
)
{
    if ((signing_key_variant != SUS_KEY_EC &&
        signing_key_variant != SUS_KEY_RSA) ||
        (subj_pubkey == NULL) ||
        (km_desc == NULL))
    {
        s_log_error("Invalid parameters!");
        return -1;
    }

    if (out != NULL) *out = NULL;


    VECTOR(u8) ret = NULL;

    VECTOR(u8) tbs = NULL;
    VECTOR(u8) sig_alg = NULL;
    VECTOR(u8) sig = NULL;

    i32 r = 1;

    /* Encode the certificate contents (To-Be-Signed AKA TBS) */
    if (construct_tbs_der(km_desc, signing_key_variant, subj_pubkey, &tbs))
        goto_error("Couldn't generate the TBS certificate");

    /* Create the signature algorithm sequence */
    if (set_x509_signature_algorithm(&sig_alg, signing_key_variant))
        goto_error("Couldn't set the X.509 signatureAlgorithm");

    /* Generate the signature (over TBS) */
    if (sus_cert_sign(tbs, &sig, signing_key_variant))
        goto_error("Couldn't sign the X509 cert");

    /* Finally, glue everything together */
    ret = construct_x509_der(tbs, sig_alg, sig);
    if (ret == NULL)
        goto_error("Couldn't construct the final X509 certificate sequence");

    r = 0;
    if (out != NULL)
        *out = ret;
    else
        vector_destroy(&ret);

err:
    /* `ret` need not be freed here under any circumstances */

    vector_destroy(&sig);
    vector_destroy(&sig_alg);
    vector_destroy(&tbs);

    return r;
}

static i32 set_serial(X509 *x509, i64 val)
{
    ASN1_INTEGER *i = NULL;
    i32 ret = 1;

    i = ASN1_INTEGER_new();
    if (i == NULL)
        goto_error("Couldn't allocate a new ASN.1 INTEGER");

    if (ASN1_INTEGER_set_int64(i, val) == 0)
        goto_error("Couldn't set the value of an ASN.1 INTEGER");

    if (X509_set_serialNumber(x509, i) == 0)
        goto_error("Couldn't set the X.509 serial number");

    ret = 0;

err:
    if (i != NULL) {
        ASN1_INTEGER_free(i);
        i = NULL;
    }
    return ret;
}

static i32 set_tbs_signature_algorithm(X509 *x509,
        enum sus_key_variant signing_key_variant)
{
    /* Set the appropriate signature algorithm */
    const i32 sig_nid = signing_key_variant == SUS_KEY_EC ?
        NID_ecdsa_with_SHA256 : NID_sha256WithRSAEncryption ;

    /* openssl unfortunately doesn't provide us
     * with a way to do this cleanly :( */
    X509_ALGOR *const tbs_sig_alg = ((X509_ALGOR *)X509_get0_tbs_sigalg(x509));
    if (X509_ALGOR_set0(tbs_sig_alg, OBJ_nid2obj(sig_nid),
                V_ASN1_NULL, NULL) == 0)
    {
        s_log_error("Couldn't set the TBS signature algorithm");
        return 1;
    }

    return 0;
}

static i32 set_notbefore(X509 *x509, const struct KM_KeyDescription_v3 *desc)
{
    ASN1_TIME *not_before = NULL;
    i32 ret = 1;

    /* hw activeDateTime -> hw creationDateTime -> 0 */
    time_t time_val = 0;
    if (desc->hardwareEnforced.__activeDateTime_present) {
        time_val = desc->hardwareEnforced.activeDateTime / 1000;
    } else if (desc->hardwareEnforced.__creationDateTime_present) {
        time_val = desc->hardwareEnforced.creationDateTime / 1000;
    } else {
        s_log_warn("No activeDateTime or creationDateTime in key description; "
                "setting `notBefore` to 0 (Jan 1 1970)");
        time_val = 0;
    }

    not_before = ASN1_TIME_new();
    if (not_before == NULL)
        goto_error("Failed to allocate a new ASN.1 TIME object!");

    if (ASN1_TIME_set(not_before, time_val) == 0)
        goto_error("Couldn't set the value of an ASN.1 TIME object!");

    if (X509_set1_notBefore(x509, not_before) == 0)
        goto_error("Couldn't set the X509 `notBefore` value");

    ret = 0;

err:
    if (not_before != NULL) {
        ASN1_TIME_free(not_before);
        not_before = NULL;
    }
    return ret;
}

static i32 set_notafter(X509 *x509, const struct KM_KeyDescription_v3 *desc,
        i64 issuer_not_after)
{
    ASN1_TIME *not_after = NULL;
    i32 ret = 1;

    /* hw usageExpireDateTime -> issuer cert notAfter */
    time_t time_val = 0;
    if (desc->hardwareEnforced.__usageExpireDateTime_present) {
        time_val = desc->hardwareEnforced.usageExpireDateTime / 1000;
    } else {
        s_log_debug("No usageExpireDateTime present in key description; "
                "setting `notAfter` to the expiration date of the "
                "attestation batch key certificate");
        time_val = issuer_not_after;
    }

    not_after = ASN1_TIME_new();
    if (not_after == NULL)
        goto_error("Failed to allocate a new ASN.1 TIME object!");

    if (ASN1_TIME_set(not_after, time_val) == 0)
        goto_error("Couldn't set the value of an ASN.1 TIME object!");

    if (X509_set1_notAfter(x509, not_after) == 0)
        goto_error("Couldn't set the X509 `notAfter` value");

    ret = 0;

err:
    if (not_after != NULL) {
        ASN1_TIME_free(not_after);
        not_after = NULL;
    }
    return ret;
}

static i32 set_issuer_from_keybox(X509 *x509, i64 *out_issuer_not_after,
        enum sus_key_variant signing_key_variant)
{
    const struct keybox *kb = NULL;
    i32 ret = 1;

    /* Read all keybox-specific data in one go
     * (issuer name & notAfter) */
    if (keybox_read_lock_current(&kb)) {
        s_log_error("Couldn't read-lock the current keybox");
        return -1;
    }
    {
        /* Set the issuer to the issuer's subject info */
        const VECTOR(u8) title =
            keybox_get_issuer_title(kb, signing_key_variant);
        const VECTOR(u8) serial =
            keybox_get_issuer_serial(kb, signing_key_variant);
        if (title == NULL || serial == NULL)
            goto_error("Couldn't retrieve the issuer cert's subject info");

        if (set_issuer(x509, title, serial))
            goto_error("Couldn't set the certificate issuer");

        /* Get the issuer notAfter value while we have the keybox locked */
        if (keybox_get_issuer_not_after(out_issuer_not_after,
                    kb, signing_key_variant))
            goto_error("Couldn't retrieve the issuer cert's notAfter value");

        ret = 0;
    }
err:
    keybox_unlock_current(&kb);
    return ret;
}

static i32 set_issuer(X509 *x509,
        const VECTOR(u8) title, const VECTOR(u8) serial)
{
    X509_NAME *issuer = NULL;
    i32 ret = 1;

    issuer = X509_NAME_new();
    if (issuer == NULL)
        goto_error("Couldn't allocate the issuer X509 NAME");

    if (X509_NAME_add_entry_by_NID(issuer,
                NID_title, V_ASN1_UTF8STRING,
                title, vector_size(title),
                -1, 0) == 0)
        goto_error("Couldn't add the issuer title entry");

    if (X509_NAME_add_entry_by_NID(issuer,
                NID_serialNumber, V_ASN1_PRINTABLESTRING,
                serial, vector_size(serial),
                -1, 0) == 0)
        goto_error("Couldn't add the issuer serial entry");

    if (X509_set_issuer_name(x509, issuer) == 0)
        goto_error("Couldn't set the X509 issuer name");

    ret = 0;

err:
    if (issuer != NULL) {
        X509_NAME_free(issuer);
        issuer = NULL;
    }

    return ret;
}

static i32 set_subject(X509 *x509, const u8 *common_name_str)
{
    X509_NAME *subject = NULL;
    i32 ret = 1;

    subject = X509_NAME_new();
    if (subject == NULL)
        goto_error("Couldn't allocate an X509_NAME for the subject");

    if (X509_NAME_add_entry_by_NID(subject, NID_commonName, V_ASN1_UTF8STRING,
                common_name_str, -1, -1, 0) == 0)
        goto_error("Couldn't set the subject common-name field");

    if (X509_set_subject_name(x509, subject) == 0)
        goto_error("Couldn't set the X509 subject");

    ret = 0;

err:
    if (subject != NULL) {
        X509_NAME_free(subject);
        subject = NULL;
    }

    return ret;
}

static i32 set_keyusage(X509 *x509, const struct KM_KeyDescription_v3 *desc)
{
    u16 val = 0x0000;
    ASN1_BIT_STRING *bstr = NULL;
    i32 ret = 1;

    if (desc->hardwareEnforced.__purpose_present) {
        VECTOR(enum KM_KeyPurpose) hw_purpose = desc->hardwareEnforced.purpose;
        for (u32 i = 0; i < vector_size(hw_purpose); i++) {
            switch (hw_purpose[i]) {
            case KM_PURPOSE_SIGN:
            case KM_PURPOSE_VERIFY:
                val |= KU_DIGITAL_SIGNATURE;
                break;
            case KM_PURPOSE_ENCRYPT:
            case KM_PURPOSE_DECRYPT:
                val |= KU_DATA_ENCIPHERMENT;
            case KM_PURPOSE_WRAP_KEY:
                val |= KU_KEY_ENCIPHERMENT;
                break;
            }
        }
    }

    bstr = ASN1_BIT_STRING_new();
    if (bstr == NULL)
        goto_error("Couldn't allocate a new ASN.1 BIT STRING");

    if (ASN1_BIT_STRING_set(bstr, (u8 *)&val, sizeof(val)) == 0)
        goto_error("Couldn't set the value of an ASN.1 BIT STRING");

    if (X509_add1_ext_i2d(x509, NID_key_usage, bstr,
                true, X509V3_ADD_DEFAULT) == 0)
        goto_error("Couldn't serialize & add the X.509v3 KeyUsage extension");

    ret = 0;
err:
    if (bstr != NULL) {
        ASN1_BIT_STRING_free(bstr);
        bstr = NULL;
    }
    return ret;
}

static i32 set_attestation_extension(X509 *x509,
        const struct KM_KeyDescription_v3 *desc)
{
    ASN1_OCTET_STRING *key_desc_str = NULL;
    ASN1_OBJECT *km_ext_obj = NULL;
    X509_EXTENSION *km_ext = NULL;
    i32 ret = 1;

    key_desc_str = key_desc_repack(desc);
    if (key_desc_str == NULL)
        goto_error("Failed to repack the key description");

    km_ext_obj = OBJ_txt2obj(KM_kAttestionRecordOid, 1);
    if (km_ext_obj == NULL)
        goto_error("Couldn't create the KM Attestation Record OID");

    km_ext = X509_EXTENSION_create_by_OBJ(NULL, km_ext_obj, false,
            key_desc_str);
    if (km_ext == NULL)
        goto_error("Couldn't create the Android Attestation Extension");

    if (X509_add_ext(x509, km_ext, -1) == 0)
        goto_error("Couldn't add the Android Attestation Extension "
                "to the cert");

    ret = 0;
err:
    if (km_ext != NULL) {
        X509_EXTENSION_free(km_ext);
        km_ext = NULL;
    }
    if (km_ext_obj != NULL) {
        ASN1_OBJECT_free(km_ext_obj);
        km_ext_obj = NULL;
    }
    if (key_desc_str != NULL) {
        ASN1_OCTET_STRING_free(key_desc_str);
        key_desc_str = NULL;
    }

    return ret;
}

static i32 construct_tbs_der(const struct KM_KeyDescription_v3 *km_desc,
        enum sus_key_variant signing_key_variant, EVP_PKEY *subj_pubkey,
        VECTOR(u8) *out_der)
{
    X509 *x509 = NULL;
    i64 issuer_not_after = 0;
    unsigned char *der = NULL;
    int der_len = 0;
    i32 ret = 1;
    VECTOR(u8) der_ret = NULL;

    x509 = X509_new();
    if (x509 == NULL)
        goto_error("Couldn't allocate the X509 cert structure");

    /* Version must be 3 */
    if (X509_set_version(x509, X509_VERSION_3) == 0)
        goto_error("Couldn't set the X509 version to 3");

    /* All Android Attestation certs must have serial `1` */
    if (set_serial(x509, 1))
        goto_error("Couldn't set the cert's serial number to 1");

    /* Set the TBS signatureAlgorithm */
    if (set_tbs_signature_algorithm(x509, signing_key_variant))
        goto_error("Couldn't set the cert's signature algorithm");

    /* Set the issuer sequence to the keybox issuer cert's subject,
     * and also read out the issuer's notAfter value while we're at it */
    if (set_issuer_from_keybox(x509, &issuer_not_after, signing_key_variant))
        goto err; /* errors already logged by the function */

    /* Set the cert validity */
    if (set_notbefore(x509, km_desc) ||
            set_notafter(x509, km_desc, issuer_not_after))
        goto_error("Couldn't set the cert's validity");

    /* Set the subject CN to "Android Keystore Key", as required by the spec */
    if (set_subject(x509, (const u8 *)"Android Keystore Key"))
        goto_error("Couldn't set the cert's subject");

    /* Set the subjectPublicKeyInfo (the attested public key) */
    if (X509_set_pubkey(x509, subj_pubkey) == 0)
        goto_error("Couldn't set the subject public key info");

    /* Set the `keyUsage` extension depening on the key's purpose(s) */
    if (set_keyusage(x509, km_desc))
        goto_error("Couldn't set the cert's key usage");

    /* Set the android attestation extension */
    if (set_attestation_extension(x509, km_desc))
        goto_error("Couldn't set the Android attestation extension");

    /** Construct the outer X509 certificate sequence **/

    /* Serialize the TBS part of the cert */
    der_len = i2d_re_X509_tbs(x509, &der);
    if (der_len <= 0)
        goto_error("Couldn't serialize the X509 To-Be-Signed certificate");

    if (out_der != NULL) {
        der_ret = vector_new(u8);
        vector_resize(&der_ret, der_len);
        memcpy(der_ret, der, der_len);

        *out_der = der_ret;
    }

    OPENSSL_free(der);
    der = NULL;

err:
    /* both `der` and `der_ret` are guaranteed to be uninitialized
     * in all error cases */

    if (x509 != NULL) {
        X509_free(x509);
        x509 = NULL;
    }
    return ret;
}

static i32 set_x509_signature_algorithm(VECTOR(u8) *out_der,
        enum sus_key_variant signing_key_variant)
{
    X509_ALGOR *sig_alg = NULL;
    unsigned char *sig_alg_der = NULL;
    long sig_alg_der_len = 0;
    i32 ret = 1;

    const int sig_nid = signing_key_variant == SUS_KEY_RSA ?
        NID_sha256WithRSAEncryption : NID_ecdsa_with_SHA256;

    sig_alg = X509_ALGOR_new();
    if (sig_alg == NULL)
        goto_error("Couldn't allocate a new X509 ALGOR structure");

    if (X509_ALGOR_set0(sig_alg, OBJ_nid2obj(sig_nid), V_ASN1_NULL, NULL) == 0)
        goto_error("Couldn't set the outer signature algorithm");

    sig_alg_der_len = i2d_X509_ALGOR(sig_alg, &sig_alg_der);
    if (sig_alg_der_len <= 0)
        goto_error("Couldn't serialize the X509 signature algorithm sequence");

    *out_der = vector_new(u8);
    vector_resize(out_der, sig_alg_der_len);
    memcpy(*out_der, sig_alg_der, sig_alg_der_len);

    OPENSSL_free(sig_alg_der);
    sig_alg_der = NULL;

    ret = 0;

err:
    /* `out_der` and `sig_alg_der` are both
     * guaranteed to be unused in all error cases */

    if (sig_alg != NULL) {
        X509_ALGOR_free(sig_alg);
        sig_alg = NULL;
    }

    return ret;
}

static VECTOR(u8) construct_x509_der(const VECTOR(u8) tbs,
        const VECTOR(u8) sig_alg, const VECTOR(u8) sig)
{
    /* See:
     * https://source.android.com/docs/security/features/keystore/attestation#certificate-sequence
     */

    long sig_str_len = 0;
    VECTOR(u8) ret = NULL;
    unsigned char *p = NULL;

    const u32 tbs_len = vector_size(tbs);
    const u32 sig_alg_len = vector_size(sig_alg);
    const u32 sig_len = vector_size(sig);

    /* First wrap the signature in a BIT_STRING */

    sig_str_len = get_bitstr_tl_length(sig_len) + sig_len;
    if (sig_str_len <= 3)
        goto_error("Invalid size of signature bit string: %ld", sig_str_len);

    /* Allocate buffer */
    const u64 inner_length = tbs_len + sig_alg_len + sig_str_len;
    const u64 outer_length =
        ASN1_object_size(true, inner_length, V_ASN1_SEQUENCE);

    ret = vector_new(u8);
    vector_resize(&ret, outer_length);

    /* Put the raw bytes */

    p = ret;

    ASN1_put_object(&p, true, inner_length, V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL);

    memcpy(p, tbs, tbs_len);
    p += tbs_len;

    memcpy(p, sig_alg, sig_alg_len);
    p += sig_alg_len;

    encode_der_sig_bitstr_tl(&p, sig_len);
    memcpy(p, sig, sig_len);
    p += sig_len;

    u8 *const end = ret + outer_length;
    if (p != end)
        goto_error("Wrote an incorrect amount of bytes");

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

    return 1 + 1 + lensz + 1; /* TAG | LENSZ | <LEN> | UNUSED BITS */
}

static void encode_der_sig_bitstr_tl(unsigned char **p, unsigned long len)
{
    /* TAG */
    **p = (u8)V_ASN1_BIT_STRING;
    (*p)++;

    /* LENGTH */
    len++; /* count the unused bits field */

    if (len <= 127) {
        /* Short-form length */
        **p = (u8)(len & 0x7f);
        (*p)++;
    } else {
        /* Long-form length */
        u8 lensz = 0;
        unsigned long tmp = len;
        while (tmp != 0) {
            lensz++;
            tmp >>= 8;
        }

        /* LENGTH SIZE */
        **p = 0x80 | lensz;
        (*p)++;

        /* LENGTH (Big endian) */
        for (int i = lensz - 1; i >= 0; i--) {
            *(*p) = (len >> (8*i)) & 0xFF;
            (*p)++;
        }
    }

    /* UNUSED BITS (must always be 0 for DER-encoded X.509 signatures) */
    **p = 0x00;
    (*p)++;
}
