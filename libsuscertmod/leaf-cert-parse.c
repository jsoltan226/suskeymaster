#include "leaf-cert.h"
#include "key-desc.h"
#include "keymaster-types.h"
#include <core/int.h>
#include <core/log.h>
#include <core/util.h>
#include <core/math.h>
#include <libgenericutil/cert-types.h>
#include <stdbool.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/x509v3.h>
#include <openssl/crypto.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <openssl/core_names.h>

#define MODULE_NAME "leaf-cert"

static i32 rsa_pss_sig_sanity(const X509 *cert);

static i32 rsa_pubkey_sanity(const EVP_PKEY *key);
static i32 ec_pubkey_sanity(const EVP_PKEY *key);

i32 leaf_cert_parse(const VECTOR(u8) cert,
        enum sus_key_variant *out_variant,
        EVP_PKEY **out_subj_pubkey,
        struct KM_KeyDescription_v3 **out_km_desc
)
{
    bool ok = false;

    if (cert == NULL) {
        s_log_error("Invalid parameters!");
        return -1;
    }

    if (out_variant != NULL) *out_variant = SUS_KEY_INVALID_;
    if (out_subj_pubkey != NULL) *out_subj_pubkey = NULL;
    if (out_km_desc != NULL) *out_km_desc = NULL;

    /* See:
     * https://source.android.com/docs/security/features/keystore/attestation#certificate-sequence
     */

    X509 *x509 = NULL;
    const unsigned char *p = NULL;

    i64 x509_version = 0;
    const ASN1_INTEGER *x509_serial = 0;
    i64 x509_serial_val = 0;

    i32 sig_nid = 0;
    enum sus_key_variant key_variant = SUS_KEY_INVALID_;
    const char *sig_variant_str = "N/A";

    const X509_PUBKEY *subj_pubkey_x509 = NULL;
    EVP_PKEY *subj_pubkey = NULL;
    i32 expected_subj_pubkey_type = NID_undef;
    i32 subj_pubkey_type = NID_undef;
    EVP_PKEY_CTX *subj_pubkey_ctx = NULL;

    const X509_NAME *issuer = NULL;
    const X509_NAME *subject = NULL;
#define SUBJ_CN_BUF_SIZE 256
    char subject_cn_buf[SUBJ_CN_BUF_SIZE] = { 0 };

    const ASN1_TIME *notBefore = NULL;
    const ASN1_TIME *notAfter = NULL;

    i32 km_ext_index = 0;
    /* const */ X509_EXTENSION *km_ext = NULL;
    ASN1_OCTET_STRING *km_ext_str = NULL;
    struct KM_KeyDescription_v3 *km_desc = NULL;

    i32 keyusage_ext_index = 0;
    /* const */ X509_EXTENSION *keyusage_ext = NULL;
    ASN1_OCTET_STRING *keyusage_ext_data = NULL;

    p = cert;
    x509 = d2i_X509(NULL, &p, vector_size(cert));
    if (x509 == NULL)
        goto_error("Couldn't deserialize the provided DER");

    /* Attestation certs must be version 3 */
    x509_version = X509_get_version(x509);
    if (x509_version != X509_VERSION_3)
        goto_error("Unexpected X509 version in leaf cert: 0x%llx",
                (unsigned long long)x509_version);

    /* As per the android spec, the serial number must always be set to `1` */
    x509_serial = X509_get0_serialNumber(x509);
    if (x509_serial == NULL)
        goto_error("Couldn't get the X509 serial number");

    if (ASN1_INTEGER_get_int64(&x509_serial_val, x509_serial) == 0)
        goto_error("Couldn't get the X509 serial number");

    if (x509_serial_val != 1)
        goto_error("Unexpected X509 serial number: 0x%llx (expected `1`)",
                (unsigned long long)x509_serial_val);

    /* Decide which cert chain we'll be using */
    sig_nid = X509_get_signature_nid(x509);
    if (sig_nid == NID_undef)
        goto_error("Failed to query the old leaf cert's signature algorithm!");

    /* Only RSA and ECDSA signatures are allowed,
     * with either SHA256, SHA384 or SHA512 hashes */

    if (sig_nid == NID_ecdsa_with_SHA256 ||
        sig_nid == NID_ecdsa_with_SHA384 ||
        sig_nid == NID_ecdsa_with_SHA512)
    {
        sig_variant_str = "ECDSA";
        expected_subj_pubkey_type = EVP_PKEY_EC;
    } else if (sig_nid == NID_sha256WithRSAEncryption ||
            sig_nid == NID_sha384WithRSAEncryption ||
            sig_nid == NID_sha512WithRSAEncryption)
    {
        sig_variant_str = "RSA-SHA256";
        expected_subj_pubkey_type = EVP_PKEY_RSA;
    } else if (sig_nid == NID_rsassaPss) {
        /* Additional sanity checks for RSA-PSS signatures */
        if (rsa_pss_sig_sanity(x509))
            goto_error("Invalid RSA-PSS signature");

        sig_variant_str = "RSA-PSS";
        expected_subj_pubkey_type = EVP_PKEY_RSA;
    } else {
        goto_error("Unsupported leaf cert signature algorithm: %d", sig_nid);
    }

    /* Check that the subject public key matches the signature algorithm */
    subj_pubkey_x509 = X509_get_X509_PUBKEY(x509);
    if (subj_pubkey_x509 == NULL)
        goto_error("Missing subject public key in certificate!");

    subj_pubkey = X509_PUBKEY_get(subj_pubkey_x509);
    if (subj_pubkey == NULL)
        goto_error("Couldn't decode the subject public key!");

    subj_pubkey_type = EVP_PKEY_base_id(subj_pubkey);
    if (subj_pubkey_type != expected_subj_pubkey_type)
        goto_error("Mismatched signature algorithm and subject public key "
                "(sig: %d, spk_type: %d)!", sig_nid, subj_pubkey_type);

    if (subj_pubkey_type == EVP_PKEY_EC)
        key_variant = SUS_KEY_EC;
    else if (subj_pubkey_type == EVP_PKEY_RSA)
        key_variant = SUS_KEY_RSA;
    else
        s_log_fatal("Impossible outcome!");

    /* Additional public key sanity checks */
    if (subj_pubkey_type == EVP_PKEY_EC &&
            ec_pubkey_sanity(subj_pubkey))
    {
        goto_error("Invalid ECDSA subject public key!");
    }
    else if (subj_pubkey_type == EVP_PKEY_RSA &&
            rsa_pubkey_sanity(subj_pubkey))
    {
        goto_error("Invalid RSA subject public key!");
    }
    else if (subj_pubkey_type != EVP_PKEY_RSA &&
            subj_pubkey_type != EVP_PKEY_EC)
    {
        s_log_fatal("Impossible outcome!");
    }

    subj_pubkey_ctx = EVP_PKEY_CTX_new(subj_pubkey, NULL);
    if (subj_pubkey_ctx == NULL)
        goto_error("Failed to create the subject public key context!");

    if (EVP_PKEY_public_check(subj_pubkey_ctx) <= 0)
        goto_error("Invalid subject public key (check failed)!");

    /* Check that the issuer field exists */
    issuer = X509_get_issuer_name(x509);
    if (issuer == NULL)
        goto_error("Couldn't get the cert issuer name!");

    /* Check the certificate's expiration fields */
    notBefore = X509_get_notBefore(x509);
    if (notBefore == NULL)
        goto_error("Couldn't get the notBefore field!");

    notAfter = X509_get_notAfter(x509);
    if (notAfter == NULL)
        goto_error("Couldn't get the notAfter field!");

    /* Check the subject CN (must be "Android Keystore Key") */
    subject = X509_get_subject_name(x509);
    if (subject == NULL)
        goto_error("Couldn't get the cert subject name!");

    if (X509_NAME_get_text_by_NID(subject, NID_commonName,
                subject_cn_buf, SUBJ_CN_BUF_SIZE - 1) == 0)
        goto_error("Couldn't get the cert subject common name!");

    if (memcmp(subject_cn_buf, "Android Keystore Key",
                u_min(u_strlen("Android Keystore Key"), SUBJ_CN_BUF_SIZE)))
        goto_error("Invalid value of the subject common name: %s "
                "(expected \"Android Keystore Key\")", subject_cn_buf);

    /* Get & deserialize the Android attestation extension */
    km_ext_index = X509_get_ext_by_OBJ(x509,
            OBJ_txt2obj(KM_kAttestionRecordOid, 1), -1);
    if (km_ext_index < 0)
        goto_error("The X509 attestation extension wasn't found!");

    km_ext = X509_get_ext(x509, km_ext_index);
    if (km_ext == NULL)
        goto_error("Couldn't retrieve the X509 attestation extension!");

    km_ext_str = X509_EXTENSION_get_data(km_ext);
    if (km_ext_str == NULL)
        goto_error("Couldn't get the X509 attestation extension data!");

    /* Parse the KeyDescription sequence contained within the extension */
    km_desc = key_desc_unpack(km_ext_str);
    if (km_desc == NULL)
        goto_error("Failed to parse the X509 attestation extension data!");

    /* Check that the KeyUsage extension exists */
    keyusage_ext_index = X509_get_ext_by_NID(x509, NID_key_usage, -1);
    if (keyusage_ext_index < 0)
        goto_error("Couldn't find the KeyUsage extension!");

    keyusage_ext = X509_get_ext(x509, keyusage_ext_index);
    if (keyusage_ext == NULL)
        goto_error("Couldn't retrieve the KeyUsage extension!");

    if (X509_EXTENSION_get_critical(keyusage_ext) != 1)
        s_log_warn("The KeyUsage extension is not `critical`!");

    keyusage_ext_data = X509_EXTENSION_get_data(keyusage_ext);
    if (keyusage_ext_data == NULL)
        goto_error("Couldn't get the KeyUsage extension data!");


    /* The remaining field:
     * `extensions/CRL distribution points`
     * is "TBD", so we don't care about its value
     */

    s_log_info("Leaf cert signature algorithm is >%s<", sig_variant_str);
    ok = true;

err:

    if (out_variant != NULL)
        *out_variant = key_variant;

    if (out_subj_pubkey != NULL) {
        *out_subj_pubkey = subj_pubkey;
    } else {
        EVP_PKEY_free(subj_pubkey);
        subj_pubkey = NULL;
    }

    if (out_km_desc != NULL)
        *out_km_desc = km_desc;
    else
        key_desc_destroy(&km_desc);

    if (subj_pubkey_ctx != NULL) {
        EVP_PKEY_CTX_free(subj_pubkey_ctx);
        subj_pubkey_ctx = NULL;
    }

    if (!ok) {
        /* `km_desc` doesn't have to be freed under any circumstances */

        if (subj_pubkey != NULL) {
            EVP_PKEY_free(subj_pubkey);
            subj_pubkey = NULL;
        }
    }

    if (x509 != NULL) {
        X509_free(x509);
        x509 = NULL;
    }

    return ok ? 0 : 1;
}

static i32 rsa_pss_sig_sanity(const X509 *cert)
{
    bool ok = false;

    const X509_ALGOR *alg = NULL;
    const ASN1_BIT_STRING *sig = NULL;
    RSA_PSS_PARAMS *pss = NULL;

    i32 hash_nid = 0;

    i32 expected_salt_length = -1;
    i32 salt_length = 0;

    const ASN1_OBJECT *mgf_obj = NULL;
    const void *mgf_val = NULL;
    i32 mgf_enc_type = 0;
    i32 mgf_type_nid = 0;

    i32 mgf_hash_nid = 0;

    X509_get0_signature(&sig, &alg, cert);
    if (sig == NULL || alg == NULL)
        goto_error("Couldn't get the X509 signature!");

    if (alg->parameter == NULL ||
            ASN1_TYPE_get(alg->parameter) != V_ASN1_SEQUENCE)
        goto_error("Invalid RSA-PSS algorithm data!");

    pss = ASN1_item_unpack((const ASN1_STRING *)alg->parameter,
            ASN1_ITEM_rptr(RSA_PSS_PARAMS));
    if (pss == NULL)
        goto_error("Couldn't retrieve the RSA-PSS parameters!");

    if (pss->maskGenAlgorithm == NULL || pss->hashAlgorithm == NULL
            || pss->saltLength == NULL || pss->maskHash == NULL
            || pss->trailerField == NULL)
        goto_error("Invalid RSA-PSS parameters!");


    /* Only SHA256, SHA384 and SHA512 hashes are allowed */
    hash_nid = OBJ_obj2nid(pss->hashAlgorithm->algorithm);
    if (hash_nid == NID_undef)
        goto_error("Couldn't get the RSA-PSS hash algorithm!");

    if (hash_nid != NID_sha256 &&
        hash_nid != NID_sha384 &&
        hash_nid != NID_sha512)
    {
        goto_error("Unsupported RSA-PSS hash algorithm: %d", hash_nid);
    }
    else if (hash_nid == NID_sha256)
        expected_salt_length = 32;
    else if (hash_nid == NID_sha384)
        expected_salt_length = 48;
    else if (hash_nid == NID_sha512)
        expected_salt_length = 64;

    /* Sanity-check the salt length */
    salt_length = ASN1_INTEGER_get(pss->saltLength);
    if (salt_length != expected_salt_length)
        goto_error("Invalid RSA-PSS salt length: %d (expected: %d)",
                salt_length, expected_salt_length);

    /* Only MGF-1 masks with the above hashes are allowed */
    X509_ALGOR_get0(&mgf_obj, &mgf_enc_type, &mgf_val, pss->maskGenAlgorithm);
    if (mgf_obj == NULL || mgf_enc_type == 0 || mgf_val == NULL)
        goto_error("Couldn't get the MGF data of the RSA-PSS signature");

    if (mgf_enc_type != V_ASN1_SEQUENCE)
        goto_error("Unsupported RSA-PSS MGF encoding: %d", mgf_enc_type);

    mgf_type_nid = OBJ_obj2nid(mgf_obj);
    if (mgf_type_nid != NID_mgf1)
        goto_error("Unsupported RSA-PSS mask-gen algorithm: %d", mgf_type_nid);

    mgf_hash_nid = OBJ_obj2nid(pss->maskHash->algorithm);
    if (mgf_hash_nid != hash_nid)
        goto_error("RSA-PSS MGF-1 hash algorithm mismatch (%d - expected %d)",
                mgf_hash_nid, hash_nid);

    /* Check the trailer field */
    if (ASN1_INTEGER_get(pss->trailerField) != 1)
        goto_error("Invalid RSA-PSS trailer field value!");

    ok = true;

err:
    if (pss != NULL) {
        RSA_PSS_PARAMS_free(pss);
        pss = NULL;
    }

    return ok ? 0 : 1;
}

static i32 rsa_pubkey_sanity(const EVP_PKEY *key)
{
    bool ok = false;

    i32 bits = 0;
    BIGNUM *modulus = NULL;
    BIGNUM *exponent = NULL;;

    if (EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_N, &modulus) == 0)
        goto_error("Couldn't get the RSA modulus!");

    bits = BN_num_bits(modulus);
    if (bits < 2048)
        goto_error("RSA modulus is too small (%d - minimal: 2048)", bits);

    if (EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_E, &exponent) == 0)
        goto_error("Couldn't get the RSA exponent!");

    if (!BN_is_odd(exponent))
        goto_error("Invalid RSA exponent (even value)!");

    ok = true;

err:
    if (exponent != NULL) {
        BN_free(exponent);
        exponent = NULL;
    }
    if (modulus != NULL) {
        BN_free(modulus);
        modulus = NULL;
    }

    return ok ? 0 : 1;
}

static i32 ec_pubkey_sanity(const EVP_PKEY *key)
{
    bool ok = false;

    char group_name[64] = { 0 };
    u64 group_name_len = 0;

    if (EVP_PKEY_get_utf8_string_param(key, OSSL_PKEY_PARAM_GROUP_NAME,
                group_name, u_arr_size(group_name), &group_name_len) == 0)
    {
        goto_error("Failed to get the curve name");
    }
    group_name[u_arr_size(group_name) - 1] = '\0';

    if (strncmp(group_name, "prime256v1", u_arr_size(group_name)) &&
        strncmp(group_name, "secp384r1", u_arr_size(group_name)) &&
        strncmp(group_name, "secp521r1", u_arr_size(group_name)))
    {
        goto_error("Unsupported EC curve name: %s", group_name);
    }

    ok = true;

err:

    return ok ? 0 : 1;
}
