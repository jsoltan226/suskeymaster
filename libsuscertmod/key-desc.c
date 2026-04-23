#define OPENSSL_API_COMPAT 0x10002000L
#include "key-desc.h"
#include <core/log.h>
#include <core/util.h>
#include <core/vector.h>
#include <libsuskmhal/util/dump-utils.h>
#include <libsuskmhal/util/keymaster-types-c.h>
#include <stdint.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/crypto.h>

#define MODULE_NAME "key-desc"

static i32 validate_km_desc(const KM_KEY_DESC_V3 *desc);

KM_KEY_DESC_V3 * key_desc_unpack(const ASN1_OCTET_STRING *desc)
{
    KM_KEY_DESC_V3 *ret = NULL;

    const unsigned char *p = NULL;
    long total_len = 0;
    const unsigned char *end = NULL;

    p = ASN1_STRING_get0_data(desc);
    if (p == NULL)
        goto_error("Couldn't get the KM extension string's data");

    total_len = ASN1_STRING_length(desc);
    if (total_len <= 0)
        goto_error("Invalid length of KM extension string: %ld", total_len);
    end = p + total_len;

    ret = d2i_KM_KEY_DESC_V3(NULL, &p, total_len);
    if (ret == NULL)
        goto_error("Failed to deserialize the key description DER");
    if (p != end)
        goto_error("Trailing data after key description sequence");

    if (validate_km_desc(ret))
        goto_error("Invalid values were found in the key description");

    return ret;

err:
    if (ret != NULL) {
        KM_KEY_DESC_V3_free(ret);
        ret = NULL;
    }

    return NULL;
}

ASN1_OCTET_STRING * key_desc_repack(const KM_KEY_DESC_V3 *desc)
{
    unsigned char *der = NULL;
    int der_len = 0;

    ASN1_OCTET_STRING *ret = NULL;

    /* Construct the actual KeyDescription sequence */
    {
        der_len = i2d_KM_KEY_DESC_V3(desc, NULL);
        if (der_len <= 0)
            goto_error("Failed to measure the length of the key description DER");

        der = OPENSSL_malloc(der_len);
        if (der == NULL)
            goto_error("Failed to allocate the key description DER");

        unsigned char *p = der;
        unsigned char *const end = p + der_len;

        if (i2d_KM_KEY_DESC_V3(desc, &p) != der_len)
            goto_error("Failed to i2d the key description");
        else if (p != end)
            goto_error("Invalid number of bytes written");
    }

    /* Pack everything up */
    ret = ASN1_OCTET_STRING_new();
    if (ret == NULL)
        goto_error("Failed to allocate the output OCTET_STRING");

    if (ASN1_OCTET_STRING_set(ret, der, der_len) == 0)
        goto_error("Failed to set the new OCTET_STRING to the sequence DER");
    der = NULL;

    return ret;

err:
    if (ret != NULL) {
        ASN1_OCTET_STRING_free(ret);
        ret = NULL;
    }
    if (der != NULL) {
        OPENSSL_free(der);
        der = NULL;
    }

    return NULL;
}

void key_desc_dump(KM_dump_log_proc_t log_proc, const KM_KEY_DESC_V3 *desc,
        uint8_t indent, const char *field_name)
{
    char indent_buf[1024];
    ASN1_INTEGER *tmp_int = NULL;
    ASN1_OCTET_STRING *tmp_octet_string = NULL;

    KM_DUMP_sprint_indent(indent_buf, indent);

    if ((tmp_int = ASN1_INTEGER_new()) == NULL) {
        log_proc("ERROR: Failed to create a new temporary ASN.1 INTEGER");
        goto out;
    }
    if ((tmp_octet_string = ASN1_OCTET_STRING_new()) == NULL) {
        log_proc("ERROR: Failed to create a new temporary ASN.1 OCTET_STRING");
        goto out;
    }

    if (field_name == NULL) {
        log_proc("%s===== BEGIN KEY DESCRIPTION DUMP =====", indent_buf);

        if (desc == NULL) {
            log_proc("%sKM_KEY_DESC_V3 desc = { /* empty */ };",
                    indent_buf);
            goto out;
        }

        log_proc("KM_KEY_DESC_V3 key_desc = {");
    } else {
        if (desc == NULL) {
            log_proc("%s.%s = { /* empty */ };", indent_buf, field_name);
            goto out;
        }

        log_proc("%s.%s = {", indent_buf, field_name);
    }

    KM_dump_u64(log_proc, "attestationVersion",
            desc->attestationVersion, indent + 1);

    {
        int64_t e = 0LL;
        if (desc->attestationSecurityLevel == NULL ||
                !ASN1_ENUMERATED_get_int64(&e, desc->attestationSecurityLevel))
        {
            log_proc("ERROR: Failed to get the value of "
                    "the attestationSecurityLevel ASN.1 ENUMERATED field");
        } else {
            e &= 0x00000000FFFFFFFF;
            log_proc("%s" KM_DUMP_SINGLE_INDENT
                    ".attestationSecurityLevel = %lld, // %s",
                    indent_buf,
                    (long long int)e, KM_SecurityLevel_toString((int)e));
        }
    }

    KM_dump_u64(log_proc, "keymasterVersion",
            desc->keymasterVersion, indent + 1);

    {
        int64_t e = 0LL;
        if (desc->keymasterSecurityLevel == NULL ||
                !ASN1_ENUMERATED_get_int64(&e, desc->keymasterSecurityLevel))
        {
            log_proc("ERROR: Failed to get the value of "
                    "the keymasterSecurityLevel ASN.1 ENUMERATED field");
        } else {
            e &= 0x00000000FFFFFFFF;
            log_proc("%s" KM_DUMP_SINGLE_INDENT
                    ".keymasterSecurityLevel = %lld, // %s",
                    indent_buf,
                    (long long int)e, KM_SecurityLevel_toString((int)e));
        }
    }

    KM_dump_hex(log_proc, "attestationChallenge",
            desc->attestationChallenge, indent + 1);

    KM_dump_hex(log_proc, "uniqueId", desc->uniqueId, indent + 1);

    KM_dump_param_list(log_proc, desc->softwareEnforced,
            indent + 1, "softwareEnforced");
    KM_dump_param_list(log_proc, desc->hardwareEnforced,
            indent + 1, "hardwareEnforced");

    if (field_name != NULL) {
        log_proc("%s};", indent_buf);
        log_proc("%s====== END KEY DESCRIPTION DUMP ======", indent_buf);
    } else {
        log_proc("%s},", indent_buf);
    }

out:
    if (tmp_octet_string != NULL) {
        ASN1_OCTET_STRING_free(tmp_octet_string);
        tmp_octet_string = NULL;
    }
    if (tmp_int != NULL) {
        ASN1_INTEGER_free(tmp_int);
        tmp_int = NULL;
    }
}

static i32 validate_km_desc(const KM_KEY_DESC_V3 *desc)
{
#define ATTESTATION_VERSION 3
#define KEYMASTER_VERSION 4
    int64_t i = 0;

    if (desc->attestationVersion == NULL ||
            !ASN1_INTEGER_get_int64(&i, desc->attestationVersion))
    {
        s_log_error("Failed to get the value of "
                "the attestationVersion INTEGER");
        return -1;
    }
    i &= 0x00000000FFFFFFFF;
    if (i != ATTESTATION_VERSION) {
        s_log_error("Unsupported attestation version: %lld", (long long int)i);
        return 1;
    }

    if (desc->attestationSecurityLevel == NULL ||
            !ASN1_ENUMERATED_get_int64(&i, desc->attestationSecurityLevel))
    {
        s_log_error("Failed to get the value of "
                "the attestationSecurityLevel INTEGER");
        return -1;
    }
    i &= 0x00000000FFFFFFFF;
    switch (i) {
    case KM_SECURITY_LEVEL_SOFTWARE:
    case KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT:
    case KM_SECURITY_LEVEL_STRONGBOX:
        break;
    default:
        s_log_error("Invalid attestation security level: %lld",
                (long long int)i);
        return 1;
    }

    if (desc->keymasterVersion == NULL ||
            !ASN1_INTEGER_get_int64(&i, desc->keymasterVersion))
    {
        s_log_error("Failed to get the value of the keymasterVersion INTEGER");
        return -1;
    }
    i &= 0x00000000FFFFFFFF;
    if (i != KEYMASTER_VERSION) {
        s_log_error("Unsupported keymaster version: %lld", (long long int)i);
        return 1;
    }

    if (desc->keymasterSecurityLevel == NULL ||
            !ASN1_ENUMERATED_get_int64(&i, desc->keymasterSecurityLevel))
    {
        s_log_error("Failed to get the value of the "
                "keymasterSecurityLevel ENUMERATED field");
        return 1;
    }
    i &= 0x00000000FFFFFFFF;
    switch (i) {
    case KM_SECURITY_LEVEL_SOFTWARE:
    case KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT:
    case KM_SECURITY_LEVEL_STRONGBOX:
        break;
    default:
        s_log_error("Invalid keymaster security level: %lld", (long long int)i);
        return 1;
    }

    if (desc->attestationChallenge == NULL) {
        s_log_error("Missing attestationChallenge");
        return 1;
    }

    if (desc->uniqueId == NULL) {
        s_log_error("Missing uniqueId field");
        return 1;
    }

    if (desc->softwareEnforced == NULL) {
        s_log_error("Missing softwareEnforced authorization list");
        return 1;
    }

    if (desc->hardwareEnforced == NULL) {
        s_log_error("Missing hardwareEnforced authorization list");
        return 1;
    }

    /* attestationChallenge- and uniqueId's presence
     * have already been validated previously */

    /* All fields in the authorization lists are technically optional */

    if (desc->hardwareEnforced->rootOfTrust != NULL) {
        const ASN1_INTEGER *const vbstate_asn1 =
            desc->hardwareEnforced->rootOfTrust->verifiedBootState;

        if (vbstate_asn1 == NULL ||
                !ASN1_ENUMERATED_get_int64(&i, vbstate_asn1))
        {
            s_log_error("Failed to get the value of the "
                    "rootOfTrust verifiedBootState ENUMERATED field");
            return -1;
        }
        i &= 0x00000000FFFFFFFF;

        switch (i) {
        case KM_VERIFIED_BOOT_FAILED:
            s_log_warn("KM_VERIFIED_BOOT_FAILED shouldn't be possible");
        case KM_VERIFIED_BOOT_UNVERIFIED:
        case KM_VERIFIED_BOOT_SELF_SIGNED:
        case KM_VERIFIED_BOOT_VERIFIED:
            break;
        default:
            s_log_error("Invalid verified boot state "
                    "in hardwareEnforced authorization list: %lld",
                    (long long int)i);
            return 1;
        }
    }

    return 0;
}
