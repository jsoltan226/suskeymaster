#include "key-desc.h"
#include "keymaster-types.h"
#include <core/log.h>
#include <core/util.h>
#include <core/vector.h>
#include <openssl/asn1.h>
#include <openssl/crypto.h>
#include <stdlib.h>
#include <string.h>

#define MODULE_NAME "key-desc"

static bool parse_auth_list(struct KM_AuthorizationList_v3 *out,
        const unsigned char **p, long len);

static bool parse_root_of_trust(struct KM_RootOfTrust_v3 *out,
        const unsigned char **p, long len);

static bool unwrap_asn1_sequence(const unsigned char **p, long len,
        const unsigned char **out_start, const unsigned char **out_end,
        long *out_len);

static bool parse_integer_64(const unsigned char **p, long len, int64_t *out);
static bool parse_integer_32(const unsigned char **p, long len, int32_t *out);
static bool parse_enumerated(const unsigned char **p, long len, int32_t *out);
static bool parse_octet_string(const unsigned char **p, long len,
        VECTOR(u8) *out);
static bool parse_set_of_int64(const unsigned char **p, long len,
        VECTOR(int64_t) *out);
static bool parse_set_of_int32(const unsigned char **p, long len,
        VECTOR(int32_t) *out);
static bool parse_boolean(const unsigned char **p, long len, bool *out);

static i32 validate_km_desc(const struct KM_KeyDescription_v3 *desc);

struct KM_KeyDescription_v3 * key_desc_new(void)
{
    return calloc(1, sizeof(struct KM_KeyDescription_v3));
}

struct KM_KeyDescription_v3 * key_desc_unpack(const ASN1_OCTET_STRING *desc)
{
    struct KM_KeyDescription_v3 *ret = NULL;

    const unsigned char *p = NULL;
    long total_len = 0;

    const unsigned char *seq_end = NULL;

    p = ASN1_STRING_get0_data(desc);
    if (p == NULL)
        goto_error("Couldn't get the KM extension string's data");

    total_len = ASN1_STRING_length(desc);
    if (total_len <= 0)
        goto_error("Invalid length of KM extension string: %d", total_len);

    if (!unwrap_asn1_sequence(&p, total_len, NULL, &seq_end, NULL))
        goto_error("Failed to unwrap the KeyDescription SEQUENCE!");

    ret = key_desc_new();
    if (ret == NULL)
        goto_error("Failed to allocate a new key description struct");

    if (!parse_integer_64(&p, seq_end - p, &ret->attestationVersion))
        goto_error("Missing attestation version in key description");

    if (!parse_enumerated(&p, seq_end - p,
            (int32_t *)&ret->attestationSecurityLevel))
        goto_error("Missing attestationSecurityLevel in key description");

    if (!parse_integer_64(&p, seq_end - p, &ret->keymasterVersion))
        goto_error("Missing keymaster version in key description");

    if (!parse_enumerated(&p, seq_end - p,
            (int32_t *)&ret->keymasterSecurityLevel))
        goto_error("Missing keymasterSecurityLevel in key description");

    if (!parse_octet_string(&p, seq_end - p, &ret->attestationChallenge))
        goto_error("Missing attestation challenge in key description");

    /* Samsung TEEs don't populate `uniqueId` for some reason */
    if (!parse_octet_string(&p, seq_end - p, &ret->uniqueId))
        goto_error("Missing uniqueId field in key description");


    if (!parse_auth_list(&ret->softwareEnforced, &p, seq_end - p))
        goto_error("Missing or invalid softwareEnforced authorization list");

    if (!parse_auth_list(&ret->hardwareEnforced, &p, seq_end - p))
        goto_error("Missing or invalid hardwareEnforced authorization list");

    if (p != seq_end)
        goto_error("Trailing data after key description sequence");

    if (validate_km_desc(ret))
        goto_error("Invalid values were found in the key description");

    return ret;

err:
    if (ret != NULL)
        key_desc_destroy(&ret);

    return NULL;
}


static bool parse_auth_list(struct KM_AuthorizationList_v3 *out,
        const unsigned char **p, long len)
{
    const unsigned char *seq_end = NULL;
    long seq_len = 0;

    if (!unwrap_asn1_sequence(p, len, NULL, &seq_end, &seq_len)) {
        s_log_error("Couldn't unwrap the AuthorizationList SEQUENCE!");
        return false;
    }

    while (*p < seq_end) {
        long field_len = 0;
        i32 field_tag = 0, field_class = 0;
        i32 asn1_getobj_ret = 0;

        asn1_getobj_ret = ASN1_get_object(p, &field_len,
                &field_tag, &field_class, seq_end - *p);
        if (asn1_getobj_ret & 0x80) {
            return false;
        } else if (field_class != V_ASN1_CONTEXT_SPECIFIC) {
            /* Unknown stuff, skip */
            *p += field_len;
            continue;
        } else if (!(asn1_getobj_ret & V_ASN1_CONSTRUCTED)) {
            s_log_error("Authorization list field is not EXPLICIT!");
            return false;
        }

        switch (field_tag) {
        case __KM_TAG_MASK(KM_TAG_PURPOSE):
            out->__purpose_present = parse_set_of_int32(p, field_len,
                    (VECTOR(int32_t) *)&out->purpose);
            break;
        case __KM_TAG_MASK(KM_TAG_ALGORITHM):
            out->__algorithm_present = parse_integer_32(p, field_len,
                    (int32_t *)&out->algorithm);
            break;
        case __KM_TAG_MASK(KM_TAG_KEY_SIZE):
            out->__keySize_present = parse_integer_64(p, field_len,
                    (int64_t *)&out->keySize);
            break;
        case __KM_TAG_MASK(KM_TAG_BLOCK_MODE):
            out->__blockMode_present = parse_set_of_int32(p, field_len,
                    (VECTOR(int32_t) *)&out->blockMode);
            break;
        case __KM_TAG_MASK(KM_TAG_DIGEST):
            out->__digest_present = parse_set_of_int32(p, field_len,
                    (VECTOR(int32_t) *)&out->digest);
            break;
        case __KM_TAG_MASK(KM_TAG_PADDING):
            out->__padding_present = parse_set_of_int32(p, field_len,
                    (VECTOR(int32_t) *)&out->padding);
            break;
        case __KM_TAG_MASK(KM_TAG_CALLER_NONCE):
            out->__callerNonce_present = out->callerNonce = true;
            *p += field_len;
            break;
        case __KM_TAG_MASK(KM_TAG_MIN_MAC_LENGTH):
            out->__minMacLength_present = parse_integer_64(p, field_len,
                    (int64_t *)&out->minMacLength);
            break;
        case __KM_TAG_MASK(KM_TAG_EC_CURVE):
            out->__ecCurve_present = parse_integer_32(p, field_len,
                    (int32_t *)&out->ecCurve);
            break;
        case __KM_TAG_MASK(KM_TAG_RSA_PUBLIC_EXPONENT):
            out->__rsaPublicExponent_present = parse_integer_64(p, field_len,
                    (int64_t *)&out->rsaPublicExponent);
            break;
        case __KM_TAG_MASK(KM_TAG_ROLLBACK_RESISTANCE):
            out->__rollbackResistance_present = out->rollbackResistance = true;
            *p += field_len;
            break;
        case __KM_TAG_MASK(KM_TAG_ACTIVE_DATETIME):
            out->__activeDateTime_present = parse_integer_64(p, field_len,
                    &out->activeDateTime);
            break;
        case __KM_TAG_MASK(KM_TAG_ORIGINATION_EXPIRE_DATETIME):
            out->__originationExpireDateTime_present =
                parse_integer_64(p, field_len, &out->originationExpireDateTime);
            break;
        case __KM_TAG_MASK(KM_TAG_USAGE_EXPIRE_DATETIME):
            out->__usageExpireDateTime_present = parse_integer_64(p, field_len,
                    &out->usageExpireDateTime);
            break;
        case __KM_TAG_MASK(KM_TAG_USER_SECURE_ID):
            out->__userSecureId_present = parse_set_of_int64(p, field_len,
                    (VECTOR(int64_t) *)&out->userSecureId);
            break;
        case __KM_TAG_MASK(KM_TAG_NO_AUTH_REQUIRED):
            out->__noAuthRequired_present = out->noAuthRequired = true;
            *p += field_len;
            break;
        case __KM_TAG_MASK(KM_TAG_USER_AUTH_TYPE):
            out->__userAuthType_present = parse_integer_32(p, field_len,
                    (int32_t *)&out->userAuthType);
            break;
        case __KM_TAG_MASK(KM_TAG_ALLOW_WHILE_ON_BODY):
            out->__allowWhileOnBody_present = out->allowWhileOnBody = true;
            *p += field_len;
            break;
        case __KM_TAG_MASK(KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED):
            out->__trustedUserPresenceReq_present =
                out->trustedUserPresenceReq = true;
            *p += field_len;
            break;
        case __KM_TAG_MASK(KM_TAG_TRUSTED_CONFIRMATION_REQUIRED):
            out->__trustedConfirmationReq_present =
                out->trustedConfirmationReq = true;
            *p += field_len;
            break;
        case __KM_TAG_MASK(KM_TAG_UNLOCKED_DEVICE_REQUIRED):
            out->__unlockedDeviceReq_present = out->unlockedDeviceReq = true;
            *p += field_len;
            break;
        case __KM_TAG_MASK(KM_TAG_CREATION_DATETIME):
            out->__creationDateTime_present = parse_integer_64(p, field_len,
                    &out->creationDateTime);
            break;
        case __KM_TAG_MASK(KM_TAG_ORIGIN):
            out->__keyOrigin_present = parse_integer_32(p, field_len,
                    (int32_t *)&out->keyOrigin);
            break;
        case __KM_TAG_MASK(KM_TAG_ROOT_OF_TRUST):
            out->__rootOfTrust_present = parse_root_of_trust(&out->rootOfTrust,
                    p, field_len);
            break;
        case __KM_TAG_MASK(KM_TAG_OS_VERSION):
            out->__osVersion_present = parse_integer_64(p, field_len,
                    (int64_t *)&out->osVersion);
            break;
        case __KM_TAG_MASK(KM_TAG_OS_PATCHLEVEL):
            out->__osPatchLevel_present = parse_integer_64(p, field_len,
                    (int64_t *)&out->osPatchLevel);
            break;
        case __KM_TAG_MASK(KM_TAG_ATTESTATION_APPLICATION_ID):
            out->__attestationApplicationId_present =
                parse_octet_string(p, field_len,
                        &out->attestationApplicationId
                );
            break;
        case __KM_TAG_MASK(KM_TAG_ATTESTATION_ID_BRAND):
            out->__attestationIdBrand_present = parse_octet_string(p, field_len,
                    &out->attestationIdBrand);
            break;
        case __KM_TAG_MASK(KM_TAG_ATTESTATION_ID_DEVICE):
            out->__attestationIdDevice_present =
                parse_octet_string(p, field_len, &out->attestationIdDevice);
            break;
        case __KM_TAG_MASK(KM_TAG_ATTESTATION_ID_PRODUCT):
            out->__attestationIdProduct_present =
                parse_octet_string(p, field_len, &out->attestationIdProduct);
            break;
        case __KM_TAG_MASK(KM_TAG_ATTESTATION_ID_SERIAL):
            out->__attestationIdSerial_present =
                parse_octet_string(p, field_len, &out->attestationIdSerial);
            break;
        case __KM_TAG_MASK(KM_TAG_ATTESTATION_ID_IMEI):
            out->__attestationIdImei_present = parse_octet_string(p, field_len,
                    &out->attestationIdImei);
            break;
        case __KM_TAG_MASK(KM_TAG_ATTESTATION_ID_MEID):
            out->__attestationIdMeid_present = parse_octet_string(p, field_len,
                    &out->attestationIdMeid);
            break;
        case __KM_TAG_MASK(KM_TAG_ATTESTATION_ID_MANUFACTURER):
            out->__attestationIdManufacturer_present =
                parse_octet_string(p, field_len,
                        &out->attestationIdManufacturer
                );
            break;
        case __KM_TAG_MASK(KM_TAG_ATTESTATION_ID_MODEL):
            out->__attestationIdModel_present = parse_octet_string(p, field_len,
                    &out->attestationIdModel);
            break;
        case __KM_TAG_MASK(KM_TAG_VENDOR_PATCHLEVEL):
            out->__vendorPatchLevel_present = parse_integer_64(p, field_len,
                    (int64_t *)&out->vendorPatchLevel);
            break;
        case __KM_TAG_MASK(KM_TAG_BOOT_PATCHLEVEL):
            out->__bootPatchLevel_present = parse_integer_64(p, field_len,
                    (int64_t *)&out->bootPatchLevel);
            break;
        default:
            /* Unknown field; skip */
            *p += field_len;
            break;
        }
    }

    if (*p != seq_end) {
        s_log_error("Trailing data at the end of authorization list sequence!");
        return false;
    }

    return true;
}

static bool parse_root_of_trust(struct KM_RootOfTrust_v3 *out,
        const unsigned  char **p, long len)
{
    const unsigned char *seq_end = NULL;

    /* Unwrap the rootOfTrust SEQUENCE */
    if (!unwrap_asn1_sequence(p, len, NULL, &seq_end, NULL))
        goto_error("Couldn't unwrap the RootOfTrust SEQUENCE!");

    /* VerifiedBootKey
     *
     * A digest of the AVB master key,
     * or all zeroes when `deviceLocked == false` */
    if (!parse_octet_string(p, seq_end - *p, &out->verifiedBootKey))
        goto_error("Missing verifiedBootKey field in rootOfTrust sequence!");

    /* deviceLocked
     *
     * `true` if `verifiedBootState` is Green or Yellow, `false` otherwise */
    if (!parse_boolean(p, seq_end - *p, &out->deviceLocked))
        goto_error("Missing deviceLocked field in rootOfTrust sequence!");
    s_log_info("rootOfTrust: deviceLocked: %d", out->deviceLocked);

    /* verifiedBootState
     *
     * Red - Verification failed (technically impossible; device shouldn't boot)
     * Orange - Unverified ("bootloader unlocked")
     * Yellow - Locked with user-set key (unsupported on Samsung)
     * Green - Locked with vendor-set key
     */
    if (!parse_enumerated(p, seq_end - *p, (int32_t *)&out->verifiedBootState))
        goto_error("Missing verifiedBootState in rootOfTrust sequence!");

    /* verifiedBootHash
     *
     * Digest of the `vbmeta` struct */
    if (!parse_octet_string(p, seq_end - *p, &out->verifiedBootHash))
        goto_error("Missing verifiedBootHash field in rootOfTrust sequence!");

    if (*p != seq_end)
        goto_error("Invalid length of rootOfTrust sequence!");

    return true;

err:
    vector_destroy(&out->verifiedBootKey);
    vector_destroy(&out->verifiedBootHash);
    return false;
}

static bool unwrap_asn1_sequence(const unsigned char **p, long len,
        const unsigned char **out_start, const unsigned char **out_end,
        long *out_len)
{
    if (out_start != NULL) *out_start = NULL;
    if (out_end != NULL) *out_end = NULL;
    if (out_len != NULL) *out_len = 0;

    long seq_len = 0;
    i32 asn1_tag = 0, asn1_class = 0;
    const unsigned char *start = *p;

    i32 ret = ASN1_get_object(p, &seq_len, &asn1_tag, &asn1_class, len);
    if (ret & 0x80) {
        s_log_error("Couldn't get DER SEQUENCE object");
        return false;
    }

    if (asn1_class != V_ASN1_UNIVERSAL || asn1_tag != V_ASN1_SEQUENCE) {
        s_log_error("DER object is not a SEQUENCE");
        return false;
    }

    if (*p + seq_len > start + len) {
        s_log_error("DER SEQUENCE overruns buffer!");
        return false;
    }

    if (out_start != NULL) *out_start = *p;
    if (out_end != NULL) *out_end = *p + seq_len;
    if (out_len != NULL) *out_len = seq_len;

    return true;
}

static bool parse_integer_64(const unsigned char **p, long len, int64_t *out)
{
    *out = 0;
    ASN1_INTEGER *i = d2i_ASN1_INTEGER(NULL, p, len);
    if (i == NULL)
        return false;

    if (ASN1_INTEGER_get_int64(out, i) == 0) {
        ASN1_INTEGER_free(i);
        s_log_error("Couldn't get the value of an integer (64)");
        *out = 0;
        return false;
    }

    ASN1_INTEGER_free(i);
    return true;
}

static bool parse_integer_32(const unsigned char **p, long len, int32_t *out)
{
    *out = 0;
    int64_t ret = 0;

    ASN1_INTEGER *e = d2i_ASN1_INTEGER(NULL, p, len);
    if (e == NULL)
        return false;

    if (ASN1_INTEGER_get_int64(&ret, e) == 0) {
        ASN1_INTEGER_free(e);
        s_log_error("Couldn't get the value of an integer (32)");
        return false;
    }

    ASN1_INTEGER_free(e);

    *out = (ret & 0xFFFFFFFF);
    return true;
}

static bool parse_enumerated(const unsigned char **p, long len, int32_t *out)
{
    *out = 0;
    int64_t ret = 0;

    ASN1_INTEGER *e = d2i_ASN1_ENUMERATED(NULL, p, len);
    if (e == NULL)
        return false;

    if (ASN1_ENUMERATED_get_int64(&ret, e) == 0) {
        ASN1_ENUMERATED_free(e);
        s_log_error("Couldn't get the value of an enumerated type");
        return false;
    }
    ASN1_ENUMERATED_free(e);

    /* In all of our cases, the enumerated value
     * never actually overflows an int32 */
    *out = (ret & 0xFFFFFFFF);
    return true;
}

static bool parse_octet_string(const unsigned char **p, long len,
        VECTOR(u8) *out)
{
    *out = NULL;
    ASN1_OCTET_STRING *s = d2i_ASN1_OCTET_STRING(NULL, p, len);
    if (s == NULL)
        return false;

    i32 size = ASN1_STRING_length(s);
    if (size < 0) {
        s_log_error("Invalid octet string size: %d", size);
        ASN1_OCTET_STRING_free(s);
        return false;
    }

    const unsigned char *data = ASN1_STRING_get0_data(s);
    if (data == NULL) {
        s_log_error("Couldn't get octet string data");
        ASN1_OCTET_STRING_free(s);
        return false;
    }

    VECTOR(u8) ret = vector_new(u8);
    vector_resize(&ret, size);
    memcpy(ret, data, size);

    ASN1_OCTET_STRING_free(s);
    *out = ret;
    return true;
}

static bool parse_set_of_int64(const unsigned char **p, long len,
        VECTOR(int64_t) *out)
{
    const unsigned char *start = *p;
    const unsigned char *end = start + len;

    i32 tag = 0;
    i32 asn1_class = 0;
    i64 set_len = 0;

    if (ASN1_get_object(p, &set_len, &tag, &asn1_class, end - start) & 0x80) {
        return false;
    } else if (tag != V_ASN1_SET) {
        s_log_error("Invalid tag on SET OF INTEGER sequence: %d", tag);
        return false;
    } else if (asn1_class != V_ASN1_UNIVERSAL) {
        s_log_error("Invalid class on SET OF INTEGER sequence: %d", asn1_class);
        return false;
    }

    VECTOR(int64_t) ret = vector_new(int64_t);

    const unsigned char *set_end = *p + set_len;
    while (*p < set_end) {
        int64_t val = 0;
        ASN1_INTEGER *i = NULL;

        i = d2i_ASN1_INTEGER(NULL, p, set_end - *p);
        if (i == NULL) {
            vector_destroy(&ret);
            s_log_error("Failed to read an integer in a set");
            return false;
        }

        if (ASN1_INTEGER_get_int64(&val, i) == 0) {
            ASN1_INTEGER_free(i);
            vector_destroy(&ret);
            s_log_error("Failed to get the value of an integer in a set");
            return false;
        }

        vector_push_back(&ret, val);
        ASN1_INTEGER_free(i);
    }

    *out = ret;
    return true;
}

static bool parse_set_of_int32(const unsigned char **p, long len,
        VECTOR(int32_t) *out)
{
    const unsigned char *start = *p;
    const unsigned char *end = start + len;

    i32 tag = 0;
    i32 asn1_class = 0;
    i64 set_len = 0;

    if (ASN1_get_object(p, &set_len, &tag, &asn1_class, end - start) & 0x80) {
        return false;
    } else if (tag != V_ASN1_SET) {
        s_log_error("Invalid tag on SET OF INTEGER sequence: %d", tag);
        return false;
    } else if (asn1_class != V_ASN1_UNIVERSAL) {
        s_log_error("Invalid class on SET OF INTEGER sequence: %d", asn1_class);
        return false;
    }

    VECTOR(int32_t) ret = vector_new(int32_t);

    const unsigned char *set_end = *p + set_len;
    while (*p < set_end) {
        int64_t val = 0;
        ASN1_INTEGER *i = NULL;

        i = d2i_ASN1_INTEGER(NULL, p, set_end - *p);
        if (i == NULL) {
            vector_destroy(&ret);
            s_log_error("Failed to read an integer in a set");
            return false;
        }

        if (ASN1_INTEGER_get_int64(&val, i) == 0) {
            ASN1_INTEGER_free(i);
            vector_destroy(&ret);
            s_log_error("Failed to get the value of an integer in a set");
            return false;
        }

        /* Same as with `parse_enum`,
         * no keymaster enum value ever overflows a 32-bit int */
        vector_push_back(&ret, (val & 0xFFFFFFFF));
        ASN1_INTEGER_free(i);
    }

    *out = ret;
    return true;
}

static bool parse_boolean(const unsigned char **p, long len, bool *out)
{
    if (len < 3)
        return false;

    const unsigned char *curr = *p;

    /* Tag */
    if (*curr != V_ASN1_BOOLEAN)
        return false;

    curr++;

    /* Length */
    if (*curr != 1)
        return false;

    curr++;

    /* Value */
    if (*curr != 0x00 && *curr != 0xFF)
        return false;

    *out = (*curr == 0xFF);

    curr++;

    *p = curr; /* consume DER */
    return true;
}

static i32 validate_km_desc(const struct KM_KeyDescription_v3 *desc)
{
    if (desc->attestationVersion != 3) {
        s_log_error("Unsupported attestation version: %d",
                desc->attestationVersion);
        return 1;
    }
    switch (desc->attestationSecurityLevel) {
    case KM_SECURITY_LEVEL_SOFTWARE:
    case KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT:
    case KM_SECURITY_LEVEL_STRONGBOX:
        break;
    default:
        s_log_error("Invalid attestation security level: %d",
                desc->attestationSecurityLevel);
        return 1;
    }
    if (desc->keymasterVersion != 4) {
        s_log_error("Unsupported keymaster version: %d",
                desc->keymasterVersion);
    }
    switch (desc->attestationSecurityLevel) {
    case KM_SECURITY_LEVEL_SOFTWARE:
    case KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT:
    case KM_SECURITY_LEVEL_STRONGBOX:
        break;
    default:
        s_log_error("Invalid keymaster security level: %d",
                desc->keymasterSecurityLevel);
        return 1;
    }

    /* attestationChallenge- and uniqueId's presence
     * have already been validated previously */

    /* All fields in the authorization lists are technically optional */

    if (desc->softwareEnforced.__rootOfTrust_present) {
        switch (desc->softwareEnforced.rootOfTrust.verifiedBootState) {
        case KM_VERIFIED_BOOT_FAILED:
            s_log_warn("KM_VERIFIED_BOOT_FAILED shouldn't be possible");
        case KM_VERIFIED_BOOT_UNVERIFIED:
        case KM_VERIFIED_BOOT_SELF_SIGNED:
        case KM_VERIFIED_BOOT_VERIFIED:
            break;
        default:
            s_log_error("Invalid verified boot state "
                    "in softwareEnforced authorization list: %d",
                    desc->softwareEnforced.rootOfTrust.verifiedBootState);
            return 1;
        }
    }

    if (desc->hardwareEnforced.__rootOfTrust_present) {
        switch (desc->hardwareEnforced.rootOfTrust.verifiedBootState) {
        case KM_VERIFIED_BOOT_FAILED:
            s_log_warn("KM_VERIFIED_BOOT_FAILED shouldn't be possible");
        case KM_VERIFIED_BOOT_UNVERIFIED:
        case KM_VERIFIED_BOOT_SELF_SIGNED:
        case KM_VERIFIED_BOOT_VERIFIED:
            break;
        default:
            s_log_error("Invalid verified boot state "
                    "in hardwareEnforced authorization list: %d",
                    desc->hardwareEnforced.rootOfTrust.verifiedBootState);
            return 1;
        }
    }

    return 0;
}
