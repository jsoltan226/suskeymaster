#include "keymaster-types-c.h"
#include "km-def.h"
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/crypto.h>

ASN1_SEQUENCE(KM_ROOT_OF_TRUST) = {
    ASN1_SIMPLE(KM_ROOT_OF_TRUST, verifiedBootKey, ASN1_OCTET_STRING),
    ASN1_SIMPLE(KM_ROOT_OF_TRUST, deviceLocked, ASN1_BOOLEAN),
    ASN1_SIMPLE(KM_ROOT_OF_TRUST, verifiedBootState, ASN1_ENUMERATED),
    /* absent in attestation version < 3 */
    ASN1_OPT(KM_ROOT_OF_TRUST, verifiedBootHash, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(KM_ROOT_OF_TRUST)
IMPLEMENT_ASN1_FUNCTIONS(KM_ROOT_OF_TRUST)

ASN1_SEQUENCE(KM_PARAM_LIST) = {
#define KM_DECL_TAG(name, type, tag_val, param_list_field, bound_enum, asn1_type, asn1_rep) \
        ASN1_EXP##asn1_rep##OPT(KM_PARAM_LIST, param_list_field, \
                ASN1_##asn1_type, __KM_TAG_MASK(KM_TAG_##name)),
    KM_TAG_LIST__
#undef KM_DECL_TAG
} ASN1_SEQUENCE_END(KM_PARAM_LIST)
IMPLEMENT_ASN1_FUNCTIONS(KM_PARAM_LIST)

ASN1_SEQUENCE(KM_KEY_DESC) = {
    ASN1_SIMPLE(KM_KEY_DESC, attestationVersion, ASN1_INTEGER),
    ASN1_SIMPLE(KM_KEY_DESC, attestationSecurityLevel, ASN1_ENUMERATED),
    ASN1_SIMPLE(KM_KEY_DESC, keymasterVersion, ASN1_INTEGER),
    ASN1_SIMPLE(KM_KEY_DESC, keymasterSecurityLevel, ASN1_ENUMERATED),
    ASN1_SIMPLE(KM_KEY_DESC, attestationChallenge, ASN1_OCTET_STRING),
    ASN1_SIMPLE(KM_KEY_DESC, uniqueId, ASN1_OCTET_STRING),
    ASN1_SIMPLE(KM_KEY_DESC, softwareEnforced, KM_PARAM_LIST),
    ASN1_SIMPLE(KM_KEY_DESC, hardwareEnforced, KM_PARAM_LIST)
} ASN1_SEQUENCE_END(KM_KEY_DESC)
IMPLEMENT_ASN1_FUNCTIONS(KM_KEY_DESC)

bool KM_Tag_is_repeatable(uint32_t tag)
{
    const enum KM_TagType tt = (enum KM_TagType)(__KM_TAG_TYPE_MASK(tag));
    return (tt == KM_TAG_TYPE_UINT_REP)
        || (tt == KM_TAG_TYPE_ENUM_REP)
        || (tt == KM_TAG_TYPE_ULONG_REP);
}

const char * KM_TagType_toString(uint32_t tt)
{
    switch ((enum KM_TagType)tt) {
        case KM_TAG_TYPE_INVALID: return "INVALID"; break;
        case KM_TAG_TYPE_ENUM: return "ENUM"; break;
        case KM_TAG_TYPE_ENUM_REP: return "ENUM_REP"; break;
        case KM_TAG_TYPE_UINT: return "UINT"; break;
        case KM_TAG_TYPE_UINT_REP: return "UINT_REP"; break;
        case KM_TAG_TYPE_ULONG: return "ULONG"; break;
        case KM_TAG_TYPE_DATE: return "DATE"; break;
        case KM_TAG_TYPE_BOOL: return "BOOL"; break;
        case KM_TAG_TYPE_BIGNUM: return "BIGNUM"; break;
        case KM_TAG_TYPE_BYTES: return "BYTES"; break;
        case KM_TAG_TYPE_ULONG_REP: return "ULONG_REP"; break;
        default: return "(unknown)";
    }
}

const char * KM_Tag_toString(uint32_t t)
{
    switch ((enum KM_Tag)t) {
        case KM_TAG_INVALID: return "INVALID";
#define KM_DECL_TAG(name, type, tag_val, param_list_field, bound_enum, asn1_type, asn1_rep)    \
        case KM_TAG_##name: return #name;
    KM_TAG_LIST__
#undef KM_DECL_TAG
        default: return "(unknown)";
    }
}

const char * KM_ErrorCode_toString(int32_t e) {
    switch ((enum KM_ErrorCode)e) {
#define KM_DECL_ERR(name, value) \
        case KM_ERROR_##name: return #name;
    KM_ERR_LIST__
#undef KM_DECL_ERR
        default: return "(unknown)";
    }
}

const char * KM_HardwareAuthenticatorType_toString(uint32_t hwautht)
{
    if (hwautht == KM_AUTHENTICATOR_ANY) {
        return "ANY";
    } else if (hwautht == KM_AUTHENTICATOR_NONE) {
        return "NONE";
    }

    /* For now there are only 2 real flags,
     * we can get away with this */
    switch (hwautht) {
        case KM_AUTHENTICATOR_PASSWORD: return "PASSWORD";
        case KM_AUTHENTICATOR_FINGERPRINT: return "FINGERPRINT";

        case KM_AUTHENTICATOR_FINGERPRINT | KM_AUTHENTICATOR_PASSWORD:
            return "PASSWORD | FINGERPRINT";

        default:
            if (hwautht & KM_AUTHENTICATOR_PASSWORD &&
                hwautht & KM_AUTHENTICATOR_FINGERPRINT)
            {
                return "PASSWORD | FINGERPRINT | (unknown)";
            } else if (hwautht & KM_AUTHENTICATOR_PASSWORD &
                       !(hwautht & KM_AUTHENTICATOR_FINGERPRINT))
            {
                return "PASSWORD | (unknown)";
            } else if (!(hwautht & KM_AUTHENTICATOR_PASSWORD) &&
                        hwautht & KM_AUTHENTICATOR_FINGERPRINT)
            {
                return "FINGERPRINT | (unknown)";
            }
    }

    return "(unknown)";
}

#define KM_DECL_ENUM_VAL(c_prefix, name, value) \
    case c_prefix##name: return #name;

#define KM_DECL_ENUM(enum_name, list_name)  \
const char * KM_##enum_name##_toString(uint32_t v)  \
{                                                   \
    switch ((enum KM_##enum_name)v) {               \
        KM_##list_name##_LIST__                     \
        default: return "(unknown)";                \
    }                                               \
}                                                   \

KM_ENUM_LIST__

#undef KM_DECL_ENUM
#undef KM_DECL_ENUM_VAL
