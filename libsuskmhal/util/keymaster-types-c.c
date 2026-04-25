#define _GNU_SOURCE
#include "keymaster-types-c.h"
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/crypto.h>

#define MODULE_NAME "keymaster-utils"

ASN1_SEQUENCE(KM_ROOT_OF_TRUST_V3) = {
    ASN1_SIMPLE(KM_ROOT_OF_TRUST_V3, verifiedBootKey, ASN1_OCTET_STRING),
    ASN1_SIMPLE(KM_ROOT_OF_TRUST_V3, deviceLocked, ASN1_BOOLEAN),
    ASN1_SIMPLE(KM_ROOT_OF_TRUST_V3, verifiedBootState, ASN1_ENUMERATED),
    ASN1_SIMPLE(KM_ROOT_OF_TRUST_V3, verifiedBootHash, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(KM_ROOT_OF_TRUST_V3)
IMPLEMENT_ASN1_FUNCTIONS(KM_ROOT_OF_TRUST_V3)

ASN1_SEQUENCE(KM_PARAM_LIST) = {
#define KM_DECL_TAG(name, type, tag_val, param_list_field, bound_enum, asn1_type, asn1_rep) \
        ASN1_EXP##asn1_rep##OPT(KM_PARAM_LIST, param_list_field, \
                ASN1_##asn1_type, __KM_TAG_MASK(KM_TAG_##name)),
    KM_TAG_LIST__
#undef KM_DECL_TAG
} ASN1_SEQUENCE_END(KM_PARAM_LIST)
IMPLEMENT_ASN1_FUNCTIONS(KM_PARAM_LIST)

ASN1_SEQUENCE(KM_KEY_DESC_V3) = {
    ASN1_SIMPLE(KM_KEY_DESC_V3, attestationVersion, ASN1_INTEGER),
    ASN1_SIMPLE(KM_KEY_DESC_V3, attestationSecurityLevel, ASN1_ENUMERATED),
    ASN1_SIMPLE(KM_KEY_DESC_V3, keymasterVersion, ASN1_INTEGER),
    ASN1_SIMPLE(KM_KEY_DESC_V3, keymasterSecurityLevel, ASN1_ENUMERATED),
    ASN1_SIMPLE(KM_KEY_DESC_V3, attestationChallenge, ASN1_OCTET_STRING),
    ASN1_SIMPLE(KM_KEY_DESC_V3, uniqueId, ASN1_OCTET_STRING),
    ASN1_SIMPLE(KM_KEY_DESC_V3, softwareEnforced, KM_PARAM_LIST),
    ASN1_SIMPLE(KM_KEY_DESC_V3, hardwareEnforced, KM_PARAM_LIST)
} ASN1_SEQUENCE_END(KM_KEY_DESC_V3)
IMPLEMENT_ASN1_FUNCTIONS(KM_KEY_DESC_V3)

bool KM_Tag_is_repeatable(uint32_t tag)
{
    const enum KM_TagType tt = (enum KM_TagType)(__KM_TAG_TYPE_MASK(tag));
    return (tt == KM_TAG_TYPE_UINT_REP)
        || (tt == KM_TAG_TYPE_ENUM_REP)
        || (tt == KM_TAG_TYPE_ULONG_REP);
}

const char * KM_TagType_toString(uint32_t tt)
{
    switch (tt) {
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
    switch (t) {
        case KM_TAG_INVALID: return "INVALID";
#define KM_DECL_TAG(name, type, tag_val, param_list_field, bound_enum, asn1_type, asn1_rep)    \
        case KM_TAG_##name: return #name;
    KM_TAG_LIST__
#undef KM_DECL_TAG
        default: return "(unknown)";
    }
}

const char * KM_ErrorCode_toString(uint32_t e) {
    switch (e) {
    case KM_OK: return "OK"; break;
    case KM_ERR_ROOT_OF_TRUST_ALREADY_SET: return "ROOT_OF_TRUST_ALREADY_SET"; break;
    case KM_ERR_UNSUPPORTED_PURPOSE: return "UNSUPPORTED_PURPOSE"; break;
    case KM_ERR_INCOMPATIBLE_PURPOSE: return "INCOMPATIBLE_PURPOSE"; break;
    case KM_ERR_UNSUPPORTED_ALGORITHM: return "UNSUPPORTED_ALGORITHM"; break;
    case KM_ERR_INCOMPATIBLE_ALGORITHM: return "INCOMPATIBLE_ALGORITHM"; break;
    case KM_ERR_UNSUPPORTED_KEY_SIZE: return "UNSUPPORTED_KEY_SIZE"; break;
    case KM_ERR_UNSUPPORTED_BLOCK_MODE: return "UNSUPPORTED_BLOCK_MODE"; break;
    case KM_ERR_INCOMPATIBLE_BLOCK_MODE: return "INCOMPATIBLE_BLOCK_MODE"; break;
    case KM_ERR_UNSUPPORTED_MAC_LENGTH: return "UNSUPPORTED_MAC_LENGTH"; break;
    case KM_ERR_UNSUPPORTED_PADDING_MODE: return "UNSUPPORTED_PADDING_MODE"; break;
    case KM_ERR_INCOMPATIBLE_PADDING_MODE: return "INCOMPATIBLE_PADDING_MODE"; break;
    case KM_ERR_UNSUPPORTED_DIGEST: return "UNSUPPORTED_DIGEST"; break;
    case KM_ERR_INCOMPATIBLE_DIGEST: return "INCOMPATIBLE_DIGEST"; break;
    case KM_ERR_INVALID_EXPIRATION_TIME: return "INVALID_EXPIRATION_TIME"; break;
    case KM_ERR_INVALID_USER_ID: return "INVALID_USER_ID"; break;
    case KM_ERR_INVALID_AUTHORIZATION_TIMEOUT: return "INVALID_AUTHORIZATION_TIMEOUT";
    case KM_ERR_UNSUPPORTED_KEY_FORMAT: return "UNSUPPORTED_KEY_FORMAT"; break;
    case KM_ERR_INCOMPATIBLE_KEY_FORMAT: return "INCOMPATIBLE_KEY_FORMAT"; break;
    case KM_ERR_UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM: return "UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM"; break;
    case KM_ERR_UNSUPPORTED_KEY_VERIFICATION_ALGORITHM: return "UNSUPPORTED_KEY_VERIFICATION_ALGORITHM"; break;
    case KM_ERR_INVALID_INPUT_LENGTH: return "INVALID_INPUT_LENGTH"; break;
    case KM_ERR_KEY_EXPORT_OPTIONS_INVALID: return "KEY_EXPORT_OPTIONS_INVALID"; break;
    case KM_ERR_DELEGATION_NOT_ALLOWED: return "DELEGATION_NOT_ALLOWED"; break;
    case KM_ERR_KEY_NOT_YET_VALID: return "KEY_NOT_YET_VALID"; break;
    case KM_ERR_KEY_EXPIRED: return "KEY_EXPIRED"; break;
    case KM_ERR_KEY_USER_NOT_AUTHENTICATED: return "KEY_USER_NOT_AUTHENTICATED"; break;
    case KM_ERR_OUTPUT_PARAMETER_NULL: return "OUTPUT_PARAMETER_NULL"; break;
    case KM_ERR_INVALID_OPERATION_HANDLE: return "INVALID_OPERATION_HANDLE"; break;
    case KM_ERR_INSUFFICIENT_BUFFER_SPACE: return "INSUFFICIENT_BUFFER_SPACE"; break;
    case KM_ERR_VERIFICATION_FAILED: return "VERIFICATION_FAILED"; break;
    case KM_ERR_TOO_MANY_OPERATIONS: return "TOO_MANY_OPERATIONS"; break;
    case KM_ERR_UNEXPECTED_NULL_POINTER: return "UNEXPECTED_NULL_POINTER"; break;
    case KM_ERR_INVALID_KEY_BLOB: return "INVALID_KEY_BLOB"; break;
    case KM_ERR_IMPORTED_KEY_NOT_ENCRYPTED: return "IMPORTED_KEY_NOT_ENCRYPTED"; break;
    case KM_ERR_IMPORTED_KEY_DECRYPTION_FAILED: return "IMPORTED_KEY_DECRYPTION_FAILED"; break;
    case KM_ERR_IMPORTED_KEY_NOT_SIGNED: return "IMPORTED_KEY_NOT_SIGNED"; break;
    case KM_ERR_IMPORTED_KEY_VERIFICATION_FAILED: return "IMPORTED_KEY_VERIFICATION_FAILED"; break;
    case KM_ERR_INVALID_ARGUMENT: return "INVALID_ARGUMENT"; break;
    case KM_ERR_UNSUPPORTED_TAG: return "UNSUPPORTED_TAG"; break;
    case KM_ERR_INVALID_TAG: return "INVALID_TAG"; break;
    case KM_ERR_MEMORY_ALLOCATION_FAILED: return "MEMORY_ALLOCATION_FAILED"; break;
    case KM_ERR_IMPORT_PARAMETER_MISMATCH: return "IMPORT_PARAMETER_MISMATCH"; break;
    case KM_ERR_SECURE_HW_ACCESS_DENIED: return "SECURE_HW_ACCESS_DENIED"; break;
    case KM_ERR_OPERATION_CANCELLED: return "OPERATION_CANCELLED"; break;
    case KM_ERR_CONCURRENT_ACCESS_CONFLICT: return "CONCURRENT_ACCESS_CONFLICT"; break;
    case KM_ERR_SECURE_HW_BUSY: return "SECURE_HW_BUSY"; break;
    case KM_ERR_SECURE_HW_COMMUNICATION_FAILED: return "SECURE_HW_COMMUNICATION_FAILED"; break;
    case KM_ERR_UNSUPPORTED_EC_FIELD: return "UNSUPPORTED_EC_FIELD"; break;
    case KM_ERR_MISSING_NONCE: return "MISSING_NONCE"; break;
    case KM_ERR_INVALID_NONCE: return "INVALID_NONCE"; break;
    case KM_ERR_MISSING_MAC_LENGTH: return "MISSING_MAC_LENGTH"; break;
    case KM_ERR_KEY_RATE_LIMIT_EXCEEDED: return "KEY_RATE_LIMIT_EXCEEDED"; break;
    case KM_ERR_CALLER_NONCE_PROHIBITED: return "CALLER_NONCE_PROHIBITED"; break;
    case KM_ERR_KEY_MAX_OPS_EXCEEDED: return "KEY_MAX_OPS_EXCEEDED"; break;
    case KM_ERR_INVALID_MAC_LENGTH: return "INVALID_MAC_LENGTH"; break;
    case KM_ERR_MISSING_MIN_MAC_LENGTH: return "MISSING_MIN_MAC_LENGTH"; break;
    case KM_ERR_UNSUPPORTED_MIN_MAC_LENGTH: return "UNSUPPORTED_MIN_MAC_LENGTH"; break;
    case KM_ERR_UNSUPPORTED_KDF: return "UNSUPPORTED_KDF"; break;
    case KM_ERR_UNSUPPORTED_EC_CURVE: return "UNSUPPORTED_EC_CURVE"; break;
    case KM_ERR_KEY_REQUIRES_UPGRADE: return "KEY_REQUIRES_UPGRADE"; break;
    case KM_ERR_ATTESTATION_CHALLENGE_MISSING: return "ATTESTATION_CHALLENGE_MISSING"; break;
    case KM_ERR_KEYMASTER_NOT_CONFIGURED: return "KEYMASTER_NOT_CONFIGURED"; break;
    case KM_ERR_ATTESTATION_APPLICATION_ID_MISSING: return "ATTESTATION_APPLICATION_ID_MISSING"; break;
    case KM_ERR_CANNOT_ATTEST_IDS: return "CANNOT_ATTEST_IDS"; break;
    case KM_ERR_ROLLBACK_RESISTANCE_UNAVAILABLE: return "ROLLBACK_RESISTANCE_UNAVAILABLE"; break;
    case KM_ERR_HARDWARE_TYPE_UNAVAILABLE: return "HARDWARE_TYPE_UNAVAILABLE"; break;
    case KM_ERR_PROOF_OF_PRESENCE_REQUIRED: return "PROOF_OF_PRESENCE_REQUIRED"; break;
    case KM_ERR_CONCURRENT_PROOF_OF_PRESENCE_REQUESTED: return "CONCURRENT_PROOF_OF_PRESENCE_REQUESTED"; break;
    case KM_ERR_NO_USER_CONFIRMATION: return "NO_USER_CONFIRMATION"; break;
    case KM_ERR_DEVICE_LOCKED: return "DEVICE_LOCKED"; break;
    case KM_ERR_UNIMPLEMENTED: return "UNIMPLEMENTED"; break;
    case KM_ERR_VERSION_MISMATCH: return "VERSION_MISMATCH"; break;
    case KM_ERR_UNKNOWN_ERROR: return "UNKNOWN_ERROR"; break;
    default: return "(unknown)";
    }
}

const char * KM_SecurityLevel_toString(uint32_t sl)
{
    switch ((enum KM_SecurityLevel)sl) {
    case KM_SECURITY_LEVEL_SOFTWARE: return "KM_SECURITY_LEVEL_SOFTWARE";
    case KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT: return "KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT";
    case KM_SECURITY_LEVEL_STRONGBOX: return "KM_SECURITY_LEVEL_STRONGBOX";
    default: return "(unknown)";
    }
}

const char * KM_VerifiedBootState_toString(uint32_t vb)
{
    switch ((enum KM_VerifiedBootState)vb) {
    case KM_VERIFIED_BOOT_VERIFIED: return "KM_VERIFIED_BOOT_VERIFIED";
    case KM_VERIFIED_BOOT_SELF_SIGNED: return "KM_VERIFIED_BOOT_SELF_SIGNED";
    case KM_VERIFIED_BOOT_UNVERIFIED: return "KM_VERIFIED_BOOT_UNVERIFIED";
    case KM_VERIFIED_BOOT_FAILED: return "KM_VERIFIED_BOOT_FAILED";
    default: return "(unknown)";
    }
}

const char * KM_KeyPurpose_toString(uint32_t kp)
{
    switch (kp) {
    case KM_PURPOSE_ENCRYPT: return "KM_PURPOSE_ENCRYPT";
    case KM_PURPOSE_DECRYPT: return "KM_PURPOSE_DECRYPT";
    case KM_PURPOSE_SIGN: return "KM_PURPOSE_SIGN";
    case KM_PURPOSE_VERIFY: return "KM_PURPOSE_VERIFY";
    case KM_PURPOSE_WRAP_KEY: return "KM_PURPOSE_WRAP_KEY";
    default: return "(unknown)";
    }
}

const char * KM_Algorithm_toString(uint32_t alg)
{
    switch (alg) {
    case KM_ALG_RSA: return "KM_ALG_RSA";
    case KM_ALG_EC: return "KM_ALG_EC";
    case KM_ALG_AES: return "KM_ALG_AES";
    case KM_ALG_TRIPLE_DES: return "KM_ALG_TRIPLE_DES";
    case KM_ALG_HMAC: return "KM_ALG_HMAC";
    default: return "(unknown)";
    }
}

const char * KM_BlockMode_toString(uint32_t bm)
{
    switch (bm) {
    case KM_BLOCK_MODE_ECB: return "KM_BLOCK_MODE_ECB";
    case KM_BLOCK_MODE_CBC: return "KM_BLOCK_MODE_CBC";
    case KM_BLOCK_MODE_CTR: return "KM_BLOCK_MODE_CTR";
    case KM_BLOCK_MODE_GCM: return "KM_BLOCK_MODE_GCM";
    default: return "(unknown)";
    }
}

const char * KM_Digest_toString(uint32_t dig)
{
    switch (dig) {
    case KM_DIGEST_NONE: return "KM_DIGEST_NONE";
    case KM_DIGEST_MD5: return "KM_DIGEST_MD5";
    case KM_DIGEST_SHA1: return "KM_DIGEST_SHA1";
    case KM_DIGEST_SHA_2_224: return "KM_DIGEST_SHA_2_224";
    case KM_DIGEST_SHA_2_256: return "KM_DIGEST_SHA_2_256";
    case KM_DIGEST_SHA_2_384: return "KM_DIGEST_SHA_2_384";
    case KM_DIGEST_SHA_2_512: return "KM_DIGEST_SHA_2_512";
    default: return "(unknown)";
    }
}

const char * KM_PaddingMode_toString(uint32_t pm)
{
    switch (pm) {
    case KM_PADDING_NONE: return "KM_PADDING_NONE";
    case KM_PADDING_RSA_OAEP: return "KM_PADDING_RSA_OAEP";
    case KM_PADDING_RSA_PSS: return "KM_PADDING_RSA_PSS";
    case KM_PADDING_RSA_PKCS1_1_5_ENCRYPT:
        return "KM_PADDING_RSA_PKCS1_1_5_ENCRYPT";
    case KM_PADDING_RSA_PKCS1_1_5_SIGN: return "KM_PADDING_RSA_PKCS1_1_5_SIGN";
    case KM_PADDING_PKCS7: return "KM_PADDING_PKCS7";
    default: return "(unknown)";
    }
}

const char * KM_EcCurve_toString(uint32_t ec)
{
    switch (ec) {
    case KM_EC_CURVE_P_224: return "KM_EC_CURVE_P_224";
    case KM_EC_CURVE_P_256: return "KM_EC_CURVE_P_256";
    case KM_EC_CURVE_P_384: return "KM_EC_CURVE_P_384";
    case KM_EC_CURVE_P_521: return "KM_EC_CURVE_P_521";
    default: return "(unknown)";
    }
}

const char * KM_KeyOrigin_toString(uint32_t ko)
{
    switch (ko) {
    case KM_ORIGIN_GENERATED: return "KM_ORIGIN_GENERATED";
    case KM_ORIGIN_DERIVED: return "KM_ORIGIN_DERIVED";
    case KM_ORIGIN_IMPORTED: return "KM_ORIGIN_IMPORTED";
    case KM_ORIGIN_UNKNOWN: return "KM_ORIGIN_UNKNOWN";
    case KM_ORIGIN_SECURELY_IMPORTED: return "KM_ORIGIN_SECURELY_IMPORTED";
    default: return "(unknown)";
    }
}

const char * KM_KeyBlobUsageRequirements_toString(uint32_t kbur)
{
    switch (kbur) {
    case KM_USAGE_STANDALONE: return "KM_USAGE_STANDALONE";
    case KM_USAGE_REQUIRES_FILE_SYSTEM: return "KM_USAGE_REQUIRES_FILE_SYSTEM";
    default: return "(unknown)";
    }
}

const char * KM_KeyDerivationFunction_toString(uint32_t kdf)
{
    switch (kdf) {
    case KM_DERIVATION_NONE: return "KM_DERIVATION_NONE";
    case KM_DERIVATION_ISO18033_2_KDF1_SHA1:
        return "KM_DERIVATION_ISO18033_2_KDF1_SHA1";
    case KM_DERIVATION_ISO18033_2_KDF1_SHA256:
        return "KM_DERIVATION_ISO18033_2_KDF1_SHA256";
    case KM_DERIVATION_ISO18033_2_KDF2_SHA1:
        return "KM_DERIVATION_ISO18033_2_KDF2_SHA1";
    case KM_DERIVATION_ISO18033_2_KDF2_SHA256:
        return "KM_DERIVATION_ISO18033_2_KDF2_SHA256";
    case KM_DERIVATION_RFC5869_SHA256: return "KM_DERIVATION_RFC5869_SHA256";
    default: return "(unknown)";
    }
}

const char * KM_HardwareAuthenticatorType_toString(uint32_t hwautht)
{
    switch (hwautht) {
    case KM_AUTHENTICATOR_NONE: return "KM_AUTHENTICATOR_NONE";
    case KM_AUTHENTICATOR_PASSWORD: return "KM_AUTHENTICATOR_PASSWORD";
    case KM_AUTHENTICATOR_FINGERPRINT: return "KM_AUTHENTICATOR_FINGERPRINT";
    case KM_AUTHENTICATOR_ANY: return "KM_AUTHENTICATOR_ANY";
    default: return "(unknown)";
    }
}
