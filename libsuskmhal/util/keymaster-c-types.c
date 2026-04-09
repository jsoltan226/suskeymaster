#include "../keymaster-types-c.h"
#include "core/util.h"
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <core/log.h>
#include <core/int.h>
#include <openssl/crypto.h>

#define MODULE_NAME "keymaster-utils"

ASN1_SEQUENCE(KM_ROOT_OF_TRUST_SEQ) = {
    ASN1_SIMPLE(KM_ROOT_OF_TRUST_SEQ, verifiedBootKey, ASN1_OCTET_STRING),
    ASN1_SIMPLE(KM_ROOT_OF_TRUST_SEQ, deviceLocked, ASN1_BOOLEAN),
    ASN1_SIMPLE(KM_ROOT_OF_TRUST_SEQ, verifiedBootState, ASN1_ENUMERATED),
    ASN1_SIMPLE(KM_ROOT_OF_TRUST_SEQ, verifiedBootHash, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(KM_ROOT_OF_TRUST_SEQ)
IMPLEMENT_ASN1_FUNCTIONS(KM_ROOT_OF_TRUST_SEQ)

ASN1_SEQUENCE(KM_PARAM_LIST_SEQ) = {
    ASN1_EXP_SET_OF_OPT(KM_PARAM_LIST_SEQ, purpose, ASN1_INTEGER, __KM_TAG_MASK(KM_TAG_PURPOSE)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, algorithm, ASN1_INTEGER, __KM_TAG_MASK(KM_TAG_ALGORITHM)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, keySize, ASN1_INTEGER, __KM_TAG_MASK(KM_TAG_KEY_SIZE)),
    ASN1_EXP_SET_OF_OPT(KM_PARAM_LIST_SEQ, blockMode, ASN1_INTEGER, __KM_TAG_MASK(KM_TAG_BLOCK_MODE)),
    ASN1_EXP_SET_OF_OPT(KM_PARAM_LIST_SEQ, digest, ASN1_INTEGER, __KM_TAG_MASK(KM_TAG_DIGEST)),
    ASN1_EXP_SET_OF_OPT(KM_PARAM_LIST_SEQ, padding, ASN1_INTEGER, __KM_TAG_MASK(KM_TAG_PADDING)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, callerNonce, ASN1_NULL, __KM_TAG_MASK(KM_TAG_CALLER_NONCE)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, minMacLength, ASN1_INTEGER, __KM_TAG_MASK(KM_TAG_MIN_MAC_LENGTH)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, ecCurve, ASN1_INTEGER, __KM_TAG_MASK(KM_TAG_EC_CURVE)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, rsaPublicExponent, ASN1_INTEGER, __KM_TAG_MASK(KM_TAG_RSA_PUBLIC_EXPONENT)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, rollbackResistance, ASN1_NULL, __KM_TAG_MASK(KM_TAG_ROLLBACK_RESISTANCE)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, activeDateTime, ASN1_INTEGER, __KM_TAG_MASK(KM_TAG_ACTIVE_DATETIME)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, originationExpireDateTime, ASN1_INTEGER, __KM_TAG_MASK(KM_TAG_ORIGINATION_EXPIRE_DATETIME)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, usageExpireDateTime, ASN1_INTEGER, __KM_TAG_MASK(KM_TAG_USAGE_EXPIRE_DATETIME)),
    ASN1_EXP_SET_OF_OPT(KM_PARAM_LIST_SEQ, userSecureId, ASN1_INTEGER, __KM_TAG_MASK(KM_TAG_USER_SECURE_ID)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, noAuthRequired, ASN1_NULL, __KM_TAG_MASK(KM_TAG_NO_AUTH_REQUIRED)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, userAuthType, ASN1_INTEGER, __KM_TAG_MASK(KM_TAG_USER_AUTH_TYPE)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, authTimeout, ASN1_INTEGER, __KM_TAG_MASK(KM_TAG_AUTH_TIMEOUT)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, allowWhileOnBody, ASN1_NULL, __KM_TAG_MASK(KM_TAG_ALLOW_WHILE_ON_BODY)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, trustedUserPresenceReq, ASN1_NULL, __KM_TAG_MASK(KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, trustedConfirmationReq, ASN1_NULL, __KM_TAG_MASK(KM_TAG_TRUSTED_CONFIRMATION_REQUIRED)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, unlockedDeviceReq, ASN1_NULL, __KM_TAG_MASK(KM_TAG_UNLOCKED_DEVICE_REQUIRED)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, creationDateTime, ASN1_INTEGER, __KM_TAG_MASK(KM_TAG_CREATION_DATETIME)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, keyOrigin, ASN1_INTEGER, __KM_TAG_MASK(KM_TAG_ORIGIN)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, rootOfTrust, KM_ROOT_OF_TRUST_SEQ, __KM_TAG_MASK(KM_TAG_ROOT_OF_TRUST)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, osVersion, ASN1_INTEGER, __KM_TAG_MASK(KM_TAG_OS_VERSION)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, osPatchLevel, ASN1_INTEGER, __KM_TAG_MASK(KM_TAG_OS_PATCHLEVEL)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, attestationApplicationId, ASN1_OCTET_STRING, __KM_TAG_MASK(KM_TAG_ATTESTATION_APPLICATION_ID)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, attestationIdBrand, ASN1_OCTET_STRING, __KM_TAG_MASK(KM_TAG_ATTESTATION_ID_BRAND)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, attestationIdDevice, ASN1_OCTET_STRING, __KM_TAG_MASK(KM_TAG_ATTESTATION_ID_DEVICE)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, attestationIdProduct, ASN1_OCTET_STRING, __KM_TAG_MASK(KM_TAG_ATTESTATION_ID_PRODUCT)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, attestationIdSerial, ASN1_OCTET_STRING, __KM_TAG_MASK(KM_TAG_ATTESTATION_ID_SERIAL)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, attestationIdImei, ASN1_OCTET_STRING, __KM_TAG_MASK(KM_TAG_ATTESTATION_ID_IMEI)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, attestationIdMeid, ASN1_OCTET_STRING, __KM_TAG_MASK(KM_TAG_ATTESTATION_ID_MEID)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, attestationIdManufacturer, ASN1_OCTET_STRING, __KM_TAG_MASK(KM_TAG_ATTESTATION_ID_MANUFACTURER)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, attestationIdModel, ASN1_OCTET_STRING, __KM_TAG_MASK(KM_TAG_ATTESTATION_ID_MODEL)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, vendorPatchLevel, ASN1_INTEGER, __KM_TAG_MASK(KM_TAG_VENDOR_PATCHLEVEL)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, bootPatchLevel, ASN1_INTEGER, __KM_TAG_MASK(KM_TAG_BOOT_PATCHLEVEL)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, includeUniqueId, ASN1_NULL, __KM_TAG_MASK(KM_TAG_INCLUDE_UNIQUE_ID)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, keyBlobUsageRequirements, ASN1_INTEGER, __KM_TAG_MASK(KM_TAG_BLOB_USAGE_REQUIREMENTS)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, bootloaderOnly, ASN1_NULL, __KM_TAG_MASK(KM_TAG_BOOTLOADER_ONLY)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, hardwareType, ASN1_INTEGER, __KM_TAG_MASK(KM_TAG_HARDWARE_TYPE)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, minSecondsBetweenOps, ASN1_INTEGER, __KM_TAG_MASK(KM_TAG_MIN_SECONDS_BETWEEN_OPS)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, maxUsesPerBoot, ASN1_INTEGER, __KM_TAG_MASK(KM_TAG_MAX_USES_PER_BOOT)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, userId, ASN1_INTEGER, __KM_TAG_MASK(KM_TAG_USER_ID)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, applicationId, ASN1_OCTET_STRING, __KM_TAG_MASK(KM_TAG_APPLICATION_ID)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, applicationData, ASN1_OCTET_STRING, __KM_TAG_MASK(KM_TAG_APPLICATION_DATA)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, uniqueId, ASN1_OCTET_STRING, __KM_TAG_MASK(KM_TAG_UNIQUE_ID)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, attestationChallenge, ASN1_OCTET_STRING, __KM_TAG_MASK(KM_TAG_ATTESTATION_CHALLENGE)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, associatedData, ASN1_OCTET_STRING, __KM_TAG_MASK(KM_TAG_ASSOCIATED_DATA)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, nonce, ASN1_OCTET_STRING, __KM_TAG_MASK(KM_TAG_NONCE)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, macLength, ASN1_INTEGER, __KM_TAG_MASK(KM_TAG_MAC_LENGTH)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, resetSinceIdRotation, ASN1_NULL, __KM_TAG_MASK(KM_TAG_RESET_SINCE_ID_ROTATION)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, confirmationToken, ASN1_OCTET_STRING, __KM_TAG_MASK(KM_TAG_CONFIRMATION_TOKEN)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, authToken, ASN1_OCTET_STRING, __KM_TAG_MASK(KM_TAG_AUTH_TOKEN)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, verificationToken, ASN1_OCTET_STRING, __KM_TAG_MASK(KM_TAG_VERIFICATION_TOKEN)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, allUsers, ASN1_NULL, __KM_TAG_MASK(KM_TAG_ALL_USERS)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, eciesSingleHashMode, ASN1_NULL, __KM_TAG_MASK(KM_TAG_ECIES_SINGLE_HASH_MODE)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, kdf, ASN1_INTEGER, __KM_TAG_MASK(KM_TAG_KDF)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, exportable, ASN1_NULL, __KM_TAG_MASK(KM_TAG_EXPORTABLE)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, keyAuth, ASN1_NULL, __KM_TAG_MASK(KM_TAG_KEY_AUTH)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, opAuth, ASN1_NULL, __KM_TAG_MASK(KM_TAG_OP_AUTH)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, operationHandle, ASN1_INTEGER, __KM_TAG_MASK(KM_TAG_OPERATION_HANDLE)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, operationFailed, ASN1_NULL, __KM_TAG_MASK(KM_TAG_OPERATION_FAILED)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, internalCurrentDateTime, ASN1_INTEGER, __KM_TAG_MASK(KM_TAG_INTERNAL_CURRENT_DATETIME)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, ekeyBlobIV, ASN1_OCTET_STRING, __KM_TAG_MASK(KM_TAG_EKEY_BLOB_IV)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, ekeyBlobAuthTag, ASN1_OCTET_STRING, __KM_TAG_MASK(KM_TAG_EKEY_BLOB_AUTH_TAG)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, ekeyBlobCurrentUsesPerBoot, ASN1_INTEGER, __KM_TAG_MASK(KM_TAG_EKEY_BLOB_CURRENT_USES_PER_BOOT)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, ekeyBlobLastOpTimestamp, ASN1_INTEGER, __KM_TAG_MASK(KM_TAG_EKEY_BLOB_LAST_OP_TIMESTAMP)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, ekeyBlobDoUpgrade, ASN1_INTEGER, __KM_TAG_MASK(KM_TAG_EKEY_BLOB_DO_UPGRADE)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, ekeyBlobPassword, ASN1_OCTET_STRING, __KM_TAG_MASK(KM_TAG_EKEY_BLOB_PASSWORD)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, ekeyBlobSalt, ASN1_OCTET_STRING, __KM_TAG_MASK(KM_TAG_EKEY_BLOB_SALT)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, ekeyBlobEncVer, ASN1_INTEGER, __KM_TAG_MASK(KM_TAG_EKEY_BLOB_ENC_VER)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, ekeyBlobRaw, ASN1_INTEGER, __KM_TAG_MASK(KM_TAG_EKEY_BLOB_RAW)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, ekeyBlobUniqKDM, ASN1_OCTET_STRING, __KM_TAG_MASK(KM_TAG_EKEY_BLOB_UNIQ_KDM)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, ekeyBlobIncUseCount, ASN1_INTEGER, __KM_TAG_MASK(KM_TAG_EKEY_BLOB_INC_USE_COUNT)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, samsungRequestingTA, ASN1_OCTET_STRING, __KM_TAG_MASK(KM_TAG_SAMSUNG_REQUESTING_TA)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, samsungRotRequired, ASN1_NULL, __KM_TAG_MASK(KM_TAG_SAMSUNG_ROT_REQUIRED)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, samsungLegacyRot, ASN1_NULL, __KM_TAG_MASK(KM_TAG_SAMSUNG_LEGACY_ROT)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, useSecureProcessor, ASN1_NULL, __KM_TAG_MASK(KM_TAG_USE_SECURE_PROCESSOR)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, storageKey, ASN1_NULL, __KM_TAG_MASK(KM_TAG_STORAGE_KEY)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, integrityStatus, ASN1_INTEGER, __KM_TAG_MASK(KM_TAG_INTEGRITY_STATUS)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, isSamsungKey, ASN1_NULL, __KM_TAG_MASK(KM_TAG_IS_SAMSUNG_KEY)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, samsungAttestationRoot, ASN1_OCTET_STRING, __KM_TAG_MASK(KM_TAG_SAMSUNG_ATTESTATION_ROOT)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, samsungAttestIntegrity, ASN1_NULL, __KM_TAG_MASK(KM_TAG_SAMSUNG_ATTEST_INTEGRITY)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, knoxObjectProtectionRequired, ASN1_NULL, __KM_TAG_MASK(KM_TAG_KNOX_OBJECT_PROTECTION_REQUIRED)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, knoxCreatorId, ASN1_OCTET_STRING, __KM_TAG_MASK(KM_TAG_KNOX_CREATOR_ID)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, knoxAdministratorId, ASN1_OCTET_STRING, __KM_TAG_MASK(KM_TAG_KNOX_ADMINISTRATOR_ID)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, knoxAccessorId, ASN1_OCTET_STRING, __KM_TAG_MASK(KM_TAG_KNOX_ACCESSOR_ID)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, samsungAuthPackage, ASN1_OCTET_STRING, __KM_TAG_MASK(KM_TAG_SAMSUNG_AUTHENTICATE_PACKAGE)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, samsungCertificateSubject, ASN1_OCTET_STRING, __KM_TAG_MASK(KM_TAG_SAMSUNG_CERTIFICATE_SUBJECT)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, samsungKeyUsage, ASN1_INTEGER, __KM_TAG_MASK(KM_TAG_SAMSUNG_KEY_USAGE)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, samsungExtendedKeyUsage, ASN1_OCTET_STRING, __KM_TAG_MASK(KM_TAG_SAMSUNG_EXTENDED_KEY_USAGE)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, samsungSubjectAlternativeName, ASN1_OCTET_STRING, __KM_TAG_MASK(KM_TAG_SAMSUNG_SUBJECT_ALTERNATIVE_NAME)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, provGacEc1, ASN1_OCTET_STRING, __KM_TAG_MASK(KM_TAG_PROV_GAC_EC1)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, provGacEc2, ASN1_OCTET_STRING, __KM_TAG_MASK(KM_TAG_PROV_GAC_EC2)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, provGacEc3, ASN1_OCTET_STRING, __KM_TAG_MASK(KM_TAG_PROV_GAC_EC3)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, provGakEc, ASN1_OCTET_STRING, __KM_TAG_MASK(KM_TAG_PROV_GAK_EC)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, provGakEcVtoken, ASN1_OCTET_STRING, __KM_TAG_MASK(KM_TAG_PROV_GAK_EC_VTOKEN)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, provGacRsa1, ASN1_OCTET_STRING, __KM_TAG_MASK(KM_TAG_PROV_GAC_RSA1)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, provGacRsa2, ASN1_OCTET_STRING, __KM_TAG_MASK(KM_TAG_PROV_GAC_RSA2)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, provGacRsa3, ASN1_OCTET_STRING, __KM_TAG_MASK(KM_TAG_PROV_GAC_RSA3)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, provGakRsa, ASN1_OCTET_STRING, __KM_TAG_MASK(KM_TAG_PROV_GAK_RSA)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, provGakRsaVtoken, ASN1_OCTET_STRING, __KM_TAG_MASK(KM_TAG_PROV_GAK_RSA_VTOKEN)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, provSakEc, ASN1_OCTET_STRING, __KM_TAG_MASK(KM_TAG_PROV_SAK_EC)),
    ASN1_EXP_OPT(KM_PARAM_LIST_SEQ, provSakEcVtoken, ASN1_OCTET_STRING, __KM_TAG_MASK(KM_TAG_PROV_SAK_EC_VTOKEN)),
} ASN1_SEQUENCE_END(KM_PARAM_LIST_SEQ)
IMPLEMENT_ASN1_FUNCTIONS(KM_PARAM_LIST_SEQ)

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

KM_SAMSUNG_KM_PARAM_SEQ * KM_SAMSUNG_KM_PARAM_SEQ_new(void)
{
    KM_SAMSUNG_KM_PARAM_SEQ *ret = OPENSSL_malloc(sizeof(*ret));
    if (ret == NULL) {
        s_log_error("OPENSSL_malloc failed!");
        return NULL;
    }

    ret->tag = ASN1_INTEGER_new();
    if (ret->tag == NULL) {
        s_log_error("Failed to allocate a new ASN.1 INTEGER");
        KM_SAMSUNG_KM_PARAM_SEQ_free(ret);
        return NULL;
    }

    ret->val_int = ASN1_INTEGER_new();
    if (ret->val_int == NULL) {
        s_log_error("Failed to allocate a new ASN.1 INTEGER");
        KM_SAMSUNG_KM_PARAM_SEQ_free(ret);
        return NULL;
    }
    ret->val_str = ASN1_OCTET_STRING_new();
    if (ret->val_str == NULL) {
        s_log_error("Failed to allocate a new ASN.1 OCTET_STRING");
        KM_SAMSUNG_KM_PARAM_SEQ_free(ret);
        return NULL;
    }
    ret->flags = 0;

    return ret;
}

void KM_SAMSUNG_KM_PARAM_SEQ_free(KM_SAMSUNG_KM_PARAM_SEQ *par)
{
    if (par == NULL)
        return;

    par->flags = 0;
    if (par->val_str != NULL) {
        ASN1_INTEGER_free(par->val_str);
        par->val_str = NULL;
    }
    if (par->val_int != NULL) {
        ASN1_INTEGER_free(par->val_int);
        par->val_int = NULL;
    }
    if (par->tag != NULL) {
        ASN1_INTEGER_free(par->tag);
        par->tag = NULL;
    }
}

static int get_is_intval(const ASN1_INTEGER *tag, bool *out)
{
    int64_t tag_val = 0;

    if (!ASN1_INTEGER_get_int64(&tag_val, tag)) {
        s_log_error("Failed to get the value of the tag ASN.1 INTEGER");
        return 1;
    }

    switch ((enum KM_TagType)__KM_TAG_TYPE_MASK(tag_val)) {
        case KM_TAG_TYPE_BOOL:
        case KM_TAG_TYPE_ENUM:
        case KM_TAG_TYPE_ENUM_REP:
        case KM_TAG_TYPE_UINT:
        case KM_TAG_TYPE_UINT_REP:
        case KM_TAG_TYPE_ULONG:
        case KM_TAG_TYPE_ULONG_REP:
        case KM_TAG_TYPE_DATE:
            *out = true;
            return 0;

        case KM_TAG_TYPE_BYTES:
        case KM_TAG_TYPE_BIGNUM:
            *out = false;
            return 0;

        default:
        case KM_TAG_TYPE_INVALID:
            s_log_error("Invalid keymaster tag: 0x%016llx",
                    (long long unsigned)tag_val);
            return 1;
    }
}

KM_SAMSUNG_KM_PARAM_SEQ *
d2i_KM_SAMSUNG_KM_PARAM_SEQ(const unsigned char **p, long len)
{
    if (p == NULL || *p == NULL || len <= 0) {
        s_log_error("%s: Invalid parameters", __func__);
        return NULL;
    }

    KM_SAMSUNG_KM_PARAM_SEQ *ret = NULL;

    const unsigned char *end = NULL;
    long inner_len = 0;

    if (!unwrap_asn1_sequence(p, len, NULL, &end, &inner_len))
        goto_error("Failed to unwrap the ASN.1 SEQUENCE");

    ret = OPENSSL_malloc(sizeof(KM_SAMSUNG_KM_PARAM_SEQ));
    if (ret == NULL)
        goto_error("Failed to allocate a new KM_PARAM sequence");
    ret->tag = ret->val_int = ret->val_str = NULL;
    ret->flags = 0;

    ret->tag = d2i_ASN1_INTEGER(NULL, p, inner_len);
    if (ret->tag == NULL)
        goto_error("Failed to parse the tag ASN.1 INTEGER");

    bool is_intval;
    if (get_is_intval(ret->tag, &is_intval))
        goto err;

    long field_len = 0;
    int exp_tag = 0;
    int class = 0;

    int r = ASN1_get_object(p, &field_len,
            &exp_tag, &class, end - *p);
    if (r & 0x80) {
        goto_error("ASN1_get_object failed");
        return NULL;
    } else if (!(r & V_ASN1_CONSTRUCTED)) {
        s_log_error("Missing V_ASN1_CONSTRUCTED bit");
        return NULL;
    } else if (class != V_ASN1_CONTEXT_SPECIFIC) {
        s_log_error("Expected V_ASN1_CONTEXT_SPECIFIC class, "
                "got 0x%x", class);
        return NULL;
    }
    ret->flags = (uint32_t)exp_tag;

    if (is_intval) {
        ret->val_int = d2i_ASN1_INTEGER(NULL, p, inner_len);
        if (ret->val_int == NULL)
            goto_error("Expected ASN.1 INTEGER value, but d2i failed");
    } else {
        ret->val_str = d2i_ASN1_OCTET_STRING(NULL, p, inner_len);
        if (ret->val_str == NULL)
            goto_error("Expected ASN.1 OCTET_STRING value, but d2i failed");
    }

    if (*p != end)
        goto_error("Parsed an incorrect number of bytes (delta = %lld)",
                (long long int)(*p - end));

    return ret;

err:
    if (ret != NULL) {
        KM_SAMSUNG_KM_PARAM_SEQ_free(ret);
        ret = NULL;
    }
    return NULL;
}

int i2d_KM_SAMSUNG_KM_PARAM_SEQ(const KM_SAMSUNG_KM_PARAM_SEQ *par, unsigned char **p)
{
    bool is_intval = false;
    int tag_int_len = 0;
    int val_inner_len = 0, val_outer_len = 0;
    int total_inner_len = 0, total_outer_len = 0;
    {
        tag_int_len = i2d_ASN1_INTEGER(par->tag, NULL);
        if (tag_int_len < 0) {
            s_log_error("Failed to measure the size of the "
                    "ASN.1 INTEGER parameter tag");
            return -1;
        }

        if (get_is_intval(par->tag, &is_intval))
            return -1;

        if (is_intval) {
            val_inner_len = i2d_ASN1_INTEGER(par->val_int, NULL);
        } else {
            val_inner_len = i2d_ASN1_OCTET_STRING(par->val_str, NULL);
        }
        if (val_inner_len < 0) {
            s_log_error("Failed to measure the size of the ASN.1 %s "
                    "param value", (is_intval ? "INTEGER" : "OCTET_STRING"));
            return -1;
        }

        val_outer_len = ASN1_object_size(true, val_inner_len, par->flags);

        total_inner_len = tag_int_len + val_outer_len;
        total_outer_len = ASN1_object_size(true, total_inner_len, 0);
        if (total_outer_len <= 0) {
            s_log_error("Invalid final length: %d", total_outer_len);
            return -1;
        }
    }
    if (p == NULL)
        return total_outer_len;

    {
        unsigned char *const end = *p + total_outer_len;
        int r = 0;

        ASN1_put_object(p, true, total_inner_len,
                V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL);

        r = i2d_ASN1_INTEGER(par->tag, p);
        if (r != tag_int_len) {
            goto_error("Failed to serialize the ASN.1 INTEGER param tag (%d)",
                    r);
        }

        ASN1_put_object(p, true, val_inner_len,
                par->flags, V_ASN1_CONTEXT_SPECIFIC);

        if (is_intval)
            r = i2d_ASN1_INTEGER(par->val_int, p);
        else
            r = i2d_ASN1_OCTET_STRING(par->val_str, p);

        if (r != val_inner_len) {
            goto_error("Failed to serialize the ASN.1 %s param value (%d)",
                    is_intval ? "INTEGER" : "OCTET_STRING", r);
        }

        if (*p != end) {
            goto_error("Wrote an incorrect amount of bytes (delta: %lld)",
                    (long long int)(*p - end));
        }
    }

    return total_outer_len;

err:
    return -1;
}

const char * KM_TagType_toString(uint32_t tt)
{
    if (tt == KM_TAG_TYPE_INVALID) {
        return "INVALID";
    }
    if (tt == KM_TAG_TYPE_ENUM) {
        return "ENUM";
    }
    if (tt == KM_TAG_TYPE_ENUM_REP) {
        return "ENUM_REP";
    }
    if (tt == KM_TAG_TYPE_UINT) {
        return "UINT";
    }
    if (tt == KM_TAG_TYPE_UINT_REP) {
        return "UINT_REP";
    }
    if (tt == KM_TAG_TYPE_ULONG) {
        return "ULONG";
    }
    if (tt == KM_TAG_TYPE_DATE) {
        return "DATE";
    }
    if (tt == KM_TAG_TYPE_BOOL) {
        return "BOOL";
    }
    if (tt == KM_TAG_TYPE_BIGNUM) {
        return "BIGNUM";
    }
    if (tt == KM_TAG_TYPE_BYTES) {
        return "BYTES";
    }
    if (tt == KM_TAG_TYPE_ULONG_REP) {
        return "ULONG_REP";
    }

    return "(unknown)";
}

const char * KM_Tag_toString(uint32_t t)
{
    if (t == KM_TAG_INVALID) {
        return "INVALID";
    }
    if (t == KM_TAG_PURPOSE) {
        return "PURPOSE";
    }
    if (t == KM_TAG_ALGORITHM) {
        return "ALGORITHM";
    }
    if (t == KM_TAG_KEY_SIZE) {
        return "KEY_SIZE";
    }
    if (t == KM_TAG_BLOCK_MODE) {
        return "BLOCK_MODE";
    }
    if (t == KM_TAG_DIGEST) {
        return "DIGEST";
    }
    if (t == KM_TAG_PADDING) {
        return "PADDING";
    }
    if (t == KM_TAG_CALLER_NONCE) {
        return "CALLER_NONCE";
    }
    if (t == KM_TAG_MIN_MAC_LENGTH) {
        return "MIN_MAC_LENGTH";
    }
    if (t == KM_TAG_EC_CURVE) {
        return "EC_CURVE";
    }
    if (t == KM_TAG_RSA_PUBLIC_EXPONENT) {
        return "RSA_PUBLIC_EXPONENT";
    }
    if (t == KM_TAG_INCLUDE_UNIQUE_ID) {
        return "INCLUDE_UNIQUE_ID";
    }
    if (t == KM_TAG_BLOB_USAGE_REQUIREMENTS) {
        return "BLOB_USAGE_REQUIREMENTS";
    }
    if (t == KM_TAG_BOOTLOADER_ONLY) {
        return "BOOTLOADER_ONLY";
    }
    if (t == KM_TAG_ROLLBACK_RESISTANCE) {
        return "ROLLBACK_RESISTANCE";
    }
    if (t == KM_TAG_HARDWARE_TYPE) {
        return "HARDWARE_TYPE";
    }
    if (t == KM_TAG_ACTIVE_DATETIME) {
        return "ACTIVE_DATETIME";
    }
    if (t == KM_TAG_ORIGINATION_EXPIRE_DATETIME) {
        return "ORIGINATION_EXPIRE_DATETIME";
    }
    if (t == KM_TAG_USAGE_EXPIRE_DATETIME) {
        return "USAGE_EXPIRE_DATETIME";
    }
    if (t == KM_TAG_MIN_SECONDS_BETWEEN_OPS) {
        return "MIN_SECONDS_BETWEEN_OPS";
    }
    if (t == KM_TAG_MAX_USES_PER_BOOT) {
        return "MAX_USES_PER_BOOT";
    }
    if (t == KM_TAG_USER_ID) {
        return "USER_ID";
    }
    if (t == KM_TAG_USER_SECURE_ID) {
        return "USER_SECURE_ID";
    }
    if (t == KM_TAG_NO_AUTH_REQUIRED) {
        return "NO_AUTH_REQUIRED";
    }
    if (t == KM_TAG_USER_AUTH_TYPE) {
        return "USER_AUTH_TYPE";
    }
    if (t == KM_TAG_AUTH_TIMEOUT) {
        return "AUTH_TIMEOUT";
    }
    if (t == KM_TAG_ALLOW_WHILE_ON_BODY) {
        return "ALLOW_WHILE_ON_BODY";
    }
    if (t == KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED) {
        return "TRUSTED_USER_PRESENCE_REQUIRED";
    }
    if (t == KM_TAG_TRUSTED_CONFIRMATION_REQUIRED) {
        return "TRUSTED_CONFIRMATION_REQUIRED";
    }
    if (t == KM_TAG_UNLOCKED_DEVICE_REQUIRED) {
        return "UNLOCKED_DEVICE_REQUIRED";
    }
    if (t == KM_TAG_APPLICATION_ID) {
        return "APPLICATION_ID";
    }
    if (t == KM_TAG_APPLICATION_DATA) {
        return "APPLICATION_DATA";
    }
    if (t == KM_TAG_CREATION_DATETIME) {
        return "CREATION_DATETIME";
    }
    if (t == KM_TAG_ORIGIN) {
        return "ORIGIN";
    }
    if (t == KM_TAG_ROOT_OF_TRUST) {
        return "ROOT_OF_TRUST";
    }
    if (t == KM_TAG_OS_VERSION) {
        return "OS_VERSION";
    }
    if (t == KM_TAG_OS_PATCHLEVEL) {
        return "OS_PATCHLEVEL";
    }
    if (t == KM_TAG_UNIQUE_ID) {
        return "UNIQUE_ID";
    }
    if (t == KM_TAG_ATTESTATION_CHALLENGE) {
        return "ATTESTATION_CHALLENGE";
    }
    if (t == KM_TAG_ATTESTATION_APPLICATION_ID) {
        return "ATTESTATION_APPLICATION_ID";
    }
    if (t == KM_TAG_ATTESTATION_ID_BRAND) {
        return "ATTESTATION_ID_BRAND";
    }
    if (t == KM_TAG_ATTESTATION_ID_DEVICE) {
        return "ATTESTATION_ID_DEVICE";
    }
    if (t == KM_TAG_ATTESTATION_ID_PRODUCT) {
        return "ATTESTATION_ID_PRODUCT";
    }
    if (t == KM_TAG_ATTESTATION_ID_SERIAL) {
        return "ATTESTATION_ID_SERIAL";
    }
    if (t == KM_TAG_ATTESTATION_ID_IMEI) {
        return "ATTESTATION_ID_IMEI";
    }
    if (t == KM_TAG_ATTESTATION_ID_MEID) {
        return "ATTESTATION_ID_MEID";
    }
    if (t == KM_TAG_ATTESTATION_ID_MANUFACTURER) {
        return "ATTESTATION_ID_MANUFACTURER";
    }
    if (t == KM_TAG_ATTESTATION_ID_MODEL) {
        return "ATTESTATION_ID_MODEL";
    }
    if (t == KM_TAG_VENDOR_PATCHLEVEL) {
        return "VENDOR_PATCHLEVEL";
    }
    if (t == KM_TAG_BOOT_PATCHLEVEL) {
        return "BOOT_PATCHLEVEL";
    }
    if (t == KM_TAG_ASSOCIATED_DATA) {
        return "ASSOCIATED_DATA";
    }
    if (t == KM_TAG_NONCE) {
        return "NONCE";
    }
    if (t == KM_TAG_MAC_LENGTH) {
        return "MAC_LENGTH";
    }
    if (t == KM_TAG_RESET_SINCE_ID_ROTATION) {
        return "RESET_SINCE_ID_ROTATION";
    }
    if (t == KM_TAG_CONFIRMATION_TOKEN) {
        return "CONFIRMATION_TOKEN";
    }

    if (t == KM_TAG_AUTH_TOKEN) {
        return "AUTH_TOKEN";
    }
    if (t == KM_TAG_VERIFICATION_TOKEN) {
        return "VERIFICATION_TOKEN";
    }
    if (t == KM_TAG_ALL_USERS) {
        return "ALL_USERS";
    }
    if (t == KM_TAG_ECIES_SINGLE_HASH_MODE) {
        return "ECIES_SINGLE_HASH_MODE";
    }
    if (t == KM_TAG_KDF) {
        return "KDF";
    }
    if (t == KM_TAG_EXPORTABLE) {
        return "EXPORTABLE";
    }
    if (t == KM_TAG_KEY_AUTH) {
        return "KEY_AUTH";
    }
    if (t == KM_TAG_OP_AUTH) {
        return "OP_AUTH";
    }
    if (t == KM_TAG_OPERATION_HANDLE) {
        return "OPERATION_HANDLE";
    }
    if (t == KM_TAG_OPERATION_FAILED) {
        return "OPERATION_FAILED";
    }
    if (t == KM_TAG_INTERNAL_CURRENT_DATETIME) {
        return "INTERNAL_CURRENT_DATETIME";
    }
    if (t == KM_TAG_EKEY_BLOB_IV) {
        return "EKEY_BLOB_IV";
    }
    if (t == KM_TAG_EKEY_BLOB_AUTH_TAG) {
        return "EKEY_BLOB_AUTH_TAG";
    }
    if (t == KM_TAG_EKEY_BLOB_CURRENT_USES_PER_BOOT) {
        return "EKEY_BLOB_CURRENT_USES_PER_BOOT";
    }
    if (t == KM_TAG_EKEY_BLOB_LAST_OP_TIMESTAMP) {
        return "EKEY_BLOB_LAST_OP_TIMESTAMP";
    }
    if (t == KM_TAG_EKEY_BLOB_DO_UPGRADE) {
        return "EKEY_BLOB_DO_UPGRADE";
    }
    if (t == KM_TAG_EKEY_BLOB_PASSWORD) {
        return "EKEY_BLOB_PASSWORD";
    }
    if (t == KM_TAG_EKEY_BLOB_SALT) {
        return "EKEY_BLOB_SALT";
    }
    if (t == KM_TAG_EKEY_BLOB_ENC_VER) {
        return "EKEY_BLOB_ENC_VER";
    }
    if (t == KM_TAG_EKEY_BLOB_RAW) {
        return "EKEY_BLOB_RAW";
    }
    if (t == KM_TAG_EKEY_BLOB_UNIQ_KDM) {
        return "EKEY_BLOB_UNIQ_KDM";
    }
    if (t == KM_TAG_EKEY_BLOB_INC_USE_COUNT) {
        return "EKEY_BLOB_INC_USE_COUNT";
    }
    if (t == KM_TAG_SAMSUNG_REQUESTING_TA) {
        return "SAMSUNG_REQUESTING_TA";
    }
    if (t == KM_TAG_SAMSUNG_ROT_REQUIRED) {
        return "SAMSUNG_ROT_REQUIRED";
    }
    if (t == KM_TAG_SAMSUNG_LEGACY_ROT) {
        return "SAMSUNG_LEGACY_ROT";
    }
    if (t == KM_TAG_USE_SECURE_PROCESSOR) {
        return "USE_SECURE_PROCESSOR";
    }
    if (t == KM_TAG_STORAGE_KEY) {
        return "STORAGE_KEY";
    }
    if (t == KM_TAG_IS_SAMSUNG_KEY) {
        return "IS_SAMSUNG_KEY";
    }
    if (t == KM_TAG_SAMSUNG_ATTESTATION_ROOT) {
        return "SAMSUNG_ATTESTATION_ROOT";
    }
    if (t == KM_TAG_INTEGRITY_STATUS) {
        return "INTEGRITY_STATUS";
    }
    if (t == KM_TAG_SAMSUNG_ATTEST_INTEGRITY) {
        return "SAMSUNG_ATTEST_INTEGRITY";
    }
    if (t == KM_TAG_KNOX_OBJECT_PROTECTION_REQUIRED) {
        return "KNOX_OBJECT_PROTECTION_REQUIRED";
    }
    if (t == KM_TAG_KNOX_CREATOR_ID) {
        return "KNOX_CREATOR_ID";
    }
    if (t == KM_TAG_KNOX_ADMINISTRATOR_ID) {
        return "KNOX_ADMINISTRATOR_ID";
    }
    if (t == KM_TAG_KNOX_ACCESSOR_ID) {
        return "KNOX_ACCESSOR_ID";
    }
    if (t == KM_TAG_SAMSUNG_AUTHENTICATE_PACKAGE) {
        return "SAMSUNG_AUTHENTICATE_PACKAGE";
    }
    if (t == KM_TAG_SAMSUNG_CERTIFICATE_SUBJECT) {
        return "SAMSUNG_CERTIFICATE_SUBJECT";
    }
    if (t == KM_TAG_SAMSUNG_KEY_USAGE) {
        return "SAMSUNG_KEY_USAGE";
    }
    if (t == KM_TAG_SAMSUNG_EXTENDED_KEY_USAGE) {
        return "SAMSUNG_EXTENDED_KEY_USAGE";
    }
    if (t == KM_TAG_SAMSUNG_SUBJECT_ALTERNATIVE_NAME) {
        return "SAMSUNG_SUBJECT_ALTERNATIVE_NAME";
    }
    if (t == KM_TAG_PROV_GAC_EC1) {
        return "PROV_GAC_EC1";
    }
    if (t == KM_TAG_PROV_GAC_EC2) {
        return "PROV_GAC_EC2";
    }
    if (t == KM_TAG_PROV_GAC_EC3) {
        return "PROV_GAC_EC3";
    }
    if (t == KM_TAG_PROV_GAK_EC) {
        return "PROV_GAK_EC";
    }
    if (t == KM_TAG_PROV_GAK_EC_VTOKEN) {
        return "PROV_GAK_EC_VTOKEN";
    }
    if (t == KM_TAG_PROV_GAC_RSA1) {
        return "PROV_GAC_RSA1";
    }
    if (t == KM_TAG_PROV_GAC_RSA2) {
        return "PROV_GAC_RSA2";
    }
    if (t == KM_TAG_PROV_GAC_RSA3) {
        return "PROV_GAC_RSA3";
    }
    if (t == KM_TAG_PROV_GAK_RSA) {
        return "PROV_GAK_RSA";
    }
    if (t == KM_TAG_PROV_GAK_RSA_VTOKEN) {
        return "PROV_GAK_RSA_VTOKEN";
    }
    if (t == KM_TAG_PROV_SAK_EC) {
        return "PROV_SAK_EC";
    }
    if (t == KM_TAG_PROV_SAK_EC_VTOKEN) {
        return "PROV_SAK_EC_VTOKEN";
    }

    return "(unknown)";
}

const char * KM_ErrorCode_toString(int o) {
    if (o == KM_OK) {
        return "OK";
    }
    if (o == KM_ERR_ROOT_OF_TRUST_ALREADY_SET) {
        return "ROOT_OF_TRUST_ALREADY_SET";
    }
    if (o == KM_ERR_UNSUPPORTED_PURPOSE) {
        return "UNSUPPORTED_PURPOSE";
    }
    if (o == KM_ERR_INCOMPATIBLE_PURPOSE) {
        return "INCOMPATIBLE_PURPOSE";
    }
    if (o == KM_ERR_UNSUPPORTED_ALGORITHM) {
        return "UNSUPPORTED_ALGORITHM";
    }
    if (o == KM_ERR_INCOMPATIBLE_ALGORITHM) {
        return "INCOMPATIBLE_ALGORITHM";
    }
    if (o == KM_ERR_UNSUPPORTED_KEY_SIZE) {
        return "UNSUPPORTED_KEY_SIZE";
    }
    if (o == KM_ERR_UNSUPPORTED_BLOCK_MODE) {
        return "UNSUPPORTED_BLOCK_MODE";
    }
    if (o == KM_ERR_INCOMPATIBLE_BLOCK_MODE) {
        return "INCOMPATIBLE_BLOCK_MODE";
    }
    if (o == KM_ERR_UNSUPPORTED_MAC_LENGTH) {
        return "UNSUPPORTED_MAC_LENGTH";
    }
    if (o == KM_ERR_UNSUPPORTED_PADDING_MODE) {
        return "UNSUPPORTED_PADDING_MODE";
    }
    if (o == KM_ERR_INCOMPATIBLE_PADDING_MODE) {
        return "INCOMPATIBLE_PADDING_MODE";
    }
    if (o == KM_ERR_UNSUPPORTED_DIGEST) {
        return "UNSUPPORTED_DIGEST";
    }
    if (o == KM_ERR_INCOMPATIBLE_DIGEST) {
        return "INCOMPATIBLE_DIGEST";
    }
    if (o == KM_ERR_INVALID_EXPIRATION_TIME) {
        return "INVALID_EXPIRATION_TIME";
    }
    if (o == KM_ERR_INVALID_USER_ID) {
        return "INVALID_USER_ID";
    }
    if (o == KM_ERR_INVALID_AUTHORIZATION_TIMEOUT) {
        return "INVALID_AUTHORIZATION_TIMEOUT"; }
    if (o == KM_ERR_UNSUPPORTED_KEY_FORMAT) {
        return "UNSUPPORTED_KEY_FORMAT";
    }
    if (o == KM_ERR_INCOMPATIBLE_KEY_FORMAT) {
        return "INCOMPATIBLE_KEY_FORMAT";
    }
    if (o == KM_ERR_UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM) {
        return "UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM";
    }
    if (o == KM_ERR_UNSUPPORTED_KEY_VERIFICATION_ALGORITHM) {
        return "UNSUPPORTED_KEY_VERIFICATION_ALGORITHM";
    }
    if (o == KM_ERR_INVALID_INPUT_LENGTH) {
        return "INVALID_INPUT_LENGTH";
    }
    if (o == KM_ERR_KEY_EXPORT_OPTIONS_INVALID) {
        return "KEY_EXPORT_OPTIONS_INVALID";
    }
    if (o == KM_ERR_DELEGATION_NOT_ALLOWED) {
        return "DELEGATION_NOT_ALLOWED";
    }
    if (o == KM_ERR_KEY_NOT_YET_VALID) {
        return "KEY_NOT_YET_VALID";
    }
    if (o == KM_ERR_KEY_EXPIRED) {
        return "KEY_EXPIRED";
    }
    if (o == KM_ERR_KEY_USER_NOT_AUTHENTICATED) {
        return "KEY_USER_NOT_AUTHENTICATED";
    }
    if (o == KM_ERR_OUTPUT_PARAMETER_NULL) {
        return "OUTPUT_PARAMETER_NULL";
    }
    if (o == KM_ERR_INVALID_OPERATION_HANDLE) {
        return "INVALID_OPERATION_HANDLE";
    }
    if (o == KM_ERR_INSUFFICIENT_BUFFER_SPACE) {
        return "INSUFFICIENT_BUFFER_SPACE";
    }
    if (o == KM_ERR_VERIFICATION_FAILED) {
        return "VERIFICATION_FAILED";
    }
    if (o == KM_ERR_TOO_MANY_OPERATIONS) {
        return "TOO_MANY_OPERATIONS";
    }
    if (o == KM_ERR_UNEXPECTED_NULL_POINTER) {
        return "UNEXPECTED_NULL_POINTER";
    }
    if (o == KM_ERR_INVALID_KEY_BLOB) {
        return "INVALID_KEY_BLOB";
    }
    if (o == KM_ERR_IMPORTED_KEY_NOT_ENCRYPTED) {
        return "IMPORTED_KEY_NOT_ENCRYPTED";
    }
    if (o == KM_ERR_IMPORTED_KEY_DECRYPTION_FAILED) {
        return "IMPORTED_KEY_DECRYPTION_FAILED";
    }
    if (o == KM_ERR_IMPORTED_KEY_NOT_SIGNED) {
        return "IMPORTED_KEY_NOT_SIGNED";
    }
    if (o == KM_ERR_IMPORTED_KEY_VERIFICATION_FAILED) {
        return "IMPORTED_KEY_VERIFICATION_FAILED";
    }
    if (o == KM_ERR_INVALID_ARGUMENT) {
        return "INVALID_ARGUMENT";
    }
    if (o == KM_ERR_UNSUPPORTED_TAG) {
        return "UNSUPPORTED_TAG";
    }
    if (o == KM_ERR_INVALID_TAG) {
        return "INVALID_TAG";
    }
    if (o == KM_ERR_MEMORY_ALLOCATION_FAILED) {
        return "MEMORY_ALLOCATION_FAILED";
    }
    if (o == KM_ERR_IMPORT_PARAMETER_MISMATCH) {
        return "IMPORT_PARAMETER_MISMATCH";
    }
    if (o == KM_ERR_SECURE_HW_ACCESS_DENIED) {
        return "SECURE_HW_ACCESS_DENIED";
    }
    if (o == KM_ERR_OPERATION_CANCELLED) {
        return "OPERATION_CANCELLED";
    }
    if (o == KM_ERR_CONCURRENT_ACCESS_CONFLICT) {
        return "CONCURRENT_ACCESS_CONFLICT";
    }
    if (o == KM_ERR_SECURE_HW_BUSY) {
        return "SECURE_HW_BUSY";
    }
    if (o == KM_ERR_SECURE_HW_COMMUNICATION_FAILED) {
        return "SECURE_HW_COMMUNICATION_FAILED";
    }
    if (o == KM_ERR_UNSUPPORTED_EC_FIELD) {
        return "UNSUPPORTED_EC_FIELD";
    }
    if (o == KM_ERR_MISSING_NONCE) {
        return "MISSING_NONCE";
    }
    if (o == KM_ERR_INVALID_NONCE) {
        return "INVALID_NONCE";
    }
    if (o == KM_ERR_MISSING_MAC_LENGTH) {
        return "MISSING_MAC_LENGTH";
    }
    if (o == KM_ERR_KEY_RATE_LIMIT_EXCEEDED) {
        return "KEY_RATE_LIMIT_EXCEEDED";
    }
    if (o == KM_ERR_CALLER_NONCE_PROHIBITED) {
        return "CALLER_NONCE_PROHIBITED";
    }
    if (o == KM_ERR_KEY_MAX_OPS_EXCEEDED) {
        return "KEY_MAX_OPS_EXCEEDED";
    }
    if (o == KM_ERR_INVALID_MAC_LENGTH) {
        return "INVALID_MAC_LENGTH";
    }
    if (o == KM_ERR_MISSING_MIN_MAC_LENGTH) {
        return "MISSING_MIN_MAC_LENGTH";
    }
    if (o == KM_ERR_UNSUPPORTED_MIN_MAC_LENGTH) {
        return "UNSUPPORTED_MIN_MAC_LENGTH";
    }
    if (o == KM_ERR_UNSUPPORTED_KDF) {
        return "UNSUPPORTED_KDF";
    }
    if (o == KM_ERR_UNSUPPORTED_EC_CURVE) {
        return "UNSUPPORTED_EC_CURVE";
    }
    if (o == KM_ERR_KEY_REQUIRES_UPGRADE) {
        return "KEY_REQUIRES_UPGRADE";
    }
    if (o == KM_ERR_ATTESTATION_CHALLENGE_MISSING) {
        return "ATTESTATION_CHALLENGE_MISSING";
    }
    if (o == KM_ERR_KEYMASTER_NOT_CONFIGURED) {
        return "KEYMASTER_NOT_CONFIGURED";
    }
    if (o == KM_ERR_ATTESTATION_APPLICATION_ID_MISSING) {
        return "ATTESTATION_APPLICATION_ID_MISSING";
    }
    if (o == KM_ERR_CANNOT_ATTEST_IDS) {
        return "CANNOT_ATTEST_IDS";
    }
    if (o == KM_ERR_ROLLBACK_RESISTANCE_UNAVAILABLE) {
        return "ROLLBACK_RESISTANCE_UNAVAILABLE";
    }
    if (o == KM_ERR_HARDWARE_TYPE_UNAVAILABLE) {
        return "HARDWARE_TYPE_UNAVAILABLE";
    }
    if (o == KM_ERR_PROOF_OF_PRESENCE_REQUIRED) {
        return "PROOF_OF_PRESENCE_REQUIRED";
    }
    if (o == KM_ERR_CONCURRENT_PROOF_OF_PRESENCE_REQUESTED) {
        return "CONCURRENT_PROOF_OF_PRESENCE_REQUESTED";
    }
    if (o == KM_ERR_NO_USER_CONFIRMATION) {
        return "NO_USER_CONFIRMATION";
    }
    if (o == KM_ERR_DEVICE_LOCKED) {
        return "DEVICE_LOCKED";
    }
    if (o == KM_ERR_UNIMPLEMENTED) {
        return "UNIMPLEMENTED";
    }
    if (o == KM_ERR_VERSION_MISMATCH) {
        return "VERSION_MISMATCH";
    }
    if (o == KM_ERR_UNKNOWN_ERROR) {
        return "UNKNOWN_ERROR";
    }

    return "(unknown)";
}

const char * KM_SecurityLevel_toString(int sl)
{
    switch ((enum KM_SecurityLevel)sl) {
    case KM_SECURITY_LEVEL_SOFTWARE: return "KM_SECURITY_LEVEL_SOFTWARE";
    case KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT: return "KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT";
    case KM_SECURITY_LEVEL_STRONGBOX: return "KM_SECURITY_LEVEL_STRONGBOX";
    default: return "(unknown)";
    }
}

const char * KM_VerifiedBootState_toString(int vb)
{
    switch ((enum KM_VerifiedBootState)vb) {
    case KM_VERIFIED_BOOT_VERIFIED: return "KM_VERIFIED_BOOT_VERIFIED";
    case KM_VERIFIED_BOOT_SELF_SIGNED: return "KM_VERIFIED_BOOT_SELF_SIGNED";
    case KM_VERIFIED_BOOT_UNVERIFIED: return "KM_VERIFIED_BOOT_UNVERIFIED";
    case KM_VERIFIED_BOOT_FAILED: return "KM_VERIFIED_BOOT_FAILED";
    default: return "(unknown";
    }
}

const char * KM_KeyPurpose_toString(int kp)
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

const char * KM_Algorithm_toString(int alg)
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

const char * KM_BlockMode_toString(int bm)
{
    switch (bm) {
    case KM_BLOCK_MODE_ECB: return "KM_BLOCK_MODE_ECB";
    case KM_BLOCK_MODE_CBC: return "KM_BLOCK_MODE_CBC";
    case KM_BLOCK_MODE_CTR: return "KM_BLOCK_MODE_CTR";
    case KM_BLOCK_MODE_GCM: return "KM_BLOCK_MODE_GCM";
    default: return "(unknown)";
    }
}

const char * KM_Digest_toString(int dig)
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

const char * KM_PaddingMode_toString(int pm)
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

const char * KM_EcCurve_toString(int ec)
{
    switch (ec) {
    case KM_EC_CURVE_P_224: return "KM_EC_CURVE_P_224";
    case KM_EC_CURVE_P_256: return "KM_EC_CURVE_P_256";
    case KM_EC_CURVE_P_384: return "KM_EC_CURVE_P_384";
    case KM_EC_CURVE_P_521: return "KM_EC_CURVE_P_521";
    default: return "(unknown)";
    }
}

const char * KM_KeyOrigin_toString(int ko)
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

const char * KM_KeyBlobUsageRequirements_toString(int kbur)
{
    switch (kbur) {
    case KM_USAGE_STANDALONE: return "KM_USAGE_STANDALONE";
    case KM_USAGE_REQUIRES_FILE_SYSTEM: return "KM_USAGE_REQUIRES_FILE_SYSTEM";
    default: return "(unknown)";
    }
}

const char * KM_KeyDerivationFunction_toString(int kdf)
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
