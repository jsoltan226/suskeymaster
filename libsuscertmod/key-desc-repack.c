#define OPENSSL_API_COMPAT 0x10002000L
#include "key-desc.h"
#include <core/log.h>
#include <core/util.h>
#include <core/math.h>
#include <core/vector.h>
#include <libsuskmhal/keymaster-types-c.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/crypto.h>
#include <openssl/safestack.h>

#define MODULE_NAME "key-desc"

/* All of these are `measure_outer_*` */
static i32 measure_integer_size(struct key_desc_measure_ctx *ctx,
        i64 val, u32 tag);
static i32 measure_octet_string_size(struct key_desc_measure_ctx *ctx,
        const VECTOR(u8) str, u32 tag);
static i32 measure_enumerated_size(struct key_desc_measure_ctx *ctx,
        int val, u32 tag);
static i32 measure_set_of_integer_32_size(struct key_desc_measure_ctx *ctx,
        const VECTOR(i32) set, u32 tag);
static i32 measure_set_of_integer_64_size(struct key_desc_measure_ctx *ctx,
        const VECTOR(i64) set, u32 tag);

static i32 measure_tagged_null_size(struct key_desc_measure_ctx *ctx_,
        bool value, u32 tag);

#define MEASURE_NULL_SIZE 2 /* Always <V_ASN1_NULL> <LENGTH 0x00> */
#define MEASURE_BOOLEAN_SIZE 3 /* Always <V_ASN1_BOOL> <LENGTH 0x01> <VALUE> */

/* These functions will re-use the values from inside `measure_ctx`,
 * but not modify them */

static bool write_integer(unsigned char **p, unsigned char *end,
        const struct key_desc_measure_ctx *mctx, i64 val, u32 tag);
static bool write_enumerated(unsigned char **p, unsigned char *end,
        const struct key_desc_measure_ctx *mctx, int val, u32 tag);
static bool write_boolean(unsigned char **p, unsigned char *end, bool val);
static bool write_octet_string(unsigned char **p, unsigned char *end,
        const struct key_desc_measure_ctx *mctx, const VECTOR(u8) str, u32 tag);
static bool write_set_of_integer_32(unsigned char **p, unsigned char *end,
        const struct key_desc_measure_ctx *mctx, const VECTOR(i32) s, u32 tag);
static bool write_set_of_integer_64(unsigned char **p, unsigned char *end,
        const struct key_desc_measure_ctx *mctx, const VECTOR(i64) s, u32 tag);
static bool write_tagged_null(unsigned char **p, unsigned char *end, u32 tag);

ASN1_OCTET_STRING * key_desc_repack(const struct KM_KeyDescription_v3 *desc)
{
    struct key_desc_measure_ctx m_ctx = { 0 };
    unsigned char *der = NULL;
    i32 key_desc_content_len = 0;
    u32 der_len = 0;

    unsigned char *p = NULL, *end = NULL;

    ASN1_OCTET_STRING *ret = NULL;

    if (key_desc_measure_ctx_init(&m_ctx))
        goto_error("Failed to initialize the measurement context");

    key_desc_content_len = key_desc_measure_inner_key_desc(&m_ctx, desc);
    if (key_desc_content_len < 0)
        goto_error("Failed to measure the KeyDescription's length");

    /* DER = SEQUENCE hdr { KeyDescription content } */
    der_len = ASN1_object_size(true, key_desc_content_len, V_ASN1_SEQUENCE);

    der = OPENSSL_malloc(der_len);
    if (der == NULL)
        goto_error("Failed to allocate the DER buffer");
    p = der;
    end = der + der_len;

    /* Write the KeyDescription SEQUENCE header */
    if (!key_desc_write_sequence_header(&p, end,
                key_desc_content_len, KM_TAG_INVALID))
        goto_error("Failed to write the KeyDescription SEQUENCE header");

    /* Construct the actual KeyDescription sequence */

    if (!write_integer(&p, end, &m_ctx,
                desc->attestationVersion, KM_TAG_INVALID))
        goto_error("Failed to write the attestationVersion");

    if (!write_enumerated(&p, end, &m_ctx,
            desc->attestationSecurityLevel, KM_TAG_INVALID))
        goto_error("Failed to write the attestationSecurityLevel");

    if (!write_integer(&p, end, &m_ctx, desc->keymasterVersion, KM_TAG_INVALID))
        goto_error("Failed to write the keymasterVersion");

    if (!write_enumerated(&p, end, &m_ctx,
            desc->keymasterSecurityLevel, KM_TAG_INVALID))
        goto_error("Failed to write the keymasterSecurityLevel");

    if (!write_octet_string(&p, end, &m_ctx,
            desc->attestationChallenge, KM_TAG_INVALID))
        goto_error("Failed to write the attestationChallenge string");

    if (!write_octet_string(&p, end, &m_ctx, desc->uniqueId, KM_TAG_INVALID))
        goto_error("Failed to write the uniqueId string");

    if (!key_desc_write_auth_list(&p, end, &desc->softwareEnforced, &m_ctx,
            KEY_DESC_MEASURE_AL_SOFTWARE_ENFORCED))
        goto_error("Failed to write the softwareEnforced authorization list");

    if (!key_desc_write_auth_list(&p, end, &desc->hardwareEnforced, &m_ctx,
            KEY_DESC_MEASURE_AL_HARDWARE_ENFORCED))
        goto_error("Failed to write the hardwareEnforced authorization list");

    if (p != end)
        goto_error("Invalid number of bytes written");

    /* Pack everything up */
    ret = ASN1_OCTET_STRING_new();
    if (ret == NULL)
        goto_error("Failed to allocate the output OCTET_STRING");

    if (ASN1_OCTET_STRING_set(ret, der, der_len) == 0)
        goto_error("Failed to set the new OCTET_STRING to the sequence DER");
    der = NULL;

    s_log_info("Successfully serialized the KeyDescription");

    /* Clean up */
    key_desc_measure_ctx_destroy(&m_ctx);
    /* `der` is now owned by `ret`, so it shouldn't be freed */

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

    key_desc_measure_ctx_destroy(&m_ctx);

    return NULL;
}

void key_desc_destroy(struct KM_KeyDescription_v3 **desc_p)
{
    if (desc_p == NULL || *desc_p == NULL)
        return;

    struct KM_KeyDescription_v3 *const d = *desc_p;

    vector_destroy(&d->attestationChallenge);
    vector_destroy(&d->uniqueId);

    key_desc_destroy_auth_list(&d->softwareEnforced);
    key_desc_destroy_auth_list(&d->hardwareEnforced);

    memset(d, 0, sizeof(struct KM_KeyDescription_v3));
    free(d);
    *desc_p = NULL;
}

void key_desc_destroy_auth_list(struct KM_AuthorizationList_v3 *a)
{
    vector_destroy(&a->purpose);
    vector_destroy(&a->blockMode);
    vector_destroy(&a->digest);
    vector_destroy(&a->padding);
    vector_destroy(&a->userSecureId);
    key_desc_destroy_root_of_trust(&a->rootOfTrust);
    vector_destroy(&a->attestationApplicationId);
    vector_destroy(&a->attestationIdBrand);
    vector_destroy(&a->attestationIdDevice);
    vector_destroy(&a->attestationIdProduct);
    vector_destroy(&a->attestationIdSerial);
    vector_destroy(&a->attestationIdImei);
    vector_destroy(&a->attestationIdMeid);
    vector_destroy(&a->attestationIdManufacturer);
    vector_destroy(&a->attestationIdModel);

    vector_destroy(&a->applicationId);
    vector_destroy(&a->applicationData);
    vector_destroy(&a->uniqueId);
    vector_destroy(&a->attestationChallenge);
    vector_destroy(&a->associatedData);
    vector_destroy(&a->nonce);
    vector_destroy(&a->confirmationToken);
    vector_destroy(&a->rootOfTrustBytes);

    vector_destroy(&a->samsung.authToken);
    vector_destroy(&a->samsung.verificationToken);
    vector_destroy(&a->samsung.ekeyBlobIV);
    vector_destroy(&a->samsung.ekeyBlobAuthTag);
    vector_destroy(&a->samsung.ekeyBlobPassword);
    vector_destroy(&a->samsung.ekeyBlobSalt);
    vector_destroy(&a->samsung.ekeyBlobUniqKDM);
    vector_destroy(&a->samsung.samsungRequestingTA);
    vector_destroy(&a->samsung.samsungAttestationRoot);
    vector_destroy(&a->samsung.knoxCreatorId);
    vector_destroy(&a->samsung.knoxAdministratorId);
    vector_destroy(&a->samsung.knoxAccessorId);
    vector_destroy(&a->samsung.samsungAuthPackage);
    vector_destroy(&a->samsung.samsungCertificateSubject);
    vector_destroy(&a->samsung.samsungSubjectAlternativeName);
    vector_destroy(&a->samsung.provGacEc1);
    vector_destroy(&a->samsung.provGacEc2);
    vector_destroy(&a->samsung.provGacEc3);
    vector_destroy(&a->samsung.provGakEc);
    vector_destroy(&a->samsung.provGakEcVtoken);
    vector_destroy(&a->samsung.provGacRsa1);
    vector_destroy(&a->samsung.provGacRsa2);
    vector_destroy(&a->samsung.provGacRsa3);
    vector_destroy(&a->samsung.provGakRsa);
    vector_destroy(&a->samsung.provGakRsaVtoken);
    vector_destroy(&a->samsung.provSakEc);
    vector_destroy(&a->samsung.provSakEcVtoken);
}

void key_desc_destroy_root_of_trust(struct KM_RootOfTrust_v3 *rot)
{
    vector_destroy(&rot->verifiedBootKey);
    rot->deviceLocked = 0;
    rot->verifiedBootState = 0;
    vector_destroy(&rot->verifiedBootHash);
}

i32 key_desc_measure_ctx_init(struct key_desc_measure_ctx *ctx)
{
    if (ctx == NULL) {
        s_log_error("Invalid parameters!");
        return -1;
    }

    if (ctx->initialized_) {
        s_log_error("Context already initialized!");
        return -1;
    }

    ctx->initialized_ = true;

    ctx->i = ASN1_INTEGER_new();
    if (ctx->i == NULL)
        goto_error("Failed to allocate a new ASN.1 INTEGER");

    ctx->str = ASN1_OCTET_STRING_new();
    if (ctx->str == NULL)
        goto_error("Failed to allocate a new ASN.1 OCTET_STRING");

    ctx->e = ASN1_ENUMERATED_new();
    if (ctx->e == NULL)
        goto_error("Failed to allocate a new ASN.1 ENUMERATED value");

    ctx->softwareEnforced.al_size = ctx->softwareEnforced.al_rot_size = 0;
    ctx->hardwareEnforced.al_size = ctx->hardwareEnforced.al_rot_size = 0;

    return 0;

err:
    key_desc_measure_ctx_destroy(ctx);
    return 1;
}

void key_desc_measure_ctx_destroy(struct key_desc_measure_ctx *ctx)
{
    if (ctx == NULL || !ctx->initialized_)
        return;

    ctx->initialized_ = false;
    if (ctx->e != NULL) {
        ASN1_ENUMERATED_free(ctx->e);
        ctx->e = NULL;
    }
    if (ctx->str != NULL) {
        ASN1_OCTET_STRING_free(ctx->str);
        ctx->str = NULL;
    }
    if (ctx->i != NULL) {
        ASN1_INTEGER_free(ctx->i);
        ctx->i = NULL;
    }

    ctx->softwareEnforced.al_size = ctx->softwareEnforced.al_rot_size = 0;
    ctx->hardwareEnforced.al_size = ctx->hardwareEnforced.al_rot_size = 0;
}

i32 key_desc_measure_inner_key_desc(struct key_desc_measure_ctx *ctx,
        const struct KM_KeyDescription_v3 *desc)
{
    i32 content_len = 0, tmp = 0;

    tmp = measure_integer_size(ctx, desc->attestationVersion, KM_TAG_INVALID);
    if (tmp < 0) {
        s_log_error("Failed to measure the size of the attestationVersion");
        return -1;
    }
    content_len += tmp;

    tmp = measure_enumerated_size(ctx,
            desc->attestationSecurityLevel, KM_TAG_INVALID);
    if (tmp < 0) {
        s_log_error("Failed to measure the size of the "
                "attestationSecurityLevel");
        return -1;
    }
    content_len += tmp;

    tmp = measure_integer_size(ctx, desc->keymasterVersion, KM_TAG_INVALID);
    if (tmp < 0) {
        s_log_error("Failed to measure the size of the keymasterVersion");
        return -1;
    }
    content_len += tmp;

    tmp = measure_enumerated_size(ctx,
            desc->keymasterSecurityLevel, KM_TAG_INVALID);
    if (tmp < 0) {
        s_log_error("Failed to measure the size of the keymasterSecurityLevel");
        return -1;
    }
    content_len += tmp;

    tmp = measure_octet_string_size(ctx,
            desc->attestationChallenge, KM_TAG_INVALID);
    if (tmp < 0) {
        s_log_error("Failed to measure the size of the attestation challenge");
        return -1;
    }
    content_len += tmp;

    tmp = measure_octet_string_size(ctx, desc->uniqueId, KM_TAG_INVALID);
    if (tmp < 0) {
        s_log_error("Failed to measure the size of the unique ID");
        return -1;
    }
    content_len += tmp;

    tmp = key_desc_measure_outer_auth_list(ctx, &desc->softwareEnforced,
            KEY_DESC_MEASURE_AL_SOFTWARE_ENFORCED);
    if (tmp < 0) {
        s_log_error("Failed to measure the size of the "
                "softwareEnforced authorization list!");
        return -1;
    }
    content_len += tmp;

    tmp = key_desc_measure_outer_auth_list(ctx, &desc->hardwareEnforced,
            KEY_DESC_MEASURE_AL_HARDWARE_ENFORCED);
    if (tmp < 0) {
        s_log_error("Failed to measure the size of the "
                "hardwareEnforced authorization list!");
        return -1;
    }
    content_len += tmp;

    return content_len;
}

i32 key_desc_measure_outer_auth_list(struct key_desc_measure_ctx *ctx,
        const struct KM_AuthorizationList_v3 *al,
        enum key_desc_measure_auth_list_variant variant
)
{
    if (ctx == NULL || al == NULL ||
            (variant != KEY_DESC_MEASURE_AL_SOFTWARE_ENFORCED &&
             variant != KEY_DESC_MEASURE_AL_HARDWARE_ENFORCED)
    )
    {
        s_log_error("Invalid parameters!");
        return -1;
    }

    i32 ret = 0, tmp = 0;

    /* By reading the previous function you have hopefully gotten bored
     * of the insane repetetiveness, and so you won't be upset
     * about the use of the monstrosity below */

#define try_measure(field_name, tag, fn_name, cast) do {                    \
    if (al->__##field_name##_present) {                                     \
        tmp = measure_##fn_name##_size(ctx, (cast)al->field_name, tag);     \
        if (tmp < 0) {                                                      \
            s_log_error("Couldn't measure the size of `%s`", #field_name);  \
            return -1;                                                      \
        }                                                                   \
        ret += tmp;                                                         \
    }                                                                       \
} while (0)

    try_measure(purpose, KM_TAG_PURPOSE, set_of_integer_32, VECTOR(i32));
    try_measure(algorithm, KM_TAG_ALGORITHM, integer, i32);
    try_measure(keySize, KM_TAG_KEY_SIZE, integer, u64);
    try_measure(blockMode, KM_TAG_BLOCK_MODE, set_of_integer_32, VECTOR(i32));
    try_measure(digest, KM_TAG_DIGEST, set_of_integer_32, VECTOR(i32));
    try_measure(padding, KM_TAG_PADDING, set_of_integer_32, VECTOR(i32));
    try_measure(callerNonce, KM_TAG_CALLER_NONCE, tagged_null, bool);
    try_measure(minMacLength, KM_TAG_MIN_MAC_LENGTH, integer, u64);
    try_measure(ecCurve, KM_TAG_EC_CURVE, integer, i32);
    try_measure(rsaPublicExponent, KM_TAG_RSA_PUBLIC_EXPONENT, integer, u64);
    try_measure(includeUniqueId, KM_TAG_INCLUDE_UNIQUE_ID, tagged_null, bool);
    try_measure(keyBlobUsageRequirements, KM_TAG_BLOB_USAGE_REQUIREMENTS,
            integer, i32);
    try_measure(bootloaderOnly, KM_TAG_BOOTLOADER_ONLY, tagged_null, bool);
    try_measure(rollbackResistance, KM_TAG_ROLLBACK_RESISTANCE,
            tagged_null, bool);
    try_measure(hardwareType, KM_TAG_HARDWARE_TYPE, integer, i32);
    try_measure(activeDateTime, KM_TAG_ACTIVE_DATETIME, integer, i64);
    try_measure(originationExpireDateTime, KM_TAG_ORIGINATION_EXPIRE_DATETIME,
            integer, i64);
    try_measure(usageExpireDateTime, KM_TAG_USAGE_EXPIRE_DATETIME,
            integer, i64);
    try_measure(minSecondsBetweenOps, KM_TAG_MIN_SECONDS_BETWEEN_OPS,
            integer, i32);
    try_measure(maxUsesPerBoot, KM_TAG_MAX_USES_PER_BOOT, integer, i32);
    try_measure(userId, KM_TAG_USER_ID, integer, i32);
    try_measure(userSecureId, KM_TAG_USER_SECURE_ID,
            set_of_integer_64, VECTOR(i64));
    try_measure(noAuthRequired, KM_TAG_NO_AUTH_REQUIRED, tagged_null, bool);
    try_measure(userAuthType, KM_TAG_USER_AUTH_TYPE, integer, i64);
    try_measure(authTimeout, KM_TAG_AUTH_TIMEOUT, integer, u64);
    try_measure(allowWhileOnBody, KM_TAG_ALLOW_WHILE_ON_BODY,
            tagged_null, bool);
    try_measure(trustedUserPresenceReq, KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED,
            tagged_null, bool);
    try_measure(trustedConfirmationReq, KM_TAG_TRUSTED_CONFIRMATION_REQUIRED,
            tagged_null, bool);
    try_measure(unlockedDeviceReq, KM_TAG_UNLOCKED_DEVICE_REQUIRED,
            tagged_null, bool);
    try_measure(applicationId, KM_TAG_APPLICATION_ID, octet_string, VECTOR(u8));
    try_measure(applicationData, KM_TAG_APPLICATION_DATA,
            octet_string, VECTOR(u8));
    try_measure(creationDateTime, KM_TAG_CREATION_DATETIME, integer, i64);
    try_measure(keyOrigin, KM_TAG_ORIGIN, integer, i32);

    /* For `ret`, add the full EXPLICIT TLV size:
     *  EXPLICIT (KM_TAG_ROOT_OF_TRUST) {
     *      SEQUENCE {
     *          rootOfTrust content
     *      }
     *  }
     *
     * for `mctx`, store only the rootOfTrust content len */
    if (al->__rootOfTrust_present) {
        i32 tmp = 0;
        tmp = key_desc_measure_inner_root_of_trust(ctx, &al->rootOfTrust,
                variant);
        if (tmp < 0) {
            s_log_error("Failed to measure the size of the rootOfTrust");
            return -1;
        }

        /* Inner SEQUENCE header */
        tmp = ASN1_object_size(true, tmp, V_ASN1_SEQUENCE);

        /* Outer EXPLICIT header */
        ret += ASN1_object_size(true, tmp, __KM_TAG_MASK(KM_TAG_ROOT_OF_TRUST));
    }

    try_measure(osVersion, KM_TAG_OS_VERSION, integer, u64);
    try_measure(osPatchLevel, KM_TAG_OS_PATCHLEVEL, integer, u64);
    try_measure(uniqueId, KM_TAG_UNIQUE_ID, octet_string, VECTOR(u8));
    try_measure(attestationChallenge, KM_TAG_ATTESTATION_CHALLENGE,
            octet_string, VECTOR(u8));
    try_measure(attestationApplicationId, KM_TAG_ATTESTATION_APPLICATION_ID,
            octet_string, VECTOR(u8));

    try_measure(attestationIdBrand, KM_TAG_ATTESTATION_ID_BRAND,
            octet_string, VECTOR(u8));
    try_measure(attestationIdDevice, KM_TAG_ATTESTATION_ID_DEVICE,
            octet_string, VECTOR(u8));
    try_measure(attestationIdProduct, KM_TAG_ATTESTATION_ID_PRODUCT,
            octet_string, VECTOR(u8));
    try_measure(attestationIdSerial, KM_TAG_ATTESTATION_ID_SERIAL,
            octet_string, VECTOR(u8));
    try_measure(attestationIdImei, KM_TAG_ATTESTATION_ID_IMEI,
            octet_string, VECTOR(u8));
    try_measure(attestationIdMeid, KM_TAG_ATTESTATION_ID_MEID,
            octet_string, VECTOR(u8));
    try_measure(attestationIdManufacturer, KM_TAG_ATTESTATION_ID_MANUFACTURER,
            octet_string, VECTOR(u8));
    try_measure(attestationIdModel, KM_TAG_ATTESTATION_ID_MODEL,
            octet_string, VECTOR(u8));

    try_measure(vendorPatchLevel, KM_TAG_VENDOR_PATCHLEVEL, integer, u64);
    try_measure(bootPatchLevel, KM_TAG_BOOT_PATCHLEVEL, integer, u64);

    try_measure(associatedData, KM_TAG_ASSOCIATED_DATA,
            octet_string, VECTOR(u8));
    try_measure(nonce, KM_TAG_NONCE, octet_string, VECTOR(u8));
    try_measure(macLength, KM_TAG_MAC_LENGTH, integer, u32);
    try_measure(resetSinceIdRotation, KM_TAG_RESET_SINCE_ID_ROTATION,
            tagged_null, bool);
    try_measure(confirmationToken, KM_TAG_CONFIRMATION_TOKEN,
            octet_string, VECTOR(u8));


#undef try_measure
/** SAMSUNG-SPECIFIC FIELDS **/
#define try_measure(field_name, tag, fn_name, cast) do {                       \
    if (al->samsung.__##field_name##_present) {                                \
        tmp = measure_##fn_name##_size(ctx, (cast)al->samsung.field_name, tag);\
        if (tmp < 0) {                                                         \
            s_log_error("Couldn't measure the size of `samsung.%s`",           \
                #field_name);                                                  \
            return -1;                                                         \
        }                                                                      \
        ret += tmp;                                                            \
    }                                                                          \
} while (0)
    try_measure(authToken, KM_TAG_AUTH_TOKEN, octet_string, VECTOR(u8));
    try_measure(verificationToken, KM_TAG_VERIFICATION_TOKEN,
            octet_string, VECTOR(u8));
    try_measure(allUsers, KM_TAG_ALL_USERS, tagged_null, bool);
    try_measure(eciesSingleHashMode, KM_TAG_ECIES_SINGLE_HASH_MODE,
            tagged_null, bool);
    try_measure(kdf, KM_TAG_KDF, integer, u32);
    try_measure(exportable, KM_TAG_EXPORTABLE, tagged_null, bool);
    try_measure(keyAuth, KM_TAG_KEY_AUTH, tagged_null, bool);
    try_measure(opAuth, KM_TAG_OP_AUTH, tagged_null, bool);
    try_measure(operationHandle, KM_TAG_OPERATION_HANDLE, integer, u64);
    try_measure(operationFailed, KM_TAG_OPERATION_FAILED, tagged_null, bool);
    try_measure(internalCurrentDateTime, KM_TAG_INTERNAL_CURRENT_DATETIME,
            integer, i64);
    try_measure(ekeyBlobIV, KM_TAG_EKEY_BLOB_IV, octet_string, VECTOR(u8));
    try_measure(ekeyBlobAuthTag, KM_TAG_EKEY_BLOB_AUTH_TAG,
            octet_string, VECTOR(u8));
    try_measure(ekeyBlobCurrentUsesPerBoot,
            KM_TAG_EKEY_BLOB_CURRENT_USES_PER_BOOT, integer, u32);
    try_measure(ekeyBlobLastOpTimestamp,
            KM_TAG_EKEY_BLOB_LAST_OP_TIMESTAMP, integer, u64);
    try_measure(ekeyBlobDoUpgrade, KM_TAG_EKEY_BLOB_DO_UPGRADE, integer, u32);
    try_measure(ekeyBlobPassword, KM_TAG_EKEY_BLOB_PASSWORD,
            octet_string, VECTOR(u8));
    try_measure(ekeyBlobSalt, KM_TAG_EKEY_BLOB_SALT, octet_string, VECTOR(u8));
    try_measure(ekeyBlobEncVer, KM_TAG_EKEY_BLOB_ENC_VER, integer, u32);
    try_measure(ekeyBlobRaw, KM_TAG_EKEY_BLOB_RAW, integer, u32);
    try_measure(ekeyBlobUniqKDM, KM_TAG_EKEY_BLOB_UNIQ_KDM,
            octet_string, VECTOR(u8));
    try_measure(ekeyBlobIncUseCount, KM_TAG_EKEY_BLOB_INC_USE_COUNT,
            integer, u32);
    try_measure(samsungRequestingTA, KM_TAG_SAMSUNG_REQUESTING_TA,
            octet_string, VECTOR(u8));
    try_measure(samsungRotRequired, KM_TAG_SAMSUNG_ROT_REQUIRED,
            tagged_null, bool);
    try_measure(samsungLegacyRot, KM_TAG_SAMSUNG_LEGACY_ROT,
            tagged_null, bool);
    try_measure(useSecureProcessor, KM_TAG_USE_SECURE_PROCESSOR,
            tagged_null, bool);
    try_measure(storageKey, KM_TAG_STORAGE_KEY, tagged_null, bool);
    try_measure(integrityStatus, KM_TAG_INTEGRITY_STATUS, integer, u32);
    try_measure(isSamsungKey, KM_TAG_IS_SAMSUNG_KEY, tagged_null, bool);
    try_measure(samsungAttestationRoot, KM_TAG_SAMSUNG_ATTESTATION_ROOT,
            octet_string, VECTOR(u8));
    try_measure(samsungAttestIntegrity, KM_TAG_SAMSUNG_ATTEST_INTEGRITY,
            tagged_null, bool);
    try_measure(knoxObjectProtectionRequired,
            KM_TAG_KNOX_OBJECT_PROTECTION_REQUIRED, tagged_null, bool);
    try_measure(knoxCreatorId, KM_TAG_KNOX_CREATOR_ID,
            octet_string, VECTOR(u8));
    try_measure(knoxAdministratorId, KM_TAG_KNOX_ADMINISTRATOR_ID,
            octet_string, VECTOR(u8));
    try_measure(knoxAccessorId, KM_TAG_KNOX_ACCESSOR_ID,
            octet_string, VECTOR(u8));
    try_measure(samsungAuthPackage, KM_TAG_SAMSUNG_AUTHENTICATE_PACKAGE,
            octet_string, VECTOR(u8));
    try_measure(samsungCertificateSubject, KM_TAG_SAMSUNG_CERTIFICATE_SUBJECT,
            octet_string, VECTOR(u8));
    try_measure(samsungKeyUsage, KM_TAG_SAMSUNG_KEY_USAGE, integer, u32);
    try_measure(samsungExtendedKeyUsage, KM_TAG_SAMSUNG_EXTENDED_KEY_USAGE,
            octet_string, VECTOR(u8));
    try_measure(samsungSubjectAlternativeName,
            KM_TAG_SAMSUNG_SUBJECT_ALTERNATIVE_NAME, octet_string, VECTOR(u8));
    try_measure(provGacEc1, KM_TAG_PROV_GAC_EC1, octet_string, VECTOR(u8));
    try_measure(provGacEc2, KM_TAG_PROV_GAC_EC2, octet_string, VECTOR(u8));
    try_measure(provGacEc3, KM_TAG_PROV_GAC_EC3, octet_string, VECTOR(u8));
    try_measure(provGakEc, KM_TAG_PROV_GAK_EC, octet_string, VECTOR(u8));
    try_measure(provGakEcVtoken, KM_TAG_PROV_GAK_EC_VTOKEN,
            octet_string, VECTOR(u8));
    try_measure(provGacRsa1, KM_TAG_PROV_GAC_RSA1, octet_string, VECTOR(u8));
    try_measure(provGacRsa2, KM_TAG_PROV_GAC_RSA2, octet_string, VECTOR(u8));
    try_measure(provGacRsa3, KM_TAG_PROV_GAC_RSA3, octet_string, VECTOR(u8));
    try_measure(provGakRsa, KM_TAG_PROV_GAK_RSA, octet_string, VECTOR(u8));
    try_measure(provGakRsaVtoken, KM_TAG_PROV_GAK_RSA_VTOKEN,
            octet_string, VECTOR(u8));
    try_measure(provSakEc, KM_TAG_PROV_SAK_EC, octet_string, VECTOR(u8));
    try_measure(provSakEcVtoken, KM_TAG_PROV_SAK_EC_VTOKEN,
            octet_string, VECTOR(u8));

#undef try_measure

    /* `mctx` should store the length of the sequence content,
     * without the header */
    switch (variant) {
    case KEY_DESC_MEASURE_AL_SOFTWARE_ENFORCED:
        ctx->softwareEnforced.al_size = ret;
        break;
    case KEY_DESC_MEASURE_AL_HARDWARE_ENFORCED:
        ctx->hardwareEnforced.al_size = ret;
    }

    /* Add the length of the SEQUENCE header */
    ret = ASN1_object_size(true, ret, V_ASN1_SEQUENCE);
    return ret;
}

i32 key_desc_measure_inner_root_of_trust(struct key_desc_measure_ctx *ctx,
        const struct KM_RootOfTrust_v3 *rot,
        enum key_desc_measure_auth_list_variant variant)
{
    i32 r = 0;
    i32 total_size = 0;

    if (variant != KEY_DESC_MEASURE_AL_HARDWARE_ENFORCED &&
        variant != KEY_DESC_MEASURE_AL_SOFTWARE_ENFORCED)
    {
        s_log_error("Invalid parameters!");
        return -1;
    }

    r = measure_octet_string_size(ctx, rot->verifiedBootKey, KM_TAG_INVALID);
    if (r < 0) {
        s_log_error("Failed to measure the size of the verified boot key!");
        return -1;
    }
    total_size += r;

    /* `rot->deviceLocked` */
    total_size += MEASURE_BOOLEAN_SIZE;

    r = measure_enumerated_size(ctx, rot->verifiedBootState, KM_TAG_INVALID);
    if (r < 0) {
        s_log_error("Failed to measure the size of the verifiedBootState!");
        return -1;
    }
    total_size += r;

    r = measure_octet_string_size(ctx, rot->verifiedBootHash, KM_TAG_INVALID);
    if (r < 0) {
        s_log_error("Failed to measure the size of the verified boot hash!");
        return -1;
    }
    total_size += r;

    switch (variant) {
    case KEY_DESC_MEASURE_AL_SOFTWARE_ENFORCED:
        ctx->softwareEnforced.al_rot_size = total_size;
        break;
    case KEY_DESC_MEASURE_AL_HARDWARE_ENFORCED:
        ctx->hardwareEnforced.al_rot_size = total_size;
        break;
    }

    return total_size;
}

static i32 measure_integer_size(struct key_desc_measure_ctx *ctx,
        i64 val, u32 tag)
{
    if (ctx == NULL || !ctx->initialized_) {
        s_log_error("Invalid parameters!");
        return -1;
    }

    if (ASN1_INTEGER_set_int64(ctx->i, val) == 0) {
        s_log_error("Couldn't set the value of an ASN.1 INTEGER to an int64");
        return -1;
    }

    i32 content_len = i2d_ASN1_INTEGER(ctx->i, NULL);
    if (content_len < 0)
        return -1;
    else if (__KM_TAG_MASK(tag) == KM_TAG_INVALID)
        return content_len;
    else
        return ASN1_object_size(true, content_len, __KM_TAG_MASK(tag));
}

static i32 measure_octet_string_size(struct key_desc_measure_ctx *ctx,
        const VECTOR(u8) str, u32 tag)
{
    if (ctx == NULL || !ctx->initialized_ || str == NULL) {
        s_log_error("Invalid parameters!");
        return -1;
    }

    if (ASN1_OCTET_STRING_set(ctx->str, str, vector_size(str)) == 0) {
        s_log_error("Couldn't set the value of an ASN.1 OCTET_STRING");
        return -1;
    }

    i32 content_len = i2d_ASN1_OCTET_STRING(ctx->str, NULL);
    if (content_len < 0)
        return -1;
    else if (__KM_TAG_MASK(tag) == KM_TAG_INVALID)
        return content_len;
    else
        return ASN1_object_size(true, content_len, __KM_TAG_MASK(tag));
}

static i32 measure_enumerated_size(struct key_desc_measure_ctx *ctx,
        int val, u32 tag)
{
    if (ctx == NULL || !ctx->initialized_) {
        s_log_error("Invalid parameters!");
        return -1;
    }

    if (ASN1_ENUMERATED_set_int64(ctx->e, val) == 0) {
        s_log_error("Couldn't set the value of an ASN.1 ENUMERATED type");
        return -1;
    }

    i32 content_len = i2d_ASN1_ENUMERATED(ctx->e, NULL);
    if (content_len < 0)
        return -1;
    else if (__KM_TAG_MASK(tag) == KM_TAG_INVALID)
        return content_len;
    else
        return ASN1_object_size(true, content_len, __KM_TAG_MASK(tag));
}

static i32 measure_set_of_integer_32_size(struct key_desc_measure_ctx *ctx,
        const VECTOR(i32) set, u32 tag)
{
    if (ctx == NULL || !ctx->initialized_ || set == NULL) {
        s_log_error("Invalid parameters!");
        return -1;
    }

    u32 set_len = 0;
    i32 r = 0;

    for (u32 i = 0; i < vector_size(set); i++) {
        if (ASN1_INTEGER_set_int64(ctx->i, set[i]) == 0) {
            s_log_error("Couldn't set the value of an ASN.1 INTEGER");
            return -1;
        }

        r = i2d_ASN1_INTEGER(ctx->i, NULL);
        if (r < 0) {
            s_log_error("Couldn't measure the size of an ASN.1 INTEGER");
            return -1;
        }

        set_len += (u32)r;
    }

    i32 content_len = ASN1_object_size(true, (i32)set_len, V_ASN1_SET);
    if (content_len < 0) {
        s_log_error("Invalid return value of ASN1_object_size!");
        return -1;
    } else if (__KM_TAG_MASK(tag) == KM_TAG_INVALID) {
        return content_len;
    } else {
        return ASN1_object_size(true, content_len, __KM_TAG_MASK(tag));
    }
}

static i32 measure_set_of_integer_64_size(struct key_desc_measure_ctx *ctx,
        const VECTOR(i64) set, u32 tag)
{
    /* Have to duplicate the code here because doing `set[i]`
     * on a `VECTOR(i32)` is different than on a `VECTOR(i64)`
     * and trying to make things generic would add
     * more complexity than just doing copy+paste like here
     */

    if (ctx == NULL || !ctx->initialized_ || set == NULL) {
        s_log_error("Invalid parameters!");
        return -1;
    }

    u32 set_len = 0;
    i32 r = 0;

    for (u32 i = 0; i < vector_size(set); i++) {
        if (ASN1_INTEGER_set_int64(ctx->i, set[i]) == 0) {
            s_log_error("Couldn't set the value of an ASN.1 INTEGER");
            return -1;
        }

        r = i2d_ASN1_INTEGER(ctx->i, NULL);
        if (r < 0) {
            s_log_error("Couldn't measure the size of an ASN.1 INTEGER");
            return -1;
        }

        set_len += (u32)r;
    }

    i32 content_len = ASN1_object_size(true, (i32)set_len, V_ASN1_SET);
    if (content_len < 0) {
        s_log_error("Invalid return value of ASN1_object_size!");
        return -1;
    } else if (__KM_TAG_MASK(tag) == KM_TAG_INVALID) {
        return content_len;
    } else {
        return ASN1_object_size(true, content_len, __KM_TAG_MASK(tag));
    }
}

static i32 measure_tagged_null_size(struct key_desc_measure_ctx *ctx_,
        bool value, u32 tag)
{
    (void) ctx_;

    if (!value)
        return 0;
    else
        return ASN1_object_size(true, MEASURE_NULL_SIZE, __KM_TAG_MASK(tag));
}

static bool write_integer(unsigned char **p, unsigned char *end,
        const struct key_desc_measure_ctx *mctx, i64 val, u32 tag)
{
    if (ASN1_INTEGER_set_int64(mctx->i, val) == 0) {
        s_log_error("Couldn't set the value of an ASN.1 INTEGER!");
        return false;
    }

    i32 content_len = i2d_ASN1_INTEGER(mctx->i, NULL);
    if (content_len < 0) {
        s_log_error("Failed to measure the length of an ASN.1 INTEGER!");
        return false;
    }

    i32 total_len = content_len;
    if (tag != KM_TAG_INVALID)
        total_len = ASN1_object_size(true, content_len, __KM_TAG_MASK(tag));

    if (*p + total_len > end) {
        s_log_error("ASN.1 INTEGER overruns buffer!");
        return false;
    }

    if (tag != KM_TAG_INVALID) {
        ASN1_put_object(p, true, content_len, __KM_TAG_MASK(tag),
                    V_ASN1_CONTEXT_SPECIFIC);
    }

    if (i2d_ASN1_INTEGER(mctx->i, p) < 0) {
        s_log_error("Failed to serialize an ASN.1 INTEGER value!");
        return false;
    }

    return true;
}

static bool write_enumerated(unsigned char **p, unsigned char *end,
        const struct key_desc_measure_ctx *mctx, int val, u32 tag)
{
    if (ASN1_ENUMERATED_set_int64(mctx->e, val) == 0) {
        s_log_error("Couldn't set the value of an ASN.1 ENUMERATED type!");
        return false;
    }

    i32 content_len = i2d_ASN1_ENUMERATED(mctx->e, NULL);
    if (content_len < 0) {
        s_log_error("Failed to measure the length of "
                "an ASN.1 ENUMERATED value!");
        return false;
    }

    i32 total_len = content_len;
    if (tag != KM_TAG_INVALID)
        total_len = ASN1_object_size(true, content_len, __KM_TAG_MASK(tag));

    if (*p + total_len > end) {
        s_log_error("ASN.1 ENUMERATED value overruns buffer!");
        return false;
    }

    if (tag != KM_TAG_INVALID) {
        ASN1_put_object(p, true, content_len, __KM_TAG_MASK(tag),
                    V_ASN1_CONTEXT_SPECIFIC);
    }

    if (i2d_ASN1_ENUMERATED(mctx->e, p) < 0) {
        s_log_error("Failed to serialize an ASN.1 ENUMERATED value!");
        return false;
    }

    return true;
}

static bool write_boolean(unsigned char **p, unsigned char *end, bool val)
{
    _Static_assert(MEASURE_BOOLEAN_SIZE == 3,
            "Invalid #define of the ASN.1 BOOLEAN size");

    if ((*p) + MEASURE_BOOLEAN_SIZE > end) {
        s_log_error("ASN.1 BOOLEAN overruns buffer!");
        return false;
    }
    (*p)[0] = 0x01; /* ASN.1 BOOLEAN */
    (*p)[1] = 0x01; /* length 1 */
    (*p)[2] = val ? 0xFF : 0x00; /* value; true - 255, false - 0 */

    (*p) += MEASURE_BOOLEAN_SIZE;
    return true;
}

static bool write_octet_string(unsigned char **p, unsigned char *end,
        const struct key_desc_measure_ctx *mctx, const VECTOR(u8) str, u32 tag)
{
    if (ASN1_OCTET_STRING_set(mctx->str, str, vector_size(str)) == 0) {
        s_log_error("Failed to set the value of an ASN.1 OCTET_STRING!");
        return false;
    }

    i32 content_len = i2d_ASN1_OCTET_STRING(mctx->str, NULL);
    if (content_len < 0) {
        s_log_error("Failed to measure the length of an ASN.1 OCTET_STRING!");
        return false;
    }

    i32 total_len = content_len;
    if (tag != KM_TAG_INVALID)
        total_len = ASN1_object_size(true, content_len, __KM_TAG_MASK(tag));

    if (*p + total_len > end) {
        s_log_error("ASN.1 OCTET_STRING overruns buffer!");
        return false;
    }

    if (tag != KM_TAG_INVALID) {
        ASN1_put_object(p, true, content_len, __KM_TAG_MASK(tag),
                    V_ASN1_CONTEXT_SPECIFIC);
    }

    if (i2d_ASN1_OCTET_STRING(mctx->str, p) < 0) {
        s_log_error("Failed to serialize an ASN.1 OCTET_STRING!");
        return false;
    }

    return true;
}

struct der_element {
    unsigned char *der;
    i32 len;
};
static int der_element_cmp(const void *a, const void *b)
{
    const struct der_element *const da = a, *const db = b;

    int r = memcmp(da->der, db->der, u_min(da->len, db->len));
    if (r != 0)
        return r;

    if (da->len < db->len) return -1;
    else if (da->len > db->len) return 1;
    else return 0;
}
static bool serialize_set_elements_32(VECTOR(struct der_element) out,
        const VECTOR(i32) set, i32 *out_set_len, ASN1_INTEGER *cache)
{
    const u32 n_elements = vector_size(set);

    for (u32 i = 0; i < n_elements; i++) {
        if (ASN1_INTEGER_set_int64(cache, set[i]) == 0) {
            s_log_error("Couldn't set the value of an ASN.1 INTEGER!");
            return false;
        }

        out[i].len = i2d_ASN1_INTEGER(cache, &out[i].der);
        if (out[i].len < 0) {
            out[i].der = NULL;
            s_log_error("Failed to serialize an ASN.1 INTEGER!");
            return false;
        }

        *out_set_len += out[i].len;
    }

    return true;
}
static bool serialize_set_elements_64(VECTOR(struct der_element) out,
        const VECTOR(i64) set, i32 *out_set_len, ASN1_INTEGER *cache)
{
    const u32 n_elements = vector_size(set);

    for (u32 i = 0; i < n_elements; i++) {
        if (ASN1_INTEGER_set_int64(cache, set[i]) == 0) {
            s_log_error("Couldn't set the value of an ASN.1 INTEGER!");
            return false;
        }

        out[i].len = i2d_ASN1_INTEGER(cache, &out[i].der);
        if (out[i].len < 0) {
            out[i].der = NULL;
            s_log_error("Failed to serialize an ASN.1 INTEGER!");
            return false;
        }

        *out_set_len += out[i].len;
    }

    return true;
}
static bool write_set_of_integer_generic(unsigned char **p, unsigned char *end,
        const struct key_desc_measure_ctx *mctx,
        const void *set, u32 tag, bool is64)
{
    VECTOR(struct der_element) ders = NULL;
    i32 set_len = 0, set_and_tag_len = 0, total_len = 0;

    const u32 n_elements = vector_size(set);

    ders = vector_new(struct der_element);
    vector_resize(&ders, n_elements);

    if (is64) {
        if (!serialize_set_elements_64(ders, set, &set_len, mctx->i)) goto err;
    } else {
        if (!serialize_set_elements_32(ders, set, &set_len, mctx->i)) goto err;
    }

    set_and_tag_len = ASN1_object_size(true, set_len, V_ASN1_SET);

    if (tag != KM_TAG_INVALID)
        total_len = ASN1_object_size(true, set_and_tag_len, __KM_TAG_MASK(tag));
    else
        total_len = set_and_tag_len;

    if ((*p) + total_len > end)
        goto_error("SET OF ASN.1 INTEGERs overruns buffer!");

    qsort(ders, n_elements, sizeof(struct der_element), der_element_cmp);


    if (tag != KM_TAG_INVALID) {
        ASN1_put_object(p, true, set_and_tag_len,
                __KM_TAG_MASK(tag), V_ASN1_CONTEXT_SPECIFIC);
    }

    ASN1_put_object(p, true, set_len, V_ASN1_SET, V_ASN1_UNIVERSAL);

    for (u32 i = 0; i < n_elements; i++) {
        memcpy(*p, ders[i].der, ders[i].len);
        (*p) += ders[i].len;
        OPENSSL_free(ders[i].der);
        ders[i].der = NULL;
    }

    vector_destroy(&ders);
    return true;

err:
    if (ders != NULL) {
        for (u32 i = 0; i < vector_size(ders); i++) {
            if (ders[i].der != NULL) {
                OPENSSL_free(ders[i].der);
                ders[i].der = NULL;
            }
        }
        vector_destroy(&ders);
    }

    s_log_error("Failed to serialize a SET of 32-bit INTEGERs");
    return false;
}

static bool write_set_of_integer_32(unsigned char **p, unsigned char *end,
        const struct key_desc_measure_ctx *mctx,
        const VECTOR(i32) set, u32 tag)
{
    return write_set_of_integer_generic(p, end, mctx, set, tag, false);
}

static bool write_set_of_integer_64(unsigned char **p, unsigned char *end,
        const struct key_desc_measure_ctx *mctx,
        const VECTOR(i64) set, u32 tag)
{
    return write_set_of_integer_generic(p, end, mctx, set, tag, true);
}

static bool write_tagged_null(unsigned char **p, unsigned char *end, u32 tag)
{

    _Static_assert(MEASURE_NULL_SIZE == 2,
            "Invalid #define of the ASN.1 NULL size");

    i32 total_len = MEASURE_NULL_SIZE;
    if (tag != KM_TAG_INVALID)
        total_len = ASN1_object_size(true, MEASURE_NULL_SIZE, __KM_TAG_MASK(tag));

    if ((*p) + total_len > end) {
        s_log_error("ASN.1 NULL value overruns buffer!");
        return false;
    }

    if (tag != KM_TAG_INVALID) {
        ASN1_put_object(p, true, MEASURE_NULL_SIZE,
                __KM_TAG_MASK(tag), V_ASN1_CONTEXT_SPECIFIC);
    }

    (*p)[0] = V_ASN1_NULL; /* tag: ASN.1 NULL */
    (*p)[1] = 0x00; /* length: always 0 */

    (*p) += MEASURE_NULL_SIZE;
    return true;
}

bool key_desc_write_sequence_header(unsigned char **p, unsigned char *end,
        u32 content_len, u32 tag)
{
    const i32 inner_size = ASN1_object_size(true,
            content_len, V_ASN1_SEQUENCE);
    if ((*p) + inner_size > end) {
        s_log_error("SEQUENCE overruns buffer!");
        return false;
    }

    /* optional EXPLICIT outer "wrapper" tag */
    if (tag != KM_TAG_INVALID) {
        const i32 outer_size = ASN1_object_size(true,
                inner_size, __KM_TAG_MASK(tag));
        if ((*p) + outer_size > end) {
            s_log_error("EXPLICIT SEQUENCE overruns buffer!");
            return false;
        }

        ASN1_put_object(p, true, inner_size,
                __KM_TAG_MASK(tag), V_ASN1_CONTEXT_SPECIFIC);
    }

    ASN1_put_object(p, true, content_len, V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL);
    return true;
}

bool key_desc_write_auth_list(unsigned char **p, unsigned char *end,
        const struct KM_AuthorizationList_v3 *al,
        const struct key_desc_measure_ctx *mctx,
        enum key_desc_measure_auth_list_variant variant
)
{
    u32 content_len = 0;
    switch (variant) {
    case KEY_DESC_MEASURE_AL_SOFTWARE_ENFORCED:
        content_len = mctx->softwareEnforced.al_size;
        break;
    case KEY_DESC_MEASURE_AL_HARDWARE_ENFORCED:
        content_len = mctx->hardwareEnforced.al_size;
        break;
    }

    if (!key_desc_write_sequence_header(p, end, content_len, KM_TAG_INVALID)) {
        s_log_error("Failed to write the AuthorizationList SEQUENCE header!");
        return false;
    }

    /* Check whether the content fits *after* writing the SEQUENCE header */
    const unsigned char *const content_end = (*p) + content_len;
    if (content_end > end) {
        s_log_error("AuthorizationList sequence overruns buffer!");
        return false;
    }

    if (al->__purpose_present) {
        if (!write_set_of_integer_32(p, end, mctx,
                    (VECTOR(i32))al->purpose, KM_TAG_PURPOSE))
            goto_error("Failed to write the purposes set");
    }

    if (al->__algorithm_present &&
            !write_integer(p, end, mctx, al->algorithm, KM_TAG_ALGORITHM))
        goto_error("Failed to write the algorithm");

    if (al->__keySize_present &&
            !write_integer(p, end, mctx, al->keySize, KM_TAG_KEY_SIZE))
        goto_error("Failed to write the key size");

    if (al->__blockMode_present) {
        if (!write_set_of_integer_32(p, end, mctx,
                    (VECTOR(i32))al->blockMode, KM_TAG_BLOCK_MODE))
            goto_error("Failed to write the block modes set");
    }

    if (al->__digest_present) {
        if (!write_set_of_integer_32(p, end, mctx,
                    (VECTOR(i32))al->digest, KM_TAG_DIGEST))
            goto_error("Failed to write the digests set");
    }

    if (al->__padding_present) {
        if (!write_set_of_integer_32(p, end, mctx,
                    (VECTOR(i32))al->padding, KM_TAG_PADDING))
            goto_error("Failed to write the padding modes set");
    }

    if (al->__callerNonce_present && al->callerNonce &&
            !write_tagged_null(p, end, KM_TAG_CALLER_NONCE))
        goto_error("Failed to write the caller nonce field");

    if (al->__minMacLength_present) {
        if (!write_integer(p, end, mctx,
                    al->minMacLength, KM_TAG_MIN_MAC_LENGTH))
            goto_error("Failed to write the minimum MAC length");
    }

    if (al->__ecCurve_present &&
            !write_integer(p, end, mctx, al->ecCurve, KM_TAG_EC_CURVE))
        goto_error("Failed to write the EC curve");

    if (al->__rsaPublicExponent_present) {
        if (!write_integer(p, end, mctx,
                    al->rsaPublicExponent, KM_TAG_RSA_PUBLIC_EXPONENT))
            goto_error("Failed to write the RSA public exponent");
    }

    if (al->__includeUniqueId_present && al->includeUniqueId &&
            !write_tagged_null(p, end, KM_TAG_INCLUDE_UNIQUE_ID))
        goto_error("Failed to write the includeUniqueId field");

    if (al->__keyBlobUsageRequirements_present) {
        if (!write_integer(p, end, mctx,
                    al->keyBlobUsageRequirements, KM_TAG_BLOB_USAGE_REQUIREMENTS))
            goto_error("Failed to write the key blob usage requirements");
    }

    if (al->__bootloaderOnly_present && al->bootloaderOnly &&
            !write_tagged_null(p, end, KM_TAG_BOOTLOADER_ONLY))
        goto_error("Failed to write the bootloaderOnly field");

    if (al->__rollbackResistance_present && al->rollbackResistance &&
            !write_tagged_null(p, end, KM_TAG_ROLLBACK_RESISTANCE))
        goto_error("Failed to write the rollback resistance field");

    if (al->__hardwareType_present) {
        if (!write_integer(p, end, mctx,
                    al->hardwareType, KM_TAG_HARDWARE_TYPE))
            goto_error("Failed to write the hardware type");
    }

    if (al->__activeDateTime_present) {
        if (!write_integer(p, end, mctx,
                    al->activeDateTime, KM_TAG_ACTIVE_DATETIME))
            goto_error("Failed to write the active date time");
    }

    if (al->__originationExpireDateTime_present) {
        if (!write_integer(p, end, mctx, al->originationExpireDateTime,
                    KM_TAG_ORIGINATION_EXPIRE_DATETIME))
            goto_error("Failed to write the origination expire date time");
    }

    if (al->__usageExpireDateTime_present) {
        if (!write_integer(p, end, mctx,
                    al->usageExpireDateTime, KM_TAG_USAGE_EXPIRE_DATETIME))
            goto_error("Failed to write the usage expire date time");
    }

    if (al->__minSecondsBetweenOps_present) {
        if (!write_integer(p, end, mctx,
                    al->minSecondsBetweenOps, KM_TAG_MIN_SECONDS_BETWEEN_OPS))
            goto_error("Failed to write the min seconds between ops field");
    }

    if (al->__maxUsesPerBoot_present) {
        if (!write_integer(p, end, mctx,
                    al->maxUsesPerBoot, KM_TAG_MAX_USES_PER_BOOT))
            goto_error("Failed to write the max uses per boot field");
    }

    if (al->__userId_present &&
            !write_integer(p, end, mctx, al->userId, KM_TAG_USER_ID))
        goto_error("Failed to write the user id");

    if (al->__userSecureId_present) {
        if (!write_set_of_integer_64(p, end, mctx,
                    (VECTOR(i64))al->userSecureId, KM_TAG_USER_SECURE_ID))
            goto_error("Failed to write the set of user secure IDs");
    }

    if (al->__noAuthRequired_present && al->noAuthRequired &&
            !write_tagged_null(p, end, KM_TAG_NO_AUTH_REQUIRED))
        goto_error("Failed to write the noAuthRequired field");

    if (al->__userAuthType_present) {
        if (!write_integer(p, end, mctx,
                    al->userAuthType, KM_TAG_USER_AUTH_TYPE))
            goto_error("Failed to write the user auth type mask");
    }

    if (al->__authTimeout_present &&
            !write_integer(p, end, mctx, al->authTimeout, KM_TAG_AUTH_TIMEOUT))
        goto_error("Failed to write the auth timeout");

    if (al->__allowWhileOnBody_present && al->allowWhileOnBody &&
            !write_tagged_null(p, end, KM_TAG_ALLOW_WHILE_ON_BODY))
        goto_error("Failed to write the allowWhileOnBody field");

    if (al->__trustedUserPresenceReq_present && al->trustedUserPresenceReq &&
            !write_tagged_null(p, end, KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED))
        goto_error("Failed to write the trustedUserPresenceReq field");

    if (al->__trustedConfirmationReq_present && al->trustedConfirmationReq &&
            !write_tagged_null(p, end, KM_TAG_TRUSTED_CONFIRMATION_REQUIRED))
        goto_error("Failed to write the trustedConfirmationReq field");

    if (al->__unlockedDeviceReq_present && al->unlockedDeviceReq &&
            !write_tagged_null(p, end, KM_TAG_UNLOCKED_DEVICE_REQUIRED))
        goto_error("Failed to write the unlockedDeviceReq field");

    if (al->__applicationId_present) {
        if (!write_octet_string(p, end, mctx,
                    al->applicationId, KM_TAG_APPLICATION_ID))
            goto_error("Failed to write the APPLICATION_ID");
    }

    if (al->__applicationData_present) {
        if (!write_octet_string(p, end, mctx,
                    al->applicationData, KM_TAG_APPLICATION_DATA))
            goto_error("Failed to write the APPLICATION_DATA");
    }

    if (al->__creationDateTime_present) {
        if (!write_integer(p, end, mctx,
                    al->creationDateTime, KM_TAG_CREATION_DATETIME))
            goto_error("Failed to write the creation date time");
    }

    if (al->__keyOrigin_present &&
            !write_integer(p, end, mctx, al->keyOrigin, KM_TAG_ORIGIN))
        goto_error("Failed to write the key origin");

    if (al->__rootOfTrust_present) {
        if (!key_desc_write_root_of_trust(p, end, &al->rootOfTrust,
                    mctx, variant))
            goto_error("Failed to write the root of trust");
    }

    if (al->__osVersion_present &&
            !write_integer(p, end, mctx, al->osVersion, KM_TAG_OS_VERSION))
        goto_error("Failed to write the OS version");

    if (al->__osPatchLevel_present) {
        if (!write_integer(p, end, mctx,
                    al->osPatchLevel, KM_TAG_OS_PATCHLEVEL))
            goto_error("Failed to write the OS patch level");
    }

    if (al->__uniqueId_present &&
            !write_octet_string(p, end, mctx, al->uniqueId, KM_TAG_UNIQUE_ID))
        goto_error("Failed to write the unique id");

    if (al->__attestationChallenge_present) {
        if (!write_octet_string(p, end, mctx,
                    al->attestationChallenge, KM_TAG_ATTESTATION_CHALLENGE))
            goto_error("Failed to write the attestation challenge");
    }

    if (al->__attestationApplicationId_present) {
        if (!write_octet_string(p, end, mctx, al->attestationApplicationId,
                    KM_TAG_ATTESTATION_APPLICATION_ID))
            goto_error("Failed to write the attestation application ID");
    }

    if (al->__attestationIdBrand_present) {
        if (!write_octet_string(p, end, mctx,
                al->attestationIdBrand, KM_TAG_ATTESTATION_ID_BRAND))
            goto_error("Failed to write the ID-attestation brand");
    }

    if (al->__attestationIdDevice_present) {
        if (!write_octet_string(p, end, mctx,
                al->attestationIdDevice, KM_TAG_ATTESTATION_ID_DEVICE))
            goto_error("Failed to write the ID-attestation device");
    }

    if (al->__attestationIdProduct_present) {
        if (!write_octet_string(p, end, mctx,
                al->attestationIdProduct, KM_TAG_ATTESTATION_ID_PRODUCT))
            goto_error("Failed to write the ID-attestation Product");
    }

    if (al->__attestationIdSerial_present) {
        if (!write_octet_string(p, end, mctx,
                al->attestationIdSerial, KM_TAG_ATTESTATION_ID_SERIAL))
            goto_error("Failed to write the ID-attestation Serial");
    }

    if (al->__attestationIdImei_present) {
        if (!write_octet_string(p, end, mctx,
                al->attestationIdImei, KM_TAG_ATTESTATION_ID_IMEI))
            goto_error("Failed to write the ID-attestation Imei");
    }

    if (al->__attestationIdMeid_present) {
        if (!write_octet_string(p, end, mctx,
                al->attestationIdMeid, KM_TAG_ATTESTATION_ID_MEID))
            goto_error("Failed to write the ID-attestation Meid");
    }

    if (al->__attestationIdManufacturer_present) {
        if (!write_octet_string(p, end, mctx,
                al->attestationIdManufacturer, KM_TAG_ATTESTATION_ID_MANUFACTURER))
            goto_error("Failed to write the ID-attestation Manufacturer");
    }

    if (al->__attestationIdModel_present) {
        if (!write_octet_string(p, end, mctx,
                al->attestationIdModel, KM_TAG_ATTESTATION_ID_MODEL))
            goto_error("Failed to write the ID-attestation Model");
    }

    if (al->__vendorPatchLevel_present) {
        if (!write_integer(p, end, mctx,
                    al->vendorPatchLevel, KM_TAG_VENDOR_PATCHLEVEL))
            goto_error("Failed to write the vendor patch level");
    }

    if (al->__bootPatchLevel_present) {
        if (!write_integer(p, end, mctx,
                    al->bootPatchLevel, KM_TAG_BOOT_PATCHLEVEL))
            goto_error("Failed to write the boot patch level");
    }

    if (al->__associatedData_present) {
        if (!write_octet_string(p, end, mctx,
                    al->associatedData, KM_TAG_ASSOCIATED_DATA))
            goto_error("Failed to write the associated data");
    }

    if (al->__nonce_present &&
            !write_octet_string(p, end, mctx, al->nonce, KM_TAG_NONCE))
        goto_error("Failed to write the nonce");

    if (al->__macLength_present &&
            !write_integer(p, end, mctx, al->macLength, KM_TAG_MAC_LENGTH))
        goto_error("Failed to write the MAC length");

    if (al->__resetSinceIdRotation_present && al->resetSinceIdRotation &&
            !write_tagged_null(p, end, KM_TAG_RESET_SINCE_ID_ROTATION))
        goto_error("Failed to write the resetSinceIdRotation field");

    if (al->__confirmationToken_present) {
        if (write_octet_string(p, end, mctx,
                    al->confirmationToken, KM_TAG_CONFIRMATION_TOKEN))
            goto_error("Failed to write the confirmation token");
    }

    if (al->samsung.__authToken_present && !write_octet_string(p, end, mctx,
            al->samsung.authToken, KM_TAG_AUTH_TOKEN))
        goto_error("Failed to write the authToken field");

    if (al->samsung.__verificationToken_present) {
        if (!write_octet_string(p, end, mctx,
                    al->samsung.verificationToken, KM_TAG_VERIFICATION_TOKEN))
            goto_error("Failed to write the verificationToken field");
    }

    if (al->samsung.__allUsers_present && al->samsung.allUsers &&
            !write_tagged_null(p, end, KM_TAG_ALL_USERS))
        goto_error("Failed to write the allUsers field");

    if (al->samsung.__eciesSingleHashMode_present &&
            al->samsung.eciesSingleHashMode)
    {
        if (!write_tagged_null(p, end, KM_TAG_ECIES_SINGLE_HASH_MODE))
            goto_error("Failed to write the eciesSingleHashMode field");
    }

    if (al->samsung.__kdf_present && !write_integer(p, end, mctx,
            al->samsung.kdf, KM_TAG_KDF))
        goto_error("Failed to write the kdf field");

    if (al->samsung.__exportable_present && al->samsung.exportable &&
            !write_tagged_null(p, end, KM_TAG_EXPORTABLE))
        goto_error("Failed to write the exportable field");

    if (al->samsung.__keyAuth_present && al->samsung.keyAuth &&
            !write_tagged_null(p, end, KM_TAG_KEY_AUTH))
        goto_error("Failed to write the keyAuth field");

    if (al->samsung.__opAuth_present && al->samsung.opAuth &&
            !write_tagged_null(p, end, KM_TAG_OP_AUTH))
        goto_error("Failed to write the opAuth field");

    if (al->samsung.__operationHandle_present && !write_integer(p, end, mctx,
            al->samsung.operationHandle, KM_TAG_OPERATION_HANDLE))
        goto_error("Failed to write the operationHandle field");

    if (al->samsung.__operationFailed_present && al->samsung.operationFailed &&
            !write_tagged_null(p, end, KM_TAG_OPERATION_FAILED))
        goto_error("Failed to write the operationFailed field");

    if (al->samsung.__internalCurrentDateTime_present) {
        if (!write_integer(p, end, mctx, al->samsung.internalCurrentDateTime,
                    KM_TAG_INTERNAL_CURRENT_DATETIME))
            goto_error("Failed to write the internalCurrentDateTime field");
    }

    if (al->samsung.__ekeyBlobIV_present && !write_octet_string(p, end, mctx,
            al->samsung.ekeyBlobIV, KM_TAG_EKEY_BLOB_IV))
        goto_error("Failed to write the ekeyBlobIV field");

    if (al->samsung.__ekeyBlobAuthTag_present) {
        if (!write_octet_string(p, end, mctx,
                    al->samsung.ekeyBlobAuthTag, KM_TAG_EKEY_BLOB_AUTH_TAG))
            goto_error("Failed to write the ekeyBlobAuthTag field");
    }

    if (al->samsung.__ekeyBlobCurrentUsesPerBoot_present) {
        if (!write_integer(p, end, mctx, al->samsung.ekeyBlobCurrentUsesPerBoot,
                    KM_TAG_EKEY_BLOB_CURRENT_USES_PER_BOOT))
            goto_error("Failed to write the ekeyBlobCurrentUsesPerBoot field");
    }

    if (al->samsung.__ekeyBlobLastOpTimestamp_present) {
        if (!write_integer(p, end, mctx, al->samsung.ekeyBlobLastOpTimestamp,
                    KM_TAG_EKEY_BLOB_LAST_OP_TIMESTAMP))
            goto_error("Failed to write the ekeyBlobLastOpTimestamp field");
    }

    if (al->samsung.__ekeyBlobDoUpgrade_present && !write_integer(p, end, mctx,
            al->samsung.ekeyBlobDoUpgrade, KM_TAG_EKEY_BLOB_DO_UPGRADE))
        goto_error("Failed to write the ekeyBlobDoUpgrade field");

    if (al->samsung.__ekeyBlobPassword_present) {
        if (!write_octet_string(p, end, mctx,
                    al->samsung.ekeyBlobPassword, KM_TAG_EKEY_BLOB_PASSWORD))
            goto_error("Failed to write the ekeyBlobPassword field");
    }

    if (al->samsung.__ekeyBlobSalt_present && !write_octet_string(p, end, mctx,
            al->samsung.ekeyBlobSalt, KM_TAG_EKEY_BLOB_SALT))
        goto_error("Failed to write the ekeyBlobSalt field");

    if (al->samsung.__ekeyBlobEncVer_present && !write_integer(p, end, mctx,
            al->samsung.ekeyBlobEncVer, KM_TAG_EKEY_BLOB_ENC_VER))
        goto_error("Failed to write the ekeyBlobEncVer field");

    if (al->samsung.__ekeyBlobRaw_present && !write_integer(p, end, mctx,
            al->samsung.ekeyBlobRaw, KM_TAG_EKEY_BLOB_RAW))
        goto_error("Failed to write the ekeyBlobRaw field");

    if (al->samsung.__ekeyBlobUniqKDM_present) {
        if (!write_octet_string(p, end, mctx,
                    al->samsung.ekeyBlobUniqKDM, KM_TAG_EKEY_BLOB_UNIQ_KDM))
            goto_error("Failed to write the ekeyBlobUniqKDM field");
    }

    if (al->samsung.__ekeyBlobIncUseCount_present) {
        if (!write_integer(p, end, mctx,
                    al->samsung.ekeyBlobIncUseCount,
                    KM_TAG_EKEY_BLOB_INC_USE_COUNT))
            goto_error("Failed to write the ekeyBlobIncUseCount field");
    }

    if (al->samsung.__samsungRequestingTA_present) {
        if (!write_octet_string(p, end, mctx,
                    al->samsung.samsungRequestingTA,
                    KM_TAG_SAMSUNG_REQUESTING_TA))
            goto_error("Failed to write the samsungRequestingTA field");
    }

    if (al->samsung.__samsungRotRequired_present &&
            al->samsung.samsungRotRequired)
    {
        if (!write_tagged_null(p, end, KM_TAG_SAMSUNG_ROT_REQUIRED))
            goto_error("Failed to write the samsungRotRequired field");
    }

    if (al->samsung.__samsungLegacyRot_present && al->samsung.samsungLegacyRot)
        if (!write_tagged_null(p, end, KM_TAG_SAMSUNG_LEGACY_ROT))
            goto_error("Failed to write the samsungLegacyRot field");

    if (al->samsung.__useSecureProcessor_present &&
            al->samsung.useSecureProcessor)
    {
        if (!write_tagged_null(p, end, KM_TAG_USE_SECURE_PROCESSOR))
            goto_error("Failed to write the useSecureProcessor field");
    }

    if (al->samsung.__storageKey_present && al->samsung.storageKey &&
            !write_tagged_null(p, end, KM_TAG_STORAGE_KEY))
        goto_error("Failed to write the storageKey field");

    if (al->samsung.__integrityStatus_present && !write_integer(p, end, mctx,
            al->samsung.integrityStatus, KM_TAG_INTEGRITY_STATUS))
        goto_error("Failed to write the integrityStatus field");

    if (al->samsung.__isSamsungKey_present && al->samsung.isSamsungKey &&
            !write_tagged_null(p, end, KM_TAG_IS_SAMSUNG_KEY))
        goto_error("Failed to write the isSamsungKey field");

    if (al->samsung.__samsungAttestationRoot_present) {
        if (!write_octet_string(p, end, mctx,
                    al->samsung.samsungAttestationRoot,
                    KM_TAG_SAMSUNG_ATTESTATION_ROOT))
            goto_error("Failed to write the samsungAttestationRoot field");
    }

    if (al->samsung.__samsungAttestIntegrity_present &&
            al->samsung.samsungAttestIntegrity)
    {
        if (!write_tagged_null(p, end, KM_TAG_SAMSUNG_ATTEST_INTEGRITY))
            goto_error("Failed to write the samsungAttestIntegrity field");
    }

    if (al->samsung.__knoxObjectProtectionRequired_present &&
            al->samsung.knoxObjectProtectionRequired)
    {
        if (!write_tagged_null(p, end, KM_TAG_KNOX_OBJECT_PROTECTION_REQUIRED))
            goto_error("Failed to write the knoxObjectProtectionRequired "
                    "field");
    }

    if (al->samsung.__knoxCreatorId_present) {
        if (!write_octet_string(p, end, mctx,
                    al->samsung.knoxCreatorId, KM_TAG_KNOX_CREATOR_ID))
            goto_error("Failed to write the knoxCreatorId field");
    }

    if (al->samsung.__knoxAdministratorId_present) {
        if (!write_octet_string(p, end, mctx,
                    al->samsung.knoxAdministratorId,
                    KM_TAG_KNOX_ADMINISTRATOR_ID))
            goto_error("Failed to write the knoxAdministratorId field");
    }

    if (al->samsung.__knoxAccessorId_present) {
        if (!write_octet_string(p, end, mctx,
                    al->samsung.knoxAccessorId, KM_TAG_KNOX_ACCESSOR_ID))
            goto_error("Failed to write the knoxAccessorId field");
    }

    if (al->samsung.__samsungAuthPackage_present) {
        if (!write_octet_string(p, end, mctx,
                    al->samsung.samsungAuthPackage,
                    KM_TAG_SAMSUNG_AUTHENTICATE_PACKAGE))
            goto_error("Failed to write the samsungAuthPackage field");
    }

    if (al->samsung.__samsungCertificateSubject_present) {
        if (!write_octet_string(p, end, mctx,
                    al->samsung.samsungCertificateSubject,
                    KM_TAG_SAMSUNG_CERTIFICATE_SUBJECT))
            goto_error("Failed to write the samsungCertificateSubject field");
    }

    if (al->samsung.__samsungKeyUsage_present && !write_integer(p, end, mctx,
            al->samsung.samsungKeyUsage, KM_TAG_SAMSUNG_KEY_USAGE))
        goto_error("Failed to write the samsungKeyUsage field");

    if (al->samsung.__samsungExtendedKeyUsage_present) {
        if (!write_octet_string(p, end, mctx,
                    al->samsung.samsungExtendedKeyUsage,
                    KM_TAG_SAMSUNG_EXTENDED_KEY_USAGE))
            goto_error("Failed to write the samsungExtendedKeyUsage field");
    }

    if (al->samsung.__samsungSubjectAlternativeName_present) {
        if (!write_octet_string(p, end, mctx,
                    al->samsung.samsungSubjectAlternativeName,
                    KM_TAG_SAMSUNG_SUBJECT_ALTERNATIVE_NAME))
            goto_error("Failed to write the samsungSubjectAlternativeName "
                    "field");

    }

    if (al->samsung.__provGacEc1_present && !write_octet_string(p, end, mctx,
            al->samsung.provGacEc1, KM_TAG_PROV_GAC_EC1))
        goto_error("Failed to write the provGacEc1 field");

    if (al->samsung.__provGacEc2_present && !write_octet_string(p, end, mctx,
            al->samsung.provGacEc2, KM_TAG_PROV_GAC_EC2))
        goto_error("Failed to write the provGacEc2 field");

    if (al->samsung.__provGacEc3_present && !write_octet_string(p, end, mctx,
            al->samsung.provGacEc3, KM_TAG_PROV_GAC_EC3))
        goto_error("Failed to write the provGacEc3 field");

    if (al->samsung.__provGakEc_present && !write_octet_string(p, end, mctx,
            al->samsung.provGakEc, KM_TAG_PROV_GAK_EC))
        goto_error("Failed to write the provGakEc field");

    if (al->samsung.__provGakEcVtoken_present) {
        if (!write_octet_string(p, end, mctx,
                    al->samsung.provGakEcVtoken, KM_TAG_PROV_GAK_EC_VTOKEN))
            goto_error("Failed to write the provGakEcVtoken field");
    }

    if (al->samsung.__provGacRsa1_present && !write_octet_string(p, end, mctx,
            al->samsung.provGacRsa1, KM_TAG_PROV_GAC_RSA1))
        goto_error("Failed to write the provGacRsa1 field");

    if (al->samsung.__provGacRsa2_present && !write_octet_string(p, end, mctx,
            al->samsung.provGacRsa2, KM_TAG_PROV_GAC_RSA2))
        goto_error("Failed to write the provGacRsa2 field");

    if (al->samsung.__provGacRsa3_present && !write_octet_string(p, end, mctx,
            al->samsung.provGacRsa3, KM_TAG_PROV_GAC_RSA3))
        goto_error("Failed to write the provGacRsa3 field");

    if (al->samsung.__provGakRsa_present && !write_octet_string(p, end, mctx,
            al->samsung.provGakRsa, KM_TAG_PROV_GAK_RSA))
        goto_error("Failed to write the provGakRsa field");

    if (al->samsung.__provGakRsaVtoken_present) {
        if (!write_octet_string(p, end, mctx,
                    al->samsung.provGakRsaVtoken, KM_TAG_PROV_GAK_RSA_VTOKEN))
            goto_error("Failed to write the provGakRsaVtoken field");
    }

    if (al->samsung.__provSakEc_present && !write_octet_string(p, end, mctx,
            al->samsung.provSakEc, KM_TAG_PROV_SAK_EC))
        goto_error("Failed to write the provSakEc field");

    if (al->samsung.__provSakEcVtoken_present) {
        if (!write_octet_string(p, end, mctx,
                    al->samsung.provSakEcVtoken, KM_TAG_PROV_SAK_EC_VTOKEN))
            goto_error("Failed to write the provSakEcVtoken field");
    }

    if ((*p) > end)
        goto_error("Buffer overrun while writing authorization list!");

    return true;

err:
    return false;
}

bool key_desc_write_root_of_trust(unsigned char **p, unsigned char *end,
        const struct KM_RootOfTrust_v3 *rot,
        const struct key_desc_measure_ctx *mctx,
        enum key_desc_measure_auth_list_variant variant
)
{
    u32 len = 0;
    switch (variant) {
    case KEY_DESC_MEASURE_AL_SOFTWARE_ENFORCED:
        len = mctx->softwareEnforced.al_rot_size;
        break;
    case KEY_DESC_MEASURE_AL_HARDWARE_ENFORCED:
        len = mctx->hardwareEnforced.al_rot_size;
        break;
    }

    if ((*p) + len > end) {
        s_log_error("rootOfTrust SEQUENCE overruns buffer!");
        return false;
    }

    if (!key_desc_write_sequence_header(p, end, len, KM_TAG_ROOT_OF_TRUST)) {
        s_log_error("Failed to write the tagged rootOfTrust SEQUENCE header!");
        return false;
    }


    if (!write_octet_string(p, end, mctx, rot->verifiedBootKey, KM_TAG_INVALID))
    {
        s_log_error("Failed to write the verified boot key!");
        return false;
    }

    if (!write_boolean(p, end, rot->deviceLocked)) {
        s_log_error("Failed to write the `deviceLocked` value!");
        return false;
    }

    if (!write_enumerated(p, end, mctx, rot->verifiedBootState, KM_TAG_INVALID))
    {
        s_log_error("Failed to write the verified boot state!");
        return false;
    }

    if (!write_octet_string(p, end, mctx,
                rot->verifiedBootHash, KM_TAG_INVALID))
    {
        s_log_error("Failed to write the verified boot hash!");
        return false;
    }

    return true;
}
