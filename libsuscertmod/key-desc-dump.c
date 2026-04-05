#define _GNU_SOURCE
#include "key-desc.h"
#include <core/int.h>
#include <core/util.h>
#include <core/math.h>
#include <core/hex2ascii.h>
#include <libsuskmhal/keymaster-types-c.h>
#include <time.h>
#include <stdio.h>
#include <string.h>

static void dump_auth_list(const struct KM_AuthorizationList_v3 *al,
        key_desc_log_proc_t log_proc);

static const char * get_security_level_str(enum KM_SecurityLevel sl);
static const char * get_vbstate_str(enum KM_VerifiedBootState vb);

static const char * get_keypurpose_str(enum KM_KeyPurpose kp);
static const char * get_algorithm_str(enum KM_Algorithm alg);
static const char * get_blockmode_str(enum KM_BlockMode bm);
static const char * get_digest_str(enum KM_Digest dig);
static const char * get_paddingmode_str(enum KM_PaddingMode pm);
static const char * get_eccurve_str(enum KM_EcCurve ec);
static const char * get_keyorigin_str(enum KM_KeyOrigin ko);
static const char * get_usage_req_str(enum KM_KeyBlobUsageRequirements kbur);
static const char * get_kdf_str(enum KM_KeyDerivationFunction kdf);

enum dump_hex_indendation {
    INDENT_0,
    INDENT_1,
    INDENT_2,
    INDENT_3,
    INDENT_4,
};
static void dump_hex_line(char *buf, u32 buf_size,
        const u8 *data, u32 data_size, bool end_without_comma);
static void dump_hex(const char *prefix, const char *postfix,
        const VECTOR(u8) data, enum dump_hex_indendation indentation_lvl,
        key_desc_log_proc_t log_proc);

static void dump_u64_arr(const char *prefix, const char *postfix,
        const VECTOR(u64) arr, key_desc_log_proc_t log_proc);

typedef const char * (*get_enum_str_proc_t)(int);
static void dump_enum_arr(const char *prefix, const char *postfix,
        const VECTOR(i32) arr, get_enum_str_proc_t get_str_proc,
        key_desc_log_proc_t log_proc);

static void datetime_to_str(char *buf, u32 buf_size, KM_DateTime_t dt);

static const char *get_indentation_str(enum dump_hex_indendation i);

void key_desc_dump(const struct KM_KeyDescription_v3 *desc,
        key_desc_log_proc_t log_proc)
{
    log_proc("===== BEGIN KEY DESCRIPTION DUMP =====");
    log_proc("struct KM_KeyDescription_v3 desc = {");
    log_proc("    .attestationVersion = %d,", desc->attestationVersion);
    log_proc("    .attestationSecurityLevel = %d, // %s",
            desc->attestationSecurityLevel,
            get_security_level_str(desc->attestationSecurityLevel)
    );
    log_proc("    .keymasterVersion = %d,", desc->keymasterVersion);
    log_proc("    .keymasterSecurityLevel = %d, // %s",
            desc->attestationSecurityLevel,
            get_security_level_str(desc->attestationSecurityLevel)
    );
    dump_hex("    .attestationChallenge = { ", " },",
            desc->attestationChallenge, INDENT_2, log_proc);
    dump_hex("    .uniqueId = { ", " },", desc->uniqueId, INDENT_2, log_proc);
    log_proc("    .softwareEnforced = {");
    dump_auth_list(&desc->softwareEnforced, log_proc);
    log_proc("    },");
    log_proc("    .hardwareEnforced = {");
    dump_auth_list(&desc->hardwareEnforced, log_proc);
    log_proc("    }");
    log_proc("};");
    log_proc("====== END KEY DESCRIPTION DUMP ======");
}

static void dump_auth_list(const struct KM_AuthorizationList_v3 *al,
        key_desc_log_proc_t log_proc)
{
    char date_time_buf[32] = { 0 };

    if (al->__purpose_present) {
        dump_enum_arr("        .purpose = { ", " },",
                (VECTOR(i32)) al->purpose,
                (get_enum_str_proc_t) get_keypurpose_str,
                log_proc
        );
    }

    if (al->__algorithm_present)
        log_proc("        .algorithm = 0x%08x, // %s",
                al->algorithm, get_algorithm_str(al->algorithm));

    if (al->__keySize_present)
        log_proc("        .keySize = %llu,", al->keySize);

    if (al->__blockMode_present) {
        dump_enum_arr("        .blockMode = { ", " },",
                (VECTOR(i32))al->blockMode,
                (get_enum_str_proc_t)get_blockmode_str,
                log_proc
        );
    }

    if (al->__digest_present) {
        dump_enum_arr("        .digest = { ", " },", (VECTOR(i32))al->digest,
                (get_enum_str_proc_t)get_digest_str, log_proc);
    }

    if (al->__padding_present) {
        dump_enum_arr("        .padding = { ", " },",
                (VECTOR(i32))al->padding,
                (get_enum_str_proc_t)get_paddingmode_str,
                log_proc
        );
    }

    if (al->__callerNonce_present)
        log_proc("        .callerNonce = %d,", al->callerNonce);

    if (al->__minMacLength_present)
        log_proc("        .minMacLength = 0x%016llx,", al->minMacLength);

    if (al->__ecCurve_present)
        log_proc("        .ecCurve = 0x%08x, // %s",
                al->ecCurve, get_eccurve_str(al->ecCurve));

    if (al->__rsaPublicExponent_present)
        log_proc("        .rsaPublicExponent = 0x%08x,",
                al->rsaPublicExponent);

    if (al->__includeUniqueId_present)
        log_proc("        .includeUniqueId = %d,", al->includeUniqueId);

    if (al->__keyBlobUsageRequirements_present)
        log_proc("        .keyBlobUsageRequirements = 0x%08x, // %s",
                al->keyBlobUsageRequirements,
                get_usage_req_str(al->keyBlobUsageRequirements));

    if (al->__bootloaderOnly_present)
        log_proc("        .bootloaderOnly = %d,", al->bootloaderOnly);


    if (al->__rollbackResistance_present)
        log_proc("        .rollbackResistance = %d,", al->rollbackResistance);

    if (al->__hardwareType_present)
        log_proc("        .hardwareType = 0x%08x,", al->hardwareType);

    if (al->__activeDateTime_present) {
        datetime_to_str(date_time_buf, sizeof(date_time_buf),
                al->activeDateTime);
        log_proc("        .activeDateTime = %llu, // %s",
                al->activeDateTime, date_time_buf);
    }

    if (al->__originationExpireDateTime_present) {
        datetime_to_str(date_time_buf, sizeof(date_time_buf),
                al->originationExpireDateTime);
        log_proc("        .originationExpireDateTime = %llu, // %s",
                al->originationExpireDateTime, date_time_buf);
    }

    if (al->__usageExpireDateTime_present) {
        datetime_to_str(date_time_buf, sizeof(date_time_buf),
                al->usageExpireDateTime);
        log_proc("        .usageExpireDateTime = %llu, // %s",
                al->usageExpireDateTime, date_time_buf);
    }

    if (al->__minSecondsBetweenOps_present)
        log_proc("        .minSecondsBetweenOps = %u,",
                al->minSecondsBetweenOps);

    if (al->__maxUsesPerBoot_present)
        log_proc("        .maxUsesPerBoot = %u,", al->maxUsesPerBoot);

    if (al->__userId_present)
        log_proc("        .userId = 0x%08x,", al->userId);

    if (al->__userSecureId_present) {
        dump_u64_arr("        .userSecureId = { ", " },",
                al->userSecureId, log_proc);
    }

    if (al->__noAuthRequired_present)
        log_proc("        .noAuthRequired = %d,", al->noAuthRequired);

    if (al->__userAuthType_present)
        log_proc("        .userAuthType = 0x%016llx", al->userAuthType);

    if (al->__authTimeout_present)
        log_proc("        .authTimeout = %llu /* seconds */,",
                al->authTimeout);

    if (al->__allowWhileOnBody_present)
        log_proc("        .allowWhileOnBody = %d,", al->allowWhileOnBody);

    if (al->__trustedUserPresenceReq_present)
        log_proc("        .trustedUserPresenceReq = %d,",
                al->trustedUserPresenceReq);

    if (al->__trustedConfirmationReq_present)
        log_proc("        .trustedConfirmationReq = %d,",
                al->trustedConfirmationReq);

    if (al->__unlockedDeviceReq_present)
        log_proc("        .unlockedDeviceReq = %d,", al->unlockedDeviceReq);

    if (al->__applicationId_present)
        dump_hex("        .applicationId = {", "},",
                al->applicationId, INDENT_3, log_proc);

    if (al->__applicationData_present)
        dump_hex("        .applicationData = {", "},",
                al->applicationData, INDENT_3, log_proc);

    if (al->__creationDateTime_present) {
        datetime_to_str(date_time_buf, sizeof(date_time_buf),
                al->creationDateTime);
        log_proc("        .creationDateTime = %llu, // %s",
                al->creationDateTime, date_time_buf);
    }

    if (al->__keyOrigin_present)
        log_proc("        .origin = 0x%08x, // %s",
                al->keyOrigin, get_keyorigin_str(al->keyOrigin));

    if (al->__rootOfTrust_present) {
        log_proc("        .rootOfTrust = {");
        dump_hex("            .verifiedBootKey = {", "},",
                al->rootOfTrust.verifiedBootKey, INDENT_4, log_proc);
        log_proc("            .deviceLocked = %d,",
                al->rootOfTrust.deviceLocked);
        log_proc("            .verifiedBootState = %d, // %s,",
                al->rootOfTrust.verifiedBootState,
                get_vbstate_str(al->rootOfTrust.verifiedBootState)
        );
        dump_hex("            .verifiedBootHash = {", "},",
                al->rootOfTrust.verifiedBootHash, INDENT_4, log_proc);
        log_proc("        },");
    }

    if (al->__rootOfTrustBytes_present)
        dump_hex("        .rootOfTrust = {", "},",
                al->rootOfTrustBytes, INDENT_3, log_proc);

    if (al->__osVersion_present)
        log_proc("        .osVersion = %llu,", al->osVersion);

    if (al->__osPatchLevel_present)
        log_proc("        .osPatchLevel = %llu,", al->osPatchLevel);

    if (al->__uniqueId_present)
        dump_hex("        .uniqueId = {", "},",
                al->uniqueId, INDENT_3, log_proc);

    if (al->__attestationChallenge_present)
        dump_hex("        .attestationChallenge = {", "},",
                al->attestationChallenge, INDENT_3, log_proc);

    if (al->__attestationApplicationId_present)
        dump_hex("        .attestationApplicationId = {", "},",
                al->attestationApplicationId, INDENT_3, log_proc);

    if (al->__attestationIdBrand_present)
        dump_hex("        .attestationIdBrand = {", "},",
                al->attestationIdBrand, INDENT_3, log_proc);

    if (al->__attestationIdDevice_present)
        dump_hex("        .attestationIdDevice = {", "},",
                al->attestationIdDevice, INDENT_3, log_proc);

    if (al->__attestationIdProduct_present)
        dump_hex("        .attestationIdProduct = {", "},",
                al->attestationIdProduct, INDENT_3, log_proc);

    if (al->__attestationIdSerial_present) {
        dump_hex("        .attestationIdSerial = {", "},",
                al->attestationIdSerial, INDENT_3, log_proc);
    }

    if (al->__attestationIdImei_present)
        dump_hex("        .attestationIdImei = {", "},",
                al->attestationIdImei, INDENT_3, log_proc);

    if (al->__attestationIdMeid_present)
        dump_hex("        .attestationIdMeid = {", "},",
                al->attestationIdMeid, INDENT_3, log_proc);

    if (al->__attestationIdManufacturer_present)
        dump_hex("        .attestationIdManufacturer = {", "},",
                al->attestationIdManufacturer, INDENT_3, log_proc);

    if (al->__attestationIdModel_present)
        dump_hex("        .attestationIdModel = {", "},",
                al->attestationIdModel, INDENT_3, log_proc);

    if (al->__vendorPatchLevel_present)
        log_proc("        .vendorPatchLevel = %llu,",
                al->vendorPatchLevel);

    if (al->__bootPatchLevel_present)
        log_proc("        .bootPatchLevel = %llu,", al->bootPatchLevel);

    if (al->__associatedData_present)
        dump_hex("        .associatedData = {", "},",
                al->associatedData, INDENT_3, log_proc);

    if (al->__nonce_present)
        dump_hex("        .nonce = {", "},", al->nonce, INDENT_3, log_proc);

    if (al->__macLength_present)
        log_proc("        .macLength = 0x%08x,", al->macLength);

    if (al->__resetSinceIdRotation_present)
        log_proc("        .resetSinceIdRotation = %d,",
                al->resetSinceIdRotation);

    if (al->__confirmationToken_present)
        dump_hex("        .confirmationToken = {", "},",
                al->confirmationToken, INDENT_3, log_proc);

    log_proc("        .samsung = {");

    if (al->samsung.__authToken_present)
        dump_hex("             .authToken = {", "},",
                al->samsung.authToken, INDENT_4, log_proc);

    if (al->samsung.__verificationToken_present)
        dump_hex("             .verificationToken = {", "},",
                al->samsung.verificationToken, INDENT_4, log_proc);

    if (al->samsung.__allUsers_present)
        log_proc("             .allUsers = %d,", al->samsung.allUsers);

    if (al->samsung.__eciesSingleHashMode_present)
        log_proc("             .eciesSingleHashMode = %d,",
                al->samsung.eciesSingleHashMode);

    if (al->samsung.__kdf_present) {
        dump_enum_arr("            .kdf = {", "},",
                (VECTOR(i32))al->samsung.kdf,
                (get_enum_str_proc_t)get_kdf_str,
                log_proc
        );
    }

    if (al->samsung.__exportable_present)
        log_proc("            .exportable = %d,", al->samsung.exportable);

    if (al->samsung.__keyAuth_present)
        log_proc("            .keyAuth = %d,", al->samsung.keyAuth);

    if (al->samsung.__opAuth_present)
        log_proc("            .opAuth = %d,", al->samsung.opAuth);

    if (al->samsung.__operationHandle_present)
        log_proc("            .operationHandle = 0x%016llx,",
                al->samsung.operationHandle);

    if (al->samsung.__operationFailed_present)
        log_proc("            .operationFailed = %d,",
                al->samsung.operationFailed);

    if (al->samsung.__internalCurrentDateTime_present) {
        datetime_to_str(date_time_buf, sizeof(date_time_buf),
                al->samsung.internalCurrentDateTime);
        log_proc("            .internalCurrentDateTime = %llu, // %s",
                al->samsung.internalCurrentDateTime, date_time_buf);
    }

    if (al->samsung.__ekeyBlobIV_present)
        dump_hex("            .ekeyBlobIV = {", "},",
                al->samsung.ekeyBlobIV, INDENT_4, log_proc);

    if (al->samsung.__ekeyBlobAuthTag_present)
        dump_hex("            .ekeyBlobAuthTag = {", "},",
                al->samsung.ekeyBlobAuthTag, INDENT_4, log_proc);

    if (al->samsung.__ekeyBlobCurrentUsesPerBoot_present)
        log_proc("            .ekeyBlobCurrentUsesPerBoot = %u,",
                al->samsung.ekeyBlobCurrentUsesPerBoot);

    if (al->samsung.__ekeyBlobLastOpTimestamp_present)
        log_proc("            .ekeyBlobLastOpTimestamp = %llu,",
                al->samsung.ekeyBlobLastOpTimestamp);

    if (al->samsung.__ekeyBlobDoUpgrade_present)
        log_proc("            .ekeyBlobDoUpgrade = %u,",
                al->samsung.ekeyBlobDoUpgrade);

    if (al->samsung.__ekeyBlobPassword_present)
        dump_hex("            .ekeyBlobPassword = {", "},",
                al->samsung.ekeyBlobPassword, INDENT_4, log_proc);

    if (al->samsung.__ekeyBlobSalt_present)
        dump_hex("            .ekeyBlobSalt = {", "},",
                al->samsung.ekeyBlobSalt, INDENT_4, log_proc);

    if (al->samsung.__ekeyBlobEncVer_present)
        log_proc("            .ekeyBlobEncVer = %u,",
                al->samsung.ekeyBlobEncVer);

    if (al->samsung.__ekeyBlobRaw_present)
        log_proc("            .ekeyBlobRaw = %u,", al->samsung.ekeyBlobRaw);

    if (al->samsung.__ekeyBlobUniqKDM_present)
        dump_hex("            .ekeyBlobUniqKDM = {", "},",
                al->samsung.ekeyBlobUniqKDM, INDENT_4, log_proc);

    if (al->samsung.__ekeyBlobIncUseCount_present)
        log_proc("            .ekeyBlobIncUseCount = %u,",
                al->samsung.ekeyBlobIncUseCount);

    if (al->samsung.__samsungRequestingTA_present)
        dump_hex("            .samsungRequestingTA = {", "},",
                al->samsung.samsungRequestingTA, INDENT_4, log_proc);

    if (al->samsung.__samsungRotRequired_present)
        log_proc("            .samsungRotRequired = %d,",
                al->samsung.samsungRotRequired);

    if (al->samsung.__samsungLegacyRot_present)
        log_proc("            .samsungLegacyRot = %d,",
                al->samsung.samsungLegacyRot);

    if (al->samsung.__useSecureProcessor_present)
        log_proc("            .useSecureProcessor = %d,",
                al->samsung.useSecureProcessor);

    if (al->samsung.__storageKey_present)
        log_proc("            .storageKey = %d,", al->samsung.storageKey);

    if (al->samsung.__integrityStatus_present)
        log_proc("            .integrityStatus = 0x%08x,",
                al->samsung.integrityStatus);

    if (al->samsung.__isSamsungKey_present)
        log_proc("            .isSamsungKey = %d,", al->samsung.isSamsungKey);

    if (al->samsung.__samsungAttestationRoot_present)
        dump_hex("            .samsungAttestationRoot = {", "},",
                al->samsung.samsungAttestationRoot, INDENT_4, log_proc);

    if (al->samsung.__samsungAttestIntegrity_present)
        log_proc("            .samsungAttestIntegrity = %d,",
                al->samsung.samsungAttestIntegrity);

    if (al->samsung.__knoxObjectProtectionRequired_present)
        log_proc("            .knoxObjectProtectionRequired = %d,",
                al->samsung.knoxObjectProtectionRequired);

    if (al->samsung.__knoxCreatorId_present)
        dump_hex("            .knoxCreatorId = {", "},",
                al->samsung.knoxCreatorId, INDENT_4, log_proc);

    if (al->samsung.__knoxAdministratorId_present)
        dump_hex("            .knoxAdministratorId = {", "},",
                al->samsung.knoxAdministratorId, INDENT_4, log_proc);

    if (al->samsung.__knoxAccessorId_present)
        dump_hex("            .knoxAccessorId = {", "},",
                al->samsung.knoxAccessorId, INDENT_4, log_proc);

    if (al->samsung.__samsungAuthPackage_present)
        dump_hex("            .samsungAuthPackage = {", "},",
                al->samsung.samsungAuthPackage, INDENT_4, log_proc);

    if (al->samsung.__samsungCertificateSubject_present)
        dump_hex("            .samsungCertificateSubject = {", "},",
                al->samsung.samsungCertificateSubject, INDENT_4, log_proc);

    if (al->samsung.__samsungKeyUsage_present)
        log_proc("            .samsungKeyUsage = 0x%08x,",
                al->samsung.samsungKeyUsage);

    if (al->samsung.__samsungExtendedKeyUsage_present)
        dump_hex("            .extendedSamsungKeyUsage = {", "},",
                al->samsung.samsungExtendedKeyUsage, INDENT_4, log_proc);

    if (al->samsung.__samsungSubjectAlternativeName_present)
        dump_hex("            .samsungSubjectAlternativeName = {", "},",
                al->samsung.samsungSubjectAlternativeName, INDENT_4, log_proc);

    if (al->samsung.__provGacEc1_present)
        dump_hex("            .provGacEc1 = {", "},",
                al->samsung.provGacEc1, INDENT_4, log_proc);

    if (al->samsung.__provGacEc2_present)
        dump_hex("            .provGacEc2 = {", "},",
                al->samsung.provGacEc2, INDENT_4, log_proc);

    if (al->samsung.__provGacEc3_present)
        dump_hex("            .provGacEc3 = {", "},",
                al->samsung.provGacEc3, INDENT_4, log_proc);

    if (al->samsung.__provGakEc_present)
        dump_hex("            .provGakEc = {", "},",
                al->samsung.provGakEc, INDENT_4, log_proc);

    if (al->samsung.__provGakEcVtoken_present)
        dump_hex("            .provGakEcVtoken = {", "},",
                al->samsung.provGakEcVtoken, INDENT_4, log_proc);

    if (al->samsung.__provGacRsa1_present)
        dump_hex("            .provGacRsa1 = {", "},",
                al->samsung.provGacRsa1, INDENT_4, log_proc);

    if (al->samsung.__provGacRsa2_present)
        dump_hex("            .provGacRsa2 = {", "},",
                al->samsung.provGacRsa2, INDENT_4, log_proc);

    if (al->samsung.__provGacRsa3_present)
        dump_hex("            .provGacRsa3 = {", "},",
                al->samsung.provGacRsa3, INDENT_4, log_proc);

    if (al->samsung.__provGakRsa_present)
        dump_hex("            .provGakRsa = {", "},",
                al->samsung.provGakRsa, INDENT_4, log_proc);

    if (al->samsung.__provGakRsaVtoken_present)
        dump_hex("            .provGakRsaVtoken = {", "},",
                al->samsung.provGakRsaVtoken, INDENT_4, log_proc);

    if (al->samsung.__provSakEc_present)
        dump_hex("            .provSakEc = {", "},",
                al->samsung.provSakEc, INDENT_4, log_proc);

    if (al->samsung.__provSakEcVtoken_present)
        dump_hex("            .provSakEcVtoken = {", "},",
                al->samsung.provSakEcVtoken, INDENT_4, log_proc);

    log_proc("        }");
}

static const char * get_security_level_str(enum KM_SecurityLevel sl)
{
    static const char *const security_level_strings[] = {
        [KM_SECURITY_LEVEL_SOFTWARE] = "KM_SECURITY_LEVEL_SOFTWARE",
        [KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT] =
            "KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT",
        [KM_SECURITY_LEVEL_STRONGBOX] = "KM_SECURITY_LEVEL_STRONGBOX",
    };
    if (sl < 0 || sl >= u_arr_size(security_level_strings))
        return "(unknown)";

    return security_level_strings[sl];
}

static const char * get_vbstate_str(enum KM_VerifiedBootState vb)
{
    static const char *const vbstate_strings[] = {
        [KM_VERIFIED_BOOT_VERIFIED] = "KM_VERIFIED_BOOT_VERIFIED",
        [KM_VERIFIED_BOOT_SELF_SIGNED] = "KM_VERIFIED_BOOT_SELF_SIGNED",
        [KM_VERIFIED_BOOT_UNVERIFIED] = "KM_VERIFIED_BOOT_UNVERIFIED",
        [KM_VERIFIED_BOOT_FAILED] = "KM_VERIFIED_BOOT_FAILED"
    };
    if (vb < 0 || vb >= u_arr_size(vbstate_strings))
        return "(unknown)";

    return vbstate_strings[vb];
}

static const char * get_keypurpose_str(enum KM_KeyPurpose kp)
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

static const char * get_algorithm_str(enum KM_Algorithm alg)
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

static const char * get_blockmode_str(enum KM_BlockMode bm)
{
    switch (bm) {
    case KM_BLOCK_MODE_ECB: return "KM_BLOCK_MODE_ECB";
    case KM_BLOCK_MODE_CBC: return "KM_BLOCK_MODE_CBC";
    case KM_BLOCK_MODE_CTR: return "KM_BLOCK_MODE_CTR";
    case KM_BLOCK_MODE_GCM: return "KM_BLOCK_MODE_GCM";
    default: return "(unknown)";
    }
}

static const char * get_digest_str(enum KM_Digest dig)
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

static const char * get_paddingmode_str(enum KM_PaddingMode pm)
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

static const char * get_eccurve_str(enum KM_EcCurve ec)
{
    switch (ec) {
    case KM_EC_CURVE_P_224: return "KM_EC_CURVE_P_224";
    case KM_EC_CURVE_P_256: return "KM_EC_CURVE_P_256";
    case KM_EC_CURVE_P_384: return "KM_EC_CURVE_P_384";
    case KM_EC_CURVE_P_521: return "KM_EC_CURVE_P_521";
    default: return "(unknown)";
    }
}

static const char * get_keyorigin_str(enum KM_KeyOrigin ko)
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

static const char * get_usage_req_str(enum KM_KeyBlobUsageRequirements kbur)
{
    switch (kbur) {
    case KM_USAGE_STANDALONE: return "KM_USAGE_STANDALONE";
    case KM_USAGE_REQUIRES_FILE_SYSTEM: return "KM_USAGE_REQUIRES_FILE_SYSTEM";
    default: return "(unknown)";
    }
}

static const char * get_kdf_str(enum KM_KeyDerivationFunction kdf)
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

static void dump_hex_line(char *buf, u32 buf_size,
        const u8 *data, u32 data_size, bool end_without_comma)
{
    for (u32 i = 0; i < u_min(buf_size, data_size); i++) {
        char byte_buf[8] = { 0 };
        int n = 0;
        if (end_without_comma && i == u_min(buf_size, data_size) - 1)
            n = snprintf(byte_buf, 8, "0x%02x", data[i]);
        else
            n = snprintf(byte_buf, 8, "0x%02x, ", data[i]);

        if (n <= 0 || n >= 8)
            continue;

        byte_buf[7] = '\0';
        (void) strncat(buf, byte_buf, u_min((u32)n, buf_size - i - 1));
    }
}

static void dump_hex(const char *prefix, const char *postfix,
        const VECTOR(u8) data, enum dump_hex_indendation indentation_lvl,
        key_desc_log_proc_t log_proc)
{
    if (data == NULL || vector_size(data) == 0) {
        log_proc("%s/* (empty) */%s", prefix, postfix);
        return;
    }

    const u32 total_sz = vector_size(data);

#define LINE_LEN 8

    u32 n_lines = total_sz / LINE_LEN;
    u32 remainder = total_sz % LINE_LEN;
    if (remainder == 0) {
        n_lines--;
        remainder = LINE_LEN;
    }

#define LINE_BUF_SIZE (LINE_LEN * 16)
    char line_buf[LINE_BUF_SIZE] = { 0 };

    if (n_lines == 0) {
        dump_hex_line(line_buf, LINE_BUF_SIZE, data, remainder, true);
        line_buf[LINE_BUF_SIZE - 1] = '\0';
        log_proc("%s%s%s", prefix, line_buf, postfix);
        return;
    }

    const char *const indentation = get_indentation_str(indentation_lvl);

    dump_hex_line(line_buf, LINE_BUF_SIZE, data, LINE_LEN, false);
    line_buf[LINE_BUF_SIZE - 1] = '\0';
    log_proc("%s", prefix);
    log_proc("%s    %s", indentation, line_buf);

    for (u32 i = 1; i < n_lines; i++) {
        memset(line_buf, 0, LINE_BUF_SIZE);
        dump_hex_line(line_buf, LINE_BUF_SIZE,
                data + (i * LINE_LEN),
                LINE_LEN, false
        );
        line_buf[LINE_BUF_SIZE - 1] = '\0';
        log_proc("%s    %s", indentation, line_buf);
    }

    memset(line_buf, 0, LINE_BUF_SIZE);
    dump_hex_line(line_buf, LINE_BUF_SIZE,
            data + (n_lines * LINE_LEN),
            remainder, true
    );
    line_buf[LINE_BUF_SIZE - 1] = '\0';
    log_proc("%s    %s", indentation, line_buf);
    log_proc("%s%s", indentation, postfix);

#undef LINE_LEN
}

static void dump_u64_arr(const char *prefix, const char *postfix,
        const VECTOR(u64) arr, key_desc_log_proc_t log_proc)
{
    char tmp_buf[256] = { 0 };
    u32 write_index = 0;

    if (arr == NULL || vector_size(arr) == 0) {
        log_proc("%s/* (empty) */%s", prefix, postfix);
        return;
    }

    i32 r = 0;

    for (u32 i = 0; i < vector_size(arr) - 1; i++) {
        r = snprintf(tmp_buf + write_index, 256 - write_index - 1,
                "0x%016llx, ", (long long int)arr[i]
        );
        if (r <= 0 || r >= 256)
            continue;

        write_index += r;
    }
    (void) snprintf(tmp_buf + write_index, 256 - write_index - 1,
            "0x%016llx", (long long int)arr[vector_size(arr) - 1]);

    log_proc("%s%s%s", prefix, tmp_buf, postfix);
}

static void dump_enum_arr(const char *prefix, const char *postfix,
        const VECTOR(i32) arr, get_enum_str_proc_t get_str_proc,
        key_desc_log_proc_t log_proc)
{
    if (arr == NULL || vector_size(arr) == 0) {
        log_proc("%s/* (empty) */%s", prefix, postfix);
        return;
    }

    log_proc("%s", prefix);

    const char *const i2str = get_indentation_str(INDENT_3);
    for (u32 i = 0; i < vector_size(arr) - 1; i++) {
        log_proc("%s    0x%08x, // %s",
                i2str, arr[i],
                get_str_proc ? get_str_proc(arr[i]) : "N/A"
        );
    }
    const u32 last_idx = vector_size(arr) - 1;
    log_proc("%s    0x%08x // %s",
            i2str, arr[last_idx],
            get_str_proc ? get_str_proc(arr[last_idx]) : "N/A"
    );

    log_proc("%s%s", i2str, postfix);
}

static int portable_localtime(const time_t *timep, struct tm *result)
{
#ifdef _WIN32
    return localtime_s(result, timep);
#else
    return localtime_r(timep, result) ? 0 : -1;
#endif
}
static void datetime_to_str(char *buf, u32 buf_size, KM_DateTime_t dt)
{
    struct tm t = { 0 };

    const time_t s = dt / 1000;

    i32 ms = (i32)(dt % 1000);
    if (ms < 1000) ms += 1000;

    if (portable_localtime(&s, &t)) {
        (void) snprintf(buf, buf_size, "N/A");
        return;
    }

    const u64 fmt1_len = strftime(buf, buf_size, "%Y-%m-%d %H:%M:%S", &t);
    if (fmt1_len == 0) {
        (void) snprintf(buf, buf_size, "N/A");
        return;
    }

    i32 r = snprintf(buf + fmt1_len, buf_size - fmt1_len, ".%03d", ms);
    if (r <= 0 || (u32)r >= buf_size - fmt1_len) {
        buf[fmt1_len] = '\0';
        return;
    }

    const u64 fmt2_len = strftime(
            buf + fmt1_len + (u32)r,
            buf_size - fmt1_len - (u32)r,
            " %Z", &t
    );
    if (fmt2_len == 0) {
        buf[fmt1_len + r] = '\0';
        return;
    }
}

static const char *get_indentation_str(enum dump_hex_indendation i)
{
    switch (i) {
    default:
    case INDENT_0:
    case INDENT_1:
        return "";

    case INDENT_2:
        return "    ";
    case INDENT_3:
        return "        ";
    case INDENT_4:
        return "            ";
    }
}
