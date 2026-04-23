#include "samsung-utils.h"
#include "dump-utils.h"
#include "keymaster-types-c.h"
#include <core/log.h>

#define MODULE_NAME "samsung-utils"

ASN1_SEQUENCE(KM_SAMSUNG_PARAM) = {
    ASN1_SIMPLE(KM_SAMSUNG_PARAM, tag, ASN1_INTEGER),
    ASN1_EXP_OPT(KM_SAMSUNG_PARAM, i, ASN1_INTEGER, 0),
    ASN1_EXP_OPT(KM_SAMSUNG_PARAM, b, ASN1_OCTET_STRING, 1)
} ASN1_SEQUENCE_END(KM_SAMSUNG_PARAM)
IMPLEMENT_ASN1_FUNCTIONS(KM_SAMSUNG_PARAM)

ASN1_SEQUENCE(KM_SAMSUNG_INDATA) = {
    ASN1_SIMPLE(KM_SAMSUNG_INDATA, ver, ASN1_INTEGER),
    ASN1_SIMPLE(KM_SAMSUNG_INDATA, km_ver, ASN1_INTEGER),
    ASN1_SIMPLE(KM_SAMSUNG_INDATA, cmd, ASN1_INTEGER),
    ASN1_SIMPLE(KM_SAMSUNG_INDATA, pid, ASN1_INTEGER),

    ASN1_EXP_OPT(KM_SAMSUNG_INDATA, int0, ASN1_INTEGER, 0),
    ASN1_EXP_OPT(KM_SAMSUNG_INDATA, long0, ASN1_INTEGER, 1),
    ASN1_EXP_OPT(KM_SAMSUNG_INDATA, long1, ASN1_INTEGER, 2),
    ASN1_EXP_OPT(KM_SAMSUNG_INDATA, bin0, ASN1_OCTET_STRING, 3),
    ASN1_EXP_OPT(KM_SAMSUNG_INDATA, bin1, ASN1_OCTET_STRING, 4),
    ASN1_EXP_OPT(KM_SAMSUNG_INDATA, bin2, ASN1_OCTET_STRING, 5),
    ASN1_EXP_OPT(KM_SAMSUNG_INDATA, key, ASN1_OCTET_STRING, 6),

    ASN1_EXP_SET_OF_OPT(KM_SAMSUNG_INDATA, par, KM_SAMSUNG_PARAM, 8)
} ASN1_SEQUENCE_END(KM_SAMSUNG_INDATA)
IMPLEMENT_ASN1_FUNCTIONS(KM_SAMSUNG_INDATA)

ASN1_SEQUENCE(KM_SAMSUNG_OUTDATA) = {
    ASN1_SIMPLE(KM_SAMSUNG_OUTDATA, ver, ASN1_INTEGER),
    ASN1_SIMPLE(KM_SAMSUNG_OUTDATA, cmd, ASN1_INTEGER),
    ASN1_SIMPLE(KM_SAMSUNG_OUTDATA, pid, ASN1_INTEGER),
    ASN1_SIMPLE(KM_SAMSUNG_OUTDATA, err, ASN1_INTEGER),

    ASN1_EXP_OPT(KM_SAMSUNG_OUTDATA, int0, ASN1_INTEGER, 0),
    ASN1_EXP_OPT(KM_SAMSUNG_OUTDATA, long0, ASN1_INTEGER, 1),
    ASN1_EXP_OPT(KM_SAMSUNG_OUTDATA, bin0, ASN1_OCTET_STRING, 2),
    ASN1_EXP_OPT(KM_SAMSUNG_OUTDATA, bin1, ASN1_OCTET_STRING, 3),
    ASN1_EXP_SET_OF_OPT(KM_SAMSUNG_OUTDATA, par, KM_SAMSUNG_PARAM, 4),

    ASN1_IMP_SEQUENCE_OF(KM_SAMSUNG_OUTDATA, log, ASN1_OCTET_STRING, 5)
} ASN1_SEQUENCE_END(KM_SAMSUNG_OUTDATA)
IMPLEMENT_ASN1_FUNCTIONS(KM_SAMSUNG_OUTDATA)

ASN1_SEQUENCE(KM_SAMSUNG_EKEY_BLOB) = {
    ASN1_SIMPLE(KM_SAMSUNG_EKEY_BLOB, enc_ver, ASN1_INTEGER),
    ASN1_SIMPLE(KM_SAMSUNG_EKEY_BLOB, ekey, ASN1_OCTET_STRING),
    ASN1_SET_OF(KM_SAMSUNG_EKEY_BLOB, enc_par, KM_SAMSUNG_PARAM)
} ASN1_SEQUENCE_END(KM_SAMSUNG_EKEY_BLOB)
IMPLEMENT_ASN1_FUNCTIONS(KM_SAMSUNG_EKEY_BLOB)

bool KM_samsung_is_integer_param(uint32_t tag)
{
    const enum KM_TagType tt = (enum KM_TagType)(__KM_TAG_TYPE_MASK(tag));
    return (tt != KM_TAG_TYPE_BYTES && tt != KM_TAG_TYPE_BIGNUM);
}

int KM_samsung_make_integer_param(KM_SAMSUNG_PARAM **out_par,
        uint32_t tag, int64_t val)
{
    *out_par = NULL;

    KM_SAMSUNG_PARAM *p = KM_SAMSUNG_PARAM_new();
    if (p == NULL) {
        s_log_error("Couldn't allocate a new samsung key parameter");
        return 1;
    }

    if (!ASN1_INTEGER_set(p->tag, (long)tag)) {
        s_log_error("Couldn't set the value of an ASN.1 INTEGER");
        KM_SAMSUNG_PARAM_free(p);
        return 1;
    }

    p->i = ASN1_INTEGER_new();
    if (p->i == NULL) {
        s_log_error("Couldn't allocate a new ASN.1 INTEGER");
        KM_SAMSUNG_PARAM_free(p);
        return 1;
    }

    if (!ASN1_INTEGER_set_int64(p->i, (long)val)) {
        s_log_error("Couldn't set the value of an ASN.1 INTEGER");
        KM_SAMSUNG_PARAM_free(p);
        return 1;
    }

    *out_par = p;
    return 0;
}

int KM_samsung_make_octet_string_param(KM_SAMSUNG_PARAM **out_par,
        uint32_t tag, const unsigned char *data, size_t len)
{
    *out_par = NULL;

    KM_SAMSUNG_PARAM *p = KM_SAMSUNG_PARAM_new();
    if (p == NULL) {
        s_log_error("Couldn't allocate a new samsung key parameter");
        return 1;
    }

    if (!ASN1_INTEGER_set(p->tag, (long)tag)) {
        s_log_error("Couldn't set the value of an ASN.1 INTEGER");
        KM_SAMSUNG_PARAM_free(p);
        return 1;
    }

    p->b = ASN1_INTEGER_new();
    if (p->b == NULL) {
        s_log_error("Couldn't allocate a new ASN.1 OCTET_STRING");
        KM_SAMSUNG_PARAM_free(p);
        return 1;
    }

    if (!ASN1_OCTET_STRING_set(p->b, data, len)) {
        s_log_error("Couldn't set the value of an ASN.1 OCTET_STRING");
        KM_SAMSUNG_PARAM_free(p);
        return 1;
    }

    *out_par = p;
    return 0;
}

int KM_samsung_push_param_or_free(STACK_OF(KM_SAMSUNG_PARAM) *paramset,
        KM_SAMSUNG_PARAM *par)
{
    if (sk_KM_SAMSUNG_PARAM_push(paramset, par) <= 0) {
        KM_SAMSUNG_PARAM_free(par);
        s_log_error("Failed to push a key parameter to the set");
        return 1;
    }

    return 0;
}

static const char * to_be_filled_in_by_libsuskeymaster(int val)
{
    (void) val;
    return "to be filled in by libsuskeymaster";
}
void KM_samsung_dump_indata(KM_dump_log_proc_t log_proc,
        const KM_SAMSUNG_INDATA *indata, uint8_t indent,
        const char *field_name)
{
    char indent_buf[1024];
    const uint8_t i = indent + 1;

    KM_DUMP_sprint_indent(indent_buf, indent);

    if (field_name == NULL) {
        log_proc("%s===== BEGIN KM_INDATA DUMP =====", indent_buf);

        if (indata == NULL) {
            log_proc("%sKM_INDATA indata = { /* empty */ };", indent_buf);
            return;
        }

        log_proc("KM_INDATA indata = {");
    } else {
        if (indata == NULL) {
            log_proc("%s.%s = { /* empty */ };", indent_buf, field_name);
            return;
        }

        log_proc("%s.%s = {", indent_buf, field_name);
    }

    KM_dump_enum_val(log_proc, "ver", indata->ver,
            to_be_filled_in_by_libsuskeymaster, i);
    KM_dump_enum_val(log_proc, "km_ver", indata->km_ver,
            to_be_filled_in_by_libsuskeymaster, i);
    KM_dump_u64_hex(log_proc, "cmd", indata->cmd, i);
    KM_dump_enum_val(log_proc, "pid", indata->pid,
            to_be_filled_in_by_libsuskeymaster, i);

    if (indata->int0) KM_dump_u64(log_proc, "int0", indata->int0, i);
    if (indata->long0) KM_dump_u64(log_proc, "long0", indata->long0, i);
    if (indata->long1) KM_dump_u64(log_proc, "long0", indata->long1, i);
    if (indata->bin0) KM_dump_hex(log_proc, "bin0", indata->bin0, i);
    if (indata->bin1) KM_dump_hex(log_proc, "bin1", indata->bin1, i);
    if (indata->bin2) KM_dump_hex(log_proc, "bin1", indata->bin2, i);
    if (indata->key) KM_dump_hex(log_proc, "key", indata->key, i);
    if (indata->par) {
        KM_PARAM_LIST *param_list = NULL;
        if (KM_samsung_paramset_to_param_list(indata->par, &param_list)) {
            s_log_error("Faield to convert samsung KM_PARAM set to a param list");
        } else {
            KM_dump_param_list(log_proc, param_list, i, "par");
            KM_PARAM_LIST_free(param_list);
        }
    }

    if (field_name != NULL) {
        s_log_info("%s};", indent_buf);
        s_log_info("%s=====  END KM_INDATA DUMP  =====", indent_buf);
    } else {
        s_log_info("%s},", indent_buf);
    }
}

void KM_samsung_dump_outdata(KM_dump_log_proc_t log_proc,
        const KM_SAMSUNG_OUTDATA *outdata, uint8_t indent,
        const char *field_name)
{
    char indent_buf[1024];
    const uint8_t i = indent + 1;

    KM_DUMP_sprint_indent(indent_buf, indent);

    if (field_name == NULL) {
        log_proc("%s===== BEGIN KM_OUTDATA DUMP =====", indent_buf);

        if (outdata == NULL) {
            log_proc("%sKM_OUTDATA outdata = { /* empty */ };", indent_buf);
            return;
        }

        log_proc("KM_OUTDATA outdata = {");
    } else {
        if (outdata == NULL) {
            log_proc("%s.%s = { /* empty */ };", indent_buf, field_name);
            return;
        }

        log_proc("%s.%s = {", indent_buf, field_name);
    }

    KM_dump_u64_hex(log_proc, "ver", outdata->ver, i);
    KM_dump_u64_hex(log_proc, "cmd", outdata->cmd, i);
    KM_dump_u64(log_proc, "pid", outdata->pid, i);
    KM_dump_enum_val(log_proc, "err", outdata->err, KM_ErrorCode_toString, i);

    if (outdata->int0) KM_dump_u64(log_proc, "int0", outdata->int0, i);
    if (outdata->long0) KM_dump_u64(log_proc, "long0", outdata->long0, i);
    if (outdata->bin0) KM_dump_hex(log_proc, "bin0", outdata->bin0, i);
    if (outdata->bin1) KM_dump_hex(log_proc, "bin1", outdata->bin1, i);
    if (outdata->par) {
        KM_PARAM_LIST *param_list = NULL;
        if (KM_samsung_paramset_to_param_list(outdata->par, &param_list)) {
            s_log_error("Faield to convert samsung KM_PARAM set to a param list");
        } else {
            KM_dump_param_list(log_proc, param_list, i, "par");
            KM_PARAM_LIST_free(param_list);
        }
    }

    if (outdata->log) {
        log_proc("%s" KM_DUMP_SINGLE_INDENT" .log = {", indent_buf);
        int n_strs = sk_ASN1_OCTET_STRING_num(outdata->log);
        if (n_strs < 0) {
            log_proc("ERROR: Failed to get the number of OCTET_STRINGs "
                    "in the stack");
        } else {
            for (int i = 0; i < n_strs; i++) {
                const ASN1_OCTET_STRING *str =
                    sk_ASN1_OCTET_STRING_value(outdata->log, i);
                if (str == NULL) {
                    log_proc("ERROR: Failed to get an OCTET_STRING "
                            "from the stack");
                    return;
                }

                log_proc("%s" KM_DUMP_SINGLE_INDENT KM_DUMP_SINGLE_INDENT
                        "\"%s\"%s",
                        indent_buf,
                        (const char *)ASN1_STRING_get0_data(str),
                        (i < n_strs - 1) ? "," : "");
            }
        }
        log_proc("%s" KM_DUMP_SINGLE_INDENT "}", indent_buf);
    }


    if (field_name != NULL) {
        log_proc("%s};", indent_buf);
        log_proc("%s=====  END KM_OUTDATA DUMP  =====", indent_buf);
    } else {
        log_proc("%s},", indent_buf);
    }
}

int KM_samsung_paramset_to_param_list(
        const STACK_OF(KM_SAMSUNG_PARAM) *ekey_params,
        KM_PARAM_LIST **out_param_list
)
{
    KM_PARAM_LIST *ret = NULL;
    int n_params = 0;

    ret = KM_PARAM_LIST_new();
    if (ret == NULL)
        goto_error("Failed to allocate a new param list");

    n_params = sk_KM_SAMSUNG_PARAM_num(ekey_params);
    if (n_params < 0)
        goto_error("Failed to get the number of parameters in the stack");

    for (int i = 0; i < n_params; i++) {
        const KM_SAMSUNG_PARAM *const curr =
            sk_KM_SAMSUNG_PARAM_value(ekey_params, i);
        if (curr == NULL)
            goto_error("Failed to retrieve a parameter from the stack");

        int64_t tag = 0;
        if (!ASN1_INTEGER_get_int64(&tag, curr->tag))
            goto_error("Failed to get the value of the parameter tag INTEGER");
        tag &= 0x00000000FFFFFFFF;

        /* Special handling for root of trust */
        if (tag == KM_TAG_ROOT_OF_TRUST) {
            if (curr->b == NULL || ASN1_STRING_length(curr->b) <= 0) {
                s_log_warn("Expected non-empty OCTET_STRING for ROOT_OF_TRUST; "
                        "not adding");
                continue;
            }

            const unsigned char *data = ASN1_STRING_get0_data(curr->b);
            const unsigned char *p = data;
            const int len = ASN1_STRING_length(curr->b);

            ret->rootOfTrust = d2i_KM_ROOT_OF_TRUST_V3(&ret->rootOfTrust,
                    &p, len);
            if (ret->rootOfTrust == NULL) {
                s_log_warn("Failed to parse the rootOfTrust SEQUENCE; not adding");
                continue;
            }

            if (p != data + len)
                goto_error("Parsed an incorrect number of bytes (delta: %lld)",
                        (long long int)(p - (data + len)));

            continue;
        }

        enum {
            TARGET_BOOL, TARGET_INTEGER, TARGET_INTEGER_SET, TARGET_OCTET_STRING
        } target_type;
        switch ((enum KM_TagType)__KM_TAG_TYPE_MASK(tag)) {
            case KM_TAG_TYPE_BOOL:
                target_type = TARGET_BOOL;
                break;
            case KM_TAG_TYPE_ENUM:
            case KM_TAG_TYPE_UINT:
            case KM_TAG_TYPE_ULONG:
            case KM_TAG_TYPE_DATE:
                target_type = TARGET_INTEGER;
                break;
            case KM_TAG_TYPE_ENUM_REP:
            case KM_TAG_TYPE_UINT_REP:
            case KM_TAG_TYPE_ULONG_REP:
                target_type = TARGET_INTEGER_SET;
                break;
            case KM_TAG_TYPE_BYTES:
            case KM_TAG_TYPE_BIGNUM:
                target_type = TARGET_OCTET_STRING;
                break;
            default:
            case KM_TAG_TYPE_INVALID:
                goto_error("Invalid keymaster tag: 0x%016llx",
                        (long long unsigned)tag);
        }

        union {
            ASN1_NULL **b;
            ASN1_INTEGER **i;
            ASN1_SET_OF_INTEGER **iset;
            ASN1_OCTET_STRING **str;

            void *v;
        } target;

        switch ((enum KM_Tag)tag) {
        case KM_TAG_PURPOSE: target.iset = &ret->purpose; break;
        case KM_TAG_ALGORITHM: target.i = &ret->algorithm; break;
        case KM_TAG_KEY_SIZE: target.i = &ret->keySize; break;
        case KM_TAG_BLOCK_MODE: target.iset = &ret->blockMode; break;
        case KM_TAG_DIGEST: target.iset = &ret->digest; break;
        case KM_TAG_PADDING: target.iset = &ret->padding; break;
        case KM_TAG_CALLER_NONCE: target.b = &ret->callerNonce; break;
        case KM_TAG_MIN_MAC_LENGTH: target.i = &ret->minMacLength; break;
        case KM_TAG_EC_CURVE: target.i = &ret->ecCurve; break;
        case KM_TAG_RSA_PUBLIC_EXPONENT: target.i = &ret->rsaPublicExponent; break;
        case KM_TAG_ROLLBACK_RESISTANCE: target.b = &ret->rollbackResistance; break;
        case KM_TAG_ACTIVE_DATETIME: target.i = &ret->activeDateTime; break;
        case KM_TAG_ORIGINATION_EXPIRE_DATETIME: target.i = &ret->originationExpireDateTime; break;
        case KM_TAG_USAGE_EXPIRE_DATETIME: target.i = &ret->usageExpireDateTime; break;
        case KM_TAG_USER_SECURE_ID: target.iset = &ret->userSecureId; break;
        case KM_TAG_NO_AUTH_REQUIRED: target.b = &ret->noAuthRequired; break;
        case KM_TAG_USER_AUTH_TYPE: target.i = &ret->userAuthType; break;
        case KM_TAG_AUTH_TIMEOUT: target.i = &ret->authTimeout; break;
        case KM_TAG_ALLOW_WHILE_ON_BODY: target.b = &ret->allowWhileOnBody; break;
        case KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED: target.b = &ret->trustedUserPresenceReq; break;
        case KM_TAG_TRUSTED_CONFIRMATION_REQUIRED: target.b = &ret->trustedConfirmationReq; break;
        case KM_TAG_UNLOCKED_DEVICE_REQUIRED: target.b = &ret->unlockedDeviceReq; break;
        case KM_TAG_CREATION_DATETIME: target.i = &ret->creationDateTime; break;
        case KM_TAG_ORIGIN: target.i = &ret->keyOrigin; break;
        case KM_TAG_OS_VERSION: target.i = &ret->osVersion; break;
        case KM_TAG_OS_PATCHLEVEL: target.i = &ret->osPatchLevel; break;
        case KM_TAG_ATTESTATION_APPLICATION_ID: target.str = &ret->attestationApplicationId; break;
        case KM_TAG_ATTESTATION_ID_BRAND: target.str = &ret->attestationIdBrand; break;
        case KM_TAG_ATTESTATION_ID_DEVICE: target.str = &ret->attestationIdDevice; break;
        case KM_TAG_ATTESTATION_ID_PRODUCT: target.str = &ret->attestationIdProduct; break;
        case KM_TAG_ATTESTATION_ID_SERIAL: target.str = &ret->attestationIdSerial; break;
        case KM_TAG_ATTESTATION_ID_IMEI: target.str = &ret->attestationIdImei; break;
        case KM_TAG_ATTESTATION_ID_MEID: target.str = &ret->attestationIdMeid; break;
        case KM_TAG_ATTESTATION_ID_MANUFACTURER: target.str = &ret->attestationIdManufacturer; break;
        case KM_TAG_ATTESTATION_ID_MODEL: target.str = &ret->attestationIdModel; break;
        case KM_TAG_VENDOR_PATCHLEVEL: target.i = &ret->vendorPatchLevel; break;
        case KM_TAG_BOOT_PATCHLEVEL: target.i = &ret->bootPatchLevel; break;
        case KM_TAG_INCLUDE_UNIQUE_ID: target.b = &ret->includeUniqueId; break;
        case KM_TAG_BLOB_USAGE_REQUIREMENTS: target.i = &ret->keyBlobUsageRequirements; break;
        case KM_TAG_BOOTLOADER_ONLY: target.b = &ret->bootloaderOnly; break;
        case KM_TAG_HARDWARE_TYPE: target.i = &ret->hardwareType; break;
        case KM_TAG_MIN_SECONDS_BETWEEN_OPS: target.i = &ret->minSecondsBetweenOps; break;
        case KM_TAG_MAX_USES_PER_BOOT: target.i = &ret->maxUsesPerBoot; break;
        case KM_TAG_USER_ID: target.i = &ret->userId; break;
        case KM_TAG_APPLICATION_ID: target.str = &ret->applicationId; break;
        case KM_TAG_APPLICATION_DATA: target.str = &ret->applicationData; break;
        case KM_TAG_UNIQUE_ID: target.str = &ret->uniqueId; break;
        case KM_TAG_ATTESTATION_CHALLENGE: target.str = &ret->attestationChallenge; break;
        case KM_TAG_ASSOCIATED_DATA: target.str = &ret->associatedData; break;
        case KM_TAG_NONCE: target.str = &ret->nonce; break;
        case KM_TAG_MAC_LENGTH: target.i = &ret->macLength; break;
        case KM_TAG_RESET_SINCE_ID_ROTATION: target.b = &ret->resetSinceIdRotation; break;
        case KM_TAG_CONFIRMATION_TOKEN: target.str = &ret->confirmationToken; break;
        case KM_TAG_AUTH_TOKEN: target.str = &ret->authToken; break;
        case KM_TAG_VERIFICATION_TOKEN: target.str = &ret->verificationToken; break;
        case KM_TAG_ALL_USERS: target.b = &ret->allUsers; break;
        case KM_TAG_ECIES_SINGLE_HASH_MODE: target.b = &ret->eciesSingleHashMode; break;
        case KM_TAG_KDF: target.i = &ret->kdf; break;
        case KM_TAG_EXPORTABLE: target.b = &ret->exportable; break;
        case KM_TAG_KEY_AUTH: target.b = &ret->keyAuth; break;
        case KM_TAG_OP_AUTH: target.b = &ret->opAuth; break;
        case KM_TAG_OPERATION_HANDLE: target.i = &ret->operationHandle; break;
        case KM_TAG_OPERATION_FAILED: target.b = &ret->operationFailed; break;
        case KM_TAG_INTERNAL_CURRENT_DATETIME: target.i = &ret->internalCurrentDateTime; break;
        case KM_TAG_EKEY_BLOB_IV: target.str = &ret->ekeyBlobIV; break;
        case KM_TAG_EKEY_BLOB_AUTH_TAG: target.str = &ret->ekeyBlobAuthTag; break;
        case KM_TAG_EKEY_BLOB_CURRENT_USES_PER_BOOT: target.i = &ret->ekeyBlobCurrentUsesPerBoot; break;
        case KM_TAG_EKEY_BLOB_LAST_OP_TIMESTAMP: target.i = &ret->ekeyBlobLastOpTimestamp; break;
        case KM_TAG_EKEY_BLOB_DO_UPGRADE: target.i = &ret->ekeyBlobDoUpgrade; break;
        case KM_TAG_EKEY_BLOB_PASSWORD: target.str = &ret->ekeyBlobPassword; break;
        case KM_TAG_EKEY_BLOB_SALT: target.str = &ret->ekeyBlobSalt; break;
        case KM_TAG_EKEY_BLOB_ENC_VER: target.i = &ret->ekeyBlobEncVer; break;
        case KM_TAG_EKEY_BLOB_RAW: target.i = &ret->ekeyBlobRaw; break;
        case KM_TAG_EKEY_BLOB_UNIQ_KDM: target.str = &ret->ekeyBlobUniqKDM; break;
        case KM_TAG_EKEY_BLOB_INC_USE_COUNT: target.i = &ret->ekeyBlobIncUseCount; break;
        case KM_TAG_SAMSUNG_REQUESTING_TA: target.str = &ret->samsungRequestingTA; break;
        case KM_TAG_SAMSUNG_ROT_REQUIRED: target.b = &ret->samsungRotRequired; break;
        case KM_TAG_SAMSUNG_LEGACY_ROT: target.b = &ret->samsungLegacyRot; break;
        case KM_TAG_USE_SECURE_PROCESSOR: target.b = &ret->useSecureProcessor; break;
        case KM_TAG_STORAGE_KEY: target.b = &ret->storageKey; break;
        case KM_TAG_INTEGRITY_STATUS: target.i = &ret->integrityStatus; break;
        case KM_TAG_IS_SAMSUNG_KEY: target.b = &ret->isSamsungKey; break;
        case KM_TAG_SAMSUNG_ATTESTATION_ROOT: target.str = &ret->samsungAttestationRoot; break;
        case KM_TAG_SAMSUNG_ATTEST_INTEGRITY: target.b = &ret->samsungAttestIntegrity; break;
        case KM_TAG_KNOX_OBJECT_PROTECTION_REQUIRED: target.b = &ret->knoxObjectProtectionRequired; break;
        case KM_TAG_KNOX_CREATOR_ID: target.str = &ret->knoxCreatorId; break;
        case KM_TAG_KNOX_ADMINISTRATOR_ID: target.str = &ret->knoxAdministratorId; break;
        case KM_TAG_KNOX_ACCESSOR_ID: target.str = &ret->knoxAccessorId; break;
        case KM_TAG_SAMSUNG_AUTHENTICATE_PACKAGE: target.str = &ret->samsungAuthPackage; break;
        case KM_TAG_SAMSUNG_CERTIFICATE_SUBJECT: target.str = &ret->samsungCertificateSubject; break;
        case KM_TAG_SAMSUNG_KEY_USAGE: target.i = &ret->samsungKeyUsage; break;
        case KM_TAG_SAMSUNG_EXTENDED_KEY_USAGE: target.str = &ret->samsungExtendedKeyUsage; break;
        case KM_TAG_SAMSUNG_SUBJECT_ALTERNATIVE_NAME: target.str = &ret->samsungSubjectAlternativeName; break;
        case KM_TAG_PROV_GAC_EC1: target.str = &ret->provGacEc1; break;
        case KM_TAG_PROV_GAC_EC2: target.str = &ret->provGacEc2; break;
        case KM_TAG_PROV_GAC_EC3: target.str = &ret->provGacEc3; break;
        case KM_TAG_PROV_GAK_EC: target.str = &ret->provGakEc; break;
        case KM_TAG_PROV_GAK_EC_VTOKEN: target.str = &ret->provGakEcVtoken; break;
        case KM_TAG_PROV_GAC_RSA1: target.str = &ret->provGacRsa1; break;
        case KM_TAG_PROV_GAC_RSA2: target.str = &ret->provGacRsa2; break;
        case KM_TAG_PROV_GAC_RSA3: target.str = &ret->provGacRsa3; break;
        case KM_TAG_PROV_GAK_RSA: target.str = &ret->provGakRsa; break;
        case KM_TAG_PROV_GAK_RSA_VTOKEN: target.str = &ret->provGakRsaVtoken; break;
        case KM_TAG_PROV_SAK_EC: target.str = &ret->provSakEc; break;
        case KM_TAG_PROV_SAK_EC_VTOKEN: target.str = &ret->provSakEcVtoken; break;
        default:
            goto_error("Unknown keymaster tag: 0x%08lx", (long unsigned)tag);
        }

        if (target_type == TARGET_OCTET_STRING && curr->b == NULL) {
            goto_error("Unexpected NULL OCTET_STRING value in tag 0x%08lx (%s)",
                    (long unsigned)tag, KM_Tag_toString((uint32_t)tag));
        } else if (target_type != TARGET_OCTET_STRING && curr->i == NULL) {
            goto_error("Unexpected NULL INTEGER value in tag 0x%08lx (%s)",
                    (long unsigned)tag, KM_Tag_toString((uint32_t)tag));
        }

        int64_t bval;
        ASN1_INTEGER *istmp;
        switch (target_type) {
        case TARGET_BOOL:
            if (!ASN1_INTEGER_get_int64(&bval, curr->i))
                goto_error("Failed to get the value of an ASN.1 INTEGER");

            bval &= 0x00000000FFFFFFFF;
            if (bval != 0) {
                if (*target.b != NULL) {
                    s_log_warn("Value already exists for tag 0x%08lx (%s); "
                            "not adding",
                            (long unsigned)tag, KM_Tag_toString((uint32_t)tag));
                    break;
                }

                *target.b = ASN1_NULL_new();
                if (*target.b == NULL)
                    goto_error("Failed allocate a new ASN.1 NULL");
            } else {
                s_log_warn("Not adding boolean value 0 to param list "
                        "(tag 0x%08lx - %s)",
                        (long unsigned)tag, KM_Tag_toString((uint32_t)tag));
            }
            break;

        case TARGET_INTEGER:
            if (*target.i != NULL) {
                s_log_warn("Value for INTEGER tag 0x%08lx (%s) already exists "
                        "with value 0x%08lx, freeing...",
                        (long unsigned) tag, KM_Tag_toString((uint32_t)tag),
                        (long unsigned)ASN1_INTEGER_get(*target.i)
                );
                ASN1_INTEGER_free(*target.i);
            }

            *target.i = ASN1_INTEGER_dup(curr->i);
            if (*target.i == NULL)
                goto_error("Failed to duplicate an ASN.1 INTEGER");
            break;

        case TARGET_INTEGER_SET:
            istmp = ASN1_INTEGER_dup(curr->i);
            if (istmp == NULL)
                goto_error("Failed to duplicate an ASN.1 INTEGER");

            if (*target.iset == NULL) {
                *target.iset = sk_ASN1_INTEGER_new_null();
                if (*target.iset == NULL)
                    goto_error("Failed to create a new ASN.1 INTEGER set");
            }

            {
                bool found = false;
                const int n_ints = sk_ASN1_INTEGER_num(*target.iset);
                for (int i = 0; i < n_ints; i++) {
                    const ASN1_INTEGER *curr =
                        sk_ASN1_INTEGER_value(*target.iset, i);
                    if (!ASN1_INTEGER_cmp(curr, istmp)) {
                        s_log_warn("Repeatable tag 0x%08lx (%s) "
                                "with value 0x%08lx already exists; "
                                "not adding",
                                (long unsigned)tag,
                                KM_Tag_toString((uint32_t)tag),
                                (long unsigned)ASN1_INTEGER_get(curr)
                        );
                        found = true;
                        break;
                    }
                }
                if (found)
                    break;
            }

            if (sk_ASN1_INTEGER_push(*target.iset, istmp) <= 0)
                goto_error("Failed to push an ASN.1 INTEGER to the set");

            break;

        case TARGET_OCTET_STRING:
            if (*target.str != NULL) {
                s_log_warn("Value for OCTET_STRING tag 0x%08lx (%s) "
                        "already exists; freeing...",
                        (long unsigned) tag, KM_Tag_toString((uint32_t)tag)
                );
                ASN1_OCTET_STRING_free(*target.str);
            }

            *target.str = ASN1_OCTET_STRING_dup(curr->b);
            if (*target.str == NULL)
                goto_error("Failed to duplicate an ASN.1 OCTET_STRING");
            break;
        }
    }

    *out_param_list = ret;
    return 0;

err:
    if (ret != NULL) {
        KM_PARAM_LIST_free(ret);
        ret = NULL;
    }

    *out_param_list = NULL;
    return 1;
}
