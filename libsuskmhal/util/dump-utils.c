#include "dump-utils.h"
#include "keymaster-types-c.h"
#include <core/math.h>
#include <openssl/asn1.h>

static void dump_u64_(KM_dump_log_proc_t log_proc,
        const char *field_name, const ASN1_INTEGER *u,
        uint8_t indent, bool hex);
void KM_dump_u64_hex(KM_dump_log_proc_t log_proc,
        const char *field_name, const ASN1_INTEGER *u,
        uint8_t indent)
{
    dump_u64_(log_proc, field_name, u, indent, true);
}
void KM_dump_u64(KM_dump_log_proc_t log_proc,
        const char *field_name, const ASN1_INTEGER *u,
        uint8_t indent)
{
    dump_u64_(log_proc, field_name, u, indent, false);
}

void KM_dump_param_list(KM_dump_log_proc_t log_proc, const KM_PARAM_LIST *ps,
        uint8_t indent, const char *field_name)
{
    ASN1_INTEGER *bool_val_1 = NULL;

    bool_val_1 = ASN1_INTEGER_new();
    if (bool_val_1 == NULL || !ASN1_INTEGER_set(bool_val_1, 1)) {
        log_proc("ERROR: Failed to prepare temporary ASN.1 INTEGER");
        goto out;
    }

    char indent_buf[1024];
    KM_DUMP_sprint_indent(indent_buf, indent);

    const uint8_t i = indent + 1;

    if (field_name == NULL) {
        log_proc("%s===== BEGIN KEY PARAMETER LIST DUMP =====", indent_buf);

        if (ps == NULL) {
            log_proc("%sKM_PARAM_LIST par = { /* empty */ };", indent_buf);
            goto out;
        }

        log_proc("KM_PARAM_LIST par = {");
    } else {
        if (ps == NULL) {
            log_proc("%s.%s = { /* empty */ };", indent_buf, field_name);
            goto out;
        }

        log_proc("%s.%s = {", indent_buf, field_name);
    }

    if (ps->purpose != NULL)
        KM_dump_enum_arr(log_proc, "purpose", ps->purpose,
                KM_KeyPurpose_toString, i);

    if (ps->algorithm != NULL)
        KM_dump_enum_val(log_proc, "algorithm", ps->algorithm,
                KM_Algorithm_toString, i);

    if (ps->keySize != NULL)
        KM_dump_u64(log_proc, "keySize", ps->keySize, i);

    if (ps->blockMode != NULL)
        KM_dump_enum_arr(log_proc, "blockMode", ps->blockMode,
                KM_BlockMode_toString, i);

    if (ps->digest != NULL)
        KM_dump_enum_arr(log_proc, "digest", ps->digest,
                KM_Digest_toString, i);

    if (ps->padding != NULL)
        KM_dump_enum_arr(log_proc, "padding", ps->padding,
                KM_PaddingMode_toString, i);

    if (ps->callerNonce != NULL)
        KM_dump_u64(log_proc, "callerNonce", bool_val_1, i);

    if (ps->minMacLength != NULL)
        KM_dump_u64(log_proc, "minMacLength", ps->minMacLength, i);

    if (ps->ecCurve != NULL)
        KM_dump_enum_val(log_proc, "ecCurve", ps->ecCurve,
                KM_EcCurve_toString, i);

    if (ps->rsaPublicExponent != NULL)
        KM_dump_u64_hex(log_proc, "rsaPublicExponent",
                ps->rsaPublicExponent, i);

    if (ps->includeUniqueId != NULL)
        KM_dump_u64(log_proc, "includeUniqueId", bool_val_1, i);

    if (ps->keyBlobUsageRequirements != NULL)
        KM_dump_enum_val(log_proc, "keyBlobUsageRequirements",
                ps->keyBlobUsageRequirements,
                KM_KeyBlobUsageRequirements_toString, i);

    if (ps->bootloaderOnly != NULL)
        KM_dump_u64(log_proc, "bootloaderOnly", bool_val_1, i);

    if (ps->rollbackResistance != NULL)
        KM_dump_u64(log_proc, "rollbackResistance", bool_val_1, i);

    if (ps->hardwareType != NULL)
        KM_dump_u64_hex(log_proc, "hardwareType", ps->hardwareType, i);

    if (ps->activeDateTime != NULL)
        KM_dump_datetime(log_proc, "activeDateTime", ps->activeDateTime, i);

    if (ps->originationExpireDateTime != NULL)
        KM_dump_datetime(log_proc, "originationExpireDateTime",
                ps->originationExpireDateTime, i);

    if (ps->usageExpireDateTime != NULL)
        KM_dump_datetime(log_proc, "usageExpireDateTime",
                ps->usageExpireDateTime, i);

    if (ps->minSecondsBetweenOps != NULL)
        KM_dump_u64(log_proc, "minSecondsBetweenOps",
                ps->minSecondsBetweenOps, i);

    if (ps->maxUsesPerBoot != NULL)
        KM_dump_u64(log_proc, "maxUsesPerBoot", ps->maxUsesPerBoot, i);

    if (ps->userId != NULL)
        KM_dump_u64(log_proc, "userId", ps->userId, i);

    if (ps->userSecureId != NULL)
        KM_dump_u64_arr(log_proc, "userSecureId", ps->userSecureId, i, false);

    if (ps->noAuthRequired != NULL)
        KM_dump_u64(log_proc, "noAuthRequired", bool_val_1, i);

    if (ps->userAuthType != NULL)
        KM_dump_u64_hex(log_proc, "userAuthType", ps->userAuthType, i);

    if (ps->authTimeout != NULL)
        KM_dump_u64(log_proc, "authTimeout", ps->authTimeout, i);

    if (ps->allowWhileOnBody != NULL)
        KM_dump_u64(log_proc, "allowWhileOnBody", bool_val_1, i);

    if (ps->trustedUserPresenceReq != NULL)
        KM_dump_u64(log_proc, "trustedUserPresenceReq", bool_val_1, i);

    if (ps->trustedConfirmationReq != NULL)
        KM_dump_u64(log_proc, "trustedConfirmationReq", bool_val_1, i);

    if (ps->unlockedDeviceReq != NULL)
        KM_dump_u64(log_proc, "unlockedDeviceReq", bool_val_1, i);

    if (ps->applicationId != NULL)
        KM_dump_hex(log_proc, "applicationId", ps->applicationId, i);

    if (ps->applicationData != NULL)
        KM_dump_hex(log_proc, "applicationData", ps->applicationData, i);

    if (ps->creationDateTime != NULL)
        KM_dump_datetime(log_proc, "creationDateTime", ps->creationDateTime, i);

    if (ps->keyOrigin != NULL)
        KM_dump_enum_val(log_proc, "keyOrigin", ps->keyOrigin,
                KM_KeyOrigin_toString, i);

    if (ps->rootOfTrust != NULL) {
        log_proc("%s" KM_DUMP_SINGLE_INDENT ".rootOfTrust = {", indent_buf);

        KM_dump_hex(log_proc, "verifiedBootKey",
            ps->rootOfTrust->verifiedBootKey, i + 1);

        log_proc("%s" KM_DUMP_SINGLE_INDENT KM_DUMP_SINGLE_INDENT
                ".deviceLocked = %d,", indent_buf,
                ps->rootOfTrust->deviceLocked);

        int64_t val = 0ULL;
        if (!ASN1_ENUMERATED_get_int64(&val,
                    ps->rootOfTrust->verifiedBootState))
        {
            log_proc("ERROR: Failed to get the value of the verifiedBootState "
                    "ASN.1 ENUMERATED field");
        } else {
            val &= 0x00000000FFFFFFFF;
            log_proc("%s" KM_DUMP_SINGLE_INDENT KM_DUMP_SINGLE_INDENT
                    ".%s = %lld, // %s", indent_buf,
                    field_name, (long long int)val,
                    KM_VerifiedBootState_toString((int)val)
            );
        }

        KM_dump_hex(log_proc, "verifiedBootHash",
                ps->rootOfTrust->verifiedBootHash, i + 1);

        log_proc("%s" KM_DUMP_SINGLE_INDENT "},", indent_buf);
    }

    if (ps->osVersion != NULL)
        KM_dump_u64(log_proc, "osVersion", ps->osVersion, i);

    if (ps->osPatchLevel != NULL)
        KM_dump_u64(log_proc, "osPatchLevel", ps->osPatchLevel, i);

    if (ps->uniqueId != NULL)
        KM_dump_hex(log_proc, "uniqueId", ps->uniqueId, i);

    if (ps->attestationChallenge != NULL)
        KM_dump_hex(log_proc, "attestationChallenge",
                ps->attestationChallenge, i);

    if (ps->attestationApplicationId != NULL)
        KM_dump_hex(log_proc, "attestationApplicationId",
                ps->attestationApplicationId, i);

    if (ps->attestationIdBrand != NULL)
        KM_dump_hex(log_proc, "attestationIdBrand", ps->attestationIdBrand, i);

    if (ps->attestationIdDevice != NULL)
        KM_dump_hex(log_proc, "attestationIdDevice",
                ps->attestationIdDevice, i);

    if (ps->attestationIdProduct != NULL)
        KM_dump_hex(log_proc, "attestationIdProduct",
                ps->attestationIdProduct, i);

    if (ps->attestationIdSerial != NULL)
        KM_dump_hex(log_proc, "attestationIdSerial",
                ps->attestationIdSerial, i);

    if (ps->attestationIdImei != NULL)
        KM_dump_hex(log_proc, "attestationIdImei", ps->attestationIdImei, i);

    if (ps->attestationIdMeid != NULL)
        KM_dump_hex(log_proc, "attestationIdMeid", ps->attestationIdMeid, i);

    if (ps->attestationIdManufacturer != NULL)
        KM_dump_hex(log_proc, "attestationIdManufacturer",
                ps->attestationIdManufacturer, i);

    if (ps->attestationIdModel != NULL)
        KM_dump_hex(log_proc, "attestationIdModel", ps->attestationIdModel, i);

    if (ps->vendorPatchLevel != NULL)
        KM_dump_u64(log_proc, "vendorPatchLevel", ps->vendorPatchLevel, i);

    if (ps->bootPatchLevel != NULL)
        KM_dump_u64(log_proc, "bootPatchLevel", ps->bootPatchLevel, i);

    if (ps->associatedData != NULL)
        KM_dump_hex(log_proc, "associatedData", ps->associatedData, i);

    if (ps->nonce != NULL)
        KM_dump_hex(log_proc, "nonce", ps->nonce, i);

    if (ps->macLength != NULL)
        KM_dump_u64(log_proc, "macLength", ps->macLength, i);

    if (ps->resetSinceIdRotation != NULL)
        KM_dump_u64(log_proc, "resetSinceIdRotation", bool_val_1, i);

    if (ps->confirmationToken != NULL)
        KM_dump_hex(log_proc, "confirmationToken", ps->confirmationToken, i);

    if (ps->authToken != NULL)
        KM_dump_hex(log_proc, "authToken", ps->authToken, i);

    if (ps->verificationToken != NULL)
        KM_dump_hex(log_proc, "verificationToken", ps->verificationToken, i);

    if (ps->allUsers != NULL)
        KM_dump_u64(log_proc, "allUsers", bool_val_1, i);

    if (ps->eciesSingleHashMode != NULL)
        KM_dump_u64(log_proc, "eciesSingleHashMode", bool_val_1, i);

    if (ps->kdf != NULL)
        KM_dump_enum_val(log_proc, "kdf",
                ps->kdf, KM_KeyDerivationFunction_toString, i);

    if (ps->exportable != NULL)
        KM_dump_u64(log_proc, "exportable", bool_val_1, i);

    if (ps->keyAuth != NULL)
        KM_dump_u64(log_proc, "keyAuth", bool_val_1, i);

    if (ps->opAuth != NULL)
        KM_dump_u64(log_proc, "opAuth", bool_val_1, i);

    if (ps->operationHandle != NULL)
        KM_dump_u64_hex(log_proc, "operationHandle", ps->operationHandle, i);

    if (ps->operationFailed != NULL)
        KM_dump_u64(log_proc, "operationFailed", bool_val_1, i);

    if (ps->internalCurrentDateTime != NULL)
        KM_dump_datetime(log_proc, "internalCurrentDateTime",
                ps->internalCurrentDateTime, i);

    if (ps->ekeyBlobIV != NULL)
        KM_dump_hex(log_proc, "ekeyBlobIV", ps->ekeyBlobIV, i);

    if (ps->ekeyBlobAuthTag != NULL)
        KM_dump_hex(log_proc, "ekeyBlobAuthTag", ps->ekeyBlobAuthTag, i);

    if (ps->ekeyBlobCurrentUsesPerBoot != NULL)
        KM_dump_u64(log_proc, "ekeyBlobCurrentUsesPerBoot",
                ps->ekeyBlobCurrentUsesPerBoot, i);

    if (ps->ekeyBlobLastOpTimestamp != NULL)
        KM_dump_u64(log_proc, "ekeyBlobLastOpTimestamp",
                ps->ekeyBlobLastOpTimestamp, i);

    if (ps->ekeyBlobDoUpgrade != NULL)
        KM_dump_u64(log_proc, "ekeyBlobDoUpgrade", ps->ekeyBlobDoUpgrade, i);

    if (ps->ekeyBlobPassword != NULL)
        KM_dump_hex(log_proc, "ekeyBlobPassword", ps->ekeyBlobPassword, i);

    if (ps->ekeyBlobSalt != NULL)
        KM_dump_hex(log_proc, "ekeyBlobSalt", ps->ekeyBlobSalt, i);

    if (ps->ekeyBlobEncVer != NULL)
        KM_dump_u64(log_proc, "ekeyBlobEncVer", ps->ekeyBlobEncVer, i);

    if (ps->ekeyBlobRaw != NULL)
        KM_dump_u64(log_proc, "ekeyBlobRaw", ps->ekeyBlobRaw, i);

    if (ps->ekeyBlobUniqKDM != NULL)
        KM_dump_hex(log_proc, "ekeyBlobUniqKDM", ps->ekeyBlobUniqKDM, i);

    if (ps->ekeyBlobIncUseCount != NULL)
        KM_dump_u64(log_proc, "ekeyBlobIncUseCount",
                ps->ekeyBlobIncUseCount, i);

    if (ps->samsungRequestingTA != NULL)
        KM_dump_hex(log_proc, "samsungRequestingTA",
                ps->samsungRequestingTA, i);

    if (ps->samsungRotRequired != NULL)
        KM_dump_u64(log_proc, "samsungRotRequired", bool_val_1, i);

    if (ps->samsungLegacyRot != NULL)
        KM_dump_u64(log_proc, "samsungLegacyRot", bool_val_1, i);

    if (ps->useSecureProcessor != NULL)
        KM_dump_u64(log_proc, "useSecureProcessor", bool_val_1, i);

    if (ps->storageKey != NULL)
        KM_dump_u64(log_proc, "storageKey", bool_val_1, i);

    if (ps->integrityStatus != NULL)
        KM_dump_u64_hex(log_proc, "integrityStatus", ps->integrityStatus, i);

    if (ps->isSamsungKey != NULL)
        KM_dump_u64(log_proc, "isSamsungKey", bool_val_1, i);

    if (ps->samsungAttestationRoot != NULL)
        KM_dump_hex(log_proc, "samsungAttestationRoot",
                ps->samsungAttestationRoot, i);

    if (ps->samsungAttestIntegrity != NULL)
        KM_dump_u64(log_proc, "samsungAttestIntegrity", bool_val_1, i);

    if (ps->knoxObjectProtectionRequired != NULL)
        KM_dump_u64(log_proc, "knoxObjectProtectionRequired", bool_val_1, i);

    if (ps->knoxCreatorId != NULL)
        KM_dump_hex(log_proc, "knoxCreatorId", ps->knoxCreatorId, i);

    if (ps->knoxAdministratorId != NULL)
        KM_dump_hex(log_proc, "knoxAdministratorId",
                ps->knoxAdministratorId, i);

    if (ps->knoxAccessorId != NULL)
        KM_dump_hex(log_proc, "knoxAccessorId", ps->knoxAccessorId, i);

    if (ps->samsungAuthPackage != NULL)
        KM_dump_hex(log_proc, "samsungAuthPackage", ps->samsungAuthPackage, i);

    if (ps->samsungCertificateSubject != NULL)
        KM_dump_hex(log_proc, "samsungCertificateSubject",
                ps->samsungCertificateSubject, i);

    if (ps->samsungKeyUsage != NULL)
        KM_dump_u64_hex(log_proc, "samsungKeyUsage", ps->samsungKeyUsage, i);

    if (ps->samsungExtendedKeyUsage != NULL)
        KM_dump_hex(log_proc, "samsungExtendedKeyUsage",
                ps->samsungExtendedKeyUsage, i);

    if (ps->samsungSubjectAlternativeName != NULL)
        KM_dump_hex(log_proc, "samsungSubjectAlternativeName",
                ps->samsungSubjectAlternativeName, i);

    if (ps->provGacEc1 != NULL)
        KM_dump_hex(log_proc, "provGacEc1", ps->provGacEc1, i);

    if (ps->provGacEc2 != NULL)
        KM_dump_hex(log_proc, "provGacEc2", ps->provGacEc2, i);

    if (ps->provGacEc3 != NULL)
        KM_dump_hex(log_proc, "provGacEc3", ps->provGacEc3, i);

    if (ps->provGakEc != NULL)
        KM_dump_hex(log_proc, "provGakEc", ps->provGakEc, i);

    if (ps->provGakEcVtoken != NULL)
        KM_dump_hex(log_proc, "provGakEcVtoken", ps->provGakEcVtoken, i);

    if (ps->provGacRsa1 != NULL)
        KM_dump_hex(log_proc, "provGacRsa1", ps->provGacRsa1, i);

    if (ps->provGacRsa2 != NULL)
        KM_dump_hex(log_proc, "provGacRsa2", ps->provGacRsa2, i);

    if (ps->provGacRsa3 != NULL)
        KM_dump_hex(log_proc, "provGacRsa3", ps->provGacRsa3, i);

    if (ps->provGakRsa != NULL)
        KM_dump_hex(log_proc, "provGakRsa", ps->provGakRsa, i);

    if (ps->provGakRsaVtoken != NULL)
        KM_dump_hex(log_proc, "provGakRsaVtoken", ps->provGakRsaVtoken, i);

    if (ps->provSakEc != NULL)
        KM_dump_hex(log_proc, "provSakEc", ps->provSakEc, i);

    if (ps->provSakEcVtoken != NULL)
        KM_dump_hex(log_proc, "provSakEcVtoken", ps->provSakEcVtoken, i);

    if (field_name == NULL) {
        log_proc("%s};", indent_buf);
        log_proc("%s=====  END KEY PARAMETER LIST DUMP  =====", indent_buf);
    } else {
        log_proc("%s},", indent_buf);
    }

out:
    if (bool_val_1 != NULL) {
        ASN1_INTEGER_free(bool_val_1);
        bool_val_1 = NULL;
    }
    return;
}

void KM_dump_hex(KM_dump_log_proc_t log_proc, const char *field_name,
        const ASN1_OCTET_STRING *data_, uint8_t indent)
{
    char indent_buf[1024];
    KM_DUMP_sprint_indent(indent_buf, indent);

    int total_sz = 0;
    if (data_ == NULL || (total_sz = ASN1_STRING_length(data_)) <= 0) {
        log_proc("%s.%s = { /* (empty) */ },", indent_buf, field_name);
        return;
    }
    const unsigned char *data = ASN1_STRING_get0_data(data_);

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
        KM_sprint_hex_line(line_buf, LINE_BUF_SIZE, data, remainder, true);
        line_buf[LINE_BUF_SIZE - 1] = '\0';
        log_proc("%s.%s = { %s },", indent_buf, field_name, line_buf);
        return;
    }

    log_proc("%s.%s = {", indent_buf, field_name);

    KM_sprint_hex_line(line_buf, LINE_BUF_SIZE, data, LINE_LEN, false);
    line_buf[LINE_BUF_SIZE - 1] = '\0';
    log_proc("%s" KM_DUMP_SINGLE_INDENT "%s", indent_buf, line_buf);

    for (u32 i = 1; i < n_lines; i++) {
        memset(line_buf, 0, LINE_BUF_SIZE);
        KM_sprint_hex_line(line_buf, LINE_BUF_SIZE,
                data + (i * LINE_LEN),
                LINE_LEN, false
        );
        line_buf[LINE_BUF_SIZE - 1] = '\0';
        log_proc("%s" KM_DUMP_SINGLE_INDENT "%s", indent_buf, line_buf);
    }

    memset(line_buf, 0, LINE_BUF_SIZE);
    KM_sprint_hex_line(line_buf, LINE_BUF_SIZE,
            data + (n_lines * LINE_LEN),
            remainder, true
    );
    line_buf[LINE_BUF_SIZE - 1] = '\0';
    log_proc("%s" KM_DUMP_SINGLE_INDENT "%s", indent_buf, line_buf);
    log_proc("%s},", indent_buf);

#undef LINE_LEN
}

void KM_sprint_hex_line(char *buf, u32 buf_size,
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

static void dump_u64_(KM_dump_log_proc_t log_proc,
        const char *field_name, const ASN1_INTEGER *a,
        uint8_t indent, bool hex)
{
    uint64_t u = 0;
    if (ASN1_INTEGER_get_uint64(&u, a) == 0) {
        log_proc("[%s] ERROR: Couldn't get the value "
                "of an ASN.1 INTEGER (as uint64_t)", field_name);
        return;
    }

    {
        char indent_buf[1024];
        KM_DUMP_sprint_indent(indent_buf, indent);

        if (hex)
            log_proc("%s.%s = 0x%llx,",
                    indent_buf, field_name, (unsigned long long)u);
        else
            log_proc("%s.%s = %llu,",
                    indent_buf, field_name, (unsigned long long)u);
    }
}

void KM_dump_u64_arr(KM_dump_log_proc_t log_proc,
        const char *field_name, const ASN1_SET_OF_INTEGER *arr,
        uint8_t indent, bool hex)
{
    char indent_buf[1024];
    char tmp_buf[1024] = { 0 };
    u32 write_index = 0;
    int arr_size = 0;
    const char *const fmt = hex ? "0x%016llx, " : "%llu, ";

    KM_DUMP_sprint_indent(indent_buf, indent);

    if (arr == NULL || (arr_size = sk_ASN1_INTEGER_num(arr)) <= 0) {
        log_proc("%s.%s = { /* (empty) */ },", indent_buf, field_name);
        return;
    }


    {
        const ASN1_INTEGER *curr = NULL;
        uint64_t u = 0;
        int r = 0;

        for (int i = 0; i < arr_size - 1; i++) {
            curr = sk_ASN1_INTEGER_value(arr, i);
            if (ASN1_INTEGER_get_uint64(&u, curr) == 0) {
                log_proc("[%s] ERROR: Couldn't get the value "
                        "of an ASN.1 INTEGER (as uint64_t) @ idx %i",
                        field_name, i);
                return;
            }

            r = snprintf(tmp_buf + write_index, 256 - write_index - 1,
                    fmt, (unsigned long long)u);
            if (r <= 0 || r >= 256) {
                log_proc("[%s] ERROR: Invalid return value of snprintf "
                        "(@ idx %d): %d", field_name, i, r);
                return;
            }

            write_index += r;
        }

        curr = sk_ASN1_INTEGER_value(arr, arr_size - 1);
        if (ASN1_INTEGER_get_uint64(&u, curr) == 0) {
            log_proc("[%s] ERROR: Couldn't get the value "
                    "of an ASN.1 INTEGER (as uint64_t) @ idx %i",
                    field_name, arr_size - 1);
            return;
        }
        r = snprintf(tmp_buf + write_index, 256 - write_index - 1,
                fmt, (unsigned long long)u);
        if (r <= 0 || r >= 256) {
            log_proc("[%s] ERROR: Invalid return value of snprintf "
                    "(@ idx %d): %d", field_name, arr_size - 1, r);
            return;
        }
    }

    log_proc("%s.%s = { %s },", indent_buf, field_name, tmp_buf);
}

void KM_dump_enum_val(KM_dump_log_proc_t log_proc,
        const char *field_name, const ASN1_INTEGER *e,
        KM_enum_toString_proc_t get_str_proc, uint8_t indent)
{
    char indent_buf[1024];
    KM_DUMP_sprint_indent(indent_buf, indent);

    const int i = ASN1_INTEGER_get(e);

    log_proc("%s.%s = %d, // %s", indent_buf, field_name,
            i, get_str_proc(i));
}

void KM_dump_enum_arr(KM_dump_log_proc_t log_proc,
        const char *field_name,
        const ASN1_SET_OF_INTEGER *arr, KM_enum_toString_proc_t get_str_proc,
        uint8_t indent)
{
    int arr_size = 0;
    char indent_buf[1024];
    KM_DUMP_sprint_indent(indent_buf, indent);

    if (arr == NULL || (arr_size = sk_ASN1_INTEGER_num(arr)) <= 0) {
        log_proc("%s.%s = { /* (empty) */ },", indent_buf, field_name);
        return;
    }

    log_proc("%s.%s = {", indent_buf, field_name);

    for (int i = 0; i < arr_size - 1; i++) {
        int64_t val = 0;
        if (ASN1_INTEGER_get_int64(&val, sk_ASN1_INTEGER_value(arr, i)) == 0) {
            log_proc("[%s] ERROR: Couldn't get the value of an ASN.1 INTEGER "
                    "(as int64_t) @ idx %i", field_name, i);
            return;
        }
        val &= 0x00000000FFFFFFFF;

        log_proc(KM_DUMP_SINGLE_INDENT "%s.%s = %lld, // %s",
                indent_buf, field_name,
                (long long int)val, get_str_proc((int)val)
        );
    }

    {
        int64_t val = 0;
        if (ASN1_INTEGER_get_int64(&val,
                    sk_ASN1_INTEGER_value(arr, arr_size - 1)) == 0)
        {
            log_proc("[%s] ERROR: Couldn't get the value of an ASN.1 INTEGER "
                    "(as int64_t) @ idx %i", field_name, arr_size - 1);
            return;
        }
        val &= 0x00000000FFFFFFFF;
        log_proc(KM_DUMP_SINGLE_INDENT "%s.%s = %lld // %s",
                indent_buf, field_name,
                (long long int)val, get_str_proc((int)val)
        );
    }

    log_proc("%s},", indent_buf);
}

void KM_dump_datetime(KM_dump_log_proc_t log_proc,
        const char *field_name, const ASN1_INTEGER *d,
        uint8_t indent)
{
    char indent_buf[1024];
    char datetime_buf[256] = { 0 };
    int64_t i = 0;

    KM_DUMP_sprint_indent(indent_buf, indent);

    if (ASN1_INTEGER_get_int64(&i, d) == 0) {
        log_proc("[%s] ERROR: Couldn't get the value of an ASN.1 INTEGER "
                "(as int64_t)", field_name);
        return;
    }

    KM_datetime_to_str(datetime_buf, sizeof(datetime_buf), i);
    log_proc("%s.%s = %lld, // %s", indent_buf, field_name,
            (long long int)i, datetime_buf);
}

int portable_localtime(const time_t *timep, struct tm *result)
{
#ifdef _WIN32
    return localtime_s(result, timep);
#else
    return localtime_r(timep, result) ? 0 : -1;
#endif
}
void KM_datetime_to_str(char *buf, u32 buf_size, int64_t dt)
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
