#include <cstdlib>
#include <openssl/crypto.h>
#define HIDL_DISABLE_INSTRUMENTATION
#include "cli.hpp"
#include <core/log.h>
#include <core/math.h>
#include <core/util.h>
#include <libsuskmhal/keymaster-types-c.h>
#include <android/hardware/keymaster/4.0/types.h>
#include <string.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <unordered_map>

#define MODULE_NAME "samsung-utils"

namespace suskeymaster {
namespace cli {
namespace samsung {

namespace ekey {

using namespace kmhal;

static void dump_param_list(const KM_PARAM_LIST_SEQ *ps);

#define INDENT_WIDTH 4
#define INDENT_CHAR ' '
#define SINGLE_INDENT "    "
#define sprint_indent(buf, n) do {                          \
    static_assert(sizeof((buf)) > INDENT_WIDTH * UINT8_MAX, \
            "Indentation buffer too small");                \
    memset((buf), INDENT_CHAR, INDENT_WIDTH * (n));         \
    (buf)[INDENT_WIDTH * (n)] = '\0';                       \
} while (0)

static void dump_hex_line(char *buf, u32 buf_size,
        const u8 *data, u32 data_size, bool end_without_comma);

static void dump_hex(const char *field_name,
        const ASN1_OCTET_STRING *data, uint8_t n_indent);
static void dump_hex(const char *field_name, const ASN1_OCTET_STRING *data)
{
    return dump_hex(field_name, data, 1);
}

#define DUMP_U64_HEX true
static void dump_u64(const char *field_name, const ASN1_INTEGER *u,
        uint8_t indent, bool hex);
static void dump_u64(const char *field_name, const ASN1_INTEGER *u, bool hex)
{
    dump_u64(field_name, u, 1, hex);
}
static void dump_u64(const char *field_name, const ASN1_INTEGER *u)
{
    dump_u64(field_name, u, 1, false);
}

static void dump_u64_arr(const char *field_name, const ASN1_SET_OF_INTEGER *arr,
        uint8_t indent, bool hex);

static void dump_enum_val(const char *field_name, const ASN1_INTEGER *e,
        KM_enum_toString_proc_t get_str_proc, uint8_t indent);
static void dump_enum_val(const char *field_name, const ASN1_INTEGER *e,
        KM_enum_toString_proc_t get_str_proc)
{
    dump_enum_val(field_name, e, get_str_proc, 1);
}

static void dump_enum_arr(const char *field_name,
        const ASN1_SET_OF_INTEGER *arr, KM_enum_toString_proc_t get_str_proc,
        uint8_t indent);
static void dump_enum_arr(const char *field_name,
        const ASN1_SET_OF_INTEGER *arr, KM_enum_toString_proc_t get_str_proc)
{
    dump_enum_arr(field_name, arr, get_str_proc, 1);
}

static void dump_datetime(const char *field_name, const ASN1_INTEGER *d,
        uint8_t indent);
static void dump_datetime(const char *field_name, const ASN1_INTEGER *d)
{
    dump_datetime(field_name, d, 1);
}

static void datetime_to_str(char *buf, u32 buf_size, int64_t dt);

static int deserialize_ekey_blob_and_params(const hidl_vec<uint8_t>& ekey,
        KM_SAMSUNG_EKEY_BLOB *& out, hidl_vec<KM_SAMSUNG_PARAM *> *out_opt_par);
static int serialize_ekey_blob(KM_SAMSUNG_EKEY_BLOB *& ekey,
        hidl_vec<uint8_t>& out_ekey_der);

static int ekey_params_to_param_list(const hidl_vec<KM_SAMSUNG_PARAM *>& ekey_params,
        KM_PARAM_LIST_SEQ **out_param_list);

int list_tags(const hidl_vec<uint8_t> &in_keyblob)
{
    int ret = -1;

    KM_SAMSUNG_EKEY_BLOB *ekey = NULL;
    hidl_vec<KM_SAMSUNG_PARAM *> ekey_params;

    KM_PARAM_LIST_SEQ *param_list = NULL;

    if (deserialize_ekey_blob_and_params(in_keyblob, ekey, &ekey_params))
        goto_error("Failed to deserialize the encrypted key blob!");

    if (ekey_params_to_param_list(ekey_params, &param_list))
        goto_error("Failed to parse the key blob parameters!");

    dump_param_list(param_list);
    ret = 0;

err:
    if (param_list != NULL) {
        KM_PARAM_LIST_SEQ_free(param_list);
        param_list = NULL;
    }

    for (size_t i = 0; i < ekey_params.size(); i++) {
        KM_SAMSUNG_PARAM_free(ekey_params[i]);
        ekey_params[i] = NULL;
    }
    if (ekey != NULL) {
        KM_SAMSUNG_EKEY_BLOB_free(ekey);
        ekey = NULL;
    }

    return ret;
}

static bool is_repeatable(int64_t tag)
{
    const TagType tt = static_cast<TagType>(__KM_TAG_TYPE_MASK(tag));
    return (tt == TagType::UINT_REP)
        || (tt == TagType::ENUM_REP)
        || (tt == TagType::ULONG_REP);
}

static bool is_integer_param(int64_t tag)
{
    const TagType tt = static_cast<TagType>(__KM_TAG_TYPE_MASK(tag));
    return (tt != TagType::BYTES && tt != TagType::BIGNUM);
}

static int make_integer_param(KM_SAMSUNG_PARAM **out_par,
        Tag tag, int64_t val)
{
    *out_par = NULL;

    KM_SAMSUNG_PARAM *p = KM_SAMSUNG_PARAM_new();
    if (p == NULL) {
        s_log_error("Couldn't allocate a new samsung key parameter");
        return 1;
    }

    if (!ASN1_INTEGER_set(p->tag, static_cast<int>(tag))) {
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

    if (!ASN1_INTEGER_set(p->i, val)) {
        s_log_error("Couldn't set the value of an ASN.1 INTEGER");
        KM_SAMSUNG_PARAM_free(p);
        return 1;
    }

    *out_par = p;
    return 0;
}

static int make_octet_string_param(KM_SAMSUNG_PARAM **out_par,
        Tag tag, hidl_vec<uint8_t> const& val)
{
    *out_par = NULL;

    KM_SAMSUNG_PARAM *p = KM_SAMSUNG_PARAM_new();
    if (p == NULL) {
        s_log_error("Couldn't allocate a new samsung key parameter");
        return 1;
    }

    if (!ASN1_INTEGER_set(p->tag, static_cast<int>(tag))) {
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

    if (!ASN1_OCTET_STRING_set(p->b, val.data(), val.size())) {
        s_log_error("Couldn't set the value of an ASN.1 OCTET_STRING");
        KM_SAMSUNG_PARAM_free(p);
        return 1;
    }

    *out_par = p;
    return 0;
}

static int push_param(STACK_OF(KM_SAMSUNG_PARAM) *paramset,
        KM_SAMSUNG_PARAM *par)
{
    if (sk_KM_SAMSUNG_PARAM_push(paramset, par) <= 0) {
        s_log_error("Failed to push a key parameter to the set");
        return 1;
    }

    return 0;
}

int add_tags(const hidl_vec<uint8_t> &in_keyblob,
        const hidl_vec<KeyParameter> &in_tags_to_add, hidl_vec<uint8_t> &out_keyblob)
{
    int ret = 1;
    KM_SAMSUNG_PARAM * curr = NULL;

    KM_SAMSUNG_EKEY_BLOB *ekey = NULL;
    hidl_vec<KM_SAMSUNG_PARAM *> blob_params;
    std::unordered_map<int64_t, std::vector<KM_SAMSUNG_PARAM *>> blob_params_map;

    if (deserialize_ekey_blob_and_params(in_keyblob, ekey, &blob_params))
        goto_error("Couldn't deserialize the encrypted key blob");

    for (uint32_t i = 0; i < blob_params.size(); i++) {
        KM_SAMSUNG_PARAM *par = blob_params[i];

        int64_t t = 0;
        if (!ASN1_INTEGER_get_int64(&t, par->tag))
            goto_error("Couldn't get the value of an ASN.1 INTEGER");
        t &= 0x00000000FFFFFFFF;

        blob_params_map[t].push_back(par);
    }

    for (const auto& kp : in_tags_to_add) {
        const int64_t t = static_cast<int64_t>(kp.tag);

        const auto& found = blob_params_map.find(t);
        const bool exists = found != blob_params_map.end()
            && found->second.size() > 0;

        if (exists) {
            if (is_repeatable(t)) {
                bool skip_adding = false;
                for (const KM_SAMSUNG_PARAM *curr : found->second) {
                    int64_t val = 0;
                    /* repeatable also means it's not an OCTET_STRING */
                    if (!ASN1_INTEGER_get_int64(&val, curr->i))
                        goto_error("Couldn't get the value of an ASN.1 INTEGER");
                    val &= 0x00000000FFFFFFFF;

                    if (val == static_cast<int64_t>(kp.f.longInteger)) {
                        skip_adding = true;
                        break;
                    }
                }

                if (!skip_adding) {
                    KM_SAMSUNG_PARAM *new_par = NULL;
                    s_log_info("Repeatable tag 0x%08lx (%s): adding value: 0x%016llx",
                            (long unsigned)kp.tag, KM_Tag_toString((uint32_t)kp.tag),
                            (long long unsigned)kp.f.longInteger);

                    if (make_integer_param(&new_par, kp.tag, kp.f.longInteger))
                        goto err;

                    if (push_param(ekey->enc_par, new_par))
                        goto err;
                } else {
                    s_log_warn("Repeatable tag 0x%08lx (%s) with value 0x%016llx "
                            "already exists; not adding",
                            (long unsigned)kp.tag, KM_Tag_toString((uint32_t)kp.tag),
                            (long long unsigned)kp.f.longInteger);
                }
            } else {
                KM_SAMSUNG_PARAM *p = found->second[0];
                if (is_integer_param(t)) {
                    s_log_info("Tag 0x%08lx (%s): changing integer value: 0x%016llx",
                            (long unsigned)kp.tag, KM_Tag_toString((uint32_t)kp.tag),
                            (long long unsigned)kp.f.longInteger);

                    if (!ASN1_INTEGER_set_int64(p->i, kp.f.longInteger))
                        goto_error("Failed to set the value of an ASN.1 INTEGER");
                } else {
                    s_log_info("Tag 0x%08lx (%s): changing octet string value...",
                            (long unsigned)kp.tag, KM_Tag_toString((uint32_t)kp.tag));

                    if (!ASN1_OCTET_STRING_set(p->b, kp.blob.data(), kp.blob.size()))
                        goto_error("Failed to set the value of an ASN.1 OCTET_STRING");
                }
            }
        } else {
            KM_SAMSUNG_PARAM *new_par = NULL;

            if (is_integer_param(t)) {
                s_log_info("Adding tag 0x%08lx (%s) with integer value: 0x%016llx",
                        (long unsigned)kp.tag, KM_Tag_toString((uint32_t)kp.tag),
                        (long long unsigned)kp.f.longInteger);

                if (make_integer_param(&new_par, kp.tag, kp.f.longInteger))
                    goto err;
            } else {
                s_log_info("Adding tag 0x%08lx (%s) with octet string value...",
                        (long unsigned)kp.tag, KM_Tag_toString((uint32_t)kp.tag));

                if (make_octet_string_param(&new_par, kp.tag, kp.blob))
                    goto err;
            }

            if (push_param(ekey->enc_par, new_par))
                goto err;
        }
    }

    if (serialize_ekey_blob(ekey, out_keyblob))
        goto_error("Couldn't serialize the new encrypted key blob!");

    s_log_info("Successfully serialized new encrypted key blob");

    ret = 0;

err:
    if (curr != NULL) {
        KM_SAMSUNG_PARAM_free(curr);
        curr = NULL;
    }

    for (KM_SAMSUNG_PARAM *&par : blob_params) {
        KM_SAMSUNG_PARAM_free(par);
        par = NULL;
    }

    if (ekey != NULL) {
        KM_SAMSUNG_EKEY_BLOB_free(ekey);
        ekey = NULL;
    }

    return ret;
}

static int km_tag_cmp(KeyParameter const& kp, KM_SAMSUNG_PARAM *p)
{
    if (p == NULL)
        return 1;

    int64_t pt;
    if (!ASN1_INTEGER_get_int64(&pt, p->tag)) {
        s_log_error("%s: Couldn't get the tag value for p", __func__);
        return -1;
    }
    pt &= 0x00000000FFFFFFFF;

    if (kp.tag == static_cast<Tag>(pt)) {
        if (!is_repeatable(pt))
            return 0;

        if (is_integer_param(pt)) {
            if (p->i == NULL)
                return 1;

            return kp.f.longInteger - ASN1_INTEGER_get(p->i);
        } else {
            if (p->b == NULL ||
                    kp.blob.data() == NULL || ASN1_STRING_get0_data(p->b) == NULL)
                return 1;

            const size_t s = std::min(
                    kp.blob.size(),
                    static_cast<size_t>(std::max(0, ASN1_STRING_length(p->b)))
            );
            return memcmp(kp.blob.data(), ASN1_STRING_get0_data(p->b), s);
        }
    }

    return static_cast<int>(kp.tag) - pt;
}

int del_tags(const hidl_vec<uint8_t> &in_keyblob,
        const hidl_vec<KeyParameter> &in_tags_to_del, hidl_vec<uint8_t> &out_keyblob)
{
    KM_SAMSUNG_EKEY_BLOB *ekey = NULL;
    int ret = 1;

    if (deserialize_ekey_blob_and_params(in_keyblob, ekey, nullptr))
        goto_error("Failed to deserialize the encrypted key blob");

    for (const auto& kp : in_tags_to_del) {
        bool found = false;
        for (int i = sk_KM_SAMSUNG_PARAM_num(ekey->enc_par) - 1; i >= 0; i--) {
            KM_SAMSUNG_PARAM *p =
                sk_KM_SAMSUNG_PARAM_value(ekey->enc_par, i);
            if (p == NULL)
                goto_error("Couldn't get the value of an encryption parameter");

            const int64_t t = static_cast<int64_t>(kp.tag);
            if (!km_tag_cmp(kp, p)) {
                if (is_integer_param(t)) {
                    uint64_t v;
                    if (!ASN1_INTEGER_get_uint64(&v, p->i))
                        goto_error("Couldn't get the value "
                                "of an ASN.1 INTEGER");

                    s_log_info("Deleting tag 0x%08lx (%s) "
                            "(with INTEGER value 0x%llx)...",
                            (long unsigned)t, KM_Tag_toString((uint32_t)t),
                            (long long unsigned)v
                    );
                } else {
                    s_log_info("Deleting tag 0x%08lx (%s) "
                            "(with OCTET_STRING value)...",
                            (long unsigned)t, KM_Tag_toString((uint32_t)t)
                    );
                }

                KM_SAMSUNG_PARAM *const removed =
                    sk_KM_SAMSUNG_PARAM_delete(ekey->enc_par, i);
                if (removed == NULL)
                    goto_error("Failed to delete tag @ idx %i", i);
                KM_SAMSUNG_PARAM_free(removed);

                found = true;
                break;
            }
        }
        if (!found) {
            const int64_t t = static_cast<int64_t>(kp.tag);
            if (is_repeatable(t)) {
                s_log_warn("No repeatable tag 0x%08lx (%s) "
                        "with the value 0x%08lx was found!",
                        (long unsigned)t, KM_Tag_toString((uint32_t)kp.tag),
                       (long unsigned)kp.f.longInteger);
            } else {
                s_log_warn("No tag 0x%08lx (%s) was found!",
                        (long unsigned)t, KM_Tag_toString((uint32_t)t));
            }
        }
    }

    if (serialize_ekey_blob(ekey, out_keyblob))
        goto_error("Failed to serialize the new encrypted key blob");

    s_log_info("Successfully serialized new encrypted key blob");
    ret = EXIT_SUCCESS;

err:
    if (ekey != NULL) {
        KM_SAMSUNG_EKEY_BLOB_free(ekey);
        ekey = NULL;
    }

    return ret;
}

static void dump_param_list(const KM_PARAM_LIST_SEQ *ps)
{
    const char *old_line = NULL;
    s_configure_log_line(S_LOG_INFO, "%s\n", &old_line);

    s_log_info("===== BEGIN KEY PARAMETER LIST DUMP =====");

    if (ps == NULL) {
        s_log_info("KM_PARAM_LIST_SEQ par = { /* empty */ };");
        goto restore_log_and_out;
    }

    s_log_info("KM_PARAM_SET_SEQ par = {");

    if (ps->purpose != NULL)
        dump_enum_arr("purpose", ps->purpose, KM_KeyPurpose_toString);

    if (ps->algorithm != NULL)
        dump_enum_val("algorithm", ps->algorithm, KM_Algorithm_toString);

    if (ps->keySize != NULL)
        dump_u64("keySize", ps->keySize, false);

    if (ps->blockMode != NULL)
        dump_enum_arr("blockMode", ps->blockMode, KM_BlockMode_toString);

    if (ps->digest != NULL)
        dump_enum_arr("digest", ps->digest, KM_Digest_toString);

    if (ps->padding != NULL)
        dump_enum_arr("padding", ps->padding, KM_PaddingMode_toString);

    if (ps->callerNonce != NULL)
        s_log_info(SINGLE_INDENT ".callerNonce = 1,");

    if (ps->minMacLength != NULL)
        dump_u64("minMacLength", ps->minMacLength);

    if (ps->ecCurve != NULL)
        dump_enum_val("ecCurve", ps->ecCurve, KM_EcCurve_toString);

    if (ps->rsaPublicExponent != NULL)
        dump_u64("rsaPublicExponent", ps->rsaPublicExponent, DUMP_U64_HEX);

    if (ps->includeUniqueId != NULL)
        s_log_info(SINGLE_INDENT ".includeUniqueId = 1,");

    if (ps->keyBlobUsageRequirements != NULL)
        dump_enum_val("keyBlobUsageRequirements", ps->keyBlobUsageRequirements,
                KM_KeyBlobUsageRequirements_toString);

    if (ps->bootloaderOnly != NULL)
        s_log_info(SINGLE_INDENT ".bootloaderOnly = 1,");

    if (ps->rollbackResistance != NULL)
        s_log_info(SINGLE_INDENT ".rollbackResistance = 1,");

    if (ps->hardwareType != NULL)
        dump_u64("hardwareType", ps->hardwareType, DUMP_U64_HEX);

    if (ps->activeDateTime != NULL)
        dump_datetime("activeDateTime", ps->activeDateTime);

    if (ps->originationExpireDateTime != NULL)
        dump_datetime("originationExpireDateTime",
                ps->originationExpireDateTime);

    if (ps->usageExpireDateTime != NULL)
        dump_datetime("usageExpireDateTime", ps->usageExpireDateTime);

    if (ps->minSecondsBetweenOps != NULL)
        dump_u64("minSecondsBetweenOps", ps->minSecondsBetweenOps);

    if (ps->maxUsesPerBoot != NULL)
        dump_u64("maxUsesPerBoot", ps->maxUsesPerBoot);

    if (ps->userId != NULL)
        dump_u64("userId", ps->userId);

    if (ps->userSecureId != NULL)
        dump_u64_arr("userSecureId", ps->userSecureId, 1, false);

    if (ps->noAuthRequired != NULL)
        s_log_info(SINGLE_INDENT ".noAuthRequired = 1,");

    if (ps->userAuthType != NULL)
        dump_u64("userAuthType", ps->userAuthType, DUMP_U64_HEX);

    if (ps->authTimeout != NULL)
        dump_u64("authTimeout", ps->authTimeout);

    if (ps->allowWhileOnBody != NULL)
        s_log_info(SINGLE_INDENT ".allowWhileOnBody = 1,");

    if (ps->trustedUserPresenceReq != NULL)
        s_log_info(SINGLE_INDENT ".trustedUserPresenceReq = 1,");

    if (ps->trustedConfirmationReq != NULL)
        s_log_info(SINGLE_INDENT ".trustedConfirmationReq = 1,");

    if (ps->unlockedDeviceReq != NULL)
        s_log_info(SINGLE_INDENT ".unlockedDeviceReq = 1,");

    if (ps->applicationId != NULL)
        dump_hex("applicationId", ps->applicationId);

    if (ps->applicationData != NULL)
        dump_hex("applicationData", ps->applicationData);

    if (ps->creationDateTime != NULL)
        dump_datetime("creationDateTime", ps->creationDateTime);

    if (ps->keyOrigin != NULL)
        dump_enum_val("keyOrigin", ps->keyOrigin, KM_KeyOrigin_toString);

    if (ps->rootOfTrust != NULL) {
        s_log_info(SINGLE_INDENT ".rootOfTrust = {");
        dump_hex("verifiedBootKey", ps->rootOfTrust->verifiedBootKey, 2);
        s_log_info(SINGLE_INDENT "    .deviceLocked = %d,",
                ps->rootOfTrust->deviceLocked);
        dump_enum_val("verifiedBootState", ps->rootOfTrust->verifiedBootState,
                KM_VerifiedBootState_toString);
        dump_hex("verifiedBootHash", ps->rootOfTrust->verifiedBootHash, 2);
        s_log_info(SINGLE_INDENT "},");
    }

    if (ps->osVersion != NULL)
        dump_u64("osVersion", ps->osVersion);

    if (ps->osPatchLevel != NULL)
        dump_u64("osPatchLevel", ps->osPatchLevel);

    if (ps->uniqueId != NULL)
        dump_hex("uniqueId", ps->uniqueId);

    if (ps->attestationChallenge != NULL)
        dump_hex("attestationChallenge", ps->attestationChallenge);

    if (ps->attestationApplicationId != NULL)
        dump_hex("attestationApplicationId", ps->attestationApplicationId);

    if (ps->attestationIdBrand != NULL)
        dump_hex("attestationIdBrand", ps->attestationIdBrand);

    if (ps->attestationIdDevice != NULL)
        dump_hex("attestationIdDevice", ps->attestationIdDevice);

    if (ps->attestationIdProduct != NULL)
        dump_hex("attestationIdProduct", ps->attestationIdProduct);

    if (ps->attestationIdSerial != NULL)
        dump_hex("attestationIdSerial", ps->attestationIdSerial);

    if (ps->attestationIdImei != NULL)
        dump_hex("attestationIdImei", ps->attestationIdImei);

    if (ps->attestationIdMeid != NULL)
        dump_hex("attestationIdMeid", ps->attestationIdMeid);

    if (ps->attestationIdManufacturer != NULL)
        dump_hex("attestationIdManufacturer", ps->attestationIdManufacturer);

    if (ps->attestationIdModel != NULL)
        dump_hex("attestationIdModel", ps->attestationIdModel);

    if (ps->vendorPatchLevel != NULL)
        dump_u64("vendorPatchLevel", ps->vendorPatchLevel);

    if (ps->bootPatchLevel != NULL)
        dump_u64("bootPatchLevel", ps->bootPatchLevel);

    if (ps->associatedData != NULL)
        dump_hex("associatedData", ps->associatedData);

    if (ps->nonce != NULL)
        dump_hex("nonce", ps->nonce);

    if (ps->macLength != NULL)
        dump_u64("macLength", ps->macLength);

    if (ps->resetSinceIdRotation != NULL)
        s_log_info(SINGLE_INDENT ".resetSinceIdRotation = 1,");

    if (ps->confirmationToken != NULL)
        dump_hex("confirmationToken", ps->confirmationToken);

    if (ps->authToken != NULL)
        dump_hex("authToken", ps->authToken);

    if (ps->verificationToken != NULL)
        dump_hex("verificationToken", ps->verificationToken);

    if (ps->allUsers != NULL)
        s_log_info(SINGLE_INDENT ".allUsers = 1,");

    if (ps->eciesSingleHashMode != NULL)
        s_log_info(SINGLE_INDENT ".eciesSingleHashMode = 1,");

    if (ps->kdf != NULL)
        dump_enum_val("kdf", ps->kdf, KM_KeyDerivationFunction_toString);

    if (ps->exportable != NULL)
        s_log_info(SINGLE_INDENT ".exportable = 1,");

    if (ps->keyAuth != NULL)
        s_log_info(SINGLE_INDENT ".keyAuth = 1,");

    if (ps->opAuth != NULL)
        s_log_info(SINGLE_INDENT ".opAuth = 1,");

    if (ps->operationHandle != NULL)
        dump_u64("operationHandle", ps->operationHandle, DUMP_U64_HEX);

    if (ps->operationFailed != NULL)
        s_log_info(SINGLE_INDENT ".operationFailed = 1,");

    if (ps->internalCurrentDateTime != NULL)
        dump_datetime("internalCurrentDateTime", ps->internalCurrentDateTime);

    if (ps->ekeyBlobIV != NULL)
        dump_hex("ekeyBlobIV", ps->ekeyBlobIV);

    if (ps->ekeyBlobAuthTag != NULL)
        dump_hex("ekeyBlobAuthTag", ps->ekeyBlobAuthTag);

    if (ps->ekeyBlobCurrentUsesPerBoot != NULL)
        dump_u64("ekeyBlobCurrentUsesPerBoot", ps->ekeyBlobCurrentUsesPerBoot);

    if (ps->ekeyBlobLastOpTimestamp != NULL)
        dump_u64("ekeyBlobLastOpTimestamp", ps->ekeyBlobLastOpTimestamp);

    if (ps->ekeyBlobDoUpgrade != NULL)
        dump_u64("ekeyBlobDoUpgrade", ps->ekeyBlobDoUpgrade);

    if (ps->ekeyBlobPassword != NULL)
        dump_hex("ekeyBlobPassword", ps->ekeyBlobPassword);

    if (ps->ekeyBlobSalt != NULL)
        dump_hex("ekeyBlobSalt", ps->ekeyBlobSalt);

    if (ps->ekeyBlobEncVer != NULL)
        dump_u64("ekeyBlobEncVer", ps->ekeyBlobEncVer);

    if (ps->ekeyBlobRaw != NULL)
        dump_u64("ekeyBlobRaw", ps->ekeyBlobRaw);

    if (ps->ekeyBlobUniqKDM != NULL)
        dump_hex("ekeyBlobUniqKDM", ps->ekeyBlobUniqKDM);

    if (ps->ekeyBlobIncUseCount != NULL)
        dump_u64("ekeyBlobIncUseCount", ps->ekeyBlobIncUseCount);

    if (ps->samsungRequestingTA != NULL)
        dump_hex("samsungRequestingTA", ps->samsungRequestingTA);

    if (ps->samsungRotRequired != NULL)
        s_log_info(SINGLE_INDENT ".samsungRotRequired = 1,");

    if (ps->samsungLegacyRot != NULL)
        s_log_info(SINGLE_INDENT ".samsungLegacyRot = 1,");

    if (ps->useSecureProcessor != NULL)
        s_log_info(SINGLE_INDENT ".useSecureProcessor = 1,");

    if (ps->storageKey != NULL)
        s_log_info(SINGLE_INDENT ".storageKey = 1,");

    if (ps->integrityStatus != NULL)
        dump_u64("integrityStatus", ps->integrityStatus, DUMP_U64_HEX);

    if (ps->isSamsungKey != NULL)
        s_log_info(SINGLE_INDENT ".isSamsungKey = 1,");

    if (ps->samsungAttestationRoot != NULL)
        dump_hex("samsungAttestationRoot", ps->samsungAttestationRoot);

    if (ps->samsungAttestIntegrity != NULL)
        s_log_info(SINGLE_INDENT ".samsungAttestIntegrity = 1,");

    if (ps->knoxObjectProtectionRequired != NULL)
        s_log_info(SINGLE_INDENT ".knoxObjectProtectionRequired = 1,");

    if (ps->knoxCreatorId != NULL)
        dump_hex("knoxCreatorId", ps->knoxCreatorId);

    if (ps->knoxAdministratorId != NULL)
        dump_hex("knoxAdministratorId", ps->knoxAdministratorId);

    if (ps->knoxAccessorId != NULL)
        dump_hex("knoxAccessorId", ps->knoxAccessorId);

    if (ps->samsungAuthPackage != NULL)
        dump_hex("samsungAuthPackage", ps->samsungAuthPackage);

    if (ps->samsungCertificateSubject != NULL)
        dump_hex("samsungCertificateSubject", ps->samsungCertificateSubject);

    if (ps->samsungKeyUsage != NULL)
        dump_u64("samsungKeyUsage", ps->samsungKeyUsage, DUMP_U64_HEX);

    if (ps->samsungExtendedKeyUsage != NULL)
        dump_hex("samsungExtendedKeyUsage", ps->samsungExtendedKeyUsage);

    if (ps->samsungSubjectAlternativeName != NULL)
        dump_hex("samsungSubjectAlternativeName",
                ps->samsungSubjectAlternativeName);

    if (ps->provGacEc1 != NULL)
        dump_hex("provGacEc1", ps->provGacEc1);

    if (ps->provGacEc2 != NULL)
        dump_hex("provGacEc2", ps->provGacEc2);

    if (ps->provGacEc3 != NULL)
        dump_hex("provGacEc3", ps->provGacEc3);

    if (ps->provGakEc != NULL)
        dump_hex("provGakEc", ps->provGakEc);

    if (ps->provGakEcVtoken != NULL)
        dump_hex("provGakEcVtoken", ps->provGakEcVtoken);

    if (ps->provGacRsa1 != NULL)
        dump_hex("provGacRsa1", ps->provGacRsa1);

    if (ps->provGacRsa2 != NULL)
        dump_hex("provGacRsa2", ps->provGacRsa2);

    if (ps->provGacRsa3 != NULL)
        dump_hex("provGacRsa3", ps->provGacRsa3);

    if (ps->provGakRsa != NULL)
        dump_hex("provGakRsa", ps->provGakRsa);

    if (ps->provGakRsaVtoken != NULL)
        dump_hex("provGakRsaVtoken", ps->provGakRsaVtoken);

    if (ps->provSakEc != NULL)
        dump_hex("provSakEc", ps->provSakEc);

    if (ps->provSakEcVtoken != NULL)
        dump_hex("provSakEcVtoken", ps->provSakEcVtoken);

    s_log_info("};");
    s_log_info("=====  END KEY PARAMETER LIST DUMP  =====");
restore_log_and_out:
    s_configure_log_line(S_LOG_INFO, old_line, NULL);
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

static void dump_hex(const char *field_name,
        const ASN1_OCTET_STRING *data_, uint8_t indent)
{
    char indent_buf[1024];
    sprint_indent(indent_buf, indent);

    int total_sz = 0;
    if (data_ == NULL || (total_sz = ASN1_STRING_length(data_)) <= 0) {
        s_log_info("%s.%s = { /* (empty) */ },", indent_buf, field_name);
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
        dump_hex_line(line_buf, LINE_BUF_SIZE, data, remainder, true);
        line_buf[LINE_BUF_SIZE - 1] = '\0';
        s_log_info("%s.%s = { %s },", indent_buf, field_name, line_buf);
        return;
    }

    s_log_info("%s.%s = {", indent_buf, field_name);

    dump_hex_line(line_buf, LINE_BUF_SIZE, data, LINE_LEN, false);
    line_buf[LINE_BUF_SIZE - 1] = '\0';
    s_log_info("%s" SINGLE_INDENT "%s", indent_buf, line_buf);

    for (u32 i = 1; i < n_lines; i++) {
        memset(line_buf, 0, LINE_BUF_SIZE);
        dump_hex_line(line_buf, LINE_BUF_SIZE,
                data + (i * LINE_LEN),
                LINE_LEN, false
        );
        line_buf[LINE_BUF_SIZE - 1] = '\0';
        s_log_info("%s" SINGLE_INDENT "%s", indent_buf, line_buf);
    }

    memset(line_buf, 0, LINE_BUF_SIZE);
    dump_hex_line(line_buf, LINE_BUF_SIZE,
            data + (n_lines * LINE_LEN),
            remainder, true
    );
    line_buf[LINE_BUF_SIZE - 1] = '\0';
    s_log_info("%s" SINGLE_INDENT "%s", indent_buf, line_buf);
    s_log_info("%s},", indent_buf);

#undef LINE_LEN
}

static void dump_u64(const char *field_name, const ASN1_INTEGER *a,
        uint8_t indent, bool hex)
{
    uint64_t u = 0;
    if (ASN1_INTEGER_get_uint64(&u, a) == 0) {
        s_log_error("[%s] Couldn't get the value "
                "of an ASN.1 INTEGER (as uint64_t)", field_name);
        return;
    }

    {
        char indent_buf[1024];
        sprint_indent(indent_buf, indent);

        if (hex)
            s_log_info("%s.%s = 0x%016llx,",
                    indent_buf, field_name, (unsigned long long)u);
        else
            s_log_info("%s.%s = %llu,",
                    indent_buf, field_name, (unsigned long long)u);
    }
}

static void dump_u64_arr(const char *field_name, const ASN1_SET_OF_INTEGER *arr,
        uint8_t indent, bool hex)
{
    char indent_buf[1024];
    char tmp_buf[1024] = { 0 };
    u32 write_index = 0;
    int arr_size = 0;
    const char *const fmt = hex ? "0x%016llx, " : "%llu, ";

    sprint_indent(indent_buf, indent);

    if (arr == NULL || (arr_size = sk_ASN1_INTEGER_num(arr)) <= 0) {
        s_log_info("%s.%s = { /* (empty) */ },", indent_buf, field_name);
        return;
    }


    {
        const ASN1_INTEGER *curr = NULL;
        uint64_t u = 0;
        int r = 0;

        for (int i = 0; i < arr_size - 1; i++) {
            curr = sk_ASN1_INTEGER_value(arr, i);
            if (ASN1_INTEGER_get_uint64(&u, curr) == 0) {
                s_log_error("[%s] Couldn't get the value of an ASN.1 INTEGER "
                        "(as uint64_t) @ idx %i", field_name, i);
                break;
            }

            r = snprintf(tmp_buf + write_index, 256 - write_index - 1,
                    fmt, (unsigned long long)u);
            if (r <= 0 || r >= 256) {
                s_log_error("[%s] Invalid return value of snprintf "
                        "(@ idx %d): %d", field_name, i, r);
                return;
            }

            write_index += r;
        }

        curr = sk_ASN1_INTEGER_value(arr, arr_size - 1);
        if (ASN1_INTEGER_get_uint64(&u, curr) == 0) {
            s_log_error("[%s] Couldn't get the value of an ASN.1 INTEGER "
                    "(as uint64_t) @ idx %i", field_name, arr_size - 1);
            return;
        }
        r = snprintf(tmp_buf + write_index, 256 - write_index - 1,
                fmt, (unsigned long long)u);
        if (r <= 0 || r >= 256) {
            s_log_error("[%s] Invalid return value of snprintf (@ idx %d): %d",
                    field_name, arr_size - 1, r);
            return;
        }
    }

    s_log_info("%s.%s = { %s },", indent_buf, field_name, tmp_buf);
}

static void dump_enum_val(const char *field_name, const ASN1_INTEGER *e,
        KM_enum_toString_proc_t get_str_proc, uint8_t indent)
{
    int64_t i = 0;
    char indent_buf[1024];
    sprint_indent(indent_buf, indent);

    if (ASN1_INTEGER_get_int64(&i, e) == 0) {
        s_log_error("[%s] Couldn't get the value "
                "of an ASN.1 INTEGER (as int64_t)", field_name);
        return;
    }
    i &= 0x00000000FFFFFFFF;

    s_log_info("%s.%s = %lld, // %s", indent_buf, field_name,
            (long long int)i, get_str_proc((int)i));
}

static void dump_enum_arr(const char *field_name,
        const ASN1_SET_OF_INTEGER *arr, KM_enum_toString_proc_t get_str_proc,
        uint8_t indent)
{
    int arr_size = 0;
    char indent_buf[1024];
    sprint_indent(indent_buf, indent);

    if (arr == NULL || (arr_size = sk_ASN1_INTEGER_num(arr)) <= 0) {
        s_log_info("%s.%s = { /* (empty) */ },", indent_buf, field_name);
        return;
    }

    s_log_info("%s.%s = {", indent_buf, field_name);

    for (int i = 0; i < arr_size - 1; i++) {
        int64_t val = 0;
        if (ASN1_INTEGER_get_int64(&val, sk_ASN1_INTEGER_value(arr, i)) == 0) {
            s_log_error("[%s] Couldn't get the value of an ASN.1 INTEGER "
                    "(as int64_t) @ idx %i", field_name, i);
            return;
        }
        val &= 0x00000000FFFFFFFF;

        s_log_info(SINGLE_INDENT "%s.%s = %lld, // %s",
                indent_buf, field_name,
                (long long int)val, get_str_proc((int)val)
        );
    }

    {
        int64_t val = 0;
        if (ASN1_INTEGER_get_int64(&val,
                    sk_ASN1_INTEGER_value(arr, arr_size - 1)) == 0)
        {
            s_log_error("[%s] Couldn't get the value of an ASN.1 INTEGER "
                    "(as int64_t) @ idx %i", field_name, arr_size - 1);
            return;
        }
        val &= 0x00000000FFFFFFFF;
        s_log_info(SINGLE_INDENT "%s.%s = %lld // %s",
                indent_buf, field_name,
                (long long int)val, get_str_proc((int)val)
        );
    }

    s_log_info("%s},", indent_buf);
}

static void dump_datetime(const char *field_name, const ASN1_INTEGER *d,
        uint8_t indent)
{
    char indent_buf[1024];
    char datetime_buf[256] = { 0 };
    int64_t i = 0;

    sprint_indent(indent_buf, indent);

    if (ASN1_INTEGER_get_int64(&i, d) == 0) {
        s_log_error("[%s] Couldn't get the value of an ASN.1 INTEGER "
                "(as int64_t)", field_name);
        return;
    }

    datetime_to_str(datetime_buf, sizeof(datetime_buf), i);
    s_log_info("%s.%s = %lld, // %s", indent_buf, field_name,
            (long long int)i, datetime_buf);
}

static int portable_localtime(const time_t *timep, struct tm *result)
{
#ifdef _WIN32
    return localtime_s(result, timep);
#else
    return localtime_r(timep, result) ? 0 : -1;
#endif
}
static void datetime_to_str(char *buf, u32 buf_size, int64_t dt)
{
    struct tm t = {};

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

static int deserialize_ekey_blob_and_params(const hidl_vec<uint8_t>& ekey,
        KM_SAMSUNG_EKEY_BLOB *& out, hidl_vec<KM_SAMSUNG_PARAM *> *out_par)
{
    const unsigned char *p = ekey.data();
    long len = (long)ekey.size();
    KM_SAMSUNG_EKEY_BLOB *ekey_blob = NULL;

    if (out_par)
        out_par->resize(0);

    ekey_blob = d2i_KM_SAMSUNG_EKEY_BLOB(NULL, &p, len);
    if (ekey_blob == NULL)
        goto_error("Failed to d2i the encrypted key blob");

    {
        int64_t blob_ver = 0;
        if (!ASN1_INTEGER_get_int64(&blob_ver, ekey_blob->enc_ver))
            goto_error("Couldn't get the encrypted key blob version INTEGER");
        s_log_info("Encrypted key blob version: %lli", (long long int)blob_ver);
    }

    if (out_par) {
        int n_params = sk_KM_SAMSUNG_PARAM_num(ekey_blob->enc_par);
        if (n_params < 0)
            goto_error("Couldn't get the number of encryption parameters");

        for (int i = 0; i < n_params; i++) {
            KM_SAMSUNG_PARAM *p =
                sk_KM_SAMSUNG_PARAM_value(ekey_blob->enc_par, i);
            if (p == NULL)
                goto_error("Couldn't get the value of an encryption parameter");

            p = KM_SAMSUNG_PARAM_dup(p);
            if (p == NULL)
                goto_error("Couldn't duplicate an encryption parameter");

            out_par->resize(out_par->size() + 1);
            (*out_par)[out_par->size() - 1] = p;
        }
    }

    out = ekey_blob;

    return 0;

err:
    if (out_par) {
        for (size_t i = 0; i < out_par->size(); i++) {
            KM_SAMSUNG_PARAM_free((*out_par)[i]);
            (*out_par)[i] = NULL;
        }
        out_par->resize(0);
    }

    if (ekey_blob != NULL) {
        KM_SAMSUNG_EKEY_BLOB_free(ekey_blob);
        ekey_blob = NULL;
    }
    out = NULL;

    return 1;
}

static int serialize_ekey_blob(KM_SAMSUNG_EKEY_BLOB *& ekey,
        hidl_vec<uint8_t>& out_ekey_der)
{
    int length = 0;
    unsigned char *der = NULL;

    length = i2d_KM_SAMSUNG_EKEY_BLOB(ekey, NULL);
    if (length <= 0)
        goto_error("Couldn't measure the length of the new ekey blob DER");

    der = (unsigned char *)OPENSSL_malloc(length);
    if (der == NULL)
        goto_error("Failed to allocate the new ekey blob DER");

    {
        unsigned char *p = der;
        if (i2d_KM_SAMSUNG_EKEY_BLOB(ekey, &p) != length ||
                p != der + length)
        {
            OPENSSL_free(der);
            goto_error("Failed to serialize the new ekey blob DER");
        }
    }

    out_ekey_der.resize(length);
    memcpy(out_ekey_der.data(), der, length);
    OPENSSL_free(der);

    return 0;

err:
    out_ekey_der.resize(0);
    if (der != NULL) {
        OPENSSL_free(der);
        der = NULL;
    }

    return 1;
}

static int ekey_params_to_param_list(const hidl_vec<KM_SAMSUNG_PARAM *>& ekey_params,
        KM_PARAM_LIST_SEQ **out_param_list)
{
    KM_PARAM_LIST_SEQ *ret = KM_PARAM_LIST_SEQ_new();
    if (ret == NULL)
        goto_error("Failed to allocate a new param list");

    for (const KM_SAMSUNG_PARAM *curr : ekey_params) {
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

            ret->rootOfTrust = d2i_KM_ROOT_OF_TRUST_SEQ(&ret->rootOfTrust,
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
        KM_PARAM_LIST_SEQ_free(ret);
        ret = NULL;
    }

    *out_param_list = NULL;
    return 1;
}

} /* namespace ekey */

} /* namespace samsung */
} /* namespace cli */
} /* namespace suskeymaster */
