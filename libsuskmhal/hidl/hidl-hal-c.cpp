#define HIDL_DISABLE_INSTRUMENTATION
#include "hidl-hal-c.h"
#include "hidl-hal.hpp"
#include "../util/keymaster-types-c.h"
#include <android/hardware/keymaster/generic/types.h>
#include <hidl/HidlSupport.h>
#include <memory>

using ::android::hardware::hidl_vec;
using namespace ::android::hardware::keymaster::generic;
using namespace ::suskeymaster::kmhal::util;

namespace suskeymaster {
namespace kmhal {
namespace hidl {

static hidl_vec<uint8_t> to_hidl_vec(VECTOR(u8 const) v)
{
    if (v == NULL || vector_size(v) == 0)
        return {};

    hidl_vec<uint8_t> ret;
    ret.resize(vector_size(v));
    memcpy(ret.data(), v, vector_size(v));
    return ret;
}
static hidl_vec<uint8_t> to_hidl_vec(VECTOR(u8) v)
{
    return to_hidl_vec(const_cast<VECTOR(u8 const)>(v));
}

static hidl_vec<KeyParameter> to_hidl_params(VECTOR(struct KM_KeyParameter const) params)
{
    if (params == NULL || vector_size(params) == 0)
        return {};

    hidl_vec<KeyParameter> out(vector_size(params));
    for (uint32_t i = 0; i < vector_size(params); i++) {
        const struct KM_KeyParameter &src = params[i];
        KeyParameter &dst = out[i];

        dst.tag = static_cast<Tag>(src.tag);

        /* Determine tag type from the upper bits */
        uint32_t tag_type = (uint32_t)src.tag & 0xFF000000u;
        if (tag_type == (uint32_t)KM_TAG_TYPE_BIGNUM ||
            tag_type == (uint32_t)KM_TAG_TYPE_BYTES)
        {
            /* blob field is a VECTOR(uint8_t) */
            auto *blob = static_cast<uint8_t *>(src.blob);
            uint32_t blob_len = blob ? vector_size(blob) : 0;
            dst.blob.setToExternal(blob, blob_len, false);
        } else {
            /* Copy the integer union directly - same size as hidl's KeyParameter.f */
            static_assert(sizeof(dst.f) >= sizeof(src.f),
                    "HIDL KeyParameter union too small for KM_IntegerParams");
            memcpy(&dst.f, &src.f, sizeof(src.f));
        }
    }
    return out;
}

static VECTOR(struct KM_KeyParameter)
from_hidl_params(const hidl_vec<KeyParameter> &src)
{
    VECTOR(struct KM_KeyParameter) out = vector_new(struct KM_KeyParameter);
    vector_resize(&out, src.size());

    for (size_t i = 0; i < src.size(); i++) {
        const KeyParameter &s = src[i];
        struct KM_KeyParameter &d = out[i];

        d.tag = static_cast<enum KM_Tag>(s.tag);
        memset(&d.f, 0, sizeof(d.f));
        d.blob = nullptr;

        uint32_t tag_type = (uint32_t)s.tag & 0xFF000000u;
        if (tag_type == (uint32_t)KM_TAG_TYPE_BIGNUM ||
            tag_type == (uint32_t)KM_TAG_TYPE_BYTES)
        {
            VECTOR(uint8_t) blob = vector_new(uint8_t);
            vector_resize(&blob, s.blob.size());
            if (s.blob.size() > 0)
                memcpy(blob, s.blob.data(), s.blob.size());
            d.blob = blob;
        } else {
            memcpy(&d.f, &s.f, sizeof(d.f));
        }
    }
    return out;
}

static VECTOR(uint8_t) from_hidl_bytes(const hidl_vec<uint8_t> &src)
{
    VECTOR(uint8_t) out = vector_new(uint8_t);
    vector_resize(&out, src.size());
    if (src.size() > 0)
        memcpy(out, src.data(), src.size());
    return out;
}

static HardwareAuthToken make_auth_token(const struct KM_HardwareAuthToken *token)
{
    if (token == NULL)
        return {};

    HardwareAuthToken t{};
    t.challenge         = token->challenge;
    t.userId            = token->userId;
    t.authenticatorId   = token->authenticatorId;
    t.authenticatorType = static_cast<HardwareAuthenticatorType>(token->authenticatorType);
    t.timestamp         = token->timestamp;
    t.mac.resize(KM_AUTH_TOKEN_MAC_LENGTH);
    memcpy(t.mac.data(), token->mac, KM_AUTH_TOKEN_MAC_LENGTH);
    return t;
}

static VerificationToken make_verification_token(const struct KM_VerificationToken *token)
{
    if (token == NULL)
        return {};

    VerificationToken t{};
    t.challenge           = token->challenge;
    t.timestamp           = token->timestamp;
    t.securityLevel       = static_cast<SecurityLevel>(token->securityLevel);

    t.parametersVerified = to_hidl_params(token->parametersVerified);

    t.mac.resize(KM_AUTH_TOKEN_MAC_LENGTH);
    memcpy(t.mac.data(), token->mac, KM_AUTH_TOKEN_MAC_LENGTH);

    return t;
}

static constexpr enum KM_ErrorCode from_hidl_error(ErrorCode e)
{
    return static_cast<enum KM_ErrorCode>(e);
}


extern "C" {

struct hidl_suskeymaster {
    std::unique_ptr<HidlSusKeymaster> impl;
};

struct hidl_suskeymaster *hidl_suskeymaster3_0_new(void)
{
#ifndef SUSKEYMASTER_HAL_DISABLE_3_0
    auto *km = new (std::nothrow) hidl_suskeymaster();
    if (!km)
        return nullptr;

    km->impl = std::make_unique<HidlSusKeymaster3_0>();
    if (!km->impl->isHALOk()) {
        delete km;
        return nullptr;
    }
    return km;
#else
    return nullptr;
#endif /* SUSKEYMASTER_HAL_DISABLE_3_0 */
}

struct hidl_suskeymaster *hidl_suskeymaster4_0_new(void)
{
#ifndef SUSKEYMASTER_HAL_DISABLE_4_0
    auto *km = new (std::nothrow) hidl_suskeymaster();
    if (!km)
        return nullptr;

    km->impl = std::make_unique<HidlSusKeymaster4_0>();
    if (!km->impl->isHALOk()) {
        delete km;
        return nullptr;
    }
    return km;
#else
    return nullptr;
#endif /* SUSKEYMASTER_HAL_DISABLE_4_0 */
}

struct hidl_suskeymaster *hidl_suskeymaster4_1_new(void)
{
#ifndef SUSKEYMASTER_HAL_DISABLE_4_1
    auto *km = new (std::nothrow) hidl_suskeymaster();
    if (!km)
        return nullptr;

    km->impl = std::make_unique<HidlSusKeymaster4_1>();
    if (!km->impl->isHALOk()) {
        delete km;
        return nullptr;
    }
    return km;
#else
    return nullptr;
#endif /* SUSKEYMASTER_HAL_DISABLE_4_1 */
}

void hidl_suskeymaster_destroy(struct hidl_suskeymaster **km_p)
{
    if (!km_p || !*km_p)
        return;
    delete *km_p;
    *km_p = nullptr;
}

bool hidl_suskeymaster_is_hal_ok(struct hidl_suskeymaster *km)
{
    if (!km) return false;
    return km->impl->isHALOk();
}

void hidl_suskeymaster_get_hardware_info(struct hidl_suskeymaster *km,
        enum KM_SecurityLevel *out_security_level,
        VECTOR(char) *out_keymaster_name,
        VECTOR(char) *out_keymaster_author_name
)
{
    if (!km) return;

    SecurityLevel slvl = SecurityLevel::SOFTWARE;
    hidl_string name, author;
    km->impl->getHardwareInfo(slvl, name, author);

    if (out_security_level)
        *out_security_level = static_cast<enum KM_SecurityLevel>(slvl);

    if (out_keymaster_name) {
        if (*out_keymaster_name == NULL)
            *out_keymaster_name = vector_new(char);
        vector_resize(out_keymaster_name, name.size());
        memcpy(*out_keymaster_name, name.c_str(), name.size());
    }

    if (out_keymaster_author_name) {
        if (*out_keymaster_author_name == NULL)
            *out_keymaster_author_name = vector_new(char);
        vector_resize(out_keymaster_author_name, author.size());
        memcpy(*out_keymaster_author_name, author.c_str(), author.size());
    }
}

enum KM_ErrorCode hidl_suskeymaster_get_hmac_sharing_parameters(struct hidl_suskeymaster *km,
        struct KM_HmacSharingParameters *out_params
)
{
    if (!km) return KM_ERR_UNEXPECTED_NULL_POINTER;

    HmacSharingParameters params{};
    ErrorCode err = km->impl->getHmacSharingParameters(params);
    if (err != ErrorCode::OK)
        return from_hidl_error(err);

    if (out_params) {
        out_params->seed = from_hidl_bytes(params.seed);
        /* both out_params->nonce & params.nonce are fixed size u8[32] arrays */
        memcpy(out_params->nonce, params.nonce.data(), 32);
    }

    return KM_OK;
}

enum KM_ErrorCode hidl_suskeymaster_compute_shared_hmac(struct hidl_suskeymaster *km,
        VECTOR(struct KM_HmacSharingParameters const) params,

        VECTOR(u8) *out_sharing_check /* caller must vector_destroy */
)
{
    if (!km) return KM_ERR_UNEXPECTED_NULL_POINTER;

    hidl_vec<HmacSharingParameters> hidl_params(vector_size(params));
    for (uint32_t i = 0; i < vector_size(params); i++) {
        hidl_params[i].seed = to_hidl_vec(params[i].seed);
        /* both hidl_params[i].nonce & params[i].nonce are fixed size u8[32] arrays */
        memcpy(hidl_params[i].nonce.data(), params[i].nonce, 32);
    }

    hidl_vec<uint8_t> sharing_check;
    ErrorCode err = km->impl->computeSharedHmac(hidl_params, sharing_check);
    if (err != ErrorCode::OK)
        return from_hidl_error(err);

    if (out_sharing_check)
        *out_sharing_check = from_hidl_bytes(sharing_check);

    return KM_OK;
}

enum KM_ErrorCode hidl_suskeymaster_verify_authorization(struct hidl_suskeymaster *km,
        uint64_t operation_handle,
        VECTOR(struct KM_KeyParameter const) params_to_verify,
        struct KM_HardwareAuthToken const *auth_token,

        struct KM_VerificationToken *out_verification_token
)
{
    if (!km) return KM_ERR_UNEXPECTED_NULL_POINTER;

    hidl_vec<KeyParameter> hidl_params = to_hidl_params(params_to_verify);
    HardwareAuthToken hidl_auth_token = make_auth_token(auth_token);

    VerificationToken vtoken{};
    ErrorCode err = km->impl->verifyAuthorization(
            operation_handle, hidl_params, hidl_auth_token, vtoken
    );
    if (err != ErrorCode::OK)
        return from_hidl_error(err);

    if (out_verification_token) {
        out_verification_token->challenge = vtoken.challenge;
        out_verification_token->timestamp = vtoken.timestamp;
        out_verification_token->parametersVerified = from_hidl_params(vtoken.parametersVerified);
        out_verification_token->securityLevel = static_cast<enum KM_SecurityLevel>
            (vtoken.securityLevel);
        vtoken.mac.resize(KM_AUTH_TOKEN_MAC_LENGTH);
        memcpy(out_verification_token->mac, vtoken.mac.data(), KM_AUTH_TOKEN_MAC_LENGTH);
    }

    return KM_OK;
}

enum KM_ErrorCode hidl_suskeymaster_add_rng_entropy(struct hidl_suskeymaster *km,
        VECTOR(u8 const) data
)
{
    if (!km) return KM_ERR_UNEXPECTED_NULL_POINTER;

    hidl_vec<uint8_t> v = to_hidl_vec(data);
    return from_hidl_error(km->impl->addRngEntropy(v));
}

/* Shared helper for the three key-returning operations */
static enum KM_ErrorCode unpack_key_characteristics(const KeyCharacteristics &kc,
        struct KM_KeyCharacteristics *out)
{
    if (out) {
        out->softwareEnforced = from_hidl_params(kc.softwareEnforced);
        out->hardwareEnforced = from_hidl_params(kc.hardwareEnforced);
    }
    return KM_OK;
}

enum KM_ErrorCode hidl_suskeymaster_generate_key(struct hidl_suskeymaster *km,
        VECTOR(struct KM_KeyParameter const) key_params,
        VECTOR(u8) *out_key_blob,                   /* caller must vector_destroy */
        struct KM_KeyCharacteristics *out_key_characteristics)
{
    if (!km) return KM_ERR_UNEXPECTED_NULL_POINTER;

    hidl_vec<KeyParameter> hidl_params = to_hidl_params(key_params);
    hidl_vec<uint8_t> key_blob;
    KeyCharacteristics kc{};

    ErrorCode err = km->impl->generateKey(hidl_params, key_blob, kc);
    if (err != ErrorCode::OK)
        return from_hidl_error(err);

    if (out_key_blob) *out_key_blob = from_hidl_bytes(key_blob);
    return unpack_key_characteristics(kc, out_key_characteristics);
}

enum KM_ErrorCode hidl_suskeymaster_import_key(struct hidl_suskeymaster *km,
        VECTOR(struct KM_KeyParameter const) key_params,
        enum KM_KeyFormat key_format, VECTOR(u8 const) key_data,

        VECTOR(u8) *out_key_blob,
        struct KM_KeyCharacteristics *out_key_characteristics
)
{
    if (!km) return KM_ERR_UNEXPECTED_NULL_POINTER;

    hidl_vec<KeyParameter> hidl_params = to_hidl_params(key_params);
    hidl_vec<uint8_t> hidl_key_data = to_hidl_vec(key_data);
    hidl_vec<uint8_t> key_blob;
    KeyCharacteristics kc{};

    ErrorCode err = km->impl->importKey(
            hidl_params,
            static_cast<KeyFormat>(key_format),
            hidl_key_data, key_blob, kc);
    if (err != ErrorCode::OK)
        return from_hidl_error(err);

    if (out_key_blob) *out_key_blob = from_hidl_bytes(key_blob);
    return unpack_key_characteristics(kc, out_key_characteristics);
}

enum KM_ErrorCode hidl_suskeymaster_import_wrapped_key(struct hidl_suskeymaster *km,
        VECTOR(u8 const) wrapped_key_data, VECTOR(u8 const) wrapping_key_blob,
        VECTOR(u8 const) masking_key, VECTOR(struct KM_KeyParameter const) unwrapping_params,
        uint64_t password_sid, uint64_t biometric_sid,

        VECTOR(u8) *out_key_blob,
        struct KM_KeyCharacteristics *out_key_characteristics
)
{
    if (!km) return KM_ERR_UNEXPECTED_NULL_POINTER;

    hidl_vec<uint8_t> hidl_key_blob;
    KeyCharacteristics kc{};

    ErrorCode err = km->impl->importWrappedKey(
            to_hidl_vec(wrapped_key_data),
            to_hidl_vec(wrapping_key_blob),
            to_hidl_vec(masking_key),
            to_hidl_params(unwrapping_params),
            password_sid, biometric_sid,
            hidl_key_blob, kc);
    if (err != ErrorCode::OK)
        return from_hidl_error(err);

    if (out_key_blob) *out_key_blob = from_hidl_bytes(hidl_key_blob);
    return unpack_key_characteristics(kc, out_key_characteristics);
}

enum KM_ErrorCode hidl_suskeymaster_get_key_characteristics(struct hidl_suskeymaster *km,
        VECTOR(u8 const) key_blob, VECTOR(u8 const) app_id, VECTOR(u8 const) app_data,
        struct KM_KeyCharacteristics *out_key_characteristics
)
{
    if (!km) return KM_ERR_UNEXPECTED_NULL_POINTER;

    KeyCharacteristics kc{};
    ErrorCode err = km->impl->getKeyCharacteristics(
            to_hidl_vec(key_blob),
            to_hidl_vec(app_id),
            to_hidl_vec(app_data),
            kc
    );
    if (err != ErrorCode::OK)
        return from_hidl_error(err);

    return unpack_key_characteristics(kc, out_key_characteristics);
}

enum KM_ErrorCode hidl_suskeymaster_export_key(struct hidl_suskeymaster *km,
        enum KM_KeyFormat key_format, VECTOR(u8 const) key_blob,
        VECTOR(u8 const) app_id, VECTOR(u8 const) app_data,

        VECTOR(u8) *out_key_material
)
{
    if (!km) return KM_ERR_UNEXPECTED_NULL_POINTER;

    hidl_vec<uint8_t> key_material;
    ErrorCode err = km->impl->exportKey(
            static_cast<KeyFormat>(key_format),
            to_hidl_vec(key_blob),
            to_hidl_vec(app_id),
            to_hidl_vec(app_data),
            key_material
    );
    if (err != ErrorCode::OK)
        return from_hidl_error(err);

    if (out_key_material)
        *out_key_material = from_hidl_bytes(key_material);

    return KM_OK;
}

enum KM_ErrorCode hidl_suskeymaster_attest_key(struct hidl_suskeymaster *km,
        VECTOR(u8 const) key_to_attest, VECTOR(struct KM_KeyParameter const) attest_params,
        VECTOR(VECTOR(u8)) *out_cert_chain /* caller must destroy each cert + the chain */
)
{
    if (!km) return KM_ERR_UNEXPECTED_NULL_POINTER;

    hidl_vec<hidl_vec<uint8_t>> cert_chain;
    ErrorCode err = km->impl->attestKey(
            to_hidl_vec(key_to_attest),
            to_hidl_params(attest_params),
            cert_chain
    );
    if (err != ErrorCode::OK)
        return from_hidl_error(err);

    if (out_cert_chain) {
        VECTOR(VECTOR(uint8_t)) chain = vector_new(VECTOR(uint8_t));
        vector_resize(&chain, cert_chain.size());
        for (size_t i = 0; i < cert_chain.size(); i++)
            chain[i] = from_hidl_bytes(cert_chain[i]);
        *out_cert_chain = chain;
    }

    return KM_OK;
}

enum KM_ErrorCode hidl_suskeymaster_upgrade_key(struct hidl_suskeymaster *km,
        VECTOR(u8 const) key_blob, VECTOR(struct KM_KeyParameter const) upgrade_params,
        VECTOR(u8) *out_upgraded_key_blob
)
{
    if (!km) return KM_ERR_UNEXPECTED_NULL_POINTER;

    hidl_vec<uint8_t> upgraded;
    ErrorCode err = km->impl->upgradeKey(
            to_hidl_vec(key_blob),
            to_hidl_params(upgrade_params),
            upgraded
    );
    if (err != ErrorCode::OK)
        return from_hidl_error(err);

    if (out_upgraded_key_blob)
        *out_upgraded_key_blob = from_hidl_bytes(upgraded);

    return KM_OK;
}

enum KM_ErrorCode hidl_suskeymaster_delete_key(struct hidl_suskeymaster *km,
        VECTOR(u8 const) key_blob)
{
    if (!km) return KM_ERR_UNEXPECTED_NULL_POINTER;
    return from_hidl_error(km->impl->deleteKey(to_hidl_vec(key_blob)));
}

enum KM_ErrorCode hidl_suskeymaster_delete_all_keys(struct hidl_suskeymaster *km)
{
    if (!km) return KM_ERR_UNEXPECTED_NULL_POINTER;
    return from_hidl_error(km->impl->deleteAllKeys());
}

enum KM_ErrorCode hidl_suskeymaster_destroy_attestation_ids(struct hidl_suskeymaster *km)
{
    if (!km) return KM_ERR_UNEXPECTED_NULL_POINTER;
    return from_hidl_error(km->impl->destroyAttestationIds());
}

enum KM_ErrorCode hidl_suskeymaster_begin(struct hidl_suskeymaster *km,
        enum KM_KeyPurpose purpose, VECTOR(u8 const) key_blob,
        VECTOR(struct KM_KeyParameter const) in_params,
        struct KM_HardwareAuthToken const *auth_token,

        VECTOR(struct KM_KeyParameter) *out_params,
        uint64_t *out_operation_handle
)
{
    if (!km) return KM_ERR_UNEXPECTED_NULL_POINTER;

    hidl_vec<KeyParameter> hidl_out_params;
    uint64_t op_handle = 0;

    ErrorCode err = km->impl->begin(
            static_cast<KeyPurpose>(purpose),
            to_hidl_vec(key_blob),
            to_hidl_params(in_params),
            make_auth_token(auth_token),
            hidl_out_params, op_handle
    );
    if (err != ErrorCode::OK)
        return from_hidl_error(err);

    if (out_params)        *out_params = from_hidl_params(hidl_out_params);
    if (out_operation_handle) *out_operation_handle = op_handle;

    return KM_OK;
}

enum KM_ErrorCode hidl_suskeymaster_update(struct hidl_suskeymaster *km,
        uint64_t operation_handle,
        VECTOR(struct KM_KeyParameter const) in_params, VECTOR(u8 const) input,
        struct KM_HardwareAuthToken *auth_token, struct KM_VerificationToken *verification_token,

        uint32_t *out_input_consumed,
        VECTOR(struct KM_KeyParameter) *out_params,
        VECTOR(u8) *out_output
)
{
    if (!km) return KM_ERR_UNEXPECTED_NULL_POINTER;

    uint32_t input_consumed = 0;
    hidl_vec<KeyParameter> hidl_out_params;
    hidl_vec<uint8_t> output;

    ErrorCode err = km->impl->update(
            operation_handle,
            to_hidl_params(in_params),
            to_hidl_vec(input),
            make_auth_token(auth_token),
            make_verification_token(verification_token),
            input_consumed, hidl_out_params, output
    );
    if (err != ErrorCode::OK)
        return from_hidl_error(err);

    if (out_input_consumed) *out_input_consumed = input_consumed;
    if (out_params)  *out_params = from_hidl_params(hidl_out_params);
    if (out_output)  *out_output = from_hidl_bytes(output);

    return KM_OK;
}

enum KM_ErrorCode hidl_suskeymaster_finish(struct hidl_suskeymaster *km,
        uint64_t operation_handle, VECTOR(struct KM_KeyParameter const) in_params,
        VECTOR(u8 const) input, VECTOR(u8 const) signature,
        struct KM_HardwareAuthToken *auth_token, struct KM_VerificationToken *verification_token,

        VECTOR(struct KM_KeyParameter) *out_params,
        VECTOR(u8) *out_output
)
{
    if (!km) return KM_ERR_UNEXPECTED_NULL_POINTER;

    hidl_vec<KeyParameter> hidl_out_params;
    hidl_vec<uint8_t> output;

    ErrorCode err = km->impl->finish(
            operation_handle,
            to_hidl_params(in_params),
            to_hidl_vec(input),
            to_hidl_vec(signature),
            make_auth_token(auth_token),
            make_verification_token(verification_token),
            hidl_out_params, output
    );
    if (err != ErrorCode::OK)
        return from_hidl_error(err);

    if (out_params) *out_params = from_hidl_params(hidl_out_params);
    if (out_output) *out_output = from_hidl_bytes(output);

    return KM_OK;
}

enum KM_ErrorCode hidl_suskeymaster_abort(
        struct hidl_suskeymaster *km,
        uint64_t operation_handle)
{
    if (!km) return KM_ERR_UNEXPECTED_NULL_POINTER;
    return from_hidl_error(km->impl->abort(operation_handle));
}

} /* extern "C" */

} /* namespace hidl */
} /* namespace kmhal */
} /* namespace suskeymaster */
