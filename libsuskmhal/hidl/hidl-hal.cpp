#define HIDL_DISABLE_INSTRUMENTATION
#include "hidl-hal-c.h"
#include "hidl-hal.hpp"
#include "../keymaster-types-c.h"
#include <core/vector.h>
#include <hidl/HidlSupport.h>
#include <android/hardware/keymaster/4.0/types.h>
#ifndef SUSKEYMASTER_BUILD_HOST
#include <android/hardware/keymaster/4.0/IKeymasterDevice.h>
#endif /* SUSKEYMASTER_BUILD_HOST */
#include <new>
#include <cstring>
#include <cstdlib>
#include <iostream>

namespace suskeymaster {
namespace kmhal {
namespace hidl {

#ifndef SUSKEYMASTER_BUILD_HOST

HidlSusKeymaster4::HidlSusKeymaster4(void)
{
    this->hal = IKeymasterDevice::tryGetService();
}

bool HidlSusKeymaster4::isHALOk(void)
{
    if (!this->hal)
        return false;

    return this->hal->ping().isOk();
}

#else /* SUSKEYMASTER_BUILD_HOST */

HidlSusKeymaster4::HidlSusKeymaster4(void)
{
}

bool HidlSusKeymaster4::isHALOk(void)
{
    std::cerr << "HIDL HAL not available in host build!" << std::endl;
    return false;
}

#endif /* SUSKEYMASTER_BUILD_HOST */

#define check_hal_ok() do {                                         \
    if (!this->isHALOk()) {                                         \
        std::cerr << __func__ << ": HAL is not OK!" << std::endl;   \
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;           \
    }                                                               \
} while (0)

void HidlSusKeymaster4::getHardwareInfo(SecurityLevel& out_securityLevel,
        hidl_string& out_keymasterName, hidl_string& out_keymasterAuthorName)
{
    if (!this->isHALOk()) {
        out_securityLevel = SecurityLevel::SOFTWARE;
        out_keymasterName = "N/A";
        out_keymasterAuthorName = "N/A";
        return;
    }

#ifndef SUSKEYMASTER_BUILD_HOST
    this->hal->getHardwareInfo(
        [&](auto const& slvl, auto const& kmName, auto const& authorName)
        {
            out_securityLevel = slvl;
            out_keymasterName = kmName;
            out_keymasterAuthorName = authorName;
        }
    );
#else
    (void) out_securityLevel;
    (void) out_keymasterName;
    (void) out_keymasterAuthorName;
#endif /* SUSKEYMASTER_BUILD_HOST */
}

ErrorCode HidlSusKeymaster4::getHmacSharingParameters(HmacSharingParameters& out_params)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

#ifndef SUSKEYMASTER_BUILD_HOST
    this->hal->getHmacSharingParameters(
        [&](ErrorCode error, auto const& params)
        {
            ret = error;
            if (error == ErrorCode::OK)
                out_params = params;
        }
    );
#else
    (void) out_params;
#endif /* SUSKEYMASTER_BUILD_HOST */
    return ret;
}

ErrorCode HidlSusKeymaster4::computeSharedHmac(hidl_vec<HmacSharingParameters> const& params,
        hidl_vec<uint8_t>& out_sharingCheck)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

#ifndef SUSKEYMASTER_BUILD_HOST
    this->hal->computeSharedHmac(params,
        [&](ErrorCode error, auto const& sharingCheck)
        {
            ret = error;
            if (error == ErrorCode::OK)
                out_sharingCheck = sharingCheck;
        }
    );
#else
    (void) params;
    (void) out_sharingCheck;
#endif /* SUSKEYMASTER_BUILD_HOST */

    return ret;
}

ErrorCode HidlSusKeymaster4::verifyAuthorization(uint64_t operationHandle,
        hidl_vec<KeyParameter> const& parametersToVerify, HardwareAuthToken const& authToken,
        VerificationToken& out_token)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

#ifndef SUSKEYMASTER_BUILD_HOST
    this->hal->verifyAuthorization(operationHandle, parametersToVerify, authToken,
        [&](ErrorCode error, auto const& verificationToken) {
            ret = error;
            if (error == ErrorCode::OK)
                out_token = verificationToken;
        }
    );
#else
    (void) operationHandle;
    (void) parametersToVerify;
    (void) authToken;
    (void) out_token;
#endif /* SUSKEYMASTER_BUILD_HOST */

    return ret;
}

ErrorCode HidlSusKeymaster4::addRngEntropy(hidl_vec<uint8_t> const& data)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

#ifndef SUSKEYMASTER_BUILD_HOST
    ret = this->hal->addRngEntropy(data);
#else
    (void) data;
#endif /* SUSKEYMASTER_BUILD_HOST */
    return ret;
}

ErrorCode HidlSusKeymaster4::generateKey(hidl_vec<KeyParameter> const& keyParams,
        hidl_vec<uint8_t>& out_keyBlob,
        KeyCharacteristics& out_keyCharacteristics)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

#ifndef SUSKEYMASTER_BUILD_HOST
    this->hal->generateKey(keyParams,
        [&](ErrorCode error, auto const& keyBlob, auto const& keyCharacteristics) {
            ret = error;
            if (error == ErrorCode::OK) {
                out_keyBlob = keyBlob;
                out_keyCharacteristics = keyCharacteristics;
            }
        }
    );
#else
    (void) keyParams;
    (void) out_keyBlob;
    (void) out_keyCharacteristics;
#endif /* SUSKEYMASTER_BUILD_HOST */

    return ret;
}

ErrorCode HidlSusKeymaster4::importKey(hidl_vec<KeyParameter> const& keyParams,
        KeyFormat keyFormat, hidl_vec<uint8_t> const& keyData,
        hidl_vec<uint8_t>& out_keyBlob,
        KeyCharacteristics& out_keyCharacteristics)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

#ifndef SUSKEYMASTER_BUILD_HOST
    this->hal->importKey(keyParams, keyFormat, keyData,
        [&](ErrorCode error, auto const& keyBlob, auto const& keyCharacteristics) {
            ret = error;
            if (error == ErrorCode::OK) {
                out_keyBlob = keyBlob;
                out_keyCharacteristics = keyCharacteristics;
            }
        }
    );
#else
    (void) keyParams;
    (void) keyFormat;
    (void) keyData;
    (void) out_keyBlob;
    (void) out_keyCharacteristics;
#endif /* SUSKEYMASTER_BUILD_HOST */

    return ret;
}

ErrorCode HidlSusKeymaster4::importWrappedKey(
        hidl_vec<uint8_t> const& wrappedKeyData,
        hidl_vec<uint8_t> const& wrappingKeyBlob,
        hidl_vec<uint8_t> const& maskingKey,
        hidl_vec<KeyParameter> const& unwrappingParams,
        uint64_t passwordSid, uint64_t biometricSid,
        hidl_vec<uint8_t>& out_keyBlob,
        KeyCharacteristics& out_keyCharacteristics)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

#ifndef SUSKEYMASTER_BUILD_HOST
    this->hal->importWrappedKey(wrappedKeyData, wrappingKeyBlob, maskingKey,
        unwrappingParams, passwordSid, biometricSid,
        [&](ErrorCode error, auto const& keyBlob, auto const& keyCharacteristics) {
            ret = error;
            if (error == ErrorCode::OK) {
                out_keyBlob = keyBlob;
                out_keyCharacteristics = keyCharacteristics;
            }
        }
    );
#else
    (void) wrappedKeyData;
    (void) wrappingKeyBlob;
    (void) maskingKey;
    (void) unwrappingParams;
    (void) passwordSid;
    (void) biometricSid;
    (void) out_keyBlob;
    (void) out_keyCharacteristics;
#endif /* SUSKEYMASTER_BUILD_HOST */

    return ret;
}

ErrorCode HidlSusKeymaster4::getKeyCharacteristics(
        hidl_vec<uint8_t> const& keyBlob,
        hidl_vec<uint8_t> const& applicationId,
        hidl_vec<uint8_t> const& applicationData,
        KeyCharacteristics& out_keyCharacteristics)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

#ifndef SUSKEYMASTER_BUILD_HOST
    this->hal->getKeyCharacteristics(keyBlob, applicationId, applicationData,
        [&](ErrorCode error, auto const& keyCharacteristics) {
            ret = error;
            if (error == ErrorCode::OK)
                out_keyCharacteristics = keyCharacteristics;
        }
    );
#else
    (void) keyBlob;
    (void) applicationId;
    (void) applicationData;
    (void) out_keyCharacteristics;
#endif /* SUSKEYMASTER_BUILD_HOST */

    return ret;
}

ErrorCode HidlSusKeymaster4::exportKey(KeyFormat keyFormat,
        hidl_vec<uint8_t> const& keyBlob,
        hidl_vec<uint8_t> const& applicationId,
        hidl_vec<uint8_t> const& applicationData,
        hidl_vec<uint8_t>& out_keyMaterial)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

#ifndef SUSKEYMASTER_BUILD_HOST
    this->hal->exportKey(keyFormat, keyBlob, applicationId, applicationData,
        [&](ErrorCode error, auto const& keyMaterial) {
            ret = error;
            if (error == ErrorCode::OK)
                out_keyMaterial = keyMaterial;
        }
    );
#else
    (void) keyFormat;
    (void) keyBlob;
    (void) applicationId;
    (void) applicationData;
    (void) out_keyMaterial;
#endif /* SUSKEYMASTER_BUILD_HOST */

    return ret;
}

ErrorCode HidlSusKeymaster4::attestKey(
        hidl_vec<uint8_t> const& keyToAttest,
        hidl_vec<KeyParameter> const& attestParams,
        hidl_vec<hidl_vec<uint8_t>>& out_certChain)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

#ifndef SUSKEYMASTER_BUILD_HOST
    this->hal->attestKey(keyToAttest, attestParams,
        [&](ErrorCode error, auto const& certChain) {
            ret = error;
            if (error == ErrorCode::OK)
                out_certChain = certChain;
        }
    );
#else
    (void) keyToAttest;
    (void) attestParams;
    (void) out_certChain;
#endif /* SUSKEYMASTER_BUILD_HOST */

    return ret;
}

ErrorCode HidlSusKeymaster4::upgradeKey(
        hidl_vec<uint8_t> const& keyBlobToUpgrade,
        hidl_vec<KeyParameter> const& upgradeParams,
        hidl_vec<uint8_t>& out_upgradedKeyBlob)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

#ifndef SUSKEYMASTER_BUILD_HOST
    this->hal->upgradeKey(keyBlobToUpgrade, upgradeParams,
        [&](ErrorCode error, auto const& upgradedKeyBlob) {
            ret = error;
            if (error == ErrorCode::OK)
                out_upgradedKeyBlob = upgradedKeyBlob;
        }
    );
#else
    (void) keyBlobToUpgrade;
    (void) upgradeParams;
    (void) out_upgradedKeyBlob;
#endif /* SUSKEYMASTER_BUILD_HOST */

    return ret;
}

ErrorCode HidlSusKeymaster4::deleteKey(hidl_vec<uint8_t> const& keyBlob)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

#ifndef SUSKEYMASTER_BUILD_HOST
    ret = this->hal->deleteKey(keyBlob);
#else
    (void) keyBlob;
#endif /* SUSKEYMASTER_BUILD_HOST */
    return ret;
}

ErrorCode HidlSusKeymaster4::deleteAllKeys(void)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

#ifndef SUSKEYMASTER_BUILD_HOST
    ret = this->hal->deleteAllKeys();
#endif /* SUSKEYMASTER_BUILD_HOST */
    return ret;
}

ErrorCode HidlSusKeymaster4::destroyAttestationIds(void)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

#ifndef SUSKEYMASTER_BUILD_HOST
    ret = this->hal->destroyAttestationIds();
#endif /* SUSKEYMASTER_BUILD_HOST */
    return ret;
}

ErrorCode HidlSusKeymaster4::begin(KeyPurpose purpose,
        hidl_vec<uint8_t> const& keyBlob,
        hidl_vec<KeyParameter> const& inParams,
        HardwareAuthToken const& authToken,
        hidl_vec<KeyParameter>& out_outParams,
        uint64_t& out_operationHandle)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

#ifndef SUSKEYMASTER_BUILD_HOST
    this->hal->begin(purpose, keyBlob, inParams, authToken,
        [&](ErrorCode error, auto const& outParams, uint64_t operationHandle) {
            ret = error;
            if (error == ErrorCode::OK) {
                out_outParams = outParams;
                out_operationHandle = operationHandle;
            }
        }
    );
#else
    (void) purpose;
    (void) keyBlob;
    (void) inParams;
    (void) authToken;
    (void) out_outParams;
    (void) out_operationHandle;
#endif /* SUSKEYMASTER_BUILD_HOST */

    return ret;
}

ErrorCode HidlSusKeymaster4::update(uint64_t operationHandle,
        hidl_vec<KeyParameter> const& inParams,
        hidl_vec<uint8_t> const& input,
        HardwareAuthToken const& authToken,
        VerificationToken const& verificationToken,
        uint32_t& out_inputConsumed,
        hidl_vec<KeyParameter>& out_outParams,
        hidl_vec<uint8_t>& out_output)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

#ifndef SUSKEYMASTER_BUILD_HOST
    this->hal->update(operationHandle, inParams, input, authToken,
        verificationToken,
        [&](ErrorCode error, uint32_t inputConsumed,
            auto const& outParams, auto const& output) {
            ret = error;
            if (error == ErrorCode::OK) {
                out_inputConsumed = inputConsumed;
                out_outParams = outParams;
                out_output = output;
            }
        }
    );
#else
    (void) operationHandle;
    (void) inParams;
    (void) input;
    (void) authToken;
    (void) verificationToken;
    (void) out_inputConsumed;
    (void) out_outParams;
    (void) out_output;
#endif /* SUSKEYMASTER_BUILD_HOST */

    return ret;
}

ErrorCode HidlSusKeymaster4::finish(uint64_t operationHandle,
        hidl_vec<KeyParameter> const& inParams,
        hidl_vec<uint8_t> const& input,
        hidl_vec<uint8_t> const& signature,
        HardwareAuthToken const& authToken,
        VerificationToken const& verificationToken,
        hidl_vec<KeyParameter>& out_outParams,
        hidl_vec<uint8_t>& out_output)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

#ifndef SUSKEYMASTER_BUILD_HOST
    this->hal->finish(operationHandle, inParams, input, signature,
        authToken, verificationToken,
        [&](ErrorCode error, auto const& outParams, auto const& output) {
            ret = error;
            if (error == ErrorCode::OK) {
                out_outParams = outParams;
                out_output = output;
            }
        }
    );
#else
    (void) operationHandle;
    (void) inParams;
    (void) input;
    (void) signature;
    (void) authToken;
    (void) verificationToken;
    (void) out_outParams;
    (void) out_output;
#endif /* SUSKEYMASTER_BUILD_HOST */

    return ret;
}

ErrorCode HidlSusKeymaster4::abort(uint64_t operationHandle)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

#ifndef SUSKEYMASTER_BUILD_HOST
    ret = this->hal->abort(operationHandle);
#else
    (void) operationHandle;
#endif /* SUSKEYMASTER_BUILD_HOST */
    return ret;
}

#undef check_hal_ok

extern "C" {

using namespace ::android::hardware::keymaster::V4_0;
using namespace ::android::hardware;

/* -------------------------------------------------------------------------
 * Helpers: C array → hidl_vec
 * ---------------------------------------------------------------------- */

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

/* Convert an array of KM_KeyParameter into a hidl_vec<KeyParameter>.
 *
 * For BYTES-type tags, the blob pointer in KM_KeyParameter is expected to
 * be a VECTOR(uint8_t) (i.e. a pointer backed by the vector metadata).
 * We wrap it with setToExternal so no copies are made for the call duration. */
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

/* Convert a hidl_vec<KeyParameter> to a freshly-allocated
 * VECTOR(KM_KeyParameter).  Blob fields are deep-copied into new vectors. */
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

/* Copy a hidl_vec<uint8_t> into a newly allocated VECTOR(uint8_t). */
static VECTOR(uint8_t) from_hidl_bytes(const hidl_vec<uint8_t> &src)
{
    VECTOR(uint8_t) out = vector_new(uint8_t);
    vector_resize(&out, src.size());
    if (src.size() > 0)
        memcpy(out, src.data(), src.size());
    return out;
}

/* Build a HardwareAuthToken from flat C fields. */
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

/* Build a VerificationToken from flat C fields. */
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

/* -------------------------------------------------------------------------
 * Error code conversion
 * ---------------------------------------------------------------------- */

static constexpr enum KM_ErrorCode from_hidl_error(ErrorCode e)
{
    return static_cast<enum KM_ErrorCode>(e);
}

/* -------------------------------------------------------------------------
 * Public C API
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * Opaque handle
 * ---------------------------------------------------------------------- */

struct hidl_suskeymaster4 {
    HidlSusKeymaster4 impl;
};

struct hidl_suskeymaster4 *hidl_suskeymaster4_new(void)
{
    auto *km = new (std::nothrow) hidl_suskeymaster4();
    if (!km)
        return nullptr;
    if (!km->impl.isHALOk()) {
        delete km;
        return nullptr;
    }
    return km;
}

void hidl_suskeymaster4_destroy(struct hidl_suskeymaster4 **km_p)
{
    if (!km_p || !*km_p)
        return;
    delete *km_p;
    *km_p = nullptr;
}

bool hidl_suskeymaster4_is_hal_ok(struct hidl_suskeymaster4 *km)
{
    if (!km) return false;
    return km->impl.isHALOk();
}

void hidl_suskeymaster4_get_hardware_info(struct hidl_suskeymaster4 *km,
        enum KM_SecurityLevel *out_security_level,
        VECTOR(char) *out_keymaster_name,
        VECTOR(char) *out_keymaster_author_name
)
{
    if (!km) return;

    SecurityLevel slvl = SecurityLevel::SOFTWARE;
    hidl_string name, author;
    km->impl.getHardwareInfo(slvl, name, author);

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

enum KM_ErrorCode hidl_suskeymaster4_get_hmac_sharing_parameters(struct hidl_suskeymaster4 *km,
        struct KM_HmacSharingParameters *out_params
)
{
    if (!km) return KM_ERR_UNEXPECTED_NULL_POINTER;

    HmacSharingParameters params{};
    ErrorCode err = km->impl.getHmacSharingParameters(params);
    if (err != ErrorCode::OK)
        return from_hidl_error(err);

    if (out_params) {
        out_params->seed = from_hidl_bytes(params.seed);
        /* both out_params->nonce & params.nonce are fixed size u8[32] arrays */
        memcpy(out_params->nonce, params.nonce.data(), 32);
    }

    return KM_OK;
}

enum KM_ErrorCode hidl_suskeymaster4_compute_shared_hmac(struct hidl_suskeymaster4 *km,
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
    ErrorCode err = km->impl.computeSharedHmac(hidl_params, sharing_check);
    if (err != ErrorCode::OK)
        return from_hidl_error(err);

    if (out_sharing_check)
        *out_sharing_check = from_hidl_bytes(sharing_check);

    return KM_OK;
}

enum KM_ErrorCode hidl_suskeymaster4_verify_authorization(struct hidl_suskeymaster4 *km,
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
    ErrorCode err = km->impl.verifyAuthorization(
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

enum KM_ErrorCode hidl_suskeymaster4_add_rng_entropy(struct hidl_suskeymaster4 *km,
        VECTOR(u8 const) data
)
{
    if (!km) return KM_ERR_UNEXPECTED_NULL_POINTER;

    hidl_vec<uint8_t> v = to_hidl_vec(data);
    return from_hidl_error(km->impl.addRngEntropy(v));
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

enum KM_ErrorCode hidl_suskeymaster4_generate_key(struct hidl_suskeymaster4 *km,
        VECTOR(struct KM_KeyParameter const) key_params,
        VECTOR(u8) *out_key_blob,                   /* caller must vector_destroy */
        struct KM_KeyCharacteristics *out_key_characteristics)
{
    if (!km) return KM_ERR_UNEXPECTED_NULL_POINTER;

    hidl_vec<KeyParameter> hidl_params = to_hidl_params(key_params);
    hidl_vec<uint8_t> key_blob;
    KeyCharacteristics kc{};

    ErrorCode err = km->impl.generateKey(hidl_params, key_blob, kc);
    if (err != ErrorCode::OK)
        return from_hidl_error(err);

    if (out_key_blob) *out_key_blob = from_hidl_bytes(key_blob);
    return unpack_key_characteristics(kc, out_key_characteristics);
}

enum KM_ErrorCode hidl_suskeymaster4_import_key(struct hidl_suskeymaster4 *km,
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

    ErrorCode err = km->impl.importKey(
            hidl_params,
            static_cast<KeyFormat>(key_format),
            hidl_key_data, key_blob, kc);
    if (err != ErrorCode::OK)
        return from_hidl_error(err);

    if (out_key_blob) *out_key_blob = from_hidl_bytes(key_blob);
    return unpack_key_characteristics(kc, out_key_characteristics);
}

enum KM_ErrorCode hidl_suskeymaster4_import_wrapped_key(struct hidl_suskeymaster4 *km,
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

    ErrorCode err = km->impl.importWrappedKey(
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

enum KM_ErrorCode hidl_suskeymaster4_get_key_characteristics(struct hidl_suskeymaster4 *km,
        VECTOR(u8 const) key_blob, VECTOR(u8 const) app_id, VECTOR(u8 const) app_data,
        struct KM_KeyCharacteristics *out_key_characteristics
)
{
    if (!km) return KM_ERR_UNEXPECTED_NULL_POINTER;

    KeyCharacteristics kc{};
    ErrorCode err = km->impl.getKeyCharacteristics(
            to_hidl_vec(key_blob),
            to_hidl_vec(app_id),
            to_hidl_vec(app_data),
            kc
    );
    if (err != ErrorCode::OK)
        return from_hidl_error(err);

    return unpack_key_characteristics(kc, out_key_characteristics);
}

enum KM_ErrorCode hidl_suskeymaster4_export_key(struct hidl_suskeymaster4 *km,
        enum KM_KeyFormat key_format, VECTOR(u8 const) key_blob,
        VECTOR(u8 const) app_id, VECTOR(u8 const) app_data,

        VECTOR(u8) *out_key_material
)
{
    if (!km) return KM_ERR_UNEXPECTED_NULL_POINTER;

    hidl_vec<uint8_t> key_material;
    ErrorCode err = km->impl.exportKey(
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

enum KM_ErrorCode hidl_suskeymaster4_attest_key(struct hidl_suskeymaster4 *km,
        VECTOR(u8 const) key_to_attest, VECTOR(struct KM_KeyParameter const) attest_params,
        VECTOR(VECTOR(u8)) *out_cert_chain /* caller must destroy each cert + the chain */
)
{
    if (!km) return KM_ERR_UNEXPECTED_NULL_POINTER;

    hidl_vec<hidl_vec<uint8_t>> cert_chain;
    ErrorCode err = km->impl.attestKey(
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

enum KM_ErrorCode hidl_suskeymaster4_upgrade_key(struct hidl_suskeymaster4 *km,
        VECTOR(u8 const) key_blob, VECTOR(struct KM_KeyParameter const) upgrade_params,
        VECTOR(u8) *out_upgraded_key_blob
)
{
    if (!km) return KM_ERR_UNEXPECTED_NULL_POINTER;

    hidl_vec<uint8_t> upgraded;
    ErrorCode err = km->impl.upgradeKey(
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

enum KM_ErrorCode hidl_suskeymaster4_delete_key(struct hidl_suskeymaster4 *km,
        VECTOR(u8 const) key_blob)
{
    if (!km) return KM_ERR_UNEXPECTED_NULL_POINTER;
    return from_hidl_error(km->impl.deleteKey(to_hidl_vec(key_blob)));
}

enum KM_ErrorCode hidl_suskeymaster4_delete_all_keys(struct hidl_suskeymaster4 *km)
{
    if (!km) return KM_ERR_UNEXPECTED_NULL_POINTER;
    return from_hidl_error(km->impl.deleteAllKeys());
}

enum KM_ErrorCode hidl_suskeymaster4_destroy_attestation_ids(struct hidl_suskeymaster4 *km)
{
    if (!km) return KM_ERR_UNEXPECTED_NULL_POINTER;
    return from_hidl_error(km->impl.destroyAttestationIds());
}

enum KM_ErrorCode hidl_suskeymaster4_begin(struct hidl_suskeymaster4 *km,
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

    ErrorCode err = km->impl.begin(
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

enum KM_ErrorCode hidl_suskeymaster4_update(struct hidl_suskeymaster4 *km,
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

    ErrorCode err = km->impl.update(
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

enum KM_ErrorCode hidl_suskeymaster4_finish(struct hidl_suskeymaster4 *km,
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

    ErrorCode err = km->impl.finish(
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

enum KM_ErrorCode hidl_suskeymaster4_abort(
        struct hidl_suskeymaster4 *km,
        uint64_t operation_handle)
{
    if (!km) return KM_ERR_UNEXPECTED_NULL_POINTER;
    return from_hidl_error(km->impl.abort(operation_handle));
}

} /* extern "C" */
} /* namespace hidl */
} /* namespace kmhal */
} /* namespace suskeymaster */
