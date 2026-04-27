#ifndef SUSKEYMASTER_HAL_DISABLE_4_0
#define HIDL_DISABLE_INSTRUMENTATION
#include "hidl-hal.hpp"
#include <core/vector.h>
#include <hidl/HidlSupport.h>
#include <android/hardware/keymaster/4.0/types.h>
#include <android/hardware/keymaster/generic/types.h>
#ifndef SUSKEYMASTER_BUILD_HOST
#include <android/hardware/keymaster/4.0/IKeymasterDevice.h>
#endif /* SUSKEYMASTER_BUILD_HOST */

using namespace ::android::hardware::keymaster::generic;
using ::android::hardware::hidl_vec;

namespace suskeymaster {
namespace kmhal {
namespace hidl {

#ifndef SUSKEYMASTER_BUILD_HOST

HidlSusKeymaster4_0::HidlSusKeymaster4_0(void)
{
    this->hal = ::android::hardware::keymaster::V4_0::IKeymasterDevice::tryGetService();
}

bool HidlSusKeymaster4_0::isHALOk(void)
{
    if (!this->hal)
        return false;

    return this->hal->ping().isOk();
}

using ErrorCode_4_0 = ::android::hardware::keymaster::V4_0::ErrorCode;
using KeyFormat_4_0 = ::android::hardware::keymaster::V4_0::KeyFormat;
using KeyPurpose_4_0 = ::android::hardware::keymaster::V4_0::KeyPurpose;
using KeyParameter_4_0 = ::android::hardware::keymaster::V4_0::KeyParameter;
using SecurityLevel_4_0 = ::android::hardware::keymaster::V4_0::SecurityLevel;
using KeyCharacteristics_4_0 = ::android::hardware::keymaster::V4_0::KeyCharacteristics;
using HardwareAuthToken_4_0 = ::android::hardware::keymaster::V4_0::HardwareAuthToken;
using VerificationToken_4_0 = ::android::hardware::keymaster::V4_0::VerificationToken;
using HmacSharingParameters_4_0 = ::android::hardware::keymaster::V4_0::HmacSharingParameters;

static constexpr ErrorCode from_4_0(ErrorCode_4_0 e) { return static_cast<ErrorCode>(e); }

static constexpr KeyFormat_4_0 to_4_0(KeyFormat e) { return static_cast<KeyFormat_4_0>(e); }

static constexpr KeyPurpose_4_0 to_4_0(KeyPurpose e) { return static_cast<KeyPurpose_4_0>(e); }

static constexpr SecurityLevel from_4_0(SecurityLevel_4_0 e) {
    return static_cast<SecurityLevel>(e);
}

static_assert(sizeof(KeyParameter) == sizeof(KeyParameter_4_0));
static_assert(alignof(KeyParameter) == alignof(KeyParameter_4_0));
static_assert(sizeof(hidl_vec<KeyParameter>) == sizeof(hidl_vec<KeyParameter_4_0>));
static_assert(alignof(hidl_vec<KeyParameter>) == alignof(hidl_vec<KeyParameter_4_0>));
static const hidl_vec<KeyParameter_4_0>& to_4_0(const hidl_vec<KeyParameter>& params)
{
    /* V4.0 and `generic` KeyParameter structs are identical */
    return *reinterpret_cast<const hidl_vec<KeyParameter_4_0> *>(&params);
}
static const hidl_vec<KeyParameter>& from_4_0(const hidl_vec<KeyParameter_4_0>& params)
{
    return *reinterpret_cast<const hidl_vec<KeyParameter> *>(&params);
}


static_assert(sizeof(KeyCharacteristics) == sizeof(KeyCharacteristics_4_0));
static_assert(alignof(KeyCharacteristics) == alignof(KeyCharacteristics_4_0));
static const KeyCharacteristics& from_4_0(const KeyCharacteristics_4_0& kc)
{
    /* V4.0 and `generic` KeyCharacteristics structs are identical */
    return *reinterpret_cast<const KeyCharacteristics *>(&kc);
}

static_assert(sizeof(HardwareAuthToken) == sizeof(HardwareAuthToken_4_0));
static_assert(alignof(HardwareAuthToken) == alignof(HardwareAuthToken_4_0));
static const HardwareAuthToken_4_0& to_4_0(const HardwareAuthToken& at)
{
    /* V4.0 and `generic` HardwareAuthToken structs are identical */
    return *reinterpret_cast<const HardwareAuthToken_4_0 *>(&at);
}

static_assert(sizeof(VerificationToken) == sizeof(VerificationToken_4_0));
static_assert(alignof(VerificationToken) == alignof(VerificationToken_4_0));
static const VerificationToken_4_0& to_4_0(const VerificationToken& vt)
{
    /* V4.0 and `generic` VerificationToken structs are identical */
    return *reinterpret_cast<const VerificationToken_4_0 *>(&vt);
}
static const VerificationToken& from_4_0(const VerificationToken_4_0& vt)
{
    return *reinterpret_cast<const VerificationToken *>(&vt);
}

static_assert(sizeof(HmacSharingParameters) == sizeof(HmacSharingParameters_4_0));
static_assert(alignof(HmacSharingParameters) == alignof(HmacSharingParameters_4_0));
static_assert(sizeof(hidl_vec<HmacSharingParameters>) ==
        sizeof(hidl_vec<HmacSharingParameters_4_0>));
static_assert(alignof(hidl_vec<HmacSharingParameters>) ==
        alignof(hidl_vec<HmacSharingParameters_4_0>));
static const HmacSharingParameters& from_4_0(const HmacSharingParameters_4_0& sp)
{
    return *reinterpret_cast<const HmacSharingParameters *>(&sp);
}
static const hidl_vec<HmacSharingParameters_4_0>& to_4_0(
        const hidl_vec<HmacSharingParameters>& sp_vec
)
{
    return *reinterpret_cast<const hidl_vec<HmacSharingParameters_4_0> *>(&sp_vec);
}

#define check_hal_ok() do {                                         \
    if (!this->isHALOk()) {                                         \
        std::cerr << __func__ << ": HAL is not OK!" << std::endl;   \
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;           \
    }                                                               \
} while (0)

void HidlSusKeymaster4_0::getHardwareInfo(SecurityLevel& out_securityLevel,
        hidl_string& out_keymasterName, hidl_string& out_keymasterAuthorName)
{
    if (!this->isHALOk()) {
        out_securityLevel = SecurityLevel::SOFTWARE;
        out_keymasterName = "N/A";
        out_keymasterAuthorName = "N/A";
        return;
    }

    this->hal->getHardwareInfo(
        [&](SecurityLevel_4_0 securityLevel,
            const auto& keymasterName, const auto& keymasterAuthorName)
        {
            out_securityLevel = from_4_0(securityLevel);
            out_keymasterName = keymasterName;
            out_keymasterAuthorName = keymasterAuthorName;
        }
    );
}

ErrorCode HidlSusKeymaster4_0::getHmacSharingParameters(HmacSharingParameters& out_params)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

    this->hal->getHmacSharingParameters([&](ErrorCode_4_0 err,
                const HmacSharingParameters_4_0& params)
        {
            ret = from_4_0(err);
            if (err == ErrorCode_4_0::OK)
                out_params = from_4_0(params);
        }
    );
    return ret;
}

ErrorCode HidlSusKeymaster4_0::computeSharedHmac(hidl_vec<HmacSharingParameters> const& params,
            hidl_vec<uint8_t>& out_sharingCheck)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

    this->hal->computeSharedHmac(to_4_0(params), [&](ErrorCode_4_0 err, const auto& sharingCheck)
        {
            ret = from_4_0(err);
            if (err == ErrorCode_4_0::OK)
                out_sharingCheck = sharingCheck;
        }
    );
    return ret;
}

ErrorCode HidlSusKeymaster4_0::verifyAuthorization(uint64_t operationHandle,
            hidl_vec<KeyParameter> const& parametersToVerify, HardwareAuthToken const& authToken,
            VerificationToken& out_token)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

    this->hal->verifyAuthorization(operationHandle,
            to_4_0(parametersToVerify), to_4_0(authToken),
        [&](ErrorCode_4_0 err, const VerificationToken_4_0& token)
        {
            ret = from_4_0(err);
            if (err == ErrorCode_4_0::OK)
                out_token = from_4_0(token);
        }
    );
    return ret;
}

ErrorCode HidlSusKeymaster4_0::addRngEntropy(hidl_vec<uint8_t> const& data)
{
    check_hal_ok();
    return from_4_0(this->hal->addRngEntropy(data));
}

ErrorCode HidlSusKeymaster4_0::generateKey(hidl_vec<KeyParameter> const& keyParams,
        hidl_vec<uint8_t>& out_keyBlob,
        KeyCharacteristics& out_keyCharacteristics)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

    this->hal->generateKey(to_4_0(keyParams),
        [&](ErrorCode_4_0 error, auto const& keyBlob,
            KeyCharacteristics_4_0 const& keyCharacteristics)
        {
            ret = from_4_0(error);
            if (error == ErrorCode_4_0::OK) {
                out_keyBlob = keyBlob;
                out_keyCharacteristics = from_4_0(keyCharacteristics);
            }
        }
    );
    return ret;
}

ErrorCode HidlSusKeymaster4_0::importKey(hidl_vec<KeyParameter> const& keyParams,
        KeyFormat keyFormat, hidl_vec<uint8_t> const& keyData,
        hidl_vec<uint8_t>& out_keyBlob,
        KeyCharacteristics& out_keyCharacteristics)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

    this->hal->importKey(to_4_0(keyParams), to_4_0(keyFormat), keyData,
        [&](ErrorCode_4_0 error, auto const& keyBlob, auto const& keyCharacteristics) {
            ret = from_4_0(error);
            if (error == ErrorCode_4_0::OK) {
                out_keyBlob = keyBlob;
                out_keyCharacteristics = from_4_0(keyCharacteristics);
            }
        }
    );
    return ret;
}

ErrorCode HidlSusKeymaster4_0::importWrappedKey(hidl_vec<uint8_t> const& wrappedKeyData,
            hidl_vec<uint8_t> const& wrappingKeyBlob, hidl_vec<uint8_t> const& maskingKey,
            hidl_vec<KeyParameter> const& unwrappingParams,
            uint64_t passwordSid, uint64_t biometricSid,
            hidl_vec<uint8_t>& out_keyBlob, KeyCharacteristics& out_keyCharacteristics)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

    this->hal->importWrappedKey(wrappedKeyData, wrappingKeyBlob, maskingKey,
            to_4_0(unwrappingParams), passwordSid, biometricSid,
        [&](ErrorCode_4_0 err, const auto& keyBlob, const auto& keyCharacteristics)
        {
            ret = from_4_0(err);
            if (err == ErrorCode_4_0::OK) {
                out_keyBlob = keyBlob;
                out_keyCharacteristics = from_4_0(keyCharacteristics);
            }
        }
    );
    return ret;
}

ErrorCode HidlSusKeymaster4_0::getKeyCharacteristics(
        hidl_vec<uint8_t> const& keyBlob,
        hidl_vec<uint8_t> const& applicationId,
        hidl_vec<uint8_t> const& applicationData,
        KeyCharacteristics& out_keyCharacteristics)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

    this->hal->getKeyCharacteristics(keyBlob, applicationId, applicationData,
        [&](ErrorCode_4_0 error, auto const& keyCharacteristics) {
            ret = from_4_0(error);
            if (error == ErrorCode_4_0::OK)
                out_keyCharacteristics = from_4_0(keyCharacteristics);
        }
    );
    return ret;
}

ErrorCode HidlSusKeymaster4_0::exportKey(KeyFormat keyFormat,
        hidl_vec<uint8_t> const& keyBlob,
        hidl_vec<uint8_t> const& applicationId,
        hidl_vec<uint8_t> const& applicationData,
        hidl_vec<uint8_t>& out_keyMaterial)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

    this->hal->exportKey(to_4_0(keyFormat), keyBlob, applicationId, applicationData,
        [&](ErrorCode_4_0 error, auto const& keyMaterial) {
            ret = from_4_0(error);
            if (error == ErrorCode_4_0::OK)
                out_keyMaterial = keyMaterial;
        }
    );
    return ret;
}

ErrorCode HidlSusKeymaster4_0::attestKey(
        hidl_vec<uint8_t> const& keyToAttest,
        hidl_vec<KeyParameter> const& attestParams,
        hidl_vec<hidl_vec<uint8_t>>& out_certChain)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

    this->hal->attestKey(keyToAttest, to_4_0(attestParams),
        [&](ErrorCode_4_0 error, auto const& certChain) {
            ret = from_4_0(error);
            if (error == ErrorCode_4_0::OK)
                out_certChain = certChain;
        }
    );
    return ret;
}

ErrorCode HidlSusKeymaster4_0::upgradeKey(
        hidl_vec<uint8_t> const& keyBlobToUpgrade,
        hidl_vec<KeyParameter> const& upgradeParams,
        hidl_vec<uint8_t>& out_upgradedKeyBlob)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

    this->hal->upgradeKey(keyBlobToUpgrade, to_4_0(upgradeParams),
        [&](ErrorCode_4_0 error, auto const& upgradedKeyBlob) {
            ret = from_4_0(error);
            if (error == ErrorCode_4_0::OK)
                out_upgradedKeyBlob = upgradedKeyBlob;
        }
    );
    return ret;
}

ErrorCode HidlSusKeymaster4_0::deleteKey(hidl_vec<uint8_t> const& keyBlob)
{
    check_hal_ok();
    return from_4_0(this->hal->deleteKey(keyBlob));
}

ErrorCode HidlSusKeymaster4_0::deleteAllKeys(void)
{
    check_hal_ok();
    return from_4_0(this->hal->deleteAllKeys());
}

ErrorCode HidlSusKeymaster4_0::destroyAttestationIds(void)
{
    check_hal_ok();
    return from_4_0(this->hal->destroyAttestationIds());
}

ErrorCode HidlSusKeymaster4_0::begin(KeyPurpose purpose,
        hidl_vec<uint8_t> const& keyBlob,
        hidl_vec<KeyParameter> const& inParams,
        HardwareAuthToken const& authToken,
        hidl_vec<KeyParameter>& out_outParams,
        uint64_t& out_operationHandle)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

    this->hal->begin(to_4_0(purpose), keyBlob, to_4_0(inParams), to_4_0(authToken),
        [&](ErrorCode_4_0 error, auto const& outParams, uint64_t operationHandle) {
            ret = from_4_0(error);
            if (error == ErrorCode_4_0::OK) {
                out_outParams = from_4_0(outParams);
                out_operationHandle = operationHandle;
            }
        }
    );
    return ret;
}

ErrorCode HidlSusKeymaster4_0::update(uint64_t operationHandle,
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

    this->hal->update(operationHandle, to_4_0(inParams), input,
            to_4_0(authToken), to_4_0(verificationToken),
        [&](ErrorCode_4_0 error, uint32_t inputConsumed,
            auto const& outParams, auto const& output) {
            ret = from_4_0(error);
            if (error == ErrorCode_4_0::OK) {
                out_inputConsumed = inputConsumed;
                out_outParams = from_4_0(outParams);
                out_output = output;
            }
        }
    );
    return ret;
}

ErrorCode HidlSusKeymaster4_0::finish(uint64_t operationHandle,
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

    this->hal->finish(operationHandle, to_4_0(inParams), input, signature,
            to_4_0(authToken), to_4_0(verificationToken),
        [&](ErrorCode_4_0 error, auto const& outParams, auto const& output) {
            ret = from_4_0(error);
            if (error == ErrorCode_4_0::OK) {
                out_outParams = from_4_0(outParams);
                out_output = output;
            }
        }
    );
    return ret;
}

ErrorCode HidlSusKeymaster4_0::abort(uint64_t operationHandle)
{
    check_hal_ok();
    return from_4_0(this->hal->abort(operationHandle));
}

#undef check_hal_ok

#else /* SUSKEYMASTER_BUILD_HOST */

HidlSusKeymaster4_0::HidlSusKeymaster4_0(void)
{
}

bool HidlSusKeymaster4_0::isHALOk(void)
{
    std::cerr << "Keymaster 4.0 HIDL HAL not available in host build!" << std::endl;
    return false;
}

#endif /* SUSKEYMASTER_BUILD_HOST */

} /* namespace hidl */
} /* namespace kmhal */
} /* namespace suskeymaster */
#endif /* SUSKEYMASTER_HAL_DISABLE_4_0 */
