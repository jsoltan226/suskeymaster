#ifndef SUSKEYMASTER_HAL_DISABLE_3_0
#define HIDL_DISABLE_INSTRUMENTATION
#include "hidl-hal.hpp"
#include <core/vector.h>
#include <hidl/HidlSupport.h>
#include <android/hardware/keymaster/3.0/types.h>
#include <android/hardware/keymaster/generic/types.h>
#ifndef SUSKEYMASTER_BUILD_HOST
#include <android/hardware/keymaster/3.0/IKeymasterDevice.h>
#endif /* SUSKEYMASTER_BUILD_HOST */
#include <iostream>

using namespace ::android::hardware::keymaster::generic;
using ::android::hardware::hidl_vec;

namespace suskeymaster {
namespace kmhal {
namespace hidl {

#ifndef SUSKEYMASTER_BUILD_HOST

HidlSusKeymaster3_0::HidlSusKeymaster3_0(void)
{
    this->hal = ::android::hardware::keymaster::V3_0::IKeymasterDevice::tryGetService();
}

bool HidlSusKeymaster3_0::isHALOk(void)
{
    if (!this->hal)
        return false;

    return this->hal->ping().isOk();
}

using ErrorCode_3_0 = ::android::hardware::keymaster::V3_0::ErrorCode;
using KeyFormat_3_0 = ::android::hardware::keymaster::V3_0::KeyFormat;
using KeyPurpose_3_0 = ::android::hardware::keymaster::V3_0::KeyPurpose;
using KeyParameter_3_0 = ::android::hardware::keymaster::V3_0::KeyParameter;
using KeyCharacteristics_3_0 = ::android::hardware::keymaster::V3_0::KeyCharacteristics;

static constexpr ErrorCode from_3_0(ErrorCode_3_0 e) { return static_cast<ErrorCode>(e); }

static constexpr KeyFormat_3_0 to_3_0(KeyFormat e) { return static_cast<KeyFormat_3_0>(e); }

static constexpr KeyPurpose_3_0 to_3_0(KeyPurpose e) { return static_cast<KeyPurpose_3_0>(e); }

static_assert(sizeof(KeyParameter) == sizeof(KeyParameter_3_0));
static_assert(alignof(KeyParameter) == alignof(KeyParameter_3_0));
static_assert(sizeof(hidl_vec<KeyParameter>) == sizeof(hidl_vec<KeyParameter_3_0>));
static_assert(alignof(hidl_vec<KeyParameter>) == alignof(hidl_vec<KeyParameter_3_0>));
static const hidl_vec<KeyParameter_3_0>& to_3_0(const hidl_vec<KeyParameter>& params)
{
    /* V3.0 and V4.0 KeyParameter structs are identical in layout */
    return *reinterpret_cast<const hidl_vec<KeyParameter_3_0> *>(&params);
}
static const hidl_vec<KeyParameter>& from_3_0(const hidl_vec<KeyParameter_3_0>& params)
{
    return *reinterpret_cast<const hidl_vec<KeyParameter> *>(&params);
}


static_assert(sizeof(KeyCharacteristics) == sizeof(KeyCharacteristics_3_0));
static_assert(alignof(KeyCharacteristics) == alignof(KeyCharacteristics_3_0));
static const KeyCharacteristics& from_3_0(const KeyCharacteristics_3_0& kc)
{
    return *reinterpret_cast<const KeyCharacteristics *>(&kc);
}

#define check_hal_ok() do {                                         \
    if (!this->isHALOk()) {                                         \
        std::cerr << __func__ << ": HAL is not OK!" << std::endl;   \
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;           \
    }                                                               \
} while (0)

void HidlSusKeymaster3_0::getHardwareInfo(SecurityLevel& out_securityLevel,
        hidl_string& out_keymasterName, hidl_string& out_keymasterAuthorName)
{
    if (!this->isHALOk()) {
        out_securityLevel = SecurityLevel::SOFTWARE;
        out_keymasterName = "N/A";
        out_keymasterAuthorName = "N/A";
        return;
    }

    this->hal->getHardwareFeatures(
        [&](bool isSecure,
            bool supportsEllipticCurve, bool supportsSymmetricCryptography,
            bool supportsAttestation, bool supportsAllDigests,
            const auto& keymasterName, const auto& keymasterAuthorName)
        {
            out_securityLevel = isSecure ? SecurityLevel::TRUSTED_ENVIRONMENT
                                          : SecurityLevel::SOFTWARE;
            std::cout << "Keymaster 3.0: supportsEllipticCurve: "
                    << supportsEllipticCurve << std::endl;
            std::cout << "Keymaster 3.0: supportsSymmetricCryptography: "
                    << supportsSymmetricCryptography << std::endl;
            std::cout << "Keymaster 3.0: supportsAttestation: "
                    << supportsAttestation << std::endl;
            std::cout << "Keymaster 3.0: supportsAllDigests: "
                    << supportsAllDigests << std::endl;

            out_keymasterName = keymasterName;
            out_keymasterAuthorName = keymasterAuthorName;
        }
    );
}

ErrorCode HidlSusKeymaster3_0::addRngEntropy(hidl_vec<uint8_t> const& data)
{
    check_hal_ok();
    return from_3_0(this->hal->addRngEntropy(data));
}

ErrorCode HidlSusKeymaster3_0::generateKey(hidl_vec<KeyParameter> const& keyParams,
        hidl_vec<uint8_t>& out_keyBlob,
        KeyCharacteristics& out_keyCharacteristics)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

    this->hal->generateKey(to_3_0(keyParams),
        [&](ErrorCode_3_0 error, auto const& keyBlob, KeyCharacteristics_3_0 const& keyCharacteristics) {
            ret = from_3_0(error);
            if (error == ErrorCode_3_0::OK) {
                out_keyBlob = keyBlob;
                out_keyCharacteristics = from_3_0(keyCharacteristics);
            }
        }
    );
    return ret;
}

ErrorCode HidlSusKeymaster3_0::importKey(hidl_vec<KeyParameter> const& keyParams,
        KeyFormat keyFormat, hidl_vec<uint8_t> const& keyData,
        hidl_vec<uint8_t>& out_keyBlob,
        KeyCharacteristics& out_keyCharacteristics)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

    this->hal->importKey(to_3_0(keyParams), to_3_0(keyFormat), keyData,
        [&](ErrorCode_3_0 error, auto const& keyBlob, auto const& keyCharacteristics) {
            ret = from_3_0(error);
            if (error == ErrorCode_3_0::OK) {
                out_keyBlob = keyBlob;
                out_keyCharacteristics = from_3_0(keyCharacteristics);
            }
        }
    );
    return ret;
}

ErrorCode HidlSusKeymaster3_0::getKeyCharacteristics(
        hidl_vec<uint8_t> const& keyBlob,
        hidl_vec<uint8_t> const& applicationId,
        hidl_vec<uint8_t> const& applicationData,
        KeyCharacteristics& out_keyCharacteristics)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

    this->hal->getKeyCharacteristics(keyBlob, applicationId, applicationData,
        [&](ErrorCode_3_0 error, auto const& keyCharacteristics) {
            ret = from_3_0(error);
            if (error == ErrorCode_3_0::OK)
                out_keyCharacteristics = from_3_0(keyCharacteristics);
        }
    );
    return ret;
}

ErrorCode HidlSusKeymaster3_0::exportKey(KeyFormat keyFormat,
        hidl_vec<uint8_t> const& keyBlob,
        hidl_vec<uint8_t> const& applicationId,
        hidl_vec<uint8_t> const& applicationData,
        hidl_vec<uint8_t>& out_keyMaterial)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

    this->hal->exportKey(to_3_0(keyFormat), keyBlob, applicationId, applicationData,
        [&](ErrorCode_3_0 error, auto const& keyMaterial) {
            ret = from_3_0(error);
            if (error == ErrorCode_3_0::OK)
                out_keyMaterial = keyMaterial;
        }
    );
    return ret;
}

ErrorCode HidlSusKeymaster3_0::attestKey(
        hidl_vec<uint8_t> const& keyToAttest,
        hidl_vec<KeyParameter> const& attestParams,
        hidl_vec<hidl_vec<uint8_t>>& out_certChain)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

    this->hal->attestKey(keyToAttest, to_3_0(attestParams),
        [&](ErrorCode_3_0 error, auto const& certChain) {
            ret = from_3_0(error);
            if (error == ErrorCode_3_0::OK)
                out_certChain = certChain;
        }
    );
    return ret;
}

ErrorCode HidlSusKeymaster3_0::upgradeKey(
        hidl_vec<uint8_t> const& keyBlobToUpgrade,
        hidl_vec<KeyParameter> const& upgradeParams,
        hidl_vec<uint8_t>& out_upgradedKeyBlob)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

    this->hal->upgradeKey(keyBlobToUpgrade, to_3_0(upgradeParams),
        [&](ErrorCode_3_0 error, auto const& upgradedKeyBlob) {
            ret = from_3_0(error);
            if (error == ErrorCode_3_0::OK)
                out_upgradedKeyBlob = upgradedKeyBlob;
        }
    );
    return ret;
}

ErrorCode HidlSusKeymaster3_0::deleteKey(hidl_vec<uint8_t> const& keyBlob)
{
    check_hal_ok();
    return from_3_0(this->hal->deleteKey(keyBlob));
}

ErrorCode HidlSusKeymaster3_0::deleteAllKeys(void)
{
    check_hal_ok();
    return from_3_0(this->hal->deleteAllKeys());
}

ErrorCode HidlSusKeymaster3_0::destroyAttestationIds(void)
{
    check_hal_ok();
    return from_3_0(this->hal->destroyAttestationIds());
}

ErrorCode HidlSusKeymaster3_0::begin(KeyPurpose purpose,
        hidl_vec<uint8_t> const& keyBlob,
        hidl_vec<KeyParameter> const& inParams,
        HardwareAuthToken const& authToken,
        hidl_vec<KeyParameter>& out_outParams,
        uint64_t& out_operationHandle)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

    (void) authToken;

    this->hal->begin(to_3_0(purpose), keyBlob, to_3_0(inParams),
        [&](ErrorCode_3_0 error, auto const& outParams, uint64_t operationHandle) {
            ret = from_3_0(error);
            if (error == ErrorCode_3_0::OK) {
                out_outParams = from_3_0(outParams);
                out_operationHandle = operationHandle;
            }
        }
    );
    return ret;
}

ErrorCode HidlSusKeymaster3_0::update(uint64_t operationHandle,
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

    (void) authToken;
    (void) verificationToken;

    this->hal->update(operationHandle, to_3_0(inParams), input,
        [&](ErrorCode_3_0 error, uint32_t inputConsumed,
            auto const& outParams, auto const& output) {
            ret = from_3_0(error);
            if (error == ErrorCode_3_0::OK) {
                out_inputConsumed = inputConsumed;
                out_outParams = from_3_0(outParams);
                out_output = output;
            }
        }
    );
    return ret;
}

ErrorCode HidlSusKeymaster3_0::finish(uint64_t operationHandle,
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

    (void) authToken;
    (void) verificationToken;

    this->hal->finish(operationHandle, to_3_0(inParams), input, signature,
        [&](ErrorCode_3_0 error, auto const& outParams, auto const& output) {
            ret = from_3_0(error);
            if (error == ErrorCode_3_0::OK) {
                out_outParams = from_3_0(outParams);
                out_output = output;
            }
        }
    );
    return ret;
}

ErrorCode HidlSusKeymaster3_0::abort(uint64_t operationHandle)
{
    check_hal_ok();
    return from_3_0(this->hal->abort(operationHandle));
}

#undef check_hal_ok

#else /* SUSKEYMASTER_BUILD_HOST */

HidlSusKeymaster3_0::HidlSusKeymaster3_0(void)
{
}

bool HidlSusKeymaster3_0::isHALOk(void)
{
    std::cerr << "Keymaster 3.0 HIDL HAL not available in host build!" << std::endl;
    return false;
}

#endif /* SUSKEYMASTER_BUILD_HOST */

} /* namespace hidl */
} /* namespace kmhal */
} /* namespace suskeymaster */
#endif /* SUSKEYMASTER_HAL_DISABLE_3_0 */
