#ifndef SUSKEYMASTER_HIDL_HAL_HPP_
#define SUSKEYMASTER_HIDL_HAL_HPP_

#include <cstdint>
#include <utils/StrongPointer.h>

#include <android/hardware/keymaster/4.0/types.h>
#ifndef SUSKEYMASTER_BUILD_HOST
#include <android/hardware/keymaster/4.0/IKeymasterDevice.h>
#endif /* SUSKEYMASTER_BUILD_HOST */

namespace suskeymaster {
namespace kmhal {
namespace hidl {

using namespace ::android::hardware::keymaster::V4_0;
using namespace ::android::hardware;

class HidlSusKeymaster4 {

private:
#ifndef SUSKEYMASTER_BUILD_HOST
    ::android::sp<::android::hardware::keymaster::V4_0::IKeymasterDevice> hal;
#endif /* SUSKEYMASTER_BUILD_HOST */

public:
    HidlSusKeymaster4();
    bool isHALOk(void);

    void getHardwareInfo(SecurityLevel& out_securityLevel,
            hidl_string& out_keymasterName, hidl_string& out_keymasterAuthorName);

    ErrorCode getHmacSharingParameters(HmacSharingParameters &out_params);

    ErrorCode computeSharedHmac(hidl_vec<HmacSharingParameters> const& params,
            hidl_vec<uint8_t>& out_sharingCheck);

    ErrorCode verifyAuthorization(uint64_t operationHandle,
            hidl_vec<KeyParameter> const& parametersToVerify, HardwareAuthToken const& authToken,
            VerificationToken& out_token);

    ErrorCode addRngEntropy(hidl_vec<uint8_t> const& data);

    ErrorCode generateKey(hidl_vec<KeyParameter> const& keyParams,
            hidl_vec<uint8_t>& out_keyBlob, KeyCharacteristics& out_keyCharacteristics);

    ErrorCode importKey(hidl_vec<KeyParameter> const& keyParams,
            KeyFormat keyFormat, hidl_vec<uint8_t> const& keyData,
            hidl_vec<uint8_t>& out_keyBlob, KeyCharacteristics& out_keyCharacteristics);

    ErrorCode importWrappedKey(hidl_vec<uint8_t> const& wrappedKeyData,
            hidl_vec<uint8_t> const& wrappingKeyBlob, hidl_vec<uint8_t> const& maskingKey,
            hidl_vec<KeyParameter> const& unwrappingParams,
            uint64_t passwordSid, uint64_t biometricSid,
            hidl_vec<uint8_t>& out_keyBlob, KeyCharacteristics& out_keyCharacteristics);

    ErrorCode getKeyCharacteristics(hidl_vec<uint8_t> const& keyBlob,
            hidl_vec<uint8_t> const& applicationId, hidl_vec<uint8_t> const& applicationData,
            KeyCharacteristics& out_keyCharacteristics);

    ErrorCode exportKey(KeyFormat keyFormat, hidl_vec<uint8_t> const& keyBlob,
            hidl_vec<uint8_t> const& applicationId, hidl_vec<uint8_t> const& applicationData,
            hidl_vec<uint8_t>& out_keyMaterial);

    ErrorCode attestKey(hidl_vec<uint8_t> const& keyToAttest,
            hidl_vec<KeyParameter> const& attestParams,
            hidl_vec<hidl_vec<uint8_t>>& out_certChain);

    ErrorCode upgradeKey(hidl_vec<uint8_t> const& keyBlobToUpgrade,
            hidl_vec<KeyParameter> const& upgradeParams, hidl_vec<uint8_t>& out_upgradedKeyBlob);

    ErrorCode deleteKey(hidl_vec<uint8_t> const& keyBlob);

    ErrorCode deleteAllKeys(void);

    ErrorCode destroyAttestationIds(void);

    ErrorCode begin(KeyPurpose purpose, hidl_vec<uint8_t> const& keyBlob,
            hidl_vec<KeyParameter> const& inParams, HardwareAuthToken const& authToken,
            hidl_vec<KeyParameter>& out_outParams, uint64_t& out_operationHandle);

    ErrorCode update(uint64_t operationHandle,
            hidl_vec<KeyParameter> const& inParams, hidl_vec<uint8_t> const& input,
            HardwareAuthToken const& authToken, VerificationToken const& verificationToken,
            uint32_t& out_inputConsumed, hidl_vec<KeyParameter>& out_outParams,
            hidl_vec<uint8_t>& out_output);

    ErrorCode finish(uint64_t operationHandle, hidl_vec<KeyParameter> const& inParams,
            hidl_vec<uint8_t> const& input, hidl_vec<uint8_t> const& signature,
            HardwareAuthToken const& authToken, VerificationToken const& verificationToken,
            hidl_vec<KeyParameter>& out_outParams, hidl_vec<uint8_t>& out_output);

    ErrorCode abort(uint64_t operationHandle);
};

} /* namespace hidl */
} /* namespace kmhal */
} /* namespace suskeymaster */

#endif /* SUSKEYMASTER_HIDL_HAL_HPP_ */
