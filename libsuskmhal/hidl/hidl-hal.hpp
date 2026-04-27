#ifndef SUSKEYMASTER_HIDL_HAL_HPP_
#define SUSKEYMASTER_HIDL_HAL_HPP_

#include <cstdint>
#include <utils/StrongPointer.h>

#include <android/hardware/keymaster/generic/types.h>
#ifndef SUSKEYMASTER_BUILD_HOST
#include <android/hardware/keymaster/3.0/IKeymasterDevice.h>
#include <android/hardware/keymaster/4.0/IKeymasterDevice.h>
#include <android/hardware/keymaster/4.1/IKeymasterDevice.h>
#endif /* SUSKEYMASTER_BUILD_HOST */

namespace suskeymaster {
namespace kmhal {
namespace hidl {

using namespace ::android::hardware::keymaster::generic;
using namespace ::android::hardware;

class HidlSusKeymaster {
public:
    HidlSusKeymaster(void) = default;
    virtual ~HidlSusKeymaster(void) = default;

    virtual bool isHALOk(void) { return false; };

    virtual void getHardwareInfo(SecurityLevel& out_securityLevel,
            hidl_string& out_keymasterName, hidl_string& out_keymasterAuthorName)
    {
        out_securityLevel = SecurityLevel::SOFTWARE;
        out_keymasterName = "N/A";
        out_keymasterAuthorName = "N/A";
    }

    virtual ErrorCode getHmacSharingParameters(HmacSharingParameters &out_params) {
        (void) out_params;
        return ErrorCode::UNIMPLEMENTED;
    }

    virtual ErrorCode computeSharedHmac(hidl_vec<HmacSharingParameters> const& params,
            hidl_vec<uint8_t>& out_sharingCheck)
    {
        (void) params; (void) out_sharingCheck;
        return ErrorCode::UNIMPLEMENTED;
    }

    virtual ErrorCode verifyAuthorization(uint64_t operationHandle,
            hidl_vec<KeyParameter> const& parametersToVerify, HardwareAuthToken const& authToken,
            VerificationToken& out_token)
    {
        (void) operationHandle; (void) parametersToVerify; (void) authToken; (void) out_token;
        return ErrorCode::UNIMPLEMENTED;
    }

    virtual ErrorCode addRngEntropy(hidl_vec<uint8_t> const& data) {
        (void) data; return ErrorCode::UNIMPLEMENTED;
    }

    virtual ErrorCode generateKey(hidl_vec<KeyParameter> const& keyParams,
            hidl_vec<uint8_t>& out_keyBlob, KeyCharacteristics& out_keyCharacteristics)
    {
        (void) keyParams; (void) out_keyBlob; (void) out_keyCharacteristics;
        return ErrorCode::UNIMPLEMENTED;
    }

    virtual ErrorCode importKey(hidl_vec<KeyParameter> const& keyParams,
            KeyFormat keyFormat, hidl_vec<uint8_t> const& keyData,
            hidl_vec<uint8_t>& out_keyBlob, KeyCharacteristics& out_keyCharacteristics)
    {
        (void) keyParams; (void) keyFormat; (void) keyData;
        (void) out_keyBlob; (void) out_keyCharacteristics;
        return ErrorCode::UNIMPLEMENTED;
    }

    virtual ErrorCode importWrappedKey(hidl_vec<uint8_t> const& wrappedKeyData,
            hidl_vec<uint8_t> const& wrappingKeyBlob, hidl_vec<uint8_t> const& maskingKey,
            hidl_vec<KeyParameter> const& unwrappingParams,
            uint64_t passwordSid, uint64_t biometricSid,
            hidl_vec<uint8_t>& out_keyBlob, KeyCharacteristics& out_keyCharacteristics)
    {
        (void) wrappedKeyData; (void) wrappingKeyBlob; (void) maskingKey; (void) unwrappingParams;
        (void) passwordSid; (void) biometricSid; (void) out_keyBlob; (void) out_keyCharacteristics;
        return ErrorCode::UNIMPLEMENTED;
    }

    virtual ErrorCode getKeyCharacteristics(hidl_vec<uint8_t> const& keyBlob,
            hidl_vec<uint8_t> const& applicationId, hidl_vec<uint8_t> const& applicationData,
            KeyCharacteristics& out_keyCharacteristics)
    {
        (void) keyBlob; (void) applicationId; (void) applicationData;
        (void) out_keyCharacteristics;
        return ErrorCode::UNIMPLEMENTED;
    }

    virtual ErrorCode exportKey(KeyFormat keyFormat, hidl_vec<uint8_t> const& keyBlob,
            hidl_vec<uint8_t> const& applicationId, hidl_vec<uint8_t> const& applicationData,
            hidl_vec<uint8_t>& out_keyMaterial)
    {
        (void) keyFormat; (void) keyBlob; (void) applicationId; (void) applicationData;
        (void) out_keyMaterial;
        return ErrorCode::UNIMPLEMENTED;
    }

    virtual ErrorCode attestKey(hidl_vec<uint8_t> const& keyToAttest,
            hidl_vec<KeyParameter> const& attestParams,
            hidl_vec<hidl_vec<uint8_t>>& out_certChain)
    {
        (void) keyToAttest; (void) attestParams; (void) out_certChain;
        return ErrorCode::UNIMPLEMENTED;
    }

    virtual ErrorCode upgradeKey(hidl_vec<uint8_t> const& keyBlobToUpgrade,
            hidl_vec<KeyParameter> const& upgradeParams, hidl_vec<uint8_t>& out_upgradedKeyBlob)
    {
        (void) keyBlobToUpgrade; (void) upgradeParams; (void) out_upgradedKeyBlob;
        return ErrorCode::UNIMPLEMENTED;
    }

    virtual ErrorCode deleteKey(hidl_vec<uint8_t> const& keyBlob) {
        (void) keyBlob; return ErrorCode::UNIMPLEMENTED;
    }

    virtual ErrorCode deleteAllKeys(void) { return ErrorCode::UNIMPLEMENTED; }

    virtual ErrorCode destroyAttestationIds(void) { return ErrorCode::UNIMPLEMENTED; }

    virtual ErrorCode begin(KeyPurpose purpose, hidl_vec<uint8_t> const& keyBlob,
            hidl_vec<KeyParameter> const& inParams, HardwareAuthToken const& authToken,
            hidl_vec<KeyParameter>& out_outParams, uint64_t& out_operationHandle)
    {
        (void) purpose; (void) keyBlob; (void) inParams; (void) authToken;
        (void) out_outParams; (void) out_operationHandle;
        return ErrorCode::UNIMPLEMENTED;
    }

    virtual ErrorCode update(uint64_t operationHandle,
            hidl_vec<KeyParameter> const& inParams, hidl_vec<uint8_t> const& input,
            HardwareAuthToken const& authToken, VerificationToken const& verificationToken,
            uint32_t& out_inputConsumed, hidl_vec<KeyParameter>& out_outParams,
            hidl_vec<uint8_t>& out_output)
    {
        (void) operationHandle; (void) inParams; (void) input;
        (void) authToken; (void) verificationToken;
        (void) out_inputConsumed; (void) out_outParams; (void) out_output;
        return ErrorCode::UNIMPLEMENTED;
    }

    virtual ErrorCode finish(uint64_t operationHandle, hidl_vec<KeyParameter> const& inParams,
            hidl_vec<uint8_t> const& input, hidl_vec<uint8_t> const& signature,
            HardwareAuthToken const& authToken, VerificationToken const& verificationToken,
            hidl_vec<KeyParameter>& out_outParams, hidl_vec<uint8_t>& out_output)
    {
        (void) operationHandle; (void) inParams; (void) input; (void) signature;
        (void) authToken; (void) verificationToken;
        (void) out_outParams; (void) out_output;
        return ErrorCode::UNIMPLEMENTED;
    }

    virtual ErrorCode abort(uint64_t operationHandle) {
        (void) operationHandle; return ErrorCode::UNIMPLEMENTED;
    }
};

#ifndef SUSKEYMASTER_HAL_DISABLE_3_0

class HidlSusKeymaster3_0 : public HidlSusKeymaster {
public:
    HidlSusKeymaster3_0(void);

    bool isHALOk(void) override;

#ifndef SUSKEYMASTER_BUILD_HOST
private:
    ::android::sp<::android::hardware::keymaster::V3_0::IKeymasterDevice> hal;

public:

    void getHardwareInfo(SecurityLevel& out_securityLevel,
            hidl_string& out_keymasterName, hidl_string& out_keymasterAuthorName) override;

    ErrorCode addRngEntropy(hidl_vec<uint8_t> const& data) override;

    ErrorCode generateKey(hidl_vec<KeyParameter> const& keyParams,
            hidl_vec<uint8_t>& out_keyBlob, KeyCharacteristics& out_keyCharacteristics) override;

    ErrorCode importKey(hidl_vec<KeyParameter> const& keyParams,
            KeyFormat keyFormat, hidl_vec<uint8_t> const& keyData,
            hidl_vec<uint8_t>& out_keyBlob, KeyCharacteristics& out_keyCharacteristics) override;

    ErrorCode getKeyCharacteristics(hidl_vec<uint8_t> const& keyBlob,
            hidl_vec<uint8_t> const& applicationId, hidl_vec<uint8_t> const& applicationData,
            KeyCharacteristics& out_keyCharacteristics) override;

    ErrorCode exportKey(KeyFormat keyFormat, hidl_vec<uint8_t> const& keyBlob,
            hidl_vec<uint8_t> const& applicationId, hidl_vec<uint8_t> const& applicationData,
            hidl_vec<uint8_t>& out_keyMaterial) override;

    ErrorCode attestKey(hidl_vec<uint8_t> const& keyToAttest,
            hidl_vec<KeyParameter> const& attestParams,
            hidl_vec<hidl_vec<uint8_t>>& out_certChain) override;

    ErrorCode upgradeKey(hidl_vec<uint8_t> const& keyBlobToUpgrade,
            hidl_vec<KeyParameter> const& upgradeParams, hidl_vec<uint8_t>& out_upgradedKeyBlob)
        override;

    ErrorCode deleteKey(hidl_vec<uint8_t> const& keyBlob) override;

    ErrorCode deleteAllKeys(void) override;

    ErrorCode destroyAttestationIds(void) override;

    ErrorCode begin(KeyPurpose purpose, hidl_vec<uint8_t> const& keyBlob,
            hidl_vec<KeyParameter> const& inParams, HardwareAuthToken const& authToken,
            hidl_vec<KeyParameter>& out_outParams, uint64_t& out_operationHandle) override;

    ErrorCode update(uint64_t operationHandle,
            hidl_vec<KeyParameter> const& inParams, hidl_vec<uint8_t> const& input,
            HardwareAuthToken const& authToken, VerificationToken const& verificationToken,
            uint32_t& out_inputConsumed, hidl_vec<KeyParameter>& out_outParams,
            hidl_vec<uint8_t>& out_output) override;

    ErrorCode finish(uint64_t operationHandle, hidl_vec<KeyParameter> const& inParams,
            hidl_vec<uint8_t> const& input, hidl_vec<uint8_t> const& signature,
            HardwareAuthToken const& authToken, VerificationToken const& verificationToken,
            hidl_vec<KeyParameter>& out_outParams, hidl_vec<uint8_t>& out_output) override;

    ErrorCode abort(uint64_t operationHandle) override;
#endif /* SUSKEYMASTER_BUILD_HOST */
};

#endif /* SUSKEYMASTER_HAL_DISABLE_3_0 */

#ifndef SUSKEYMASTER_HAL_DISABLE_4_0

class HidlSusKeymaster4_0 : public HidlSusKeymaster {
public:
    HidlSusKeymaster4_0(void);

    bool isHALOk(void) override;

#ifndef SUSKEYMASTER_BUILD_HOST
private:
    ::android::sp<::android::hardware::keymaster::V4_0::IKeymasterDevice> hal;

public:

    void getHardwareInfo(SecurityLevel& out_securityLevel,
            hidl_string& out_keymasterName, hidl_string& out_keymasterAuthorName) override;

    ErrorCode getHmacSharingParameters(HmacSharingParameters &out_params) override;

    ErrorCode computeSharedHmac(hidl_vec<HmacSharingParameters> const& params,
            hidl_vec<uint8_t>& out_sharingCheck) override;

    ErrorCode verifyAuthorization(uint64_t operationHandle,
            hidl_vec<KeyParameter> const& parametersToVerify, HardwareAuthToken const& authToken,
            VerificationToken& out_token) override;

    ErrorCode addRngEntropy(hidl_vec<uint8_t> const& data) override;

    ErrorCode generateKey(hidl_vec<KeyParameter> const& keyParams,
            hidl_vec<uint8_t>& out_keyBlob, KeyCharacteristics& out_keyCharacteristics) override;

    ErrorCode importKey(hidl_vec<KeyParameter> const& keyParams,
            KeyFormat keyFormat, hidl_vec<uint8_t> const& keyData,
            hidl_vec<uint8_t>& out_keyBlob, KeyCharacteristics& out_keyCharacteristics) override;

    ErrorCode importWrappedKey(hidl_vec<uint8_t> const& wrappedKeyData,
            hidl_vec<uint8_t> const& wrappingKeyBlob, hidl_vec<uint8_t> const& maskingKey,
            hidl_vec<KeyParameter> const& unwrappingParams,
            uint64_t passwordSid, uint64_t biometricSid,
            hidl_vec<uint8_t>& out_keyBlob, KeyCharacteristics& out_keyCharacteristics) override;

    ErrorCode getKeyCharacteristics(hidl_vec<uint8_t> const& keyBlob,
            hidl_vec<uint8_t> const& applicationId, hidl_vec<uint8_t> const& applicationData,
            KeyCharacteristics& out_keyCharacteristics) override;

    ErrorCode exportKey(KeyFormat keyFormat, hidl_vec<uint8_t> const& keyBlob,
            hidl_vec<uint8_t> const& applicationId, hidl_vec<uint8_t> const& applicationData,
            hidl_vec<uint8_t>& out_keyMaterial) override;

    ErrorCode attestKey(hidl_vec<uint8_t> const& keyToAttest,
            hidl_vec<KeyParameter> const& attestParams,
            hidl_vec<hidl_vec<uint8_t>>& out_certChain) override;

    ErrorCode upgradeKey(hidl_vec<uint8_t> const& keyBlobToUpgrade,
            hidl_vec<KeyParameter> const& upgradeParams, hidl_vec<uint8_t>& out_upgradedKeyBlob)
        override;

    ErrorCode deleteKey(hidl_vec<uint8_t> const& keyBlob) override;

    ErrorCode deleteAllKeys(void) override;

    ErrorCode destroyAttestationIds(void) override;

    ErrorCode begin(KeyPurpose purpose, hidl_vec<uint8_t> const& keyBlob,
            hidl_vec<KeyParameter> const& inParams, HardwareAuthToken const& authToken,
            hidl_vec<KeyParameter>& out_outParams, uint64_t& out_operationHandle) override;

    ErrorCode update(uint64_t operationHandle,
            hidl_vec<KeyParameter> const& inParams, hidl_vec<uint8_t> const& input,
            HardwareAuthToken const& authToken, VerificationToken const& verificationToken,
            uint32_t& out_inputConsumed, hidl_vec<KeyParameter>& out_outParams,
            hidl_vec<uint8_t>& out_output) override;

    ErrorCode finish(uint64_t operationHandle, hidl_vec<KeyParameter> const& inParams,
            hidl_vec<uint8_t> const& input, hidl_vec<uint8_t> const& signature,
            HardwareAuthToken const& authToken, VerificationToken const& verificationToken,
            hidl_vec<KeyParameter>& out_outParams, hidl_vec<uint8_t>& out_output) override;

    ErrorCode abort(uint64_t operationHandle) override;
#endif /* SUSKEYMASTER_BUILD_HOST */
};

#endif /* SUSKEYMASTER_HAL_DISABLE_4_0 */

#ifndef SUSKEYMASTER_HAL_DISABLE_4_1

class HidlSusKeymaster4_1 : public HidlSusKeymaster {
public:
    HidlSusKeymaster4_1(void);

    bool isHALOk(void) override;

#ifndef SUSKEYMASTER_BUILD_HOST
private:
    ::android::sp<::android::hardware::keymaster::V4_1::IKeymasterDevice> hal;

public:

    void getHardwareInfo(SecurityLevel& out_securityLevel,
            hidl_string& out_keymasterName, hidl_string& out_keymasterAuthorName) override;

    ErrorCode getHmacSharingParameters(HmacSharingParameters &out_params) override;

    ErrorCode computeSharedHmac(hidl_vec<HmacSharingParameters> const& params,
            hidl_vec<uint8_t>& out_sharingCheck) override;

    ErrorCode verifyAuthorization(uint64_t operationHandle,
            hidl_vec<KeyParameter> const& parametersToVerify, HardwareAuthToken const& authToken,
            VerificationToken& out_token) override;

    ErrorCode addRngEntropy(hidl_vec<uint8_t> const& data) override;

    ErrorCode generateKey(hidl_vec<KeyParameter> const& keyParams,
            hidl_vec<uint8_t>& out_keyBlob, KeyCharacteristics& out_keyCharacteristics) override;

    ErrorCode importKey(hidl_vec<KeyParameter> const& keyParams,
            KeyFormat keyFormat, hidl_vec<uint8_t> const& keyData,
            hidl_vec<uint8_t>& out_keyBlob, KeyCharacteristics& out_keyCharacteristics) override;

    ErrorCode importWrappedKey(hidl_vec<uint8_t> const& wrappedKeyData,
            hidl_vec<uint8_t> const& wrappingKeyBlob, hidl_vec<uint8_t> const& maskingKey,
            hidl_vec<KeyParameter> const& unwrappingParams,
            uint64_t passwordSid, uint64_t biometricSid,
            hidl_vec<uint8_t>& out_keyBlob, KeyCharacteristics& out_keyCharacteristics) override;

    ErrorCode getKeyCharacteristics(hidl_vec<uint8_t> const& keyBlob,
            hidl_vec<uint8_t> const& applicationId, hidl_vec<uint8_t> const& applicationData,
            KeyCharacteristics& out_keyCharacteristics) override;

    ErrorCode exportKey(KeyFormat keyFormat, hidl_vec<uint8_t> const& keyBlob,
            hidl_vec<uint8_t> const& applicationId, hidl_vec<uint8_t> const& applicationData,
            hidl_vec<uint8_t>& out_keyMaterial) override;

    ErrorCode attestKey(hidl_vec<uint8_t> const& keyToAttest,
            hidl_vec<KeyParameter> const& attestParams,
            hidl_vec<hidl_vec<uint8_t>>& out_certChain) override;

    ErrorCode upgradeKey(hidl_vec<uint8_t> const& keyBlobToUpgrade,
            hidl_vec<KeyParameter> const& upgradeParams, hidl_vec<uint8_t>& out_upgradedKeyBlob)
        override;

    ErrorCode deleteKey(hidl_vec<uint8_t> const& keyBlob) override;

    ErrorCode deleteAllKeys(void) override;

    ErrorCode destroyAttestationIds(void) override;

    ErrorCode begin(KeyPurpose purpose, hidl_vec<uint8_t> const& keyBlob,
            hidl_vec<KeyParameter> const& inParams, HardwareAuthToken const& authToken,
            hidl_vec<KeyParameter>& out_outParams, uint64_t& out_operationHandle) override;

    ErrorCode update(uint64_t operationHandle,
            hidl_vec<KeyParameter> const& inParams, hidl_vec<uint8_t> const& input,
            HardwareAuthToken const& authToken, VerificationToken const& verificationToken,
            uint32_t& out_inputConsumed, hidl_vec<KeyParameter>& out_outParams,
            hidl_vec<uint8_t>& out_output) override;

    ErrorCode finish(uint64_t operationHandle, hidl_vec<KeyParameter> const& inParams,
            hidl_vec<uint8_t> const& input, hidl_vec<uint8_t> const& signature,
            HardwareAuthToken const& authToken, VerificationToken const& verificationToken,
            hidl_vec<KeyParameter>& out_outParams, hidl_vec<uint8_t>& out_output) override;

    ErrorCode abort(uint64_t operationHandle) override;
#endif /* SUSKEYMASTER_BUILD_HOST */
};

#endif /* SUSKEYMASTER_HAL_DISABLE_4_1 */

} /* namespace hidl */
} /* namespace kmhal */
} /* namespace suskeymaster */

#endif /* SUSKEYMASTER_HIDL_HAL_HPP_ */
