#ifndef SUSKEYMASTER_SUSKMHAL_HPP_
#define SUSKEYMASTER_SUSKMHAL_HPP_

#include "keymaster-types-cpp.hpp"
#include <cstdint>
#include <memory>

#ifndef SUSKEYMASTER_BUILD_HOST
#include "transport/hal.h"
#endif /* SUSKEYMASTER_BUILD_HOST */

namespace suskeymaster {
namespace kmhal {

using namespace ::android::hardware::keymaster::generic;
using namespace ::android::hardware;

class SusKMHal {
public:
    SusKMHal(void) = default;
    virtual ~SusKMHal(void) = default;

    virtual struct kmhal_sp * getHalSp(void) { return nullptr; }

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

class SusHidlKeymasterHALCommon : public SusKMHal {
public:
    SusHidlKeymasterHALCommon() = delete; /* see below in `protected` */
    virtual ~SusHidlKeymasterHALCommon() = default;

    /* Non-copyable */
    SusHidlKeymasterHALCommon(const SusHidlKeymasterHALCommon&) = delete;
    SusHidlKeymasterHALCommon& operator=(const SusHidlKeymasterHALCommon&) = delete;

    /* Movable */
    SusHidlKeymasterHALCommon(SusHidlKeymasterHALCommon&&) = default;
    SusHidlKeymasterHALCommon& operator=(SusHidlKeymasterHALCommon&&) = default;

    struct kmhal_sp * getHalSp(void) override;
    bool isHALOk(void) override;

#ifndef SUSKEYMASTER_BUILD_HOST

public:
    /** All of the below methods are the exact same for all
     * supported HIDL KeyMaster versions (3.0, 4.0, 4.1) **/

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

    ErrorCode abort(uint64_t operationHandle) override;

protected:
    /* While the argument structure is always the exact same for these common methods,
     * the actual binder command IDs change between versions,
     * so each implementation (3.0, 4.0, 4.1) must provide a way to get the correct command ID. */
    enum KM_common_cmd {
        KM_COMMON_ADD_RNG_ENTROPY,
        KM_COMMON_GENERATE_KEY,
        KM_COMMON_IMPORT_KEY,
        KM_COMMON_GET_KEY_CHARACTERISTICS,
        KM_COMMON_EXPORT_KEY,
        KM_COMMON_ATTEST_KEY,
        KM_COMMON_UPGRADE_KEY,
        KM_COMMON_DELETE_KEY,
        KM_COMMON_DELETE_ALL_KEYS,
        KM_COMMON_DESTROY_ATTESTATION_IDS,
        KM_COMMON_ABORT
    };
    virtual u32 getVersionSpecificCmdID(enum KM_common_cmd cmd) = 0;


    /* Used for initializing the unique_ptr from derived classes */
    explicit SusHidlKeymasterHALCommon(struct kmhal_sp *new_hal) :
        hal_(new_hal, &transport::kmhal_sp_deleter) {}

    struct kmhal_sp * getHal() const { return hal_.get(); }

private:
    std::unique_ptr<struct kmhal_sp, decltype(&transport::kmhal_sp_deleter)> hal_;
#endif /* SUSKEYMASTER_BUILD_HOST */
};

#ifndef SUSKEYMASTER_HAL_DISABLE_3_0

class SusHidlKeymaster3_0 : public SusHidlKeymasterHALCommon {
public:
    SusHidlKeymaster3_0(void);

#ifndef SUSKEYMASTER_BUILD_HOST
protected:
    u32 getVersionSpecificCmdID(enum KM_common_cmd common_cmd) override;

public:
    /* For Keymaster 3.0, this is a wrapper around the older `getHardwareFeatures` method */
    void getHardwareInfo(SecurityLevel& out_securityLevel,
            hidl_string& out_keymasterName, hidl_string& out_keymasterAuthorName) override;

    /* Almost the same as in Keymaster 4.0 and 4.1,
     * but the `authToken` and `verificationToken` are actually unused by the HAL methods.
     * Instead, `authToken`s are passed in as `Tag::AUTH_TOKEN` in the parameters,
     * while the whole `verificationToken` thing doesn't even exist.
     *
     * Therefore, in Keymaster 3.0, if you provide an `authToken` to this function,
     * it will be automatically added to the parameter list as a `Tag::AUTH_TOKEN`.
     * `verificationToken` is always ignored because unfortunately there's no equivalent. */

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

#endif /* SUSKEYMASTER_BUILD_HOST */
};

#endif /* SUSKEYMASTER_HAL_DISABLE_3_0 */

#ifndef SUSKEYMASTER_HAL_DISABLE_4_0

class SusHidlKeymaster4_0 : public SusHidlKeymasterHALCommon {
public:
    SusHidlKeymaster4_0(void);

protected:
    /* c++ sucks */
    explicit SusHidlKeymaster4_0(const char *fqname, const char *instname);

#ifndef SUSKEYMASTER_BUILD_HOST
protected:
    u32 getVersionSpecificCmdID(enum KM_common_cmd common_cmd) override;

public:
    void getHardwareInfo(SecurityLevel& out_securityLevel,
            hidl_string& out_keymasterName, hidl_string& out_keymasterAuthorName) override;

    ErrorCode getHmacSharingParameters(HmacSharingParameters &out_params) override;

    ErrorCode computeSharedHmac(hidl_vec<HmacSharingParameters> const& params,
            hidl_vec<uint8_t>& out_sharingCheck) override;

    ErrorCode verifyAuthorization(uint64_t operationHandle,
            hidl_vec<KeyParameter> const& parametersToVerify, HardwareAuthToken const& authToken,
            VerificationToken& out_token) override;

    ErrorCode importWrappedKey(hidl_vec<uint8_t> const& wrappedKeyData,
            hidl_vec<uint8_t> const& wrappingKeyBlob, hidl_vec<uint8_t> const& maskingKey,
            hidl_vec<KeyParameter> const& unwrappingParams,
            uint64_t passwordSid, uint64_t biometricSid,
            hidl_vec<uint8_t>& out_keyBlob, KeyCharacteristics& out_keyCharacteristics) override;

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
#endif /* SUSKEYMASTER_BUILD_HOST */
};

#endif /* SUSKEYMASTER_HAL_DISABLE_4_0 */

#ifndef SUSKEYMASTER_HAL_DISABLE_4_1

/* Keymaster 4.1 is just a minor extension to 4.0,
 * providing two methods: `earlyBootEnded` and `deviceLocked`,
 * neither of which we care about.
 *
 * Everything else, including command IDs, argument layout, etc,
 * except for HAL lookup/initialization is EXACTLY the same as in Keymaster 4.0.
 */
class SusHidlKeymaster4_1 : public SusHidlKeymaster4_0 {
public:
    SusHidlKeymaster4_1(void);
};

#endif /* SUSKEYMASTER_HAL_DISABLE_4_1 */

} /* namespace kmhal */
} /* namespace suskeymaster */

#endif /* SUSKEYMASTER_SUSKMHAL_HPP_ */
