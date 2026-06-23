#ifndef SUSKEYMASTER_SUSKMHAL_HPP_
#define SUSKEYMASTER_SUSKMHAL_HPP_

#include "hal-version.hpp"
#include "keymaster-types-cpp.hpp"
#include <core/int.h>
#include <memory>
#include <vector>
#include <string>

#ifndef SUSKEYMASTER_BUILD_HOST
#include "transport/hal.h"
#endif /* SUSKEYMASTER_BUILD_HOST */

namespace suskeymaster {
namespace kmhal {

using namespace generic;
using namespace ::android::hardware;

class SusKMHal {
public:
    SusKMHal(const char *instname = "default") { (void) instname; };
    virtual ~SusKMHal(void) {};

    virtual struct kmhal_sp * getHalSp(void) const { return nullptr; }

    virtual bool isHALOk(void) const { return false; };

    virtual hal_version getVersion(void) const { return HAL_NONE; };

    virtual u64 getOpHandleChallenge(const OpaqueOpHandle&) { return UINT64_C(0); };

    virtual void getHardwareInfo(SecurityLevel& out_securityLevel,
            std::string& out_keymasterName, std::string& out_keymasterAuthorName)
    {
        out_securityLevel = SecurityLevel::SOFTWARE;
        out_keymasterName = "N/A";
        out_keymasterAuthorName = "N/A";
    }

    virtual ErrorCode addRngEntropy(std::vector<u8> const& data) {
        (void) data; return ErrorCode::UNIMPLEMENTED;
    }

    virtual ErrorCode generateKey(std::vector<KeyParameter> const& keyParams,
            std::vector<u8>& out_keyBlob, KeyCharacteristics& out_keyCharacteristics,
            std::vector<std::vector<u8>> *out_opt_keymint_cert_chain = nullptr)
    {
        (void) keyParams; (void) out_keyBlob; (void) out_keyCharacteristics;
        (void) out_opt_keymint_cert_chain;
        return ErrorCode::UNIMPLEMENTED;
    }

    virtual ErrorCode importKey(std::vector<KeyParameter> const& keyParams,
            KeyFormat keyFormat, std::vector<u8> const& keyData,
            std::vector<u8>& out_keyBlob, KeyCharacteristics& out_keyCharacteristics,
            std::vector<std::vector<u8>> *out_opt_keymint_cert_chain = nullptr)
    {
        (void) keyParams; (void) keyFormat; (void) keyData;
        (void) out_keyBlob; (void) out_keyCharacteristics;
        (void) out_opt_keymint_cert_chain;
        return ErrorCode::UNIMPLEMENTED;
    }

    virtual ErrorCode importWrappedKey(std::vector<u8> const& wrappedKeyData,
            std::vector<u8> const& wrappingKeyBlob, std::vector<u8> const& maskingKey,
            std::vector<KeyParameter> const& unwrappingParams,
            u64 passwordSid, u64 biometricSid,
            std::vector<u8>& out_keyBlob, KeyCharacteristics& out_keyCharacteristics,
            std::vector<std::vector<u8>>* out_opt_keymint_cert_chain = nullptr)
    {
        (void) wrappedKeyData; (void) wrappingKeyBlob; (void) maskingKey; (void) unwrappingParams;
        (void) passwordSid; (void) biometricSid; (void) out_keyBlob; (void) out_keyCharacteristics;
        (void) out_opt_keymint_cert_chain;
        return ErrorCode::UNIMPLEMENTED;
    }

    virtual ErrorCode getKeyCharacteristics(std::vector<u8> const& keyBlob,
            std::vector<u8> const& applicationId, std::vector<u8> const& applicationData,
            KeyCharacteristics& out_keyCharacteristics)
    {
        (void) keyBlob; (void) applicationId; (void) applicationData;
        (void) out_keyCharacteristics;
        return ErrorCode::UNIMPLEMENTED;
    }

    virtual ErrorCode exportKey(KeyFormat keyFormat, std::vector<u8> const& keyBlob,
            std::vector<u8> const& applicationId, std::vector<u8> const& applicationData,
            std::vector<u8>& out_keyMaterial)
    {
        (void) keyFormat; (void) keyBlob; (void) applicationId; (void) applicationData;
        (void) out_keyMaterial;
        return ErrorCode::UNIMPLEMENTED;
    }

    virtual ErrorCode attestKey(std::vector<u8> const& keyToAttest,
            std::vector<KeyParameter> const& attestParams,
            std::vector<std::vector<u8>>& out_certChain)
    {
        (void) keyToAttest; (void) attestParams; (void) out_certChain;
        return ErrorCode::UNIMPLEMENTED;
    }

    virtual ErrorCode upgradeKey(std::vector<u8> const& keyBlobToUpgrade,
            std::vector<KeyParameter> const& upgradeParams,
            std::vector<u8>& out_upgradedKeyBlob)
    {
        (void) keyBlobToUpgrade; (void) upgradeParams; (void) out_upgradedKeyBlob;
        return ErrorCode::UNIMPLEMENTED;
    }

    virtual ErrorCode deleteKey(std::vector<u8> const& keyBlob) {
        (void) keyBlob; return ErrorCode::UNIMPLEMENTED;
    }

    virtual ErrorCode deleteAllKeys(void) { return ErrorCode::UNIMPLEMENTED; }

    virtual ErrorCode destroyAttestationIds(void) { return ErrorCode::UNIMPLEMENTED; }

    virtual ErrorCode begin(KeyPurpose purpose, std::vector<u8> const& keyBlob,
            std::vector<KeyParameter> const& inParams, HardwareAuthToken const& authToken,
            std::vector<KeyParameter>& out_outParams, OpaqueOpHandle& out_operationHandle)
    {
        (void) purpose; (void) keyBlob; (void) inParams; (void) authToken;
        (void) out_outParams; (void) out_operationHandle;
        return ErrorCode::UNIMPLEMENTED;
    }

    virtual ErrorCode update(OpaqueOpHandle& operationHandle,
            std::vector<KeyParameter> const& inParams, std::vector<u8> const& input,
            HardwareAuthToken const& authToken,
            u32& out_inputConsumed, std::vector<KeyParameter>& out_outParams,
            std::vector<u8>& out_output)
    {
        (void) operationHandle; (void) inParams; (void) input;
        (void) authToken;
        (void) out_inputConsumed; (void) out_outParams; (void) out_output;
        return ErrorCode::UNIMPLEMENTED;
    }

    virtual ErrorCode finish(OpaqueOpHandle& operationHandle,
            std::vector<KeyParameter> const& inParams, std::vector<u8> const& input,
            std::vector<u8> const& signature, HardwareAuthToken const& authToken,
            std::vector<KeyParameter>& out_outParams, std::vector<u8>& out_output)
    {
        (void) operationHandle; (void) inParams; (void) input; (void) signature;
        (void) authToken;
        (void) out_outParams; (void) out_output;
        return ErrorCode::UNIMPLEMENTED;
    }

    virtual ErrorCode abort(OpaqueOpHandle& operationHandle) {
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

#ifndef SUSKEYMASTER_BUILD_HOST

    struct kmhal_sp * getHalSp(void) const override;
    bool isHALOk(void) const override;

    u64 getOpHandleChallenge(const OpaqueOpHandle&) override;

public:
    /** All of the below methods are the exact same for all
     * supported HIDL KeyMaster versions (3.0, 4.0, 4.1) **/

    ErrorCode addRngEntropy(std::vector<u8> const& data) override;

    ErrorCode generateKey(std::vector<KeyParameter> const& keyParams,
            std::vector<u8>& out_keyBlob,
            KeyCharacteristics& out_keyCharacteristics,
            std::vector<std::vector<u8>> * /* ignored on Keymaster */ = nullptr) override;

    ErrorCode importKey(std::vector<KeyParameter> const& keyParams,
            KeyFormat keyFormat, std::vector<u8> const& keyData,
            std::vector<u8>& out_keyBlob,
            KeyCharacteristics& out_keyCharacteristics,
            std::vector<std::vector<u8>>* /* ignored on Keymaster */ = nullptr) override;

    ErrorCode getKeyCharacteristics(std::vector<u8> const& keyBlob,
            std::vector<u8> const& applicationId, std::vector<u8> const& applicationData,
            KeyCharacteristics& out_keyCharacteristics) override;

    ErrorCode exportKey(KeyFormat keyFormat, std::vector<u8> const& keyBlob,
            std::vector<u8> const& applicationId, std::vector<u8> const& applicationData,
            std::vector<u8>& out_keyMaterial) override;

    ErrorCode attestKey(std::vector<u8> const& keyToAttest,
            std::vector<KeyParameter> const& attestParams,
            std::vector<std::vector<u8>>& out_certChain) override;

    ErrorCode upgradeKey(std::vector<u8> const& keyBlobToUpgrade,
            std::vector<KeyParameter> const& upgradeParams,
            std::vector<u8>& out_upgradedKeyBlob) override;

    ErrorCode deleteKey(std::vector<u8> const& keyBlob) override;

    ErrorCode deleteAllKeys(void) override;

    ErrorCode destroyAttestationIds(void) override;

    ErrorCode abort(OpaqueOpHandle& operationHandle) override;

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
        hal_(new_hal, transport::kmhal_sp_deleter) {}

    struct kmhal_sp * getHal() const { return hal_.get(); }

private:
    std::unique_ptr<struct kmhal_sp, decltype(&transport::kmhal_sp_deleter)> hal_;
#endif /* SUSKEYMASTER_BUILD_HOST */
};

#ifndef SUSKEYMASTER_HAL_DISABLE_3_0

class SusHidlKeymaster3_0 : public SusHidlKeymasterHALCommon {
public:
    SusHidlKeymaster3_0(const char *instname = "default");

#ifndef SUSKEYMASTER_BUILD_HOST
protected:
    u32 getVersionSpecificCmdID(enum KM_common_cmd common_cmd) override;

public:
    hal_version getVersion(void) const override { return HAL_KEYMASTER_3_0; };

    /* For Keymaster 3.0, this is a wrapper around the older `getHardwareFeatures` method */
    void getHardwareInfo(SecurityLevel& out_securityLevel,
            std::string& out_keymasterName, std::string& out_keymasterAuthorName) override;

    /* Almost the same as in Keymaster 4.0 and 4.1,
     * but the `authToken` and `verificationToken` are actually unused by the HAL methods.
     * Instead, `authToken`s are passed in as `Tag::AUTH_TOKEN` in the parameters,
     * while the whole `verificationToken` thing doesn't even exist.
     *
     * Therefore, in Keymaster 3.0, if you provide an `authToken` to this function,
     * it will be automatically added to the parameter list as a `Tag::AUTH_TOKEN`.
     * `verificationToken` is always ignored because unfortunately there's no equivalent. */

    ErrorCode begin(KeyPurpose purpose, std::vector<u8> const& keyBlob,
            std::vector<KeyParameter> const& inParams, HardwareAuthToken const& authToken,
            std::vector<KeyParameter>& out_outParams, OpaqueOpHandle& out_operationHandle)
        override;

    ErrorCode update(OpaqueOpHandle& operationHandle,
            std::vector<KeyParameter> const& inParams, std::vector<u8> const& input,
            HardwareAuthToken const& authToken,
            u32& out_inputConsumed, std::vector<KeyParameter>& out_outParams,
            std::vector<u8>& out_output) override;

    ErrorCode finish(OpaqueOpHandle& operationHandle,
            std::vector<KeyParameter> const& inParams, std::vector<u8> const& input,
            std::vector<u8> const& signature, HardwareAuthToken const& authToken,
            std::vector<KeyParameter>& out_outParams, std::vector<u8>& out_output) override;

#endif /* SUSKEYMASTER_BUILD_HOST */
};

#endif /* SUSKEYMASTER_HAL_DISABLE_3_0 */

#ifndef SUSKEYMASTER_HAL_DISABLE_4_0

class SusHidlKeymaster4_0 : public SusHidlKeymasterHALCommon {
public:
    SusHidlKeymaster4_0(const char *instname = "default");

protected:
    /* c++ sucks */
    explicit SusHidlKeymaster4_0(const char *fqname, const char *instname);

#ifndef SUSKEYMASTER_BUILD_HOST
protected:
    u32 getVersionSpecificCmdID(enum KM_common_cmd common_cmd) override;

public:
    hal_version getVersion(void) const override { return HAL_KEYMASTER_4_0; };

    void getHardwareInfo(SecurityLevel& out_securityLevel,
            std::string& out_keymasterName, std::string& out_keymasterAuthorName) override;

    ErrorCode importWrappedKey(std::vector<u8> const& wrappedKeyData,
            std::vector<u8> const& wrappingKeyBlob, std::vector<u8> const& maskingKey,
            std::vector<KeyParameter> const& unwrappingParams,
            u64 passwordSid, u64 biometricSid,
            std::vector<u8>& out_keyBlob,
            KeyCharacteristics& out_keyCharacteristics,
            std::vector<std::vector<u8>>* /* ignored on Keymaster */ = nullptr) override;

    ErrorCode begin(KeyPurpose purpose, std::vector<u8> const& keyBlob,
            std::vector<KeyParameter> const& inParams, HardwareAuthToken const& authToken,
            std::vector<KeyParameter>& out_outParams, OpaqueOpHandle& out_operationHandle)
        override;

    ErrorCode update(OpaqueOpHandle& operationHandle,
        std::vector<KeyParameter> const& inParams, std::vector<u8> const& input,
        HardwareAuthToken const& authToken,
        uint32_t& out_inputConsumed, std::vector<KeyParameter>& out_outParams,
        std::vector<u8>& out_output) override;

    ErrorCode finish(OpaqueOpHandle& operationHandle,
            std::vector<KeyParameter> const& inParams, std::vector<u8> const& input,
            std::vector<u8> const& signature, HardwareAuthToken const& authToken,
            std::vector<KeyParameter>& out_outParams, std::vector<u8>& out_output) override;
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
    SusHidlKeymaster4_1(const char *instname = "default");
#ifndef SUSKEYMASTER_BUILD_HOST
    hal_version getVersion(void) const override { return HAL_KEYMASTER_4_1; };
#endif /* SUSKEYMASTER_BUILD_HOST */
};

#endif /* SUSKEYMASTER_HAL_DISABLE_4_1 */

#ifndef SUSKEYMASTER_HAL_DISABLE_KEYMINT
class SusAidlKeyMint : public SusKMHal {
public:
    SusAidlKeyMint(const char *instname = "default");

#ifndef SUSKEYMASTER_BUILD_HOST
    ~SusAidlKeyMint();
private:
    std::unique_ptr<struct kmhal_sp, decltype(&transport::kmhal_sp_deleter)> hal_;
    i32 keymint_version = -1;

    struct op_handle {
        struct kmhal_sp *sp = nullptr;
        u64 challenge = UINT64_C(0);

        explicit op_handle(struct kmhal_sp *, u32);
        ~op_handle();

        op_handle(const op_handle& other) = delete;
        op_handle& operator=(const op_handle& other) = delete;

        const op_handle * getView() { return this; };

        op_handle(op_handle&& other) noexcept;
        op_handle& operator=(op_handle&& other) noexcept;
    };
    std::vector<op_handle> activeOperationHandles;

    /* if a dead operation handle is found, it is erased */
    int find_op_handle(OpaqueOpHandle user_handle, const op_handle *& out_view,
                       size_t *opt_out_idx = nullptr);

    /* Converts `Tag::ASSOCIATED_DATA` to `updateAad` calls in `update()` */
    ErrorCode handle_aad_compat(struct kmhal_sp *op,
        std::vector<KeyParameter>& params, const HardwareAuthToken& authToken);

    void delete_invalidate_op_handle(OpaqueOpHandle& user_handle);

public:
    struct kmhal_sp * getHalSp(void) const override;
    bool isHALOk(void) const override;

    hal_version getVersion(void) const override;

    u64 getOpHandleChallenge(const OpaqueOpHandle&) override;

    void getHardwareInfo(SecurityLevel& out_securityLevel,
            std::string& out_keymasterName, std::string& out_keymasterAuthorName) override;

    ErrorCode addRngEntropy(std::vector<u8> const& data) override;

    ErrorCode generateKey(std::vector<KeyParameter> const& keyParams,
            std::vector<u8>& out_keyBlob,
            KeyCharacteristics& out_keyCharacteristics,
            std::vector<std::vector<u8>> *out_opt_cert_chain = nullptr) override;

    ErrorCode importKey(std::vector<KeyParameter> const& keyParams,
            KeyFormat keyFormat, std::vector<u8> const& keyData,
            std::vector<u8>& out_keyBlob,
            KeyCharacteristics& out_keyCharacteristics,
            std::vector<std::vector<u8>> *out_opt_cert_chain = nullptr) override;

    ErrorCode importWrappedKey(std::vector<u8> const& wrappedKeyData,
            std::vector<u8> const& wrappingKeyBlob, std::vector<u8> const& maskingKey,
            std::vector<KeyParameter> const& unwrappingParams,
            u64 passwordSid, u64 biometricSid,
            std::vector<u8>& out_keyBlob,
            KeyCharacteristics& out_keyCharacteristics,
            std::vector<std::vector<u8>> *out_opt_cert_chain = nullptr) override;

    ErrorCode getKeyCharacteristics(std::vector<u8> const& keyBlob,
            std::vector<u8> const& applicationId, std::vector<u8> const& applicationData,
            KeyCharacteristics& out_keyCharacteristics) override;

    /* `exportKey` and `attestKey` are not supported in KeyMint */

    ErrorCode upgradeKey(std::vector<u8> const& keyBlobToUpgrade,
            std::vector<KeyParameter> const& upgradeParams,
            std::vector<u8>& out_upgradedKeyBlob) override;

    ErrorCode deleteKey(std::vector<u8> const& keyBlob) override;

    ErrorCode deleteAllKeys(void) override;

    ErrorCode destroyAttestationIds(void) override;

    ErrorCode begin(KeyPurpose purpose, std::vector<u8> const& keyBlob,
            std::vector<KeyParameter> const& inParams, HardwareAuthToken const& authToken,
            std::vector<KeyParameter>& out_outParams, OpaqueOpHandle& out_operationHandle)
        override;

    ErrorCode update(OpaqueOpHandle& operationHandle,
            std::vector<KeyParameter> const& inParams, std::vector<u8> const& input,
            HardwareAuthToken const& authToken,
            u32& out_inputConsumed, std::vector<KeyParameter>& out_outParams,
            std::vector<u8>& out_output) override;

    ErrorCode finish(OpaqueOpHandle& operationHandle,
            std::vector<KeyParameter> const& inParams, std::vector<u8> const& input,
            std::vector<u8> const& signature, HardwareAuthToken const& authToken,
            std::vector<KeyParameter>& out_outParams, std::vector<u8>& out_output) override;

    ErrorCode abort(OpaqueOpHandle& operationHandle) override;
#endif /* SUSKEYMASTER_BUILD_HOST */
};
#endif /* SUSKEYMASTER_HAL_DISABLE_KEYMINT */

} /* namespace kmhal */
} /* namespace suskeymaster */

#endif /* SUSKEYMASTER_SUSKMHAL_HPP_ */
