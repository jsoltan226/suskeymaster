#ifndef SUSKEYMASTER_HAL_DISABLE_KEYMINT

#ifndef SUSKEYMASTER_BUILD_HOST
#include "suskmhal.hpp"
#include "keymaster-types-cpp.hpp"
#include "transport/hal.h"
#include "transport/serdes-aidl.h"
#include <cstdlib>

namespace suskeymaster {
namespace kmhal {

using namespace generic;

SusAidlKeyMint::SusAidlKeyMint() :
    hal_(kmhal_aidl_sp_new_get(
                "android.hardware.security.keymint.IKeyMintDevice", "strongbox",
                nullptr, false), &transport::kmhal_sp_deleter)
{
    if (this->hal_.get() == nullptr) {
        std::cerr << "Failed to initialize KeyMint AIDL HAL" << std::endl;
        return;
    }

    if (kmhal_get_aidl_interface_version(this->hal_.get(), &this->keymint_version) != OK) {
        std::cerr << "Failed to get KeyMint interface version" << std::endl;
        this->keymint_version = -1;
        this->hal_.reset();
        return;
    }
}

#define check_hal_ok() do {                                         \
    if (!this->isHALOk()) {                                         \
        std::cerr << __func__ << ": HAL is not OK!" << std::endl;   \
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;           \
    }                                                               \
} while (0)

struct KeyMintHardwareInfo {
    i32 versionNumber;
    SecurityLevel securityLevel = SecurityLevel::SOFTWARE;
    char *keyMintName = nullptr;
    char *keyMintAuthorName = nullptr;
    i32 timestampTokenRequired;
};

static const kmhal_arg_parse_inline_data_proc_t parse_KeyMintHardwareInfo =
[](const struct kmhal_parcel *p, size_t *off_p, void *out, size_t size)
{
    if (out == nullptr || size != sizeof(KeyMintHardwareInfo)) {
        std::cerr << "invalid parameters" << std::endl;
        return -1;
    }

    KeyMintHardwareInfo *o = reinterpret_cast<KeyMintHardwareInfo *>(out);

    if (kmhal_arg_parse_u32(p, off_p,
                (const void **)&o->versionNumber, sizeof(i32)))
            return 1;

    if (kmhal_arg_parse_u32(p, off_p,
                (const void **)&o->securityLevel, sizeof(u32)))
            return 1;

    if (kmhal_aidl_arg_parse_convert_aidl_string16(p, off_p,
                (const void **)&o->keyMintName, 0))
            return 1;

    if (kmhal_aidl_arg_parse_convert_aidl_string16(p, off_p,
                (const void **)&o->keyMintAuthorName, 0))
            return 1;

    if (kmhal_arg_parse_u32(p, off_p,
                (const void **)&o->timestampTokenRequired, sizeof(u32)))
            return 1;

    return 0;
};

using /*transport::init_write, */transport::init_parse_i;

struct kmhal_sp * SusAidlKeyMint::getHalSp() const
{
    return this->hal_.get();
}

bool SusAidlKeyMint::isHALOk(void) const
{
    return this->hal_.get() != nullptr &&
        this->keymint_version > 0 &&
        kmhal_ping(this->hal_.get()) == OK;
}

u32 SusAidlKeyMint::getVersion(void) const
{
    return this->keymint_version > 0 ? this->keymint_version * 0x100 : -1;
}

void SusAidlKeyMint::getHardwareInfo(SecurityLevel& out_securityLevel,
            std::string& out_keymasterName, std::string& out_keymasterAuthorName)
{
    if (!this->isHALOk()) {
fail:
        out_securityLevel = SecurityLevel::SOFTWARE;
        out_keymasterName = "N/A";
        out_keymasterAuthorName = "N/A";
        return;
    }

    struct kmhal_arg_write_desc *const in_args = nullptr;
    const size_t n_in_args = 0;

    KeyMintHardwareInfo hwinfo;

    struct kmhal_arg_parse_desc out_args[] = {
        init_parse_i("KeyMintHardwareInfo", &hwinfo, parse_KeyMintHardwareInfo)
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_call(this->hal_.get(), 1,
            in_args, n_in_args, out_args, n_out_args) != OK)
    {
        std::cerr << "getHardwareInfo call failed!" << std::endl;
        goto fail;
    }

    out_keymasterName = std::string((const char *)hwinfo.keyMintName);
    out_keymasterAuthorName = std::string((const char *)hwinfo.keyMintAuthorName);

    free(hwinfo.keyMintName); hwinfo.keyMintName = nullptr;
    free(hwinfo.keyMintAuthorName); hwinfo.keyMintAuthorName = nullptr;

    out_securityLevel = hwinfo.securityLevel;
}

ErrorCode SusAidlKeyMint::addRngEntropy(std::vector<u8> const& data) {
    (void) data; return ErrorCode::UNIMPLEMENTED;
}

ErrorCode SusAidlKeyMint::generateKey(std::vector<KeyParameter> const& keyParams,
        std::vector<u8>& out_keyBlob, KeyCharacteristics& out_keyCharacteristics)
{
    (void) keyParams; (void) out_keyBlob; (void) out_keyCharacteristics;
    return ErrorCode::UNIMPLEMENTED;
}

ErrorCode SusAidlKeyMint::importKey(std::vector<KeyParameter> const& keyParams,
        KeyFormat keyFormat, std::vector<u8> const& keyData,
        std::vector<u8>& out_keyBlob, KeyCharacteristics& out_keyCharacteristics)
{
    (void) keyParams; (void) keyFormat; (void) keyData;
    (void) out_keyBlob; (void) out_keyCharacteristics;
    return ErrorCode::UNIMPLEMENTED;
}

ErrorCode SusAidlKeyMint::importWrappedKey(std::vector<u8> const& wrappedKeyData,
        std::vector<u8> const& wrappingKeyBlob, std::vector<u8> const& maskingKey,
        std::vector<KeyParameter> const& unwrappingParams,
        uint64_t passwordSid, uint64_t biometricSid,
        std::vector<u8>& out_keyBlob, KeyCharacteristics& out_keyCharacteristics)
{
    (void) wrappedKeyData; (void) wrappingKeyBlob; (void) maskingKey; (void) unwrappingParams;
    (void) passwordSid; (void) biometricSid; (void) out_keyBlob; (void) out_keyCharacteristics;
    return ErrorCode::UNIMPLEMENTED;
}

ErrorCode SusAidlKeyMint::getKeyCharacteristics(std::vector<u8> const& keyBlob,
        std::vector<u8> const& applicationId, std::vector<u8> const& applicationData,
        KeyCharacteristics& out_keyCharacteristics)
{
    (void) keyBlob; (void) applicationId; (void) applicationData;
    (void) out_keyCharacteristics;
    return ErrorCode::UNIMPLEMENTED;
}

ErrorCode SusAidlKeyMint::exportKey(KeyFormat keyFormat, std::vector<u8> const& keyBlob,
        std::vector<u8> const& applicationId, std::vector<u8> const& applicationData,
        std::vector<u8>& out_keyMaterial)
{
    (void) keyFormat; (void) keyBlob; (void) applicationId; (void) applicationData;
    (void) out_keyMaterial;
    return ErrorCode::UNIMPLEMENTED;
}

ErrorCode SusAidlKeyMint::attestKey(std::vector<u8> const& keyToAttest,
        std::vector<KeyParameter> const& attestParams,
        std::vector<std::vector<u8>>& out_certChain)
{
    (void) keyToAttest; (void) attestParams; (void) out_certChain;
    return ErrorCode::UNIMPLEMENTED;
}

ErrorCode SusAidlKeyMint::upgradeKey(std::vector<u8> const& keyBlobToUpgrade,
        std::vector<KeyParameter> const& upgradeParams, std::vector<u8>& out_upgradedKeyBlob)
{
    (void) keyBlobToUpgrade; (void) upgradeParams; (void) out_upgradedKeyBlob;
    return ErrorCode::UNIMPLEMENTED;
}

ErrorCode SusAidlKeyMint::deleteKey(std::vector<u8> const& keyBlob) {
    (void) keyBlob; return ErrorCode::UNIMPLEMENTED;
}

ErrorCode SusAidlKeyMint::deleteAllKeys(void) { return ErrorCode::UNIMPLEMENTED; }

ErrorCode SusAidlKeyMint::destroyAttestationIds(void) { return ErrorCode::UNIMPLEMENTED; }

ErrorCode SusAidlKeyMint::begin(KeyPurpose purpose, std::vector<u8> const& keyBlob,
        std::vector<KeyParameter> const& inParams, HardwareAuthToken const& authToken,
        std::vector<KeyParameter>& out_outParams, uint64_t& out_operationHandle)
{
    (void) purpose; (void) keyBlob; (void) inParams; (void) authToken;
    (void) out_outParams; (void) out_operationHandle;
    return ErrorCode::UNIMPLEMENTED;
}

ErrorCode SusAidlKeyMint::update(uint64_t operationHandle,
        std::vector<KeyParameter> const& inParams, std::vector<u8> const& input,
        HardwareAuthToken const& authToken,
        uint32_t& out_inputConsumed, std::vector<KeyParameter>& out_outParams,
        std::vector<u8>& out_output)
{
    (void) operationHandle; (void) inParams; (void) input;
    (void) authToken;
    (void) out_inputConsumed; (void) out_outParams; (void) out_output;
    return ErrorCode::UNIMPLEMENTED;
}

ErrorCode SusAidlKeyMint::finish(uint64_t operationHandle,
        std::vector<KeyParameter> const& inParams, std::vector<u8> const& input,
        std::vector<u8> const& signature, HardwareAuthToken const& authToken,
        std::vector<KeyParameter>& out_outParams, std::vector<u8>& out_output)
{
    (void) operationHandle; (void) inParams; (void) input; (void) signature;
    (void) authToken;
    (void) out_outParams; (void) out_output;
    return ErrorCode::UNIMPLEMENTED;
}

ErrorCode SusAidlKeyMint::abort(uint64_t operationHandle) {
    (void) operationHandle; return ErrorCode::UNIMPLEMENTED;
}

} /* namespace kmhal */
} /* namespace suskeymaster */

#else
namespace suskeymaster {
namespace kmhal {
SusAidlKeyMint() {
}
} /* namespace kmhal */
} /* namespace suskeymaster */
#endif /* SUSKEYMASTER_BUILD_HOST */

#endif /* SUSKEYMASTER_HAL_DISABLE_KEYMINT */
