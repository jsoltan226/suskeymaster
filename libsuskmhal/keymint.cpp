#ifndef SUSKEYMASTER_HAL_DISABLE_KEYMINT

#ifndef SUSKEYMASTER_BUILD_HOST
#include "suskmhal.hpp"
#include "keymaster-types-c.h"
#include "keymaster-types-cpp.hpp"
#include "transport/hal.h"
#include "transport/aidl2generic.hpp"
#include "transport/keymint-types-aidl.h"
#include <cstdlib>

namespace suskeymaster {
namespace kmhal {

enum KeyMintCmd : u32 {
    GET_HARDWARE_INFO = 1,
    ADD_RNG_ENTROPY = 2,
    GENERATE_KEY = 3,
    IMPORT_KEY = 4,
    IMPORT_WRAPPED_KEY = 5,
    UPGRADE_KEY = 6,
    DELETE_KEY = 7,
    DELETE_ALL_KEYS = 8,
    DESTROY_ATTESTATION_IDS = 9,
    BEGIN = 10,
    DEVICE_LOCKED = 11,
    EARLY_BOOT_ENDED = 12,
    CONVERT_STORAGE_KEY_TO_EPHEMERALE = 13,
    GET_KEY_CHARACTERISTICS = 14,
    GET_ROOT_OF_TRUST_CHALLENGE = 15,
    GET_ROOT_OF_TRUST = 16,
    SEND_ROOT_OF_TRUST = 17,
    SEND_ADDITIONAL_ATTESTATION_INFO = 18,
};

enum KeyMintOpCmd : u32 {
    UPDATE_AAD = 1,
    UPDATE = 2,
    FINISH = 3,
    ABORT = 4
};

using namespace generic;
using transport::init_parse_p, transport::init_write_p,
      transport::init_parse_i, transport::init_write_i;

using transport::AidlView, transport::fromAidlDestroy;
using transport::AidlVecOfU8View,
      transport::AidlKeyParameterView, transport::AidlVecOfKeyParameterView;

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

static void convertAndDestroyKeyCharacteristics(KeyCharacteristics& out,
                                struct aidl_vec_of_key_characteristics &res_kc_vec);

#define check_hal_ok() do {                                         \
    if (!this->isHALOk()) {                                         \
        std::cerr << __func__ << ": HAL is not OK!" << std::endl;   \
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;           \
    }                                                               \
} while (0)

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

    struct aidl_keymint_hardware_info hwinfo = {};

    struct kmhal_arg_parse_desc out_args[] = {
        init_parse_i("KeyMintHardwareInfo", &hwinfo, parse_aidl_keymint_hardware_info)
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_call(this->hal_.get(), KeyMintCmd::GET_HARDWARE_INFO,
            in_args, n_in_args, out_args, n_out_args, nullptr) != OK)
    {
        std::cerr << "getHardwareInfo call failed!" << std::endl;
        goto fail;
    }

    out_keymasterName = std::string((const char *)hwinfo.keyMintName);
    out_keymasterAuthorName = std::string((const char *)hwinfo.keyMintAuthorName);
    out_securityLevel = static_cast<SecurityLevel>(hwinfo.securityLevel);

    destroy_aidl_keymint_hardware_info(&hwinfo);
}

ErrorCode SusAidlKeyMint::addRngEntropy(std::vector<u8> const& data)
{
    transport::AidlVecOfU8View aidl_data(data);
    ErrorCode err = ErrorCode::UNKNOWN_ERROR;

    struct kmhal_arg_write_desc in_args[] = {
        init_write_i("data", aidl_data.get(), write_aidl_vec_of_u8)
    };
    const size_t n_in_args = u_arr_size(in_args);

    struct kmhal_arg_parse_desc *const out_args = nullptr;
    const size_t n_out_args = 0;

    if (kmhal_call(this->hal_.get(), KeyMintCmd::ADD_RNG_ENTROPY,
                in_args, n_in_args, out_args, n_out_args, reinterpret_cast<u32 *>(&err)))
    {
        std::cerr << __func__ << ": AIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }

    return err;
}

ErrorCode SusAidlKeyMint::generateKey(std::vector<KeyParameter> const& keyParams,
        std::vector<u8>& out_keyBlob, KeyCharacteristics& out_keyCharacteristics)
{
    ErrorCode err = ErrorCode::UNKNOWN_ERROR;
    AidlVecOfKeyParameterView aidl_keyParams(keyParams);

    u32 dummy = 0;
    struct kmhal_arg_write_desc in_args[] = {
        init_write_i("keyParams", aidl_keyParams.get(), write_aidl_vec_of_key_parameter),
        init_write_p("attestationKey", dummy, kmhal_arg_write_u32),
    };
    const size_t n_in_args = u_arr_size(in_args);

    struct aidl_key_creation_result res{};
    struct kmhal_arg_parse_desc out_args[] = {
        init_parse_i("KeyCreationResult", &res, parse_aidl_key_creation_result)
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_call(this->hal_.get(), KeyMintCmd::GENERATE_KEY,
                in_args, n_in_args, out_args, n_out_args, reinterpret_cast<u32 *>(&err)))
    {
        std::cerr << __func__ << ": AIDL call failed" << std::endl;
        destroy_aidl_key_creation_result(&res);
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }
    if (err == ErrorCode::OK) {
        /* Copy the keyblob */
        out_keyBlob = fromAidlDestroy(res.key_blob);

        /* Convert the KeyCharacteristics */
        convertAndDestroyKeyCharacteristics(out_keyCharacteristics, res.key_characteristics);
    }

    destroy_aidl_key_creation_result(&res);
    return err;
}

ErrorCode SusAidlKeyMint::importKey(std::vector<KeyParameter> const& keyParams,
        KeyFormat keyFormat, std::vector<u8> const& keyData,
        std::vector<u8>& out_keyBlob, KeyCharacteristics& out_keyCharacteristics)
{
    ErrorCode err = ErrorCode::UNKNOWN_ERROR;
    AidlVecOfKeyParameterView aidl_keyParams(keyParams);
    AidlVecOfU8View aidl_keyData(keyData);

    u32 dummy = 0;
    struct kmhal_arg_write_desc in_args[] = {
        init_write_i("keyParams", aidl_keyParams.get(), write_aidl_vec_of_key_parameter),
        init_write_p("keyFormat", keyFormat, kmhal_arg_write_u32),
        init_write_i("keyData", aidl_keyData.get(), write_aidl_vec_of_u8),
        init_write_p("attestationKey", dummy, kmhal_arg_write_u32),
    };
    const size_t n_in_args = u_arr_size(in_args);

    struct aidl_key_creation_result res{};
    struct kmhal_arg_parse_desc out_args[] = {
        init_parse_i("KeyCreationResult", &res, parse_aidl_key_creation_result)
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_call(this->hal_.get(), KeyMintCmd::GENERATE_KEY,
                in_args, n_in_args, out_args, n_out_args, reinterpret_cast<u32 *>(&err)))
    {
        std::cerr << __func__ << ": AIDL call failed" << std::endl;
        destroy_aidl_key_creation_result(&res);
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }
    if (err == ErrorCode::OK) {
        /* Copy the keyblob */
        out_keyBlob = fromAidlDestroy(res.key_blob);

        /* Convert the KeyCharacteristics */
        convertAndDestroyKeyCharacteristics(out_keyCharacteristics, res.key_characteristics);
    }

    destroy_aidl_key_creation_result(&res);
    return err;
}

ErrorCode SusAidlKeyMint::importWrappedKey(std::vector<u8> const& wrappedKeyData,
        std::vector<u8> const& wrappingKeyBlob, std::vector<u8> const& maskingKey,
        std::vector<KeyParameter> const& unwrappingParams,
        uint64_t passwordSid, uint64_t biometricSid,
        std::vector<u8>& out_keyBlob, KeyCharacteristics& out_keyCharacteristics)
{
    ErrorCode err = ErrorCode::UNKNOWN_ERROR;
    AidlVecOfU8View aidl_wrappedKeyData(wrappedKeyData);
    AidlVecOfU8View aidl_wrappingKeyBlob(wrappingKeyBlob);
    AidlVecOfU8View aidl_maskingKey(maskingKey);
    AidlVecOfKeyParameterView aidl_unwrappingParams(unwrappingParams);

    struct kmhal_arg_write_desc in_args[] = {
        init_write_i("wrappedKeyData", aidl_wrappedKeyData.get(), write_aidl_vec_of_u8),
        init_write_i("wrappingKeyBlob", aidl_wrappingKeyBlob.get(), write_aidl_vec_of_u8),
        init_write_i("maskingKey", aidl_maskingKey.get(), write_aidl_vec_of_u8),
        init_write_i("unwrappingParams", aidl_unwrappingParams.get(),
                write_aidl_vec_of_key_parameter),
        init_write_p("passwordSid", passwordSid, kmhal_arg_write_u64),
        init_write_p("biometricSid", biometricSid, kmhal_arg_write_u64),
    };
    const size_t n_in_args = u_arr_size(in_args);

    struct aidl_key_creation_result res{};
    struct kmhal_arg_parse_desc out_args[] = {
        init_parse_i("KeyCreationResult", &res, parse_aidl_key_creation_result)
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_call(this->hal_.get(), KeyMintCmd::GENERATE_KEY,
                in_args, n_in_args, out_args, n_out_args, reinterpret_cast<u32 *>(&err)))
    {
        std::cerr << __func__ << ": AIDL call failed" << std::endl;
        destroy_aidl_key_creation_result(&res);
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }
    if (err == ErrorCode::OK) {
        /* Copy the keyblob */
        out_keyBlob = fromAidlDestroy(res.key_blob);

        /* Convert the KeyCharacteristics */
        convertAndDestroyKeyCharacteristics(out_keyCharacteristics, res.key_characteristics);
    }

    destroy_aidl_key_creation_result(&res);
    return err;
}

ErrorCode SusAidlKeyMint::getKeyCharacteristics(std::vector<u8> const& keyBlob,
        std::vector<u8> const& applicationId, std::vector<u8> const& applicationData,
        KeyCharacteristics& out_keyCharacteristics)
{
    ErrorCode err = ErrorCode::UNKNOWN_ERROR;
    AidlVecOfU8View aidl_keyBlob(keyBlob);
    AidlVecOfU8View aidl_appId(applicationId);
    AidlVecOfU8View aidl_appData(applicationData);

    struct kmhal_arg_write_desc in_args[] = {
        init_write_i("keyBlob", aidl_keyBlob.get(), write_aidl_vec_of_u8),
        init_write_i("appId", aidl_appId.get(), write_aidl_vec_of_u8),
        init_write_i("appData", aidl_appData.get(), write_aidl_vec_of_u8),
    };
    const size_t n_in_args = u_arr_size(in_args);

    struct aidl_vec_of_key_characteristics res_kc_vec{};
    struct kmhal_arg_parse_desc out_args[] = {
        init_parse_i("KeyCharacteristics[]", &res_kc_vec, parse_aidl_vec_of_key_characteristics)
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_call(this->hal_.get(), KeyMintCmd::GET_KEY_CHARACTERISTICS,
                in_args, n_in_args, out_args, n_out_args, reinterpret_cast<u32 *>(&err)))
    {
        std::cerr << __func__ << ": AIDL call failed" << std::endl;
        destroy_aidl_vec_of_key_characteristics(&res_kc_vec);
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }
    if (err == ErrorCode::OK)
        convertAndDestroyKeyCharacteristics(out_keyCharacteristics, res_kc_vec);
    else
        destroy_aidl_vec_of_key_characteristics(&res_kc_vec);

    return err;
}

ErrorCode SusAidlKeyMint::upgradeKey(std::vector<u8> const& keyBlobToUpgrade,
        std::vector<KeyParameter> const& upgradeParams, std::vector<u8>& out_upgradedKeyBlob)
{
    ErrorCode err = ErrorCode::UNKNOWN_ERROR;
    AidlVecOfU8View aidl_keyBlobToUpgrade(keyBlobToUpgrade);
    AidlVecOfKeyParameterView aidl_upgradeParams(upgradeParams);

    struct kmhal_arg_write_desc in_args[] = {
        init_write_i("keyBlobToUpgrade", aidl_keyBlobToUpgrade.get(), write_aidl_vec_of_u8),
        init_write_i("upgradeParams", aidl_upgradeParams.get(), write_aidl_vec_of_key_parameter)
    };
    const size_t n_in_args = u_arr_size(in_args);

    struct aidl_vec_of_u8 res{};
    struct kmhal_arg_parse_desc out_args[] = {
        init_parse_i("upgradedKeyBlob", &res, parse_aidl_vec_of_u8)
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_call(this->hal_.get(), KeyMintCmd::UPGRADE_KEY,
                in_args, n_in_args, out_args, n_out_args, reinterpret_cast<u32 *>(&err)))
    {
        std::cerr << __func__ << ": AIDL call failed" << std::endl;
        destroy_aidl_vec_of_u8(&res);
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }
    if (err == ErrorCode::OK)
        out_upgradedKeyBlob = fromAidlDestroy(res);
    else
        destroy_aidl_vec_of_u8(&res);

    return err;
}

ErrorCode SusAidlKeyMint::deleteKey(std::vector<u8> const& keyBlob)
{
    ErrorCode err = ErrorCode::UNKNOWN_ERROR;
    AidlVecOfU8View aidl_keyBlob(keyBlob);

    struct kmhal_arg_write_desc in_args[] = {
        init_write_i("keyBlob", aidl_keyBlob.get(), write_aidl_vec_of_u8)
    };
    const size_t n_in_args = u_arr_size(in_args);

    struct kmhal_arg_parse_desc *const out_args = nullptr;
    const size_t n_out_args = 0;

    if (kmhal_call(this->hal_.get(), KeyMintCmd::DELETE_KEY,
                in_args, n_in_args, out_args, n_out_args, reinterpret_cast<u32 *>(&err)))
    {
        std::cerr << __func__ << ": AIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }
    return err;
}

ErrorCode SusAidlKeyMint::deleteAllKeys(void)
{
    ErrorCode err = ErrorCode::UNKNOWN_ERROR;

    if (kmhal_call(this->hal_.get(), KeyMintCmd::DELETE_ALL_KEYS,
                nullptr, 0, nullptr, 0, reinterpret_cast<u32 *>(&err)))
    {
        std::cerr << __func__ << ": AIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }
    return err;
}

ErrorCode SusAidlKeyMint::destroyAttestationIds(void)
{
    ErrorCode err = ErrorCode::UNKNOWN_ERROR;

    if (kmhal_call(this->hal_.get(), KeyMintCmd::DESTROY_ATTESTATION_IDS,
                nullptr, 0, nullptr, 0, reinterpret_cast<u32 *>(&err)))
    {
        std::cerr << __func__ << ": AIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }
    return err;
}

ErrorCode SusAidlKeyMint::begin(KeyPurpose purpose, std::vector<u8> const& keyBlob,
        std::vector<KeyParameter> const& inParams, HardwareAuthToken const& authToken,
        std::vector<KeyParameter>& out_outParams, OpaqueOpHandle& out_operationHandle)
{
    /*
    ErrorCode err = ErrorCode::UNKNOWN_ERROR;
    AidlVecOfU8View aidl_keyBlob(keyBlob);
    AidlVecOfKeyParameterView aidl_params(inParams);

    struct kmhal_arg_write_desc in_args[] = {
        init_write_p("purpose", purpose, kmhal_arg_write_u32),
        init_write_i("keyBlob", aidl_keyBlob.get(), write_aidl_vec_of_u8),
        init_write_i("params", aidl_params.get(), write_aidl_vec_of_key_parameter),
        init_write_i("authToken", aidl_
    }
    */
    (void) purpose; (void) keyBlob; (void) inParams; (void) authToken;
    (void) out_outParams; (void) out_operationHandle;
    return ErrorCode::UNIMPLEMENTED;
}

ErrorCode SusAidlKeyMint::update(OpaqueOpHandle& operationHandle,
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

ErrorCode SusAidlKeyMint::finish(OpaqueOpHandle& operationHandle,
        std::vector<KeyParameter> const& inParams, std::vector<u8> const& input,
        std::vector<u8> const& signature, HardwareAuthToken const& authToken,
        std::vector<KeyParameter>& out_outParams, std::vector<u8>& out_output)
{
    (void) operationHandle; (void) inParams; (void) input; (void) signature;
    (void) authToken;
    (void) out_outParams; (void) out_output;
    return ErrorCode::UNIMPLEMENTED;
}

ErrorCode SusAidlKeyMint::abort(OpaqueOpHandle& operationHandle) {
    (void) operationHandle; return ErrorCode::UNIMPLEMENTED;
}

static void convertAndDestroyKeyCharacteristics(KeyCharacteristics& out,
                                struct aidl_vec_of_key_characteristics &res_kc_vec)
{
    for (i32 i = 0; i < res_kc_vec.size; i++) {
        struct aidl_key_characteristics *const kc = &res_kc_vec.ptr[i];

        switch (kc->slvl) {
        default:
            std::cerr << "KeyMint: WARNING: Unknown securityLevel: " << kc->slvl
                << "; treating SECURITY_LEVEL_SOFTWARE" << std::endl;
        case KM_SECURITY_LEVEL_SOFTWARE:
        case KM_SECURITY_LEVEL_KEYSTORE:
            for (i32 i = 0; i < kc->authorizations.size; i++)
                out.softwareEnforced.emplace_back(fromAidlDestroy(kc->authorizations.ptr[i]));
            break;
        case KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT:
        case KM_SECURITY_LEVEL_STRONGBOX:
            for (i32 i = 0; i < kc->authorizations.size; i++)
                out.hardwareEnforced.emplace_back(fromAidlDestroy(kc->authorizations.ptr[i]));
            break;
        }
    }

    destroy_aidl_vec_of_key_characteristics(&res_kc_vec);
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
