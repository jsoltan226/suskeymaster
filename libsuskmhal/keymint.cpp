#include "core/util.h"
#include <sys/cdefs.h>
#ifndef SUSKEYMASTER_HAL_DISABLE_KEYMINT

#ifndef SUSKEYMASTER_BUILD_HOST
#include "suskmhal.hpp"
#include "hal-version.hpp"
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
    CONVERT_STORAGE_KEY_TO_EPHEMERAL = 13,
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
using /* transport::init_parse_p, */ transport::init_write_p,
      transport::init_parse_i, transport::init_write_i;

using transport::AidlView, transport::fromAidlDestroy;
using transport::AidlVecOfU8View,
      transport::AidlKeyParameterView, transport::AidlVecOfKeyParameterView,
      transport::AidlHardwareAuthTokenView;

SusAidlKeyMint::SusAidlKeyMint() :
    hal_(kmhal_aidl_sp_new_get(
                "android.hardware.security.keymint.IKeyMintDevice", "strongbox",
                nullptr, false), &transport::kmhal_sp_deleter)
{
    if (this->hal_.get() == nullptr) {
        /* std::cerr << "Failed to initialize KeyMint AIDL HAL" << std::endl; */
        return;
    }

    if (kmhal_get_aidl_interface_version(this->hal_.get(), &this->keymint_version) != OK) {
        std::cerr << "Failed to get KeyMint interface version" << std::endl;
        this->keymint_version = -1;
        this->hal_.reset();
        return;
    }
}

SusAidlKeyMint::~SusAidlKeyMint()
{
    if (this->activeOperationHandles.size() == 0)
        return;

    std::cerr << "WARNING: " << this->activeOperationHandles.size()
        << " active handles left during destruction" << std::endl;

    for (struct kmhal_sp *& handle : this->activeOperationHandles)
        kmhal_sp_destroy(&handle);
    this->activeOperationHandles.clear();
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

hal_version SusAidlKeyMint::getVersion(void) const
{
    switch (this->keymint_version) {
    case 1: return HAL_KEYMINT_1_0;
    case 2: return HAL_KEYMINT_2_0;
    case 3: return HAL_KEYMINT_3_0;
    case 4: return HAL_KEYMINT_4_0;
    default: return HAL_NONE;
    }
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
        std::vector<u8>& out_keyBlob, KeyCharacteristics& out_keyCharacteristics,
        std::vector<std::vector<u8>>& out_certChain)
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

        /* Copy the cert chain */
        out_certChain = fromAidlDestroy(res.certificate_chain);
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

    if (kmhal_call(this->hal_.get(), KeyMintCmd::IMPORT_KEY,
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

static void init_operation_handle(void *&out, struct kmhal_sp *kmhal, u32 handle)
{
    struct kmhal_sp *op_handle_sp = nullptr;

    op_handle_sp = kmhal_sp_new_empty(true);
    if (!op_handle_sp) {
        std::cerr << "Failed to allocate a new HAL strong pointer struct" << std::endl;
        std::abort();
    }

    kmhal_set_binder(op_handle_sp, kmhal_get_binder(kmhal, nullptr), false);
    kmhal_set_fqname(op_handle_sp, "android.hardware.security.keymint.IKeyMintOperation");
    kmhal_set_instname(op_handle_sp, kmhal_get_instname(kmhal)); /* for completeness */
    kmhal_set_handle(op_handle_sp, handle, true);

    out = op_handle_sp;
}

ErrorCode SusAidlKeyMint::begin(KeyPurpose purpose, std::vector<u8> const& keyBlob,
        std::vector<KeyParameter> const& inParams, HardwareAuthToken const& authToken,
        std::vector<KeyParameter>& out_outParams, OpaqueOpHandle& out_operationHandle)
{
    ErrorCode err = ErrorCode::UNKNOWN_ERROR;
    AidlVecOfU8View aidl_keyBlob(keyBlob);
    AidlVecOfKeyParameterView aidl_params(inParams);
    AidlHardwareAuthTokenView aidl_authToken(authToken);
    out_operationHandle = reinterpret_cast<OpaqueOpHandle>(0);

    struct kmhal_arg_write_desc in_args[] = {
        init_write_p("purpose", purpose, kmhal_arg_write_u32),
        init_write_i("keyBlob", aidl_keyBlob.get(), write_aidl_vec_of_u8),
        init_write_i("params", aidl_params.get(), write_aidl_vec_of_key_parameter),
        init_write_i("authToken", (authToken.empty() ? nullptr : aidl_authToken.get()),
                                  write_nullable_aidl_hardware_auth_token)
    };
    const size_t n_in_args = u_arr_size(in_args);

    struct aidl_begin_result res{};
    struct kmhal_arg_parse_desc out_args[] = {
        init_parse_i("BeginResult", &res, parse_aidl_begin_result)
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_call(this->hal_.get(), KeyMintCmd::BEGIN,
                in_args, n_in_args, out_args, n_out_args, reinterpret_cast<u32 *>(&err)))
    {
        std::cerr << __func__ << ": AIDL call failed" << std::endl;
        destroy_aidl_begin_result(&res);
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }
    if (err == ErrorCode::OK) {
        void *op_handle = nullptr;
        init_operation_handle(op_handle, this->hal_.get(),
                res.IKeyMintOperation_binder_handle);
        this->activeOperationHandles.push_back(
                reinterpret_cast<struct kmhal_sp *>(op_handle)
        );
        const size_t idx = this->activeOperationHandles.size() - 1;

        out_operationHandle = reinterpret_cast<OpaqueOpHandle>(idx + 1 /* skip 0 */);

        out_outParams = fromAidlDestroy(res.params);
    }

    destroy_aidl_begin_result(&res);
    return err;
}

int SusAidlKeyMint::get_op_handle(OpaqueOpHandle user_handle,
                  size_t& out_idx, struct kmhal_sp *& out_handle)
{
    if (user_handle == reinterpret_cast<OpaqueOpHandle>(0) ||
        (out_idx = reinterpret_cast<size_t>(user_handle) - 1) >=
            this->activeOperationHandles.size())
    {
        std::cerr << __func__ << ": Invalid operation handle" << std::endl;
        return 1;
    }
    out_handle = this->activeOperationHandles[out_idx];
    if (out_handle == nullptr || kmhal_ping(out_handle) != OK) {
        std::cerr << __func__ << ": Dead operation handle" << std::endl;
        this->activeOperationHandles.erase(this->activeOperationHandles.begin() + out_idx);
        return 1;
    }

    return 0;
}

ErrorCode SusAidlKeyMint::handle_aad_compat(struct kmhal_sp *op,
        std::vector<KeyParameter>& params, const HardwareAuthToken& authToken)
{
    AidlHardwareAuthTokenView aidl_authToken(authToken);
    ErrorCode err = ErrorCode::UNKNOWN_ERROR;

    if (params.size() == 0)
        return ErrorCode::OK;
    else if (params.size() > INT_MAX) {
        std::cerr << "Too many params" << std::endl;
        return ErrorCode::UNKNOWN_ERROR;
    }

    for (int i = static_cast<int>(params.size()) - 1; i >= 0; i--) {
        const auto& kp = params[i];
        if (kp.tag != Tag::ASSOCIATED_DATA)
            continue;

        std::cout << toString(this->getVersion()) << ": " << __func__ << ": " <<
            "Converting Tag::ASSOCIATED_DATA parameter to `updateAad` call" << std::endl;

        AidlVecOfU8View aidl_aad_input(kp.blob);

        struct kmhal_arg_write_desc in_args[] = {
            init_write_i("input", aidl_aad_input.get(), write_aidl_vec_of_u8),
            init_write_i("authToken", (authToken.empty() ? nullptr : aidl_authToken.get()),
                         write_nullable_aidl_hardware_auth_token),
            init_write_p("timeStampToken", 0, kmhal_arg_write_u32) /* dummy */
        };
        const size_t n_in_args = u_arr_size(in_args);

        struct kmhal_arg_parse_desc *const out_args = nullptr;
        const size_t n_out_args = 0;

        err = ErrorCode::UNKNOWN_ERROR;
        if (kmhal_call(op, KeyMintOpCmd::UPDATE_AAD,
                    in_args, n_in_args, out_args, n_out_args, reinterpret_cast<u32 *>(&err)))
        {
            err = ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
        }
        if (err != ErrorCode::OK) {
            std::cout << __func__ << ": updateAad call failed" << std::endl;
            return err == ErrorCode::UNKNOWN_ERROR ?
                ErrorCode::SECURE_HW_COMMUNICATION_FAILED : err;
        }

        params.erase(params.begin() + i);
    }

    return ErrorCode::OK;
}

void SusAidlKeyMint::delete_invalidate_op_handle(OpaqueOpHandle& user_handle)
{
    size_t idx = 0;
    if (user_handle == reinterpret_cast<OpaqueOpHandle>(0) ||
        (idx = reinterpret_cast<size_t>(user_handle) - 1) >= this->activeOperationHandles.size())
    {
        return;
    }

    kmhal_sp_destroy(&this->activeOperationHandles[idx]);
    this->activeOperationHandles.erase(this->activeOperationHandles.begin() + idx);
}

ErrorCode SusAidlKeyMint::update(OpaqueOpHandle& operationHandle,
        std::vector<KeyParameter> const& inParams, std::vector<u8> const& input,
        HardwareAuthToken const& authToken,
        uint32_t& out_inputConsumed, std::vector<KeyParameter>& out_outParams,
        std::vector<u8>& out_output)
{
    size_t idx = 0;
    struct kmhal_sp *op = nullptr;
    if (get_op_handle(operationHandle, idx, op))
        return ErrorCode::INVALID_OPERATION_HANDLE;

    ErrorCode err = ErrorCode::UNKNOWN_ERROR;
    std::vector<KeyParameter> params(inParams);
    if ((err = handle_aad_compat(op, params, authToken)) != ErrorCode::OK) {
        delete_invalidate_op_handle(operationHandle);
        return err;
    }

    AidlVecOfKeyParameterView aidl_params(params);
    AidlVecOfU8View aidl_input(input);
    AidlHardwareAuthTokenView aidl_authToken(authToken);

    err = ErrorCode::UNKNOWN_ERROR;
    struct kmhal_arg_write_desc in_args[] = {
        init_write_i("input", aidl_input.get(), write_aidl_vec_of_u8),
        init_write_i("authToken", (authToken.empty() ? nullptr : aidl_authToken.get()),
                     write_nullable_aidl_hardware_auth_token),
        init_write_p("timeStampToken", 0, kmhal_arg_write_u32) /* dummy */
    };
    const size_t n_in_args = u_arr_size(in_args);

    aidl_vec_of_u8 output{};
    struct kmhal_arg_parse_desc out_args[] = {
        init_parse_i("output", &output, parse_aidl_vec_of_u8),
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_call(op, KeyMintOpCmd::UPDATE,
                in_args, n_in_args, out_args, n_out_args, reinterpret_cast<u32 *>(&err)) ||
            err != ErrorCode::OK)
    {
        std::cout << __func__ << ": AIDL call failed" << std::endl;
        err = ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }

    if (err != ErrorCode::OK) {
        destroy_aidl_vec_of_u8(&output);
        delete_invalidate_op_handle(operationHandle);
    } else {
        out_output = fromAidlDestroy(output);
        out_outParams = {};
        out_inputConsumed = input.size();
    }

    return err;
}

ErrorCode SusAidlKeyMint::finish(OpaqueOpHandle& operationHandle,
        std::vector<KeyParameter> const& inParams, std::vector<u8> const& input,
        std::vector<u8> const& signature, HardwareAuthToken const& authToken,
        std::vector<KeyParameter>& out_outParams, std::vector<u8>& out_output)
{
    size_t idx = 0;
    struct kmhal_sp *op = nullptr;
    if (get_op_handle(operationHandle, idx, op))
        return ErrorCode::INVALID_OPERATION_HANDLE;

    ErrorCode err = ErrorCode::UNKNOWN_ERROR;

    AidlVecOfKeyParameterView aidl_params(inParams);
    AidlVecOfU8View aidl_input(input);
    AidlVecOfU8View aidl_signature(signature);
    AidlHardwareAuthTokenView aidl_authToken(authToken);

    err = ErrorCode::UNKNOWN_ERROR;
    struct kmhal_arg_write_desc in_args[] = {
        init_write_i("input", aidl_input.get(), write_aidl_vec_of_u8),
        init_write_i("signature", aidl_signature.get(), write_aidl_vec_of_u8),
        init_write_i("authToken", (authToken.empty() ? nullptr : aidl_authToken.get()),
                     write_nullable_aidl_hardware_auth_token),
        init_write_p("timeStampToken", 0, kmhal_arg_write_u32), /* dummy */
        init_write_p("confirmationToken", 0, kmhal_arg_write_u32) /* dummy */
    };
    const size_t n_in_args = u_arr_size(in_args);

    aidl_vec_of_u8 output{};
    struct kmhal_arg_parse_desc out_args[] = {
        init_parse_i("output", &output, parse_aidl_vec_of_u8),
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_call(op, KeyMintOpCmd::FINISH,
                in_args, n_in_args, out_args, n_out_args, reinterpret_cast<u32 *>(&err)) ||
            err != ErrorCode::OK)
    {
        std::cout << __func__ << ": AIDL call failed" << std::endl;
        err = ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }
    if (err == ErrorCode::OK) {
        out_output = fromAidlDestroy(output);
        out_outParams = {};
    } else {
        destroy_aidl_vec_of_u8(&output);
    }

    delete_invalidate_op_handle(operationHandle);
    return err;
}

ErrorCode SusAidlKeyMint::abort(OpaqueOpHandle& operationHandle) {
    size_t idx = 0;
    struct kmhal_sp *op = nullptr;
    if (get_op_handle(operationHandle, idx, op))
        return ErrorCode::INVALID_OPERATION_HANDLE;

    ErrorCode err = ErrorCode::UNKNOWN_ERROR;
    if (kmhal_call(op, KeyMintOpCmd::ABORT, nullptr, 0, nullptr, 0,
                reinterpret_cast<u32 *>(&err)) != OK)
    {
        std::cerr << __func__ << ": AIDL call failed" << std::endl;
        err = ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }

    delete_invalidate_op_handle(operationHandle);
    return err;
}

static void convertAndDestroyKeyCharacteristics(KeyCharacteristics& out,
                                struct aidl_vec_of_key_characteristics &res_kc_vec)
{
    for (i32 i = 0; i < res_kc_vec.size; i++) {
        struct aidl_key_characteristics *const kc = &res_kc_vec.ptr[i];

        switch (kc->security_level) {
        default:
            std::cerr << "KeyMint: WARNING: Unknown securityLevel: " << kc->security_level
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
