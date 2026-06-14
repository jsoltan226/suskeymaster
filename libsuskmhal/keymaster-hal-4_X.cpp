#ifndef SUSKEYMASTER_HAL_DISABLE_4_0

#include "suskmhal.hpp"

#ifndef SUSKEYMASTER_BUILD_HOST
#include "keymaster-types-cpp.hpp"
#include "transport/hal.h"
#include "transport/hidl-types.h"
#include "transport/keymaster-types-hidl.h"
#include <vector>
#include <string>
#include <iostream>
#endif /* SUSKEYMASTER_BUILD_HOST */

#define MODULE_NAME "keymaster-hidl-hal-4.0"

namespace suskeymaster {
namespace kmhal {

using namespace generic;
using hidl::fromHidl;

#ifndef SUSKEYMASTER_BUILD_HOST

SusHidlKeymaster4_0::SusHidlKeymaster4_0(void) :
    SusHidlKeymaster4_0("android.hardware.keymaster@4.0::IKeymasterDevice", "default")
{
}

u32 SusHidlKeymaster4_0::getVersion(void) const { return 0x40; };

SusHidlKeymaster4_0::SusHidlKeymaster4_0(const char *fqname, const char *instname) :
    SusHidlKeymasterHALCommon(kmhal_hidl_sp_new_get(fqname, instname, nullptr, false))
{
    if (!this->getHal()) {
        /* std::cerr << "Failed to get a handle to the keymaster HAL service" << std::endl; */
    }
}

SusHidlKeymaster4_1::SusHidlKeymaster4_1(void) :
    SusHidlKeymaster4_0("android.hardware.keymaster@4.1::IKeymasterDevice", "default")
{
    if (!this->getHal()) return;

    /* All the supported cmds are from the 4.0 base
     * (4.1 extends 4.0) */
    kmhal_set_fqname(this->getHal(), "android.hardware.keymaster@4.0::IKeymasterDevice");
}

u32 SusHidlKeymaster4_1::getVersion(void) const { return 0x41; };

enum KM_4_0_cmd : u32 {
    KM_4_0_GET_HARDWARE_INFO = 1,
    KM_4_0_GET_HMAC_SHARING_PARAMETERS = 2,
    KM_4_0_COMPUTE_SHARED_HMAC = 3,
    KM_4_0_VERIFY_AUTHORIZATION = 4,
    KM_4_0_ADD_RNG_ENTROPY = 5,
    KM_4_0_GENERATE_KEY = 6,
    KM_4_0_IMPORT_KEY = 7,
    KM_4_0_IMPORT_WRAPPED_KEY = 8,
    KM_4_0_GET_KEY_CHARACTERISTICS = 9,
    KM_4_0_EXPORT_KEY = 10,
    KM_4_0_ATTEST_KEY = 11,
    KM_4_0_UPGRADE_KEY = 12,
    KM_4_0_DELETE_KEY = 13,
    KM_4_0_DELETE_ALL_KEYS = 14,
    KM_4_0_DESTROY_ATTESTATION_IDS = 15,
    KM_4_0_BEGIN = 16,
    KM_4_0_UPDATE = 17,
    KM_4_0_FINISH = 18,
    KM_4_0_ABORT = 19,
    KM_4_0_N_CMDS__ = KM_4_0_ABORT
};

#define check_hal_ok() do {                                         \
    if (!this->isHALOk()) {                                         \
        std::cerr << __func__ << ": HAL is not OK!" << std::endl;   \
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;           \
    }                                                               \
} while (0)

u32 SusHidlKeymaster4_0::getVersionSpecificCmdID(enum KM_common_cmd common_cmd)
{
    using KC = SusHidlKeymasterHALCommon::KM_common_cmd;

    switch (common_cmd) {
    case KC::KM_COMMON_ADD_RNG_ENTROPY: return KM_4_0_ADD_RNG_ENTROPY;
    case KC::KM_COMMON_GENERATE_KEY: return KM_4_0_GENERATE_KEY;
    case KC::KM_COMMON_IMPORT_KEY: return KM_4_0_IMPORT_KEY;
    case KC::KM_COMMON_GET_KEY_CHARACTERISTICS: return KM_4_0_GET_KEY_CHARACTERISTICS;
    case KC::KM_COMMON_EXPORT_KEY: return KM_4_0_EXPORT_KEY;
    case KC::KM_COMMON_ATTEST_KEY: return KM_4_0_ATTEST_KEY;
    case KC::KM_COMMON_UPGRADE_KEY: return KM_4_0_UPGRADE_KEY;
    case KC::KM_COMMON_DELETE_KEY: return KM_4_0_DELETE_KEY;
    case KC::KM_COMMON_DELETE_ALL_KEYS: return KM_4_0_DELETE_ALL_KEYS;
    case KC::KM_COMMON_DESTROY_ATTESTATION_IDS: return KM_4_0_DESTROY_ATTESTATION_IDS;
    case KC::KM_COMMON_ABORT: return KM_4_0_ABORT;
    default:
        std::cerr << "Invalid common command ID: " << static_cast<u32>(common_cmd) << std::endl;
        return static_cast<u32>(-1);
    }
}

using transport::init_write_p, transport::init_parse_p,
      transport::init_write_b, transport::init_parse_b;

void SusHidlKeymaster4_0::getHardwareInfo(SecurityLevel& out_securityLevel,
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

    u32 securityLevel = 0;
    const struct kmhal_hidl_string *keymasterName = nullptr, *keymasterAuthorName = nullptr;

    struct kmhal_arg_parse_desc out_args[] = {
        init_parse_p("securityLevel", &securityLevel, kmhal_arg_parse_u32),
        init_parse_b("keymasterName", &keymasterName, kmhal_hidl_arg_parse_hidl_string),
        init_parse_b("keymasterAuthorName", &keymasterAuthorName,
                kmhal_hidl_arg_parse_hidl_string),
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_call(this->getHal(), KM_4_0_GET_HARDWARE_INFO,
            in_args, n_in_args, out_args, n_out_args, nullptr) != OK)
    {
        std::cerr << "getHardwareInfo call failed!" << std::endl;
        goto fail;
    }

    out_securityLevel = static_cast<SecurityLevel>(securityLevel);
    out_keymasterName = std::string(keymasterName->buffer, keymasterName->length);
    out_keymasterAuthorName =
        std::string(keymasterAuthorName->buffer, keymasterAuthorName->length);
}

ErrorCode SusHidlKeymaster4_0::importWrappedKey(
        std::vector<u8> const& wrappedKeyData,
        std::vector<u8> const& wrappingKeyBlob,
        std::vector<u8> const& maskingKey,
        std::vector<KeyParameter> const& unwrappingParams,
        u64 passwordSid, u64 biometricSid,
        std::vector<u8>& out_keyBlob,
        KeyCharacteristics& out_keyCharacteristics)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;
    const hidl_vec<u8> *keyBlob = nullptr;
    const hidl::KeyCharacteristics *keyCharacteristics = nullptr;

    const hidl_vec<u8> hidl_wrappedKeyData = toHidlView(wrappedKeyData);
    const hidl_vec<u8> hidl_wrappingKeyBlob = toHidlView(wrappingKeyBlob);
    const hidl_vec<u8> hidl_maskingKey = toHidlView(maskingKey);
    const hidl_vec<hidl::KeyParameter> hidl_unwrappingParams = toHidlView(unwrappingParams);

    struct kmhal_arg_write_desc in_args[] = {
        init_write_b("wrappedKeyData", &hidl_wrappedKeyData,
                kmhal_hidl_arg_write_vec_of_u8),
        init_write_b("wrappingKeyBlob", &hidl_wrappingKeyBlob,
                kmhal_hidl_arg_write_vec_of_u8),
        init_write_b("maskingKey", &hidl_maskingKey, kmhal_hidl_arg_write_vec_of_u8),
        init_write_b("unwrappingParams", &hidl_unwrappingParams,
                write_vec_of_key_parameter),
        init_write_p("passwordSid", passwordSid, kmhal_arg_write_u64),
        init_write_p("biometricSid", biometricSid, kmhal_arg_write_u64),
    };
    const size_t n_in_args = u_arr_size(in_args);
    struct kmhal_arg_parse_desc out_args[] = {
        init_parse_p("error", &ret, kmhal_arg_parse_u32),
        init_parse_b("keyBlob", &keyBlob, kmhal_hidl_arg_parse_vec_of_u8),
        init_parse_b("keyCharacteristics", &keyCharacteristics, parse_key_characteristics),
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_call(this->getHal(), KM_4_0_IMPORT_WRAPPED_KEY,
                in_args, n_in_args, out_args, n_out_args, nullptr))
    {
        std::cerr << __func__ << ": HIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }
    if (ret == ErrorCode::OK) {
        out_keyBlob = fromHidl(*keyBlob);
        out_keyCharacteristics = fromHidl(*keyCharacteristics);
    }

    return ret;
}

ErrorCode SusHidlKeymaster4_0::begin(KeyPurpose purpose,
        std::vector<u8> const& keyBlob,
        std::vector<KeyParameter> const& inParams,
        HardwareAuthToken const& authToken,
        std::vector<KeyParameter>& out_outParams,
        OpaqueOpHandle& out_operationHandle)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;
    const hidl_vec<hidl::KeyParameter> *outParams = nullptr;

    const hidl_vec<u8> hidl_keyBlob = toHidlView(keyBlob);
    const hidl_vec<hidl::KeyParameter> hidl_inParams = toHidlView(inParams);
    const hidl::HardwareAuthToken hidl_authToken = toHidlView(authToken);

    struct kmhal_arg_write_desc in_args[] = {
        init_write_p("purpose", purpose, kmhal_arg_write_u32),
        init_write_b("keyBlob", &hidl_keyBlob, kmhal_hidl_arg_write_vec_of_u8),
        init_write_b("inParams", &hidl_inParams, write_vec_of_key_parameter),
        init_write_b("authToken", &hidl_authToken, write_hardware_auth_token),
    };
    const size_t n_in_args = u_arr_size(in_args);
    struct kmhal_arg_parse_desc out_args[] = {
        init_parse_p("error", &ret, kmhal_arg_parse_u32),
        init_parse_b("outParams", &outParams, parse_vec_of_key_parameter),
        init_parse_p("operationHandle", reinterpret_cast<u64 *>(&out_operationHandle),
                kmhal_arg_parse_u64),
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_call(this->getHal(), KM_4_0_BEGIN,
                in_args, n_in_args, out_args, n_out_args, nullptr))
    {
        std::cerr << __func__ << ": HIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }
    if (ret == ErrorCode::OK)
        out_outParams = fromHidl(*outParams);

    return ret;
}

ErrorCode SusHidlKeymaster4_0::update(OpaqueOpHandle& operationHandle,
        std::vector<KeyParameter> const& inParams,
        std::vector<u8> const& input,
        HardwareAuthToken const& authToken,
        u32& out_inputConsumed,
        std::vector<KeyParameter>& out_outParams,
        std::vector<u8>& out_output)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;
    const hidl_vec<hidl::KeyParameter> *outParams = nullptr;
    const hidl_vec<u8> *output = nullptr;

    const hidl_vec<hidl::KeyParameter> hidl_inParams = toHidlView(inParams);
    const hidl_vec<u8> hidl_input = toHidlView(input);
    const hidl::HardwareAuthToken hidl_authToken = toHidlView(authToken);
    const hidl::VerificationToken hidl_verificationToken = {};

    const u64 ophandle_val = reinterpret_cast<u64>(operationHandle);
    struct kmhal_arg_write_desc in_args[] = {
        init_write_p("operationHandle", ophandle_val, kmhal_arg_write_u64),
        init_write_b("inParams", &hidl_inParams, write_vec_of_key_parameter),
        init_write_b("input", &hidl_input, kmhal_hidl_arg_write_vec_of_u8),
        init_write_b("authToken", &hidl_authToken, write_hardware_auth_token),
        init_write_b("verificationToken", &hidl_verificationToken, write_verification_token),
    };
    const size_t n_in_args = u_arr_size(in_args);
    struct kmhal_arg_parse_desc out_args[] = {
        init_parse_p("error", &ret, kmhal_arg_parse_u32),
        init_parse_p("inputConsumed", &out_inputConsumed, kmhal_arg_parse_u32),
        init_parse_b("outParams", &outParams, parse_vec_of_key_parameter),
        init_parse_b("output", &output, kmhal_hidl_arg_parse_vec_of_u8),
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_call(this->getHal(), KM_4_0_UPDATE,
                in_args, n_in_args, out_args, n_out_args, nullptr))
    {
        std::cerr << __func__ << ": HIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }
    if (ret == ErrorCode::OK) {
        out_outParams = fromHidl(*outParams);
        out_output = fromHidl(*output);
    }

    return ret;
}

ErrorCode SusHidlKeymaster4_0::finish(OpaqueOpHandle& operationHandle,
        std::vector<KeyParameter> const& inParams,
        std::vector<u8> const& input,
        std::vector<u8> const& signature,
        HardwareAuthToken const& authToken,
        std::vector<KeyParameter>& out_outParams,
        std::vector<u8>& out_output)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;
    const hidl_vec<hidl::KeyParameter> *outParams = nullptr;
    const hidl_vec<u8> *output = nullptr;

    const hidl_vec<hidl::KeyParameter> hidl_inParams = toHidlView(inParams);
    const hidl_vec<u8> hidl_input = toHidlView(input);
    const hidl_vec<u8> hidl_signature = toHidlView(signature);
    const hidl::HardwareAuthToken hidl_authToken = toHidlView(authToken);
    const hidl::VerificationToken hidl_verificationToken = {};

    const u64 ophandle_val = reinterpret_cast<u64>(operationHandle);
    struct kmhal_arg_write_desc in_args[] = {
        init_write_p("operationHandle", ophandle_val, kmhal_arg_write_u64),
        init_write_b("inParams", &hidl_inParams, write_vec_of_key_parameter),
        init_write_b("input", &hidl_input, kmhal_hidl_arg_write_vec_of_u8),
        init_write_b("signature", &hidl_signature, kmhal_hidl_arg_write_vec_of_u8),
        init_write_b("authToken", &hidl_authToken, write_hardware_auth_token),
        init_write_b("verificationToken", &hidl_verificationToken, write_verification_token),
    };
    const size_t n_in_args = u_arr_size(in_args);
    struct kmhal_arg_parse_desc out_args[] = {
        init_parse_p("error", &ret, kmhal_arg_parse_u32),
        init_parse_b("outParams", &outParams, parse_vec_of_key_parameter),
        init_parse_b("output", &output, kmhal_hidl_arg_parse_vec_of_u8),
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_call(this->getHal(), KM_4_0_FINISH,
                in_args, n_in_args, out_args, n_out_args, nullptr))
    {
        std::cerr << __func__ << ": HIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }
    if (ret == ErrorCode::OK) {
        out_outParams = fromHidl(*outParams);
        out_output = fromHidl(*output);
    }

    return ret;
}

#undef check_hal_ok

#else /* SUSKEYMASTER_BUILD_HOST */

SusHidlKeymaster4_0::SusHidlKeymaster4_0(void)
{
}

SusHidlKeymaster4_0::~SusHidlKeymaster4_0(void)
{
}

SusHidlKeymaster4_1::SusHidlKeymaster4_1(void)
{
}

SusHidlKeymaster4_1::~SusHidlKeymaster4_1(void)
{
}

#endif /* SUSKEYMASTER_BUILD_HOST */

} /* namespace kmhal */
} /* namespace suskeymaster */
#endif /* SUSKEYMASTER_HAL_DISABLE_4_0 */
