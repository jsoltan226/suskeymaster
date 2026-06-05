#include "transport/hidl-types.h"
#ifndef SUSKEYMASTER_HAL_DISABLE_3_0

#include "suskmhal.hpp"

#ifndef SUSKEYMASTER_BUILD_HOST
#include "keymaster-types-cpp.hpp"
#include "transport/hal.h"
#include "transport/km-hidl-types.hpp"
#include "transport/aosp-hidl-support.hpp"
#include <iostream>
using ::android::hardware::hidl_vec;
#endif /* SUSKEYMASTER_BUILD_HOST */

#define MODULE_NAME "keymaster-hidl-hal-3.0"

using namespace ::android::hardware::keymaster::generic;

namespace suskeymaster {
namespace kmhal {

#ifndef SUSKEYMASTER_BUILD_HOST

SusHidlKeymaster3_0::SusHidlKeymaster3_0(void) :
    SusHidlKeymasterHALCommon(
        kmhal_hidl_sp_new_get("android.hardware.keymaster@3.0::IKeymasterDevice", "default",
                              nullptr, false)
    )
{
    if (!this->getHal()) {
        /* std::cerr << "Failed to get a handle to the keymaster HAL service" << std::endl; */
        return;
    }
}

enum KM_3_0_cmd : u32 {
    KM_3_0_GET_HARDWARE_FEATURES = 1,
    KM_3_0_ADD_RNG_ENTROPY = 2,
    KM_3_0_GENERATE_KEY = 3,
    KM_3_0_IMPORT_KEY = 4,
    KM_3_0_GET_KEY_CHARACTERISTICS = 5,
    KM_3_0_EXPORT_KEY = 6,
    KM_3_0_ATTEST_KEY = 7,
    KM_3_0_UPGRADE_KEY = 8,
    KM_3_0_DELETE_KEY = 9,
    KM_3_0_DELETE_ALL_KEYS = 10,
    KM_3_0_DESTROY_ATTESTATION_IDS = 11,
    KM_3_0_BEGIN = 12,
    KM_3_0_UPDATE = 13,
    KM_3_0_FINISH = 14,
    KM_3_0_ABORT = 15,
    KM_3_0_N_CMDS__ = KM_3_0_ABORT
};

#define check_hal_ok() do {                                         \
    if (!this->isHALOk()) {                                         \
        std::cerr << __func__ << ": HAL is not OK!" << std::endl;   \
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;           \
    }                                                               \
} while (0)

using transport::init_write, transport::init_parse;

u32 SusHidlKeymaster3_0::getVersionSpecificCmdID(enum KM_common_cmd common_cmd)
{
    using KC = SusHidlKeymasterHALCommon::KM_common_cmd;

    switch (common_cmd) {
    case KC::KM_COMMON_ADD_RNG_ENTROPY: return KM_3_0_ADD_RNG_ENTROPY;
    case KC::KM_COMMON_GENERATE_KEY: return KM_3_0_GENERATE_KEY;
    case KC::KM_COMMON_IMPORT_KEY: return KM_3_0_IMPORT_KEY;
    case KC::KM_COMMON_GET_KEY_CHARACTERISTICS: return KM_3_0_GET_KEY_CHARACTERISTICS;
    case KC::KM_COMMON_EXPORT_KEY: return KM_3_0_EXPORT_KEY;
    case KC::KM_COMMON_ATTEST_KEY: return KM_3_0_ATTEST_KEY;
    case KC::KM_COMMON_UPGRADE_KEY: return KM_3_0_UPGRADE_KEY;
    case KC::KM_COMMON_DELETE_KEY: return KM_3_0_DELETE_KEY;
    case KC::KM_COMMON_DELETE_ALL_KEYS: return KM_3_0_DELETE_ALL_KEYS;
    case KC::KM_COMMON_DESTROY_ATTESTATION_IDS: return KM_3_0_DESTROY_ATTESTATION_IDS;
    case KC::KM_COMMON_ABORT: return KM_3_0_ABORT;
    default:
        std::cerr << "Invalid common command ID: " << static_cast<u32>(common_cmd) << std::endl;
        return static_cast<u32>(-1);
    }
}

void SusHidlKeymaster3_0::getHardwareInfo(SecurityLevel& out_securityLevel,
        hidl_string& out_keymasterName, hidl_string& out_keymasterAuthorName)
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

    u32 isSecure = 0, supportsEllipticCurve = 0, supportsSymmetricCryptography = 0,
        supportsAttestation = 0, supportsAllDigests = 0;
    const struct kmhal_hidl_string *keymasterName = nullptr, *keymasterAuthorName = nullptr;

    struct kmhal_arg_parse_desc out_args[] = {
        init_parse("isSecure", &isSecure, kmhal_arg_parse_u32),
        init_parse("supportsEllipticCurve", &supportsEllipticCurve, kmhal_arg_parse_u32),
        init_parse("supportsSymmetricCryptography",
                &supportsSymmetricCryptography, kmhal_arg_parse_u32),
        init_parse("supportsAttestation", &supportsAttestation, kmhal_arg_parse_u32),
        init_parse("supportsAllDigests", &supportsAllDigests, kmhal_arg_parse_u32),
        init_parse("keymasterName", &keymasterName, kmhal_hidl_arg_parse_hidl_string),
        init_parse("keymasterAuthorName", &keymasterAuthorName, kmhal_hidl_arg_parse_hidl_string)
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_call(this->getHal(), KM_3_0_GET_HARDWARE_FEATURES,
            in_args, n_in_args, out_args, n_out_args) != OK)
    {
        std::cerr << "getHardwareFeatures call failed!" << std::endl;
        goto fail;
    }

    out_securityLevel = isSecure ? SecurityLevel::TRUSTED_ENVIRONMENT : SecurityLevel::SOFTWARE;
    std::cout << "Keymaster 3.0: supportsEllipticCurve: "
            << supportsEllipticCurve << std::endl;
    std::cout << "Keymaster 3.0: supportsSymmetricCryptography: "
            << supportsSymmetricCryptography << std::endl;
    std::cout << "Keymaster 3.0: supportsAttestation: "
            << supportsAttestation << std::endl;
    std::cout << "Keymaster 3.0: supportsAllDigests: "
            << supportsAllDigests << std::endl;

    out_keymasterName = hidl_string(*reinterpret_cast<const hidl_string *>(keymasterName));
    out_keymasterAuthorName =
        hidl_string(*reinterpret_cast<const hidl_string *>(keymasterAuthorName));
}

ErrorCode SusHidlKeymaster3_0::begin(KeyPurpose purpose,
        hidl_vec<u8> const& keyBlob,
        hidl_vec<KeyParameter> const& inParams,
        HardwareAuthToken const& authToken,
        hidl_vec<KeyParameter>& out_outParams,
        u64& out_operationHandle)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;
    const hidl_vec<KeyParameter> *outParams = nullptr;

    (void) authToken;

    struct kmhal_arg_write_desc in_args[] = {
        init_write("purpose", purpose, kmhal_arg_write_u32),
        init_write("keyBlob", &keyBlob, kmhal_hidl_arg_write_vec_of_u8),
        init_write("inParams", &inParams, write_vec_of_key_parameter),
    };
    const size_t n_in_args = u_arr_size(in_args);

    struct kmhal_arg_parse_desc out_args[] = {
        init_parse("error", &ret, kmhal_arg_parse_u32),
        init_parse("outParams", &outParams, read_vec_of_key_parameter),
        init_parse("operationHandle", &out_operationHandle, kmhal_arg_parse_u64),
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_call(this->getHal(), KM_3_0_BEGIN, in_args, n_in_args, out_args, n_out_args)) {
        std::cerr << __func__ << ": HIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }
    if (ret == ErrorCode::OK)
        out_outParams = hidl_vec<KeyParameter>(*outParams);

    return ret;
}

ErrorCode SusHidlKeymaster3_0::update(u64 operationHandle,
        hidl_vec<KeyParameter> const& inParams,
        hidl_vec<u8> const& input,
        HardwareAuthToken const& authToken,
        VerificationToken const& verificationToken,
        u32& out_inputConsumed,
        hidl_vec<KeyParameter>& out_outParams,
        hidl_vec<u8>& out_output)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;
    const hidl_vec<KeyParameter> *outParams = nullptr;
    const hidl_vec<u8> *output = nullptr;

    (void) authToken;
    (void) verificationToken;

    struct kmhal_arg_write_desc in_args[] = {
        init_write("operationHandle", operationHandle, kmhal_arg_write_u64),
        init_write("inParams", &inParams, write_vec_of_key_parameter),
        init_write("input", &input, kmhal_hidl_arg_write_vec_of_u8),
    };
    const size_t n_in_args = u_arr_size(in_args);

    struct kmhal_arg_parse_desc out_args[] = {
        init_parse("error", &ret, kmhal_arg_parse_u32),
        init_parse("inputConsumed", &out_inputConsumed, kmhal_arg_parse_u32),
        init_parse("outParams", &outParams, read_vec_of_key_parameter),
        init_parse("output", &output, kmhal_hidl_arg_parse_vec_of_u8),
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_call(this->getHal(), KM_3_0_UPDATE, in_args, n_in_args, out_args, n_out_args)) {
        std::cerr << __func__ << ": HIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }
    if (ret == ErrorCode::OK) {
        out_outParams = hidl_vec<KeyParameter>(*outParams);
        out_output = hidl_vec<u8>(*output);
    }

    return ret;
}

ErrorCode SusHidlKeymaster3_0::finish(u64 operationHandle,
        hidl_vec<KeyParameter> const& inParams,
        hidl_vec<u8> const& input,
        hidl_vec<u8> const& signature,
        HardwareAuthToken const& authToken,
        VerificationToken const& verificationToken,
        hidl_vec<KeyParameter>& out_outParams,
        hidl_vec<u8>& out_output)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;
    const hidl_vec<KeyParameter> *outParams = nullptr;
    const hidl_vec<u8> *output = nullptr;

    (void) authToken;
    (void) verificationToken;

    struct kmhal_arg_write_desc in_args[] = {
        init_write("operationHandle", operationHandle, kmhal_arg_write_u64),
        init_write("inParams", &inParams, write_vec_of_key_parameter),
        init_write("input", &input, kmhal_hidl_arg_write_vec_of_u8),
        init_write("signature", &signature, kmhal_hidl_arg_write_vec_of_u8),
    };
    const size_t n_in_args = u_arr_size(in_args);

    struct kmhal_arg_parse_desc out_args[] = {
        init_parse("error", &ret, kmhal_arg_parse_u32),
        init_parse("outParams", &outParams, read_vec_of_key_parameter),
        init_parse("output", &output, kmhal_hidl_arg_parse_vec_of_u8),
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_call(this->getHal(), KM_3_0_FINISH, in_args, n_in_args, out_args, n_out_args)) {
        std::cerr << __func__ << ": HIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }
    if (ret == ErrorCode::OK) {
        out_outParams = hidl_vec<KeyParameter>(*outParams);
        out_output = hidl_vec<u8>(*output);
    }

    return ret;
}

#undef check_hal_ok

#else /* SUSKEYMASTER_BUILD_HOST */

SusHidlKeymaster3_0::SusHidlKeymaster3_0(void)
{
}

SusHidlKeymaster3_0::~SusHidlKeymaster3_0(void)
{
}

#endif /* SUSKEYMASTER_BUILD_HOST */

} /* namespace kmhal */
} /* namespace suskeymaster */
#endif /* SUSKEYMASTER_HAL_DISABLE_3_0 */
