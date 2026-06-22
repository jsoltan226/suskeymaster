#ifndef SUSKEYMASTER_HAL_DISABLE_3_0

#include "suskmhal.hpp"

#ifndef SUSKEYMASTER_BUILD_HOST
#include "keymaster-types-cpp.hpp"
#include "transport/hal.h"
#include "transport/hidl-types.h"
#include "transport/aosp-hidl-support.hpp"
#include "transport/keymaster-types-hidl.h"
#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <endian.h>
#endif /* SUSKEYMASTER_BUILD_HOST */

#define MODULE_NAME "keymaster-hidl-hal-3.0"

namespace suskeymaster {
namespace kmhal {

using namespace generic;
using hidl::fromHidl;

#ifndef SUSKEYMASTER_BUILD_HOST

static void handle_auth_token_compat(hidl_vec<hidl::KeyParameter>& par,
                                     HardwareAuthToken const& at,
                                     const char *func);

SusHidlKeymaster3_0::SusHidlKeymaster3_0(const char *instname) :
    SusHidlKeymasterHALCommon(
        kmhal_hidl_sp_new_get("android.hardware.keymaster@3.0::IKeymasterDevice", instname,
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

using transport::init_write_p, transport::init_parse_p,
      transport::init_write_b, transport::init_parse_b;

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

    u32 isSecure = 0, supportsEllipticCurve = 0, supportsSymmetricCryptography = 0,
        supportsAttestation = 0, supportsAllDigests = 0;
    const struct kmhal_hidl_string *keymasterName = nullptr, *keymasterAuthorName = nullptr;

    struct kmhal_arg_parse_desc out_args[] = {
        init_parse_p("isSecure", &isSecure, kmhal_arg_parse_u32),
        init_parse_p("supportsEllipticCurve", &supportsEllipticCurve, kmhal_arg_parse_u32),
        init_parse_p("supportsSymmetricCryptography",
                &supportsSymmetricCryptography, kmhal_arg_parse_u32),
        init_parse_p("supportsAttestation", &supportsAttestation, kmhal_arg_parse_u32),
        init_parse_p("supportsAllDigests", &supportsAllDigests, kmhal_arg_parse_u32),
        init_parse_b("keymasterName", &keymasterName, kmhal_hidl_arg_parse_hidl_string),
        init_parse_b("keymasterAuthorName", &keymasterAuthorName, kmhal_hidl_arg_parse_hidl_string)
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_call(this->getHal(), KM_3_0_GET_HARDWARE_FEATURES,
            in_args, n_in_args, out_args, n_out_args, nullptr) != OK)
    {
        std::cerr << "getHardwareFeatures call failed!" << std::endl;
        goto fail;
    }

    out_securityLevel = isSecure ? SecurityLevel::TRUSTED_ENVIRONMENT : SecurityLevel::SOFTWARE;
    if (!supportsEllipticCurve)
        std::cout << "Keymaster 3.0: supportsEllipticCurve: "
                << supportsEllipticCurve << std::endl;
    if (!supportsSymmetricCryptography)
        std::cout << "Keymaster 3.0: supportsSymmetricCryptography: "
                << supportsSymmetricCryptography << std::endl;
    if (!supportsAttestation)
        std::cout << "Keymaster 3.0: supportsAttestation: "
                << supportsAttestation << std::endl;
    if (!supportsAllDigests)
        std::cout << "Keymaster 3.0: supportsAllDigests: "
                << supportsAllDigests << std::endl;

    out_keymasterName = std::string(keymasterName->buffer, keymasterName->length);
    out_keymasterAuthorName =
        std::string(keymasterAuthorName->buffer, keymasterAuthorName->length);
}

ErrorCode SusHidlKeymaster3_0::begin(KeyPurpose purpose,
        std::vector<u8> const& keyBlob,
        std::vector<generic::KeyParameter> const& inParams,
        HardwareAuthToken const& authToken,
        std::vector<generic::KeyParameter>& out_outParams,
        OpaqueOpHandle& out_operationHandle)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;
    const hidl_vec<hidl::KeyParameter> *outParams = nullptr;

    const hidl_vec<u8> hidl_keyBlob = toHidlView(keyBlob);
    hidl_vec<hidl::KeyParameter> hidl_inParams = toHidlView(inParams);

    handle_auth_token_compat(hidl_inParams, authToken, "begin");

    struct kmhal_arg_write_desc in_args[] = {
        init_write_p("purpose", purpose, kmhal_arg_write_u32),
        init_write_b("keyBlob", &hidl_keyBlob, kmhal_hidl_arg_write_vec_of_u8),
        init_write_b("inParams", &hidl_inParams, write_vec_of_key_parameter),
    };
    const size_t n_in_args = u_arr_size(in_args);
    struct kmhal_arg_parse_desc out_args[] = {
        init_parse_p("error", &ret, kmhal_arg_parse_u32),
        init_parse_b("outParams", &outParams, parse_vec_of_key_parameter),
        init_parse_p("operationHandle", reinterpret_cast<u64 *>(&out_operationHandle),
                kmhal_arg_parse_u64),
    };
    const size_t n_out_args = u_arr_size(out_args);
    if (kmhal_call(this->getHal(), KM_3_0_BEGIN,
                in_args, n_in_args, out_args, n_out_args, nullptr))
    {
        std::cerr << __func__ << ": HIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }
    if (ret == ErrorCode::OK)
        out_outParams = fromHidl(*outParams);

    return ret;
}

ErrorCode SusHidlKeymaster3_0::update(OpaqueOpHandle& operationHandle,
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

    hidl_vec<hidl::KeyParameter> hidl_inParams = toHidlView(inParams);
    const hidl_vec<u8> hidl_input = toHidlView(input);

    handle_auth_token_compat(hidl_inParams, authToken, "update");

    const u64 ophandle_val = reinterpret_cast<u64>(operationHandle);
    struct kmhal_arg_write_desc in_args[] = {
        init_write_p("operationHandle", ophandle_val, kmhal_arg_write_u64),
        init_write_b("inParams", &hidl_inParams, write_vec_of_key_parameter),
        init_write_b("input", &hidl_input, kmhal_hidl_arg_write_vec_of_u8),
    };
    const size_t n_in_args = u_arr_size(in_args);
    struct kmhal_arg_parse_desc out_args[] = {
        init_parse_p("error", &ret, kmhal_arg_parse_u32),
        init_parse_p("inputConsumed", &out_inputConsumed, kmhal_arg_parse_u32),
        init_parse_b("outParams", &outParams, parse_vec_of_key_parameter),
        init_parse_b("output", &output, kmhal_hidl_arg_parse_vec_of_u8),
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_call(this->getHal(), KM_3_0_UPDATE,
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

ErrorCode SusHidlKeymaster3_0::finish(OpaqueOpHandle& operationHandle,
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

    hidl_vec<hidl::KeyParameter> hidl_inParams = toHidlView(inParams);
    const hidl_vec<u8> hidl_input = toHidlView(input);
    const hidl_vec<u8> hidl_signature = toHidlView(signature);

    handle_auth_token_compat(hidl_inParams, authToken, "finish");

    const u64 ophandle_val = reinterpret_cast<u64>(operationHandle);
    struct kmhal_arg_write_desc in_args[] = {
        init_write_p("operationHandle", ophandle_val, kmhal_arg_write_u64),
        init_write_b("inParams", &hidl_inParams, write_vec_of_key_parameter),
        init_write_b("input", &hidl_input, kmhal_hidl_arg_write_vec_of_u8),
        init_write_b("signature", &hidl_signature, kmhal_hidl_arg_write_vec_of_u8),
    };
    const size_t n_in_args = u_arr_size(in_args);
    struct kmhal_arg_parse_desc out_args[] = {
        init_parse_p("error", &ret, kmhal_arg_parse_u32),
        init_parse_b("outParams", &outParams, parse_vec_of_key_parameter),
        init_parse_b("output", &output, kmhal_hidl_arg_parse_vec_of_u8),
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_call(this->getHal(), KM_3_0_FINISH,
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

static void handle_auth_token_compat(hidl_vec<hidl::KeyParameter>& par,
                                     HardwareAuthToken const& at,
                                     const char *func)
{
    /* non-empty MAC means non-empty auth token */
    if (at.mac.size() > 0) {

        par.resize(par.size() + 1);
        par[par.size() - 1].tag = Tag::AUTH_TOKEN;
        par[par.size() - 1].blob = hidl_vec<u8>(serialize_auth_token(at));
        /*
        std::cout << "Keymaster 3.0: " << func <<
            ": Converted authToken argument to Tag::AUTH_TOKEN key parameter" << std::endl;
            */
        (void) func;
    }
}

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
