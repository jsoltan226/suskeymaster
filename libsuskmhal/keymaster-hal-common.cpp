#ifndef SUSKEYMASTER_BUILD_HOST

#include "suskmhal.hpp"
#include "keymaster-types-cpp.hpp"
#include "transport/hal.h"
#include "transport/hidl-types.h"
#include "transport/keymaster-types-hidl.h"

namespace suskeymaster {
namespace kmhal {

using namespace generic;
using hidl::fromHidl;

#define check_hal_ok() do {                                         \
    if (!this->isHALOk()) {                                         \
        std::cerr << __func__ << ": HAL is not OK!" << std::endl;   \
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;           \
    }                                                               \
} while (0)

struct kmhal_sp * SusHidlKeymasterHALCommon::getHalSp(void) const
{
    return this->getHal();
}

bool SusHidlKeymasterHALCommon::isHALOk(void) const
{
    if (!this->getHal()) {
        /* std::cout << __func__ << ": false" << std::endl; */
        return false;
    }

    return kmhal_ping(this->getHal()) == OK;
}

u64 SusHidlKeymasterHALCommon::getOpHandleChallenge(const OpaqueOpHandle& user_handle)
{
    /* In Keymaster, the handle value itself is the challenge */
    return reinterpret_cast<u64>(user_handle);
}

using transport::init_write_p, transport::init_parse_p,
      transport::init_write_b, transport::init_parse_b;

ErrorCode SusHidlKeymasterHALCommon::addRngEntropy(std::vector<u8> const& data)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

    const hidl_vec<u8> hidl_data = toHidlView(data);

    struct kmhal_arg_write_desc in_args[] = {
        init_write_b("data", &hidl_data, kmhal_hidl_arg_write_vec_of_u8)
    };
    const size_t n_in_args = u_arr_size(in_args);
    struct kmhal_arg_parse_desc out_args[] = {
        init_parse_p("error", &ret, kmhal_arg_parse_u32)
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_call(this->getHal(), getVersionSpecificCmdID(KM_COMMON_ADD_RNG_ENTROPY),
                in_args, n_in_args, out_args, n_out_args, nullptr))
    {
        std::cerr << __func__ << ": HIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }

    return ret;
}

ErrorCode SusHidlKeymasterHALCommon::generateKey(
        std::vector<KeyParameter> const& keyParams,
        std::vector<u8>& out_keyBlob,
        KeyCharacteristics& out_keyCharacteristics,
        std::vector<std::vector<u8>>* /* ignored on Keymaster */)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;
    const hidl_vec<u8> *keyBlob = nullptr;
    const hidl::KeyCharacteristics *keyCharacteristics = nullptr;

    const hidl_vec<hidl::KeyParameter> hidl_keyParams = toHidlView(keyParams);

    struct kmhal_arg_write_desc in_args[] = {
        init_write_b("keyParams", &hidl_keyParams, write_vec_of_key_parameter)
    };
    const size_t n_in_args = u_arr_size(in_args);
    struct kmhal_arg_parse_desc out_args[] = {
        init_parse_p("error", &ret, kmhal_arg_parse_u32),
        init_parse_b("keyBlob", &keyBlob, kmhal_hidl_arg_parse_vec_of_u8),
        init_parse_b("keyCharacteristics", &keyCharacteristics, parse_key_characteristics)
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_call(this->getHal(), getVersionSpecificCmdID(KM_COMMON_GENERATE_KEY),
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

ErrorCode SusHidlKeymasterHALCommon::importKey(
        std::vector<KeyParameter> const& keyParams,
        KeyFormat keyFormat, std::vector<u8> const& keyData,
        std::vector<u8>& out_keyBlob,
        KeyCharacteristics& out_keyCharacteristics,
        std::vector<std::vector<u8>> * /* ignored on Keymaster */)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;
    const hidl_vec<u8> *keyBlob = nullptr;
    const hidl::KeyCharacteristics *keyCharacteristics = nullptr;

    const hidl_vec<hidl::KeyParameter> hidl_keyParams = toHidlView(keyParams);
    const hidl_vec<u8> hidl_keyData = toHidlView(keyData);

    struct kmhal_arg_write_desc in_args[] = {
        init_write_b("keyParams", &hidl_keyParams, write_vec_of_key_parameter),
        init_write_p("keyFormat", keyFormat, kmhal_arg_write_u32),
        init_write_b("keyData", &hidl_keyData, kmhal_hidl_arg_write_vec_of_u8),
    };
    const size_t n_in_args = u_arr_size(in_args);
    struct kmhal_arg_parse_desc out_args[] = {
        init_parse_p("error", &ret, kmhal_arg_parse_u32),
        init_parse_b("keyBlob", &keyBlob, kmhal_hidl_arg_parse_vec_of_u8),
        init_parse_b("keyCharacteristics", &keyCharacteristics, parse_key_characteristics),
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_call(this->getHal(), getVersionSpecificCmdID(KM_COMMON_IMPORT_KEY),
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

ErrorCode SusHidlKeymasterHALCommon::getKeyCharacteristics(
        std::vector<u8> const& keyBlob,
        std::vector<u8> const& applicationId,
        std::vector<u8> const& applicationData,
        KeyCharacteristics& out_keyCharacteristics)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;
    const hidl::KeyCharacteristics *keyCharacteristics = nullptr;

    const hidl_vec<u8> hidl_keyBlob = toHidlView(keyBlob);
    const hidl_vec<u8> hidl_applicationId = toHidlView(applicationId);
    const hidl_vec<u8> hidl_applicationData = toHidlView(applicationData);

    struct kmhal_arg_write_desc in_args[] = {
        init_write_b("keyBlob", &hidl_keyBlob, kmhal_hidl_arg_write_vec_of_u8),
        init_write_b("applicationId", &hidl_applicationId, kmhal_hidl_arg_write_vec_of_u8),
        init_write_b("applicationData", &hidl_applicationData,
                kmhal_hidl_arg_write_vec_of_u8),
    };
    const size_t n_in_args = u_arr_size(in_args);
    struct kmhal_arg_parse_desc out_args[] = {
        init_parse_p("error", &ret, kmhal_arg_parse_u32),
        init_parse_b("keyCharacteristics", &keyCharacteristics, parse_key_characteristics),
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_call(this->getHal(),
                getVersionSpecificCmdID(KM_COMMON_GET_KEY_CHARACTERISTICS),
                in_args, n_in_args, out_args, n_out_args, nullptr))
    {
        std::cerr << __func__ << ": HIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }
    if (ret == ErrorCode::OK)
        out_keyCharacteristics = fromHidl(*keyCharacteristics);

    return ret;
}

ErrorCode SusHidlKeymasterHALCommon::exportKey(KeyFormat keyFormat,
        std::vector<u8> const& keyBlob,
        std::vector<u8> const& applicationId,
        std::vector<u8> const& applicationData,
        std::vector<u8>& out_keyMaterial)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;
    const hidl_vec<u8> *keyMaterial = nullptr;

    const hidl_vec<u8> hidl_keyBlob = toHidlView(keyBlob);
    const hidl_vec<u8> hidl_applicationId = toHidlView(applicationId);
    const hidl_vec<u8> hidl_applicationData = toHidlView(applicationData);

    struct kmhal_arg_write_desc in_args[] = {
        init_write_p("keyFormat", keyFormat, kmhal_arg_write_u32),
        init_write_b("keyBlob", &hidl_keyBlob, kmhal_hidl_arg_write_vec_of_u8),
        init_write_b("applicationId", &hidl_applicationId, kmhal_hidl_arg_write_vec_of_u8),
        init_write_b("applicationData", &hidl_applicationData,
                kmhal_hidl_arg_write_vec_of_u8),
    };
    const size_t n_in_args = u_arr_size(in_args);
    struct kmhal_arg_parse_desc out_args[] = {
        init_parse_p("error", &ret, kmhal_arg_parse_u32),
        init_parse_b("keyMaterial", &keyMaterial, kmhal_hidl_arg_parse_vec_of_u8),
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_call(this->getHal(), getVersionSpecificCmdID(KM_COMMON_EXPORT_KEY),
                in_args, n_in_args, out_args, n_out_args, nullptr))
    {
        std::cerr << __func__ << ": HIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }
    if (ret == ErrorCode::OK)
        out_keyMaterial = fromHidl(*keyMaterial);

    return ret;
}

ErrorCode SusHidlKeymasterHALCommon::attestKey(
        std::vector<u8> const& keyToAttest,
        std::vector<KeyParameter> const& attestParams,
        std::vector<std::vector<u8>>& out_certChain)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;
    const hidl_vec<hidl_vec<u8>> *certChain = nullptr;

    const hidl_vec<u8> hidl_keyToAttest = toHidlView(keyToAttest);
    const hidl_vec<hidl::KeyParameter> hidl_attestParams = toHidlView(attestParams);

    struct kmhal_arg_write_desc in_args[] = {
        init_write_b("keyToAttest", &hidl_keyToAttest, kmhal_hidl_arg_write_vec_of_u8),
        init_write_b("attestParams", &hidl_attestParams, write_vec_of_key_parameter),
    };
    const size_t n_in_args = u_arr_size(in_args);
    struct kmhal_arg_parse_desc out_args[] = {
        init_parse_p("error", &ret, kmhal_arg_parse_u32),
        init_parse_b("certChain", &certChain, kmhal_hidl_arg_parse_vec_of_vec_of_u8),
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_call(this->getHal(), getVersionSpecificCmdID(KM_COMMON_ATTEST_KEY),
                in_args, n_in_args, out_args, n_out_args, nullptr))
    {
        std::cerr << __func__ << ": HIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }
    if (ret == ErrorCode::OK)
        out_certChain = fromHidl(*certChain);

    return ret;
}

ErrorCode SusHidlKeymasterHALCommon::upgradeKey(
        std::vector<u8> const& keyBlobToUpgrade,
        std::vector<KeyParameter> const& upgradeParams,
        std::vector<u8>& out_upgradedKeyBlob)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;
    const hidl_vec<u8> *upgradedKeyBlob = nullptr;

    const hidl_vec<u8> hidl_keyBlobToUpgrade = toHidlView(keyBlobToUpgrade);
    const hidl_vec<hidl::KeyParameter> hidl_upgradeParams = toHidlView(upgradeParams);

    struct kmhal_arg_write_desc in_args[] = {
        init_write_b("keyBlobToUpgrade", &hidl_keyBlobToUpgrade,
                kmhal_hidl_arg_write_vec_of_u8),
        init_write_b("upgradeParams", &hidl_upgradeParams, write_vec_of_key_parameter),
    };
    const size_t n_in_args = u_arr_size(in_args);
    struct kmhal_arg_parse_desc out_args[] = {
        init_parse_p("error", &ret, kmhal_arg_parse_u32),
        init_parse_b("upgradedKeyBlob", &upgradedKeyBlob, kmhal_hidl_arg_parse_vec_of_u8),
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_call(this->getHal(), getVersionSpecificCmdID(KM_COMMON_UPGRADE_KEY),
                in_args, n_in_args, out_args, n_out_args, nullptr))
    {
        std::cerr << __func__ << ": HIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }
    if (ret == ErrorCode::OK)
        out_upgradedKeyBlob = fromHidl(*upgradedKeyBlob);

    return ret;
}

ErrorCode SusHidlKeymasterHALCommon::deleteKey(std::vector<u8> const& keyBlob)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

    const hidl_vec<u8> hidl_keyBlob = toHidlView(keyBlob);

    struct kmhal_arg_write_desc in_args[] = {
        init_write_b("keyBlob", &hidl_keyBlob, kmhal_hidl_arg_write_vec_of_u8),
    };
    const size_t n_in_args = u_arr_size(in_args);
    struct kmhal_arg_parse_desc out_args[] = {
        init_parse_p("error", &ret, kmhal_arg_parse_u32),
    };
    const size_t n_out_args = u_arr_size(out_args);
    if (kmhal_call(this->getHal(), getVersionSpecificCmdID(KM_COMMON_DELETE_KEY),
                in_args, n_in_args, out_args, n_out_args, nullptr))
    {
        std::cerr << __func__ << ": HIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }
    return ret;
}

ErrorCode SusHidlKeymasterHALCommon::deleteAllKeys(void)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

    struct kmhal_arg_write_desc *const in_args = nullptr;
    const size_t n_in_args = 0;
    struct kmhal_arg_parse_desc out_args[] = {
        init_parse_p("error", &ret, kmhal_arg_parse_u32),
    };
    const size_t n_out_args = u_arr_size(out_args);
    if (kmhal_call(this->getHal(), getVersionSpecificCmdID(KM_COMMON_DELETE_ALL_KEYS),
                in_args, n_in_args, out_args, n_out_args, nullptr))
    {
        std::cerr << __func__ << ": HIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }
    return ret;
}

ErrorCode SusHidlKeymasterHALCommon::destroyAttestationIds(void)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

    struct kmhal_arg_write_desc *const in_args = nullptr;
    const size_t n_in_args = 0;
    struct kmhal_arg_parse_desc out_args[] = {
        init_parse_p("error", &ret, kmhal_arg_parse_u32),
    };
    const size_t n_out_args = u_arr_size(out_args);
    if (kmhal_call(this->getHal(),
                getVersionSpecificCmdID(KM_COMMON_DESTROY_ATTESTATION_IDS),
                in_args, n_in_args, out_args, n_out_args, nullptr))
    {
        std::cerr << __func__ << ": HIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }
    return ret;
}

ErrorCode SusHidlKeymasterHALCommon::abort(OpaqueOpHandle& operationHandle)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

    const u64 ophandle_val = reinterpret_cast<u64>(operationHandle);
    struct kmhal_arg_write_desc in_args[] = {
        init_write_p("operationHandle", ophandle_val, kmhal_arg_write_u64)
    };
    const size_t n_in_args = u_arr_size(in_args);
    struct kmhal_arg_parse_desc out_args[] = {
        init_parse_p("error", &ret, kmhal_arg_parse_u32)
    };
    const size_t n_out_args = u_arr_size(out_args);
    if (kmhal_call(this->getHal(), getVersionSpecificCmdID(KM_COMMON_ABORT),
                in_args, n_in_args, out_args, n_out_args, nullptr))
    {
        std::cerr << __func__ << ": HIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }
    return ret;
}

} /* namespace kmhal */
} /* namespace suskeymaster */

#endif /* SUSKEYMASTER_BUILD_HOST */
