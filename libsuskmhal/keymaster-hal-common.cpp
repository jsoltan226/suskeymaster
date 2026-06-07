#ifndef SUSKEYMASTER_BUILD_HOST

#include "suskmhal.hpp"
#include "transport/hal.h"
#include "transport/hidl-types.h"
#include "transport/keymaster-types-hidl.h"

namespace suskeymaster {
namespace kmhal {

#define check_hal_ok() do {                                         \
    if (!this->isHALOk()) {                                         \
        std::cerr << __func__ << ": HAL is not OK!" << std::endl;   \
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;           \
    }                                                               \
} while (0)

bool SusHidlKeymasterHALCommon::isHALOk(void)
{
    if (!this->getHal())
        return false;

    return kmhal_ping(this->getHal()) == OK;
}

struct kmhal_sp * SusHidlKeymasterHALCommon::getHalSp(void)
{
    return this->getHal();
}

using transport::init_write, transport::init_parse;

ErrorCode SusHidlKeymasterHALCommon::addRngEntropy(hidl_vec<u8> const& data)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

    struct kmhal_arg_write_desc in_args[] = {
        init_write<hidl_vec<u8>>("data", &data, kmhal_hidl_arg_write_vec_of_u8)
    };
    const size_t n_in_args = u_arr_size(in_args);

    struct kmhal_arg_parse_desc out_args[] = {
        init_parse<ErrorCode>("error", &ret, kmhal_arg_parse_u32)
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_call(this->getHal(), getVersionSpecificCmdID(KM_COMMON_ADD_RNG_ENTROPY),
                in_args, n_in_args, out_args, n_out_args))
    {
        std::cerr << __func__ << ": HIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }

    return ret;
}

ErrorCode SusHidlKeymasterHALCommon::generateKey(hidl_vec<KeyParameter> const& keyParams,
        hidl_vec<u8>& out_keyBlob,
        KeyCharacteristics& out_keyCharacteristics)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;
    const hidl_vec<u8> *keyBlob = nullptr;
    const KeyCharacteristics *keyCharacteristics = nullptr;

    struct kmhal_arg_write_desc in_args[] = {
        init_write<hidl_vec<KeyParameter>>("keyParams", &keyParams, write_vec_of_key_parameter)
    };
    const size_t n_in_args = u_arr_size(in_args);

    struct kmhal_arg_parse_desc out_args[] = {
        init_parse<ErrorCode>("error", &ret, kmhal_arg_parse_u32),
        init_parse<hidl_vec<u8>>("keyBlob", &keyBlob, kmhal_hidl_arg_parse_vec_of_u8),
        init_parse<KeyCharacteristics>("keyBlob", &keyCharacteristics, parse_key_characteristics)
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_call(this->getHal(), getVersionSpecificCmdID(KM_COMMON_GENERATE_KEY),
                in_args, n_in_args, out_args, n_out_args))
    {
        std::cerr << __func__ << ": HIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }
    if (ret == ErrorCode::OK) {
        out_keyBlob = hidl_vec<u8>(*keyBlob);
        out_keyCharacteristics = KeyCharacteristics(*keyCharacteristics);
    }

    return ret;
}

ErrorCode SusHidlKeymasterHALCommon::importKey(hidl_vec<KeyParameter> const& keyParams,
        KeyFormat keyFormat, hidl_vec<u8> const& keyData,
        hidl_vec<u8>& out_keyBlob,
        KeyCharacteristics& out_keyCharacteristics)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;
    const hidl_vec<u8> *keyBlob = nullptr;
    const KeyCharacteristics *keyCharacteristics = nullptr;

    struct kmhal_arg_write_desc in_args[] = {
        init_write("keyParams", &keyParams, write_vec_of_key_parameter),
        init_write("keyFormat", keyFormat, kmhal_arg_write_u32),
        init_write("keyData", &keyData, kmhal_hidl_arg_write_vec_of_u8),
    };
    const size_t n_in_args = u_arr_size(in_args);

    struct kmhal_arg_parse_desc out_args[] = {
        init_parse("error", &ret, kmhal_arg_parse_u32),
        init_parse("keyBlob", &keyBlob, kmhal_hidl_arg_parse_vec_of_u8),
        init_parse("keyCharacteristics", &keyCharacteristics, parse_key_characteristics),
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_call(this->getHal(), getVersionSpecificCmdID(KM_COMMON_IMPORT_KEY),
                in_args, n_in_args, out_args, n_out_args))
    {
        std::cerr << __func__ << ": HIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }
    if (ret == ErrorCode::OK) {
        out_keyBlob = hidl_vec<u8>(*keyBlob);
        out_keyCharacteristics = KeyCharacteristics(*keyCharacteristics);
    }

    return ret;
}

ErrorCode SusHidlKeymasterHALCommon::getKeyCharacteristics(
        hidl_vec<u8> const& keyBlob,
        hidl_vec<u8> const& applicationId,
        hidl_vec<u8> const& applicationData,
        KeyCharacteristics& out_keyCharacteristics)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;
    const KeyCharacteristics *keyCharacteristics = nullptr;

    struct kmhal_arg_write_desc in_args[] = {
        init_write("keyBlob", &keyBlob, kmhal_hidl_arg_write_vec_of_u8),
        init_write("applicationId", &applicationId, kmhal_hidl_arg_write_vec_of_u8),
        init_write("applicationData", &applicationData, kmhal_hidl_arg_write_vec_of_u8),
    };
    const size_t n_in_args = u_arr_size(in_args);

    struct kmhal_arg_parse_desc out_args[] = {
        init_parse("error", &ret, kmhal_arg_parse_u32),
        init_parse("keyCharacteristics", &keyCharacteristics, parse_key_characteristics),
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_call(this->getHal(), getVersionSpecificCmdID(KM_COMMON_GET_KEY_CHARACTERISTICS),
                in_args, n_in_args, out_args, n_out_args))
    {
        std::cerr << __func__ << ": HIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }
    if (ret == ErrorCode::OK)
        out_keyCharacteristics = KeyCharacteristics(*keyCharacteristics);

    return ret;
}

ErrorCode SusHidlKeymasterHALCommon::exportKey(KeyFormat keyFormat,
        hidl_vec<u8> const& keyBlob,
        hidl_vec<u8> const& applicationId,
        hidl_vec<u8> const& applicationData,
        hidl_vec<u8>& out_keyMaterial)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;
    const hidl_vec<u8> *keyMaterial = nullptr;

    struct kmhal_arg_write_desc in_args[] = {
        init_write("keyFormat", keyFormat, kmhal_arg_write_u32),
        init_write("keyBlob", &keyBlob, kmhal_hidl_arg_write_vec_of_u8),
        init_write("applicationId", &applicationId, kmhal_hidl_arg_write_vec_of_u8),
        init_write("applicationData", &applicationData, kmhal_hidl_arg_write_vec_of_u8),
    };
    const size_t n_in_args = u_arr_size(in_args);

    struct kmhal_arg_parse_desc out_args[] = {
        init_parse("error", &ret, kmhal_arg_parse_u32),
        init_parse("keyMaterial", &keyMaterial, kmhal_hidl_arg_parse_vec_of_u8),
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_call(this->getHal(), getVersionSpecificCmdID(KM_COMMON_EXPORT_KEY),
                in_args, n_in_args, out_args, n_out_args))
    {
        std::cerr << __func__ << ": HIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }
    if (ret == ErrorCode::OK)
        out_keyMaterial = hidl_vec<u8>(*keyMaterial);

    return ret;
}

ErrorCode SusHidlKeymasterHALCommon::attestKey(
        hidl_vec<u8> const& keyToAttest,
        hidl_vec<KeyParameter> const& attestParams,
        hidl_vec<hidl_vec<u8>>& out_certChain)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;
    const hidl_vec<hidl_vec<u8>> *certChain = nullptr;

    struct kmhal_arg_write_desc in_args[] = {
        init_write("keyToAttest", &keyToAttest, kmhal_hidl_arg_write_vec_of_u8),
        init_write("attestParams", &attestParams, write_vec_of_key_parameter),
    };
    const size_t n_in_args = u_arr_size(in_args);

    struct kmhal_arg_parse_desc out_args[] = {
        init_parse("error", &ret, kmhal_arg_parse_u32),
        init_parse("certChain", &certChain, kmhal_hidl_arg_parse_vec_of_vec_of_u8),
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_call(this->getHal(), getVersionSpecificCmdID(KM_COMMON_ATTEST_KEY),
                in_args, n_in_args, out_args, n_out_args))
    {
        std::cerr << __func__ << ": HIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }
    if (ret == ErrorCode::OK) {
        out_certChain = hidl_vec<hidl_vec<u8>>(
                *reinterpret_cast<const hidl_vec<hidl_vec<u8>> *>(certChain)
        );
    }

    return ret;
}

ErrorCode SusHidlKeymasterHALCommon::upgradeKey(
        hidl_vec<u8> const& keyBlobToUpgrade,
        hidl_vec<KeyParameter> const& upgradeParams,
        hidl_vec<u8>& out_upgradedKeyBlob)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;
    const hidl_vec<u8> *upgradedKeyBlob = nullptr;

    struct kmhal_arg_write_desc in_args[] = {
        init_write("keyBlobToUpgrade", &keyBlobToUpgrade, kmhal_hidl_arg_write_vec_of_u8),
        init_write("upgradeParams", &upgradeParams, write_vec_of_key_parameter),
    };
    const size_t n_in_args = u_arr_size(in_args);

    struct kmhal_arg_parse_desc out_args[] = {
        init_parse("error", &ret, kmhal_arg_parse_u32),
        init_parse("upgradedKeyBlob", &upgradedKeyBlob, kmhal_hidl_arg_parse_vec_of_u8),
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_call(this->getHal(), getVersionSpecificCmdID(KM_COMMON_UPGRADE_KEY),
                in_args, n_in_args, out_args, n_out_args))
    {
        std::cerr << __func__ << ": HIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }
    if (ret == ErrorCode::OK)
        out_upgradedKeyBlob = hidl_vec<u8>(*upgradedKeyBlob);

    return ret;
}

ErrorCode SusHidlKeymasterHALCommon::deleteKey(hidl_vec<u8> const& keyBlob)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

    struct kmhal_arg_write_desc in_args[] = {
        init_write("keyBlob", &keyBlob, kmhal_hidl_arg_write_vec_of_u8),
    };
    const size_t n_in_args = u_arr_size(in_args);

    struct kmhal_arg_parse_desc out_args[] = {
        init_parse("error", &ret, kmhal_arg_parse_u32),
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_call(this->getHal(), getVersionSpecificCmdID(KM_COMMON_DELETE_KEY),
                in_args, n_in_args, out_args, n_out_args))
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
        init_parse("error", &ret, kmhal_arg_parse_u32),
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_call(this->getHal(), getVersionSpecificCmdID(KM_COMMON_DELETE_ALL_KEYS),
                in_args, n_in_args, out_args, n_out_args))
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
        init_parse("error", &ret, kmhal_arg_parse_u32),
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_call(this->getHal(), getVersionSpecificCmdID(KM_COMMON_DESTROY_ATTESTATION_IDS),
                in_args, n_in_args, out_args, n_out_args))
    {
        std::cerr << __func__ << ": HIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }

    return ret;
}

ErrorCode SusHidlKeymasterHALCommon::abort(u64 operationHandle)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

    struct kmhal_arg_write_desc in_args[] = {
        init_write("operationHandle", operationHandle, kmhal_arg_write_u64)
    };
    const size_t n_in_args = u_arr_size(in_args);

    struct kmhal_arg_parse_desc out_args[] = {
        init_parse("error", &ret, kmhal_arg_parse_u32)
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_call(this->getHal(), getVersionSpecificCmdID(KM_COMMON_ABORT),
                in_args, n_in_args, out_args, n_out_args))
    {
        std::cerr << __func__ << ": HIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }

    return ret;
}

} /* namespace kmhal */
} /* namespace suskeymaster */

#else /* SUSKEYMASTER_BUILD_HOST */

#include "suskmhal.hpp"

namespace suskeymaster {
namespace kmhal {

bool SusHidlKeymasterHALCommon::isHALOk(void)
{
    std::cerr << "Keymaster HAL not available in host build!" << std::endl;
    return false;
}

struct kmhal_sp * SusHidlKeymasterHALCommon::getHalSp(void)
{
    return nullptr;
}

} /* namespace kmhal */
} /* namespace suskeymaster */

#endif /* SUSKEYMASTER_BUILD_HOST */
