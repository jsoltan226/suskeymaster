#ifndef SUSKEYMASTER_HAL_DISABLE_4_1
#define HIDL_DISABLE_INSTRUMENTATION
#include "km-hidl-hal.hpp"
#ifndef SUSKEYMASTER_BUILD_HOST
#include "hidl-base.h"
#include "hidl-hal.h"
#include "km-hidl-types.hpp"
#include "aosp-hidl-support.hpp"
#include "../util/keymaster-types-cpp.hpp"
#include <cstdint>
using ::android::hardware::hidl_vec;
#endif /* SUSKEYMASTER_BUILD_HOST */
#include <core/int.h>
#include <core/util.h>
#include <core/vector.h>
#include <iostream>

#define MODULE_NAME "keymaster-hidl-hal-4.1"

using namespace ::android::hardware::keymaster::generic;

namespace suskeymaster {
namespace kmhal {
namespace hidl {

#ifndef SUSKEYMASTER_BUILD_HOST

HidlSusKeymaster4_1::HidlSusKeymaster4_1(void)
{
    this->hal = kmhal_hidl_hal_sp_new_get(
            "android.hardware.keymaster@4.1::IKeymasterDevice", "default",
            nullptr, false
    );
    if (!this->hal) {
        /* std::cerr << "Failed to get a handle to the keymaster HAL service" << std::endl; */
        return;
    }

    /* All the supported cmds are from the 4.0 base
     * (4.1 extends 4.0) */
    kmhal_hidl_hal_set_fqname(this->hal, "android.hardware.keymaster@4.0::IKeymasterDevice");
}

HidlSusKeymaster4_1::~HidlSusKeymaster4_1(void)
{
    if (this->hal != NULL)
        kmhal_hidl_hal_sp_destroy(&this->hal);
}

bool HidlSusKeymaster4_1::isHALOk(void)
{
    s_log_info("%s: ret: %d", __func__, this->hal && kmhal_hidl_hal_ping(this->hal) == OK);
    if (!this->hal)
        return false;

    return kmhal_hidl_hal_ping(this->hal) == OK;
}

struct kmhal_hidl_hal_sp * HidlSusKeymaster4_1::getHalSp(void)
{
    return this->hal;
}

enum kmhal_hidl_KM_4_0_cmd {
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
    KM_4_1_DEVICE_LOCKED = 20,
    KM_4_1_EARLY_BOOT_ENDED = 21,
    KM_4_0_N_CMDS__ = KM_4_1_EARLY_BOOT_ENDED
};

#define check_hal_ok() do {                                         \
    if (!this->isHALOk()) {                                         \
        std::cerr << __func__ << ": HAL is not OK!" << std::endl;   \
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;           \
    }                                                               \
} while (0)

static inline const void ** to_data_p(ErrorCode *e) {
    return reinterpret_cast<const void **>(e);
}
static inline const void ** to_data_p(u32 *u) {
    return reinterpret_cast<const void **>(u);
}
static inline const void ** to_data_p(u64 *u) {
    return reinterpret_cast<const void **>(u);
}
static inline const void ** to_data_p(const struct kmhal_hidl_string **u) {
    return reinterpret_cast<const void **>(u);
}

void HidlSusKeymaster4_1::getHardwareInfo(SecurityLevel& out_securityLevel,
        hidl_string& out_keymasterName, hidl_string& out_keymasterAuthorName)
{
    if (!this->isHALOk()) {
fail:
        out_securityLevel = SecurityLevel::SOFTWARE;
        out_keymasterName = "N/A";
        out_keymasterAuthorName = "N/A";
        return;
    }

    struct kmhal_hidl_hal_arg_write_desc *const in_args = nullptr;
    const size_t n_in_args = 0;

    u32 securityLevel = 0;
    const struct kmhal_hidl_string *keymasterName = nullptr, *keymasterAuthorName = nullptr;

    struct kmhal_hidl_hal_arg_parse_desc out_args[] = {
        { "securityLevel", to_data_p(&securityLevel), sizeof(u32), kmhal_hidl_hal_arg_parse_u32 },
        { "keymasterName", to_data_p(&keymasterName), sizeof(hidl_string),
            kmhal_hidl_hal_arg_parse_hidl_string },
        { "keymasterAuthorName", to_data_p(&keymasterAuthorName), sizeof(hidl_string),
            kmhal_hidl_hal_arg_parse_hidl_string },
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_hidl_hal_call(this->hal, KM_4_0_GET_HARDWARE_INFO,
            in_args, n_in_args, out_args, n_out_args) != OK)
    {
        std::cerr << "getHardwareInfo call failed!" << std::endl;
        goto fail;
    }

    out_securityLevel = static_cast<SecurityLevel>(securityLevel);
    out_keymasterName = hidl_string(*reinterpret_cast<const hidl_string *>(keymasterName));
    out_keymasterAuthorName =
        hidl_string(*reinterpret_cast<const hidl_string *>(keymasterAuthorName));
}

ErrorCode HidlSusKeymaster4_1::getHmacSharingParameters(HmacSharingParameters &out_params)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;
    const void *params = nullptr;

    struct kmhal_hidl_hal_arg_write_desc *const in_args = nullptr;
    const size_t n_in_args = 0;

    struct kmhal_hidl_hal_arg_parse_desc out_args[] = {
        { "error", to_data_p(&ret), sizeof(u32), kmhal_hidl_hal_arg_parse_u32 },
        { "params", &params, sizeof(HmacSharingParameters), read_hmac_sharing_parameters },
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_hidl_hal_call(this->hal, KM_4_0_GET_HMAC_SHARING_PARAMETERS,
                in_args, n_in_args, out_args, n_out_args))
    {
        std::cerr << __func__ << ": HIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }
    if (ret == ErrorCode::OK) {
        out_params = HmacSharingParameters(
                *reinterpret_cast<const HmacSharingParameters *>(params)
        );
    }

    return ret;
}

ErrorCode HidlSusKeymaster4_1::computeSharedHmac(hidl_vec<HmacSharingParameters> const& params,
        hidl_vec<uint8_t>& out_sharingCheck)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;
    const void *sharingCheck = nullptr;

    struct kmhal_hidl_hal_arg_write_desc in_args[] = {
        { "params", &params, sizeof(hidl_vec<HmacSharingParameters>),
            write_vec_of_hmac_sharing_parameters },
    };
    const size_t n_in_args = u_arr_size(in_args);

    struct kmhal_hidl_hal_arg_parse_desc out_args[] = {
        { "error", to_data_p(&ret), sizeof(u32), kmhal_hidl_hal_arg_parse_u32 },
        { "sharingCheck", &sharingCheck, sizeof(hidl_vec<uint8_t>), read_vec_of_primitive<u8> },
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_hidl_hal_call(this->hal, KM_4_0_GET_HMAC_SHARING_PARAMETERS,
                in_args, n_in_args, out_args, n_out_args))
    {
        std::cerr << __func__ << ": HIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }
    if (ret == ErrorCode::OK) {
        out_sharingCheck = hidl_vec<uint8_t>(
                *reinterpret_cast<const hidl_vec<uint8_t> *>(sharingCheck)
        );
    }

    return ret;
}

ErrorCode HidlSusKeymaster4_1::verifyAuthorization(uint64_t operationHandle,
        hidl_vec<KeyParameter> const& parametersToVerify, HardwareAuthToken const& authToken,
        VerificationToken& out_token)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;
    const void *token = nullptr;

    struct kmhal_hidl_hal_arg_write_desc in_args[] = {
        { "parametersToVerify", &parametersToVerify, sizeof(hidl_vec<KeyParameter>),
            write_vec_of_key_parameter },
        { "authToken", &authToken, sizeof(HardwareAuthToken), write_hardware_auth_token },
    };
    const size_t n_in_args = u_arr_size(in_args);

    struct kmhal_hidl_hal_arg_parse_desc out_args[] = {
        { "error", to_data_p(&ret), sizeof(u32), kmhal_hidl_hal_arg_parse_u32 },
        { "token", &token, sizeof(VerificationToken), read_verification_token },
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_hidl_hal_call(this->hal, KM_4_0_GET_HMAC_SHARING_PARAMETERS,
                in_args, n_in_args, out_args, n_out_args))
    {
        std::cerr << __func__ << ": HIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }
    if (ret == ErrorCode::OK)
        out_token = VerificationToken(*reinterpret_cast<const VerificationToken *>(token));

    return ret;
}

ErrorCode HidlSusKeymaster4_1::addRngEntropy(hidl_vec<uint8_t> const& data)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

    struct kmhal_hidl_hal_arg_write_desc in_args[] = {
        { "data", &data, sizeof(hidl_vec<uint8_t>), write_vec_of_primitive<uint8_t> },
    };
    const size_t n_in_args = u_arr_size(in_args);

    struct kmhal_hidl_hal_arg_parse_desc out_args[] = {
        { "error", to_data_p(&ret), sizeof(u32), kmhal_hidl_hal_arg_parse_u32 },
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_hidl_hal_call(this->hal, KM_4_0_ADD_RNG_ENTROPY,
                in_args, n_in_args, out_args, n_out_args))
    {
        std::cerr << __func__ << ": HIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }

    return ret;
}

ErrorCode HidlSusKeymaster4_1::generateKey(hidl_vec<KeyParameter> const& keyParams,
        hidl_vec<uint8_t>& out_keyBlob,
        KeyCharacteristics& out_keyCharacteristics)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;
    const void *keyBlob = nullptr, *keyCharacteristics = nullptr;

    struct kmhal_hidl_hal_arg_write_desc in_args[] = {
        { "keyParams", &keyParams, sizeof(hidl_vec<KeyParameter>), write_vec_of_key_parameter }
    };
    const size_t n_in_args = u_arr_size(in_args);

    struct kmhal_hidl_hal_arg_parse_desc out_args[] = {
        { "error", to_data_p(&ret), sizeof(u32), kmhal_hidl_hal_arg_parse_u32 },
        { "keyBlob", &keyBlob, sizeof(hidl_vec<u8>), read_vec_of_primitive<u8> },
        { "keyCharacteristics", &keyCharacteristics, sizeof(KeyCharacteristics),
            read_key_characteristics }
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_hidl_hal_call(this->hal, KM_4_0_GENERATE_KEY,
                in_args, n_in_args, out_args, n_out_args))
    {
        std::cerr << __func__ << ": HIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }
    if (ret == ErrorCode::OK) {
        out_keyBlob = hidl_vec<uint8_t>(*reinterpret_cast<const hidl_vec<uint8_t> *>(keyBlob));
        out_keyCharacteristics =
            KeyCharacteristics(*reinterpret_cast<const KeyCharacteristics *>(keyCharacteristics));
    }

    return ret;
}

ErrorCode HidlSusKeymaster4_1::importKey(hidl_vec<KeyParameter> const& keyParams,
        KeyFormat keyFormat, hidl_vec<uint8_t> const& keyData,
        hidl_vec<uint8_t>& out_keyBlob,
        KeyCharacteristics& out_keyCharacteristics)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;
    const void *keyBlob = nullptr, *keyCharacteristics = nullptr;

    struct kmhal_hidl_hal_arg_write_desc in_args[] = {
        { "keyParams", &keyParams, sizeof(hidl_vec<KeyParameter>), write_vec_of_key_parameter },
        { "keyFormat", &keyFormat, sizeof(u32), kmhal_hidl_hal_arg_write_u32 },
        { "keyData", &keyData, sizeof(hidl_vec<u8>), write_vec_of_primitive<u8> },
    };
    const size_t n_in_args = u_arr_size(in_args);

    struct kmhal_hidl_hal_arg_parse_desc out_args[] = {
        { "error", to_data_p(&ret), sizeof(u32), kmhal_hidl_hal_arg_parse_u32 },
        { "keyBlob", &keyBlob, sizeof(hidl_vec<u8>), read_vec_of_primitive<u8> },
        { "keyCharacteristics", &keyCharacteristics, sizeof(KeyCharacteristics),
            read_key_characteristics }
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_hidl_hal_call(this->hal, KM_4_0_IMPORT_KEY,
                in_args, n_in_args, out_args, n_out_args))
    {
        std::cerr << __func__ << ": HIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }
    if (ret == ErrorCode::OK) {
        out_keyBlob = hidl_vec<uint8_t>(*reinterpret_cast<const hidl_vec<uint8_t> *>(keyBlob));
        out_keyCharacteristics =
            KeyCharacteristics(*reinterpret_cast<const KeyCharacteristics *>(keyCharacteristics));
    }

    return ret;
}

ErrorCode HidlSusKeymaster4_1::importWrappedKey(hidl_vec<uint8_t> const& wrappedKeyData,
            hidl_vec<uint8_t> const& wrappingKeyBlob, hidl_vec<uint8_t> const& maskingKey,
            hidl_vec<KeyParameter> const& unwrappingParams,
            uint64_t passwordSid, uint64_t biometricSid,
            hidl_vec<uint8_t>& out_keyBlob, KeyCharacteristics& out_keyCharacteristics)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;
    const void *keyBlob = nullptr, *keyCharacteristics = nullptr;

    struct kmhal_hidl_hal_arg_write_desc in_args[] = {
        { "wrappedKeyData", &wrappedKeyData, sizeof(hidl_vec<u8>), write_vec_of_primitive<u8> },
        { "wrappingKeyBlob", &wrappingKeyBlob, sizeof(hidl_vec<u8>), write_vec_of_primitive<u8> },
        { "maskingKey", &maskingKey, sizeof(hidl_vec<u8>), write_vec_of_primitive<u8> },
        { "unwrappingParams", &unwrappingParams, sizeof(hidl_vec<KeyParameter>),
            write_vec_of_key_parameter },
        { "passwordSid", &passwordSid, sizeof(u64), kmhal_hidl_hal_arg_write_u64 },
        { "biometricSid", &biometricSid, sizeof(u64), kmhal_hidl_hal_arg_write_u64 },
    };
    const size_t n_in_args = u_arr_size(in_args);

    struct kmhal_hidl_hal_arg_parse_desc out_args[] = {
        { "error", to_data_p(&ret), sizeof(u32), kmhal_hidl_hal_arg_parse_u32 },
        { "keyBlob", &keyBlob, sizeof(hidl_vec<u8>), read_vec_of_primitive<u8> },
        { "keyCharacteristics", &keyCharacteristics, sizeof(KeyCharacteristics),
            read_key_characteristics }
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_hidl_hal_call(this->hal, KM_4_0_IMPORT_WRAPPED_KEY,
                in_args, n_in_args, out_args, n_out_args))
    {
        std::cerr << __func__ << ": HIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }
    if (ret == ErrorCode::OK) {
        out_keyBlob = hidl_vec<uint8_t>(*reinterpret_cast<const hidl_vec<uint8_t> *>(keyBlob));
        out_keyCharacteristics =
            KeyCharacteristics(*reinterpret_cast<const KeyCharacteristics *>(keyCharacteristics));
    }

    return ret;
}

ErrorCode HidlSusKeymaster4_1::getKeyCharacteristics(
        hidl_vec<uint8_t> const& keyBlob,
        hidl_vec<uint8_t> const& applicationId,
        hidl_vec<uint8_t> const& applicationData,
        KeyCharacteristics& out_keyCharacteristics)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;
    const void *keyCharacteristics = nullptr;

    struct kmhal_hidl_hal_arg_write_desc in_args[] = {
        { "keyBlob", &keyBlob, sizeof(hidl_vec<u8>), write_vec_of_primitive<u8> },
        { "applicationId", &applicationId, sizeof(hidl_vec<u8>), write_vec_of_primitive<u8> },
        { "applicationData", &applicationData, sizeof(hidl_vec<u8>), write_vec_of_primitive<u8> },
    };
    const size_t n_in_args = u_arr_size(in_args);

    struct kmhal_hidl_hal_arg_parse_desc out_args[] = {
        { "error", to_data_p(&ret), sizeof(u32), kmhal_hidl_hal_arg_parse_u32 },
        { "keyCharacteristics", &keyCharacteristics, sizeof(KeyCharacteristics),
            read_key_characteristics }
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_hidl_hal_call(this->hal, KM_4_0_GET_KEY_CHARACTERISTICS,
                in_args, n_in_args, out_args, n_out_args))
    {
        std::cerr << __func__ << ": HIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }
    if (ret == ErrorCode::OK) {
        out_keyCharacteristics =
            KeyCharacteristics(*reinterpret_cast<const KeyCharacteristics *>(keyCharacteristics));
    }

    return ret;
}

ErrorCode HidlSusKeymaster4_1::exportKey(KeyFormat keyFormat,
        hidl_vec<uint8_t> const& keyBlob,
        hidl_vec<uint8_t> const& applicationId,
        hidl_vec<uint8_t> const& applicationData,
        hidl_vec<uint8_t>& out_keyMaterial)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;
    const void *keyMaterial = nullptr;

    struct kmhal_hidl_hal_arg_write_desc in_args[] = {
        { "keyFormat", &keyFormat, sizeof(u32), kmhal_hidl_hal_arg_write_u32 },
        { "keyBlob", &keyBlob, sizeof(hidl_vec<u8>), write_vec_of_primitive<u8> },
        { "applicationId", &applicationId, sizeof(hidl_vec<u8>), write_vec_of_primitive<u8> },
        { "applicationData", &applicationData, sizeof(hidl_vec<u8>), write_vec_of_primitive<u8> },
    };
    const size_t n_in_args = u_arr_size(in_args);

    struct kmhal_hidl_hal_arg_parse_desc out_args[] = {
        { "error", to_data_p(&ret), sizeof(u32), kmhal_hidl_hal_arg_parse_u32 },
        { "keyMaterial", &keyMaterial, sizeof(hidl_vec<u8>), read_vec_of_primitive<u8> },
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_hidl_hal_call(this->hal, KM_4_0_EXPORT_KEY,
                in_args, n_in_args, out_args, n_out_args))
    {
        std::cerr << __func__ << ": HIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }
    if (ret == ErrorCode::OK) {
        out_keyMaterial =
            hidl_vec<uint8_t>(*reinterpret_cast<const hidl_vec<uint8_t> *>(keyMaterial));
    }

    return ret;
}

ErrorCode HidlSusKeymaster4_1::attestKey(
        hidl_vec<uint8_t> const& keyToAttest,
        hidl_vec<KeyParameter> const& attestParams,
        hidl_vec<hidl_vec<uint8_t>>& out_certChain)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;
    const void *certChain = nullptr;

    struct kmhal_hidl_hal_arg_write_desc in_args[] = {
        { "keyToAttest", &keyToAttest, sizeof(hidl_vec<u8>), write_vec_of_primitive<u8> },
        { "attestParams", &attestParams, sizeof(hidl_vec<KeyParameter>),
            write_vec_of_key_parameter }
    };
    const size_t n_in_args = u_arr_size(in_args);

    struct kmhal_hidl_hal_arg_parse_desc out_args[] = {
        { "error", to_data_p(&ret), sizeof(u32), kmhal_hidl_hal_arg_parse_u32 },
        { "certChain", &certChain, sizeof(hidl_vec<hidl_vec<u8>>),
            read_vec_of_vec_of_primitive<u8> },
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_hidl_hal_call(this->hal, KM_4_0_ATTEST_KEY,
                in_args, n_in_args, out_args, n_out_args))
    {
        std::cerr << __func__ << ": HIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }
    if (ret == ErrorCode::OK) {
        out_certChain = hidl_vec<hidl_vec<uint8_t>>(
                *reinterpret_cast<const hidl_vec<hidl_vec<uint8_t>> *>(certChain)
        );
    }

    return ret;
}

ErrorCode HidlSusKeymaster4_1::upgradeKey(
        hidl_vec<uint8_t> const& keyBlobToUpgrade,
        hidl_vec<KeyParameter> const& upgradeParams,
        hidl_vec<uint8_t>& out_upgradedKeyBlob)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;
    const void *upgradedKeyBlob = nullptr;

    struct kmhal_hidl_hal_arg_write_desc in_args[] = {
        { "keyBlobToUpgrade", &keyBlobToUpgrade, sizeof(hidl_vec<u8>),
            write_vec_of_primitive<u8> },
        { "upgradeParams", &upgradeParams, sizeof(hidl_vec<KeyParameter>),
            write_vec_of_key_parameter }
    };
    const size_t n_in_args = u_arr_size(in_args);

    struct kmhal_hidl_hal_arg_parse_desc out_args[] = {
        { "error", to_data_p(&ret), sizeof(u32), kmhal_hidl_hal_arg_parse_u32 },
        { "upgradedKeyBlob", &upgradedKeyBlob, sizeof(hidl_vec<u8>),
            read_vec_of_primitive<u8> },
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_hidl_hal_call(this->hal, KM_4_0_UPGRADE_KEY,
                in_args, n_in_args, out_args, n_out_args))
    {
        std::cerr << __func__ << ": HIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }
    if (ret == ErrorCode::OK) {
        out_upgradedKeyBlob =
            hidl_vec<uint8_t>(*reinterpret_cast<const hidl_vec<uint8_t> *>(upgradedKeyBlob));
    }

    return ret;
}

ErrorCode HidlSusKeymaster4_1::deleteKey(hidl_vec<uint8_t> const& keyBlob)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

    struct kmhal_hidl_hal_arg_write_desc in_args[] = {
        { "keyBlob", &keyBlob, sizeof(hidl_vec<u8>), write_vec_of_primitive<u8> },
    };
    const size_t n_in_args = u_arr_size(in_args);

    struct kmhal_hidl_hal_arg_parse_desc out_args[] = {
        { "error", to_data_p(&ret), sizeof(u32), kmhal_hidl_hal_arg_parse_u32 },
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_hidl_hal_call(this->hal, KM_4_0_DELETE_KEY,
                in_args, n_in_args, out_args, n_out_args))
    {
        std::cerr << __func__ << ": HIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }

    return ret;
}

ErrorCode HidlSusKeymaster4_1::deleteAllKeys(void)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

    struct kmhal_hidl_hal_arg_write_desc *const in_args = nullptr;
    const size_t n_in_args = 0;

    struct kmhal_hidl_hal_arg_parse_desc out_args[] = {
        { "error", to_data_p(&ret), sizeof(u32), kmhal_hidl_hal_arg_parse_u32 },
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_hidl_hal_call(this->hal, KM_4_0_DELETE_ALL_KEYS,
                in_args, n_in_args, out_args, n_out_args))
    {
        std::cerr << __func__ << ": HIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }

    return ret;
}

ErrorCode HidlSusKeymaster4_1::destroyAttestationIds(void)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

    struct kmhal_hidl_hal_arg_write_desc *const in_args = nullptr;
    const size_t n_in_args = 0;

    struct kmhal_hidl_hal_arg_parse_desc out_args[] = {
        { "error", to_data_p(&ret), sizeof(u32), kmhal_hidl_hal_arg_parse_u32 },
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_hidl_hal_call(this->hal, KM_4_0_DESTROY_ATTESTATION_IDS,
                in_args, n_in_args, out_args, n_out_args))
    {
        std::cerr << __func__ << ": HIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }

    return ret;
}

ErrorCode HidlSusKeymaster4_1::begin(KeyPurpose purpose,
        hidl_vec<uint8_t> const& keyBlob,
        hidl_vec<KeyParameter> const& inParams,
        HardwareAuthToken const& authToken,
        hidl_vec<KeyParameter>& out_outParams,
        uint64_t& out_operationHandle)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;
    const void *outParams = nullptr;

    struct kmhal_hidl_hal_arg_write_desc in_args[] = {
        { "purpose", &purpose, sizeof(u32), kmhal_hidl_hal_arg_write_u32 },
        { "keyBlob", &keyBlob, sizeof(hidl_vec<u8>), write_vec_of_primitive<u8> },
        { "inParams", &inParams, sizeof(hidl_vec<KeyParameter>), write_vec_of_key_parameter },
        { "authToken", &authToken, sizeof(HardwareAuthToken), write_hardware_auth_token }
    };
    const size_t n_in_args = u_arr_size(in_args);

    struct kmhal_hidl_hal_arg_parse_desc out_args[] = {
        { "error", to_data_p(&ret), sizeof(u32), kmhal_hidl_hal_arg_parse_u32 },
        { "outParams", &outParams, sizeof(hidl_vec<KeyParameter>), read_vec_of_key_parameter },
        { "operationHandle", to_data_p(&out_operationHandle), sizeof(u64),
            kmhal_hidl_hal_arg_parse_u64 }
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_hidl_hal_call(this->hal, KM_4_0_BEGIN, in_args, n_in_args, out_args, n_out_args)) {
        std::cerr << __func__ << ": HIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }
    if (ret == ErrorCode::OK) {
        out_outParams = hidl_vec<KeyParameter>(
                *reinterpret_cast<const hidl_vec<KeyParameter> *>(outParams)
        );
    }

    return ret;
}

ErrorCode HidlSusKeymaster4_1::update(uint64_t operationHandle,
        hidl_vec<KeyParameter> const& inParams,
        hidl_vec<uint8_t> const& input,
        HardwareAuthToken const& authToken,
        VerificationToken const& verificationToken,
        uint32_t& out_inputConsumed,
        hidl_vec<KeyParameter>& out_outParams,
        hidl_vec<uint8_t>& out_output)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;
    const void *outParams = nullptr, *output = nullptr;

    struct kmhal_hidl_hal_arg_write_desc in_args[] = {
        { "operationHandle", &operationHandle, sizeof(u64), kmhal_hidl_hal_arg_write_u64 },
        { "inParams", &inParams, sizeof(hidl_vec<KeyParameter>), write_vec_of_key_parameter },
        { "input", &input, sizeof(hidl_vec<u8>), write_vec_of_primitive<u8> },
        { "authToken", &authToken, sizeof(HardwareAuthToken), write_hardware_auth_token },
        { "verificationToken", &verificationToken, sizeof(VerificationToken),
            write_verification_token }
    };
    const size_t n_in_args = u_arr_size(in_args);

    struct kmhal_hidl_hal_arg_parse_desc out_args[] = {
        { "error", to_data_p(&ret), sizeof(u32), kmhal_hidl_hal_arg_parse_u32 },
        { "inputConsumed", to_data_p(&out_inputConsumed), sizeof(u32),
            kmhal_hidl_hal_arg_parse_u32 },
        { "outParams", &outParams, sizeof(hidl_vec<KeyParameter>), read_vec_of_key_parameter },
        { "output", &output, sizeof(hidl_vec<u8>), read_vec_of_primitive<u8> },
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_hidl_hal_call(this->hal, KM_4_0_UPDATE, in_args, n_in_args, out_args, n_out_args)) {
        std::cerr << __func__ << ": HIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }
    if (ret == ErrorCode::OK) {
        out_outParams = hidl_vec<KeyParameter>(
                *reinterpret_cast<const hidl_vec<KeyParameter> *>(outParams)
        );
        out_output = hidl_vec<uint8_t>(*reinterpret_cast<const hidl_vec<uint8_t> *>(output));
    }

    return ret;
}

ErrorCode HidlSusKeymaster4_1::finish(uint64_t operationHandle,
        hidl_vec<KeyParameter> const& inParams,
        hidl_vec<uint8_t> const& input,
        hidl_vec<uint8_t> const& signature,
        HardwareAuthToken const& authToken,
        VerificationToken const& verificationToken,
        hidl_vec<KeyParameter>& out_outParams,
        hidl_vec<uint8_t>& out_output)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;
    const void *outParams = nullptr, *output = nullptr;

    struct kmhal_hidl_hal_arg_write_desc in_args[] = {
        { "operationHandle", &operationHandle, sizeof(u64), kmhal_hidl_hal_arg_write_u64 },
        { "inParams", &inParams, sizeof(hidl_vec<KeyParameter>), write_vec_of_key_parameter },
        { "input", &input, sizeof(hidl_vec<u8>), write_vec_of_primitive<u8> },
        { "signature", &signature, sizeof(hidl_vec<u8>), write_vec_of_primitive<u8> },
        { "authToken", &authToken, sizeof(HardwareAuthToken), write_hardware_auth_token },
        { "verificationToken", &verificationToken, sizeof(VerificationToken),
            write_verification_token }
    };
    const size_t n_in_args = u_arr_size(in_args);

    struct kmhal_hidl_hal_arg_parse_desc out_args[] = {
        { "error", to_data_p(&ret), sizeof(u32), kmhal_hidl_hal_arg_parse_u32 },
        { "outParams", &outParams, sizeof(hidl_vec<KeyParameter>), read_vec_of_key_parameter },
        { "output", &output, sizeof(hidl_vec<u8>), read_vec_of_primitive<u8> },
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_hidl_hal_call(this->hal, KM_4_0_FINISH, in_args, n_in_args, out_args, n_out_args)) {
        std::cerr << __func__ << ": HIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }
    if (ret == ErrorCode::OK) {
        out_outParams = hidl_vec<KeyParameter>(
                *reinterpret_cast<const hidl_vec<KeyParameter> *>(outParams)
        );
        out_output = hidl_vec<uint8_t>(*reinterpret_cast<const hidl_vec<uint8_t> *>(output));
    }

    return ret;
}

ErrorCode HidlSusKeymaster4_1::abort(uint64_t operationHandle)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

    struct kmhal_hidl_hal_arg_write_desc in_args[] = {
        { "operationHandle", &operationHandle, sizeof(u64), kmhal_hidl_hal_arg_write_u64 },
    };
    const size_t n_in_args = u_arr_size(in_args);

    struct kmhal_hidl_hal_arg_parse_desc out_args[] = {
        { "error", to_data_p(&ret), sizeof(u32), kmhal_hidl_hal_arg_parse_u32 },
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_hidl_hal_call(this->hal, KM_4_0_ABORT, in_args, n_in_args, out_args, n_out_args)) {
        std::cerr << __func__ << ": HIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }

    return ret;
}

#undef check_hal_ok

#else /* SUSKEYMASTER_BUILD_HOST */

HidlSusKeymaster4_1::HidlSusKeymaster4_1(void)
{
}

HidlSusKeymaster4_1::~HidlSusKeymaster4_1(void)
{
}

bool HidlSusKeymaster4_1::isHALOk(void)
{
    std::cerr << "Keymaster 4.1 HIDL HAL not available in host build!" << std::endl;
    return false;
}

struct kmhal_hidl_hal_sp * HidlSusKeymaster4_1::getHalSp(void)
{
    return nullptr;
}

#endif /* SUSKEYMASTER_BUILD_HOST */

} /* namespace hidl */
} /* namespace kmhal */
} /* namespace suskeymaster */
#endif /* SUSKEYMASTER_HAL_DISABLE_4_1 */
