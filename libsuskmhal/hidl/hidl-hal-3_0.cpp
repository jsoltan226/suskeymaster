#ifndef SUSKEYMASTER_HAL_DISABLE_3_0
#define HIDL_DISABLE_INSTRUMENTATION
#include "base.h"
#include "hal.h"
#include "hidl-hal.hpp"
#include "keymaster-hidl.hpp"
#include <core/int.h>
#include <core/util.h>
#include <core/vector.h>
#include <cstdint>
#include <hidl/HidlSupport.h>
#include <android/hardware/keymaster/generic/types.h>
#include <iostream>

#define MODULE_NAME "keymaster-hidl-hal-3.0"

using namespace ::android::hardware::keymaster::generic;
using ::android::hardware::hidl_vec;

namespace suskeymaster {
namespace kmhal {
namespace hidl {

#ifndef SUSKEYMASTER_BUILD_HOST

HidlSusKeymaster3_0::HidlSusKeymaster3_0(void)
{
    this->hal = kmhal_hidl_hal_sp_new_get(
            "android.hardware.keymaster@3.0::IKeymasterDevice", "default",
            nullptr, false
    );
    if (!this->hal) {
        /* std::cerr << "Failed to get a handle to the keymaster HAL service" << std::endl; */
        return;
    }
}

HidlSusKeymaster3_0::~HidlSusKeymaster3_0(void)
{
    if (this->hal != NULL)
        kmhal_hidl_hal_sp_destroy(&this->hal);
}

struct kmhal_hidl_hal_sp * HidlSusKeymaster3_0::getHalSp(void) {
    return this->hal;
};

bool HidlSusKeymaster3_0::isHALOk(void)
{
    if (!this->hal)
        return false;

    return kmhal_hidl_hal_ping(this->hal) == OK;
}

enum kmhal_hidl_KM_3_0_cmd {
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

void HidlSusKeymaster3_0::getHardwareInfo(SecurityLevel& out_securityLevel,
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

    u32 isSecure = 0, supportsEllipticCurve = 0, supportsSymmetricCryptography = 0,
        supportsAttestation = 0, supportsAllDigests = 0;
    const struct kmhal_hidl_string *keymasterName = nullptr, *keymasterAuthorName = nullptr;

    struct kmhal_hidl_hal_arg_parse_desc out_args[] = {
        { "isSecure", to_data_p(&isSecure), sizeof(u32), kmhal_hidl_hal_arg_parse_u32 },
        { "supportsEllipticCurve", to_data_p(&supportsEllipticCurve), sizeof(u32),
            kmhal_hidl_hal_arg_parse_u32 },
        { "supportsSymmetricCryptography", to_data_p(&supportsSymmetricCryptography),
            sizeof(u32), kmhal_hidl_hal_arg_parse_u32 },
        { "supportsAttestation", to_data_p(&supportsAttestation), sizeof(u32),
            kmhal_hidl_hal_arg_parse_u32 },
        { "supportsAllDigests", to_data_p(&supportsAllDigests), sizeof(u32),
            kmhal_hidl_hal_arg_parse_u32 },
        { "keymasterName", to_data_p(&keymasterName), sizeof(hidl_string),
            kmhal_hidl_hal_arg_parse_hidl_string },
        { "keymasterAuthorName", to_data_p(&keymasterAuthorName), sizeof(hidl_string),
            kmhal_hidl_hal_arg_parse_hidl_string },
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_hidl_hal_call(this->hal, KM_3_0_GET_HARDWARE_FEATURES,
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

ErrorCode HidlSusKeymaster3_0::addRngEntropy(hidl_vec<uint8_t> const& data)
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

    if (kmhal_hidl_hal_call(this->hal, KM_3_0_ADD_RNG_ENTROPY,
                in_args, n_in_args, out_args, n_out_args))
    {
        std::cerr << __func__ << ": HIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }

    return ret;
}

ErrorCode HidlSusKeymaster3_0::generateKey(hidl_vec<KeyParameter> const& keyParams,
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

    if (kmhal_hidl_hal_call(this->hal, KM_3_0_GENERATE_KEY,
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

ErrorCode HidlSusKeymaster3_0::importKey(hidl_vec<KeyParameter> const& keyParams,
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

    if (kmhal_hidl_hal_call(this->hal, KM_3_0_IMPORT_KEY,
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

ErrorCode HidlSusKeymaster3_0::getKeyCharacteristics(
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

    if (kmhal_hidl_hal_call(this->hal, KM_3_0_GET_KEY_CHARACTERISTICS,
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

ErrorCode HidlSusKeymaster3_0::exportKey(KeyFormat keyFormat,
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

    if (kmhal_hidl_hal_call(this->hal, KM_3_0_EXPORT_KEY,
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

ErrorCode HidlSusKeymaster3_0::attestKey(
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

    if (kmhal_hidl_hal_call(this->hal, KM_3_0_ATTEST_KEY,
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

ErrorCode HidlSusKeymaster3_0::upgradeKey(
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

    if (kmhal_hidl_hal_call(this->hal, KM_3_0_UPGRADE_KEY,
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

ErrorCode HidlSusKeymaster3_0::deleteKey(hidl_vec<uint8_t> const& keyBlob)
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

    if (kmhal_hidl_hal_call(this->hal, KM_3_0_DELETE_KEY,
                in_args, n_in_args, out_args, n_out_args))
    {
        std::cerr << __func__ << ": HIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }

    return ret;
}

ErrorCode HidlSusKeymaster3_0::deleteAllKeys(void)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

    struct kmhal_hidl_hal_arg_write_desc *const in_args = nullptr;
    const size_t n_in_args = 0;

    struct kmhal_hidl_hal_arg_parse_desc out_args[] = {
        { "error", to_data_p(&ret), sizeof(u32), kmhal_hidl_hal_arg_parse_u32 },
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_hidl_hal_call(this->hal, KM_3_0_DELETE_ALL_KEYS,
                in_args, n_in_args, out_args, n_out_args))
    {
        std::cerr << __func__ << ": HIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }

    return ret;
}

ErrorCode HidlSusKeymaster3_0::destroyAttestationIds(void)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;

    struct kmhal_hidl_hal_arg_write_desc *const in_args = nullptr;
    const size_t n_in_args = 0;

    struct kmhal_hidl_hal_arg_parse_desc out_args[] = {
        { "error", to_data_p(&ret), sizeof(u32), kmhal_hidl_hal_arg_parse_u32 },
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_hidl_hal_call(this->hal, KM_3_0_DESTROY_ATTESTATION_IDS,
                in_args, n_in_args, out_args, n_out_args))
    {
        std::cerr << __func__ << ": HIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }

    return ret;
}

ErrorCode HidlSusKeymaster3_0::begin(KeyPurpose purpose,
        hidl_vec<uint8_t> const& keyBlob,
        hidl_vec<KeyParameter> const& inParams,
        HardwareAuthToken const& authToken,
        hidl_vec<KeyParameter>& out_outParams,
        uint64_t& out_operationHandle)
{
    check_hal_ok();
    ErrorCode ret = ErrorCode::UNKNOWN_ERROR;
    const void *outParams = nullptr;

    (void) authToken;

    struct kmhal_hidl_hal_arg_write_desc in_args[] = {
        { "purpose", &purpose, sizeof(u32), kmhal_hidl_hal_arg_write_u32 },
        { "keyBlob", &keyBlob, sizeof(hidl_vec<u8>), write_vec_of_primitive<u8> },
        { "inParams", &inParams, sizeof(hidl_vec<KeyParameter>), write_vec_of_key_parameter },
    };
    const size_t n_in_args = u_arr_size(in_args);

    struct kmhal_hidl_hal_arg_parse_desc out_args[] = {
        { "error", to_data_p(&ret), sizeof(u32), kmhal_hidl_hal_arg_parse_u32 },
        { "outParams", &outParams, sizeof(hidl_vec<KeyParameter>), read_vec_of_key_parameter },
        { "operationHandle", to_data_p(&out_operationHandle), sizeof(u64),
            kmhal_hidl_hal_arg_parse_u64 }
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_hidl_hal_call(this->hal, KM_3_0_BEGIN, in_args, n_in_args, out_args, n_out_args)) {
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

ErrorCode HidlSusKeymaster3_0::update(uint64_t operationHandle,
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

    (void) authToken;
    (void) verificationToken;

    struct kmhal_hidl_hal_arg_write_desc in_args[] = {
        { "operationHandle", &operationHandle, sizeof(u64), kmhal_hidl_hal_arg_write_u64 },
        { "inParams", &inParams, sizeof(hidl_vec<KeyParameter>), write_vec_of_key_parameter },
        { "input", &input, sizeof(hidl_vec<u8>), write_vec_of_primitive<u8> },
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

    if (kmhal_hidl_hal_call(this->hal, KM_3_0_UPDATE, in_args, n_in_args, out_args, n_out_args)) {
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

ErrorCode HidlSusKeymaster3_0::finish(uint64_t operationHandle,
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

    (void) authToken;
    (void) verificationToken;

    struct kmhal_hidl_hal_arg_write_desc in_args[] = {
        { "operationHandle", &operationHandle, sizeof(u64), kmhal_hidl_hal_arg_write_u64 },
        { "inParams", &inParams, sizeof(hidl_vec<KeyParameter>), write_vec_of_key_parameter },
        { "input", &input, sizeof(hidl_vec<u8>), write_vec_of_primitive<u8> },
        { "signature", &signature, sizeof(hidl_vec<u8>), write_vec_of_primitive<u8> },
    };
    const size_t n_in_args = u_arr_size(in_args);

    struct kmhal_hidl_hal_arg_parse_desc out_args[] = {
        { "error", to_data_p(&ret), sizeof(u32), kmhal_hidl_hal_arg_parse_u32 },
        { "outParams", &outParams, sizeof(hidl_vec<KeyParameter>), read_vec_of_key_parameter },
        { "output", &output, sizeof(hidl_vec<u8>), read_vec_of_primitive<u8> },
    };
    const size_t n_out_args = u_arr_size(out_args);

    if (kmhal_hidl_hal_call(this->hal, KM_3_0_FINISH, in_args, n_in_args, out_args, n_out_args)) {
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

ErrorCode HidlSusKeymaster3_0::abort(uint64_t operationHandle)
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

    if (kmhal_hidl_hal_call(this->hal, KM_3_0_ABORT, in_args, n_in_args, out_args, n_out_args)) {
        std::cerr << __func__ << ": HIDL call failed" << std::endl;
        return ErrorCode::SECURE_HW_COMMUNICATION_FAILED;
    }

    return ret;
}

#undef check_hal_ok

#else /* SUSKEYMASTER_BUILD_HOST */

HidlSusKeymaster3_0::HidlSusKeymaster3_0(void)
{
}

HidlSusKeymaster3_0::~HidlSusKeymaster3_0(void)
{
}

bool HidlSusKeymaster3_0::isHALOk(void)
{
    std::cerr << "Keymaster 3.0 HIDL HAL not available in host build!" << std::endl;
    return false;
}

struct kmhal_hidl_hal_sp * HidlSusKeymaster3_0::getHalSp(void) {
    return nullptr;
};

#endif /* SUSKEYMASTER_BUILD_HOST */

} /* namespace hidl */
} /* namespace kmhal */
} /* namespace suskeymaster */
#endif /* SUSKEYMASTER_HAL_DISABLE_3_0 */
