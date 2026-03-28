#include "cli.hpp"
#include "hidl-hal.hpp"
#include <cstdlib>
#include <libgenericutil/util.h>
#include <libgenericutil/atomic-wrapper.h>
#include <libsuscertmod/keymaster-types.h>
#include <libsuscertmod/key-desc.h>
#include <utils/StrongPointer.h>
#include <android/hardware/keymaster/4.0/types.h>
#include <android/hardware/keymaster/4.0/IKeymasterDevice.h>
#include <ctime>
#include <cstdio>
#include <cstdarg>
#include <iostream>
#include <semaphore.h>

namespace suskeymaster {
namespace cli {

using namespace ::android::hardware::keymaster::V4_0;
using ::android::hardware::hidl_vec;

static void pr_info(const char *fmt, ...) {
    va_list vlist;
    va_start(vlist, fmt);
    std::vprintf(fmt, vlist);
    std::putchar('\n');
    va_end(vlist);
}

int sign(HidlSusKeymaster4& hal,
        const hidl_vec<uint8_t>& message, const hidl_vec<uint8_t>& key,
        const hidl_vec<KeyParameter>& in_sign_params, hidl_vec<uint8_t>& out)
{
    hidl_vec<KeyParameter> params = in_sign_params;

    /* Initialize the operation */
    uint64_t operation_handle = 0;
    hidl_vec<KeyParameter> kp_tmp;
    ErrorCode e = hal.begin(KeyPurpose::SIGN, key, params, {}, kp_tmp, operation_handle);
    if (e != ErrorCode::OK) {
        std::cerr << "BEGIN operation failed: "
            << static_cast<int>(e) << " (" << toString(e) << ")" << std::endl;
        return 1;
    }

    /* Finalize (actually perform) the operation */
    e = hal.finish(operation_handle, params, message, {}, {}, {}, kp_tmp, out);
    if (e != ErrorCode::OK) {
        std::cerr << "FINISH operation failed: "
            << static_cast<int>(e) << " (" << toString(e) << ")" << std::endl;
        return 1;
    }

    std::cout << "Signing operation OK" << std::endl;
    return 0;
}

int get_key_characteristics(HidlSusKeymaster4& hal,
    const hidl_vec<uint8_t>& key, const hidl_vec<KeyParameter>& in_application_id_data
)
{
    hidl_vec<uint8_t> application_id;
    hidl_vec<uint8_t> application_data;
    for (auto const& kp : in_application_id_data) {
        if (kp.tag == Tag::APPLICATION_ID)
            application_id = kp.blob;
        else if (kp.tag == Tag::APPLICATION_DATA)
            application_data = kp.blob;
    }

    KeyCharacteristics kc;
    ErrorCode e = hal.getKeyCharacteristics(key, application_id, application_data, kc);
    if (e != ErrorCode::OK) {
        std::cerr << "Couldn't get the key's characteristics: "
            << static_cast<int>(e) << " (" << toString(e) << ")" << std::endl;
        return 1;
    }

    struct certmod::KM_KeyDescription_v3 *key_desc = certmod::key_desc_new();
    if (key_desc == NULL) {
        std::cerr << "Failed to allocate a new key description" << std::endl;
        return EXIT_FAILURE;
    }

    key_params_2_auth_list(kc.softwareEnforced,
            &key_desc->softwareEnforced);
    key_params_2_auth_list(kc.hardwareEnforced,
            &key_desc->hardwareEnforced);
    certmod::key_desc_dump(key_desc, pr_info);
    key_desc_destroy(&key_desc);

    return EXIT_SUCCESS;
}

} /* namespace cli */
} /* namespace suskeymaster */
