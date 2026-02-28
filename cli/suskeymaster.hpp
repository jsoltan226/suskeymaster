#pragma once

#include <cstdint>
#include <utils/StrongPointer.h>
#include <android/hardware/keymaster/4.0/types.h>
#include <android/hardware/keymaster/4.0/IKeymasterDevice.h>

namespace suskeymaster {
    using namespace ::android::hardware::keymaster::V4_0;
    using ::android::hardware::hidl_vec;
    using ::android::sp;

    int generate_key(sp<IKeymasterDevice> hal, Algorithm alg, hidl_vec<uint8_t>& out);
    int attest_key(sp<IKeymasterDevice> hal, const hidl_vec<uint8_t>& key);

    int import_key(sp<IKeymasterDevice> hal,
            const hidl_vec<uint8_t>& priv_pkcs8, hidl_vec<uint8_t>& out,
            Algorithm alg);
    int export_key(sp<IKeymasterDevice> hal,
            const hidl_vec<uint8_t>& key, hidl_vec<uint8_t>& out_public_key_x509);

    int sign(sp<IKeymasterDevice> hal,
            const hidl_vec<uint8_t>& message, const hidl_vec<uint8_t>& key,
            hidl_vec<uint8_t>& out);
};
