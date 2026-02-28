#pragma once

#define HIDL_DISABLE_INSTRUMENTATION
#include <android/hidl/base/1.0/types.h>
#include <android/hardware/keymaster/4.0/types.h>
#include <android/hardware/keymaster/4.0/IKeymasterDevice.h>

namespace libsuskeymaster {
    using ::android::hardware::hidl_vec;
    using namespace ::android::hardware::keymaster::V4_0;

    int sus_keymaster_hack_cert_chain(hidl_vec<hidl_vec<uint8_t>>& cert_chain);

    extern "C" void sus_attest_cb(
            void * _this,
            void * _err,
            void * _certChain
    );
}
