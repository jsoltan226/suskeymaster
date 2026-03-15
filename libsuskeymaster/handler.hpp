#pragma once

#define HIDL_DISABLE_INSTRUMENTATION
#include <android/hidl/base/1.0/types.h>
#include <android/hardware/keymaster/4.0/types.h>
#include <android/hardware/keymaster/4.0/IKeymasterDevice.h>

namespace suskeymaster {
    int sus_keymaster_hack_cert_chain(
        ::android::hardware::hidl_vec< ::android::hardware::hidl_vec<uint8_t> >& cert_chain
    );

    extern "C" void sus_attest_cb(
            void * _this,
            void * _err,
            void * _certChain
    );
}
