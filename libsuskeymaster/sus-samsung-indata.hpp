#pragma once
#define HIDL_DISABLE_INSTRUMENTATION

#include <core/int.h>
#include <core/vector.h>
#include <libsuskmhal/transport/aosp-hidl-support.hpp>
#include <cstdint>

namespace suskeymaster {
    using ::android::hardware::hidl_vec;

    int run_sus_samsung_indata(const VECTOR(u8) indata,
            hidl_vec<hidl_vec<uint8_t>>& out_cert_chain);
}
