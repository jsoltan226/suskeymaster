#define HIDL_DISABLE_INSTRUMENTATION
#include "cli.hpp"
#include <core/vector.h>
#include <libsuscertmod/key-desc.h>
#include <libsuscertmod/leaf-cert.h>
#include <libsuskmhal/hidl/hidl-hal.hpp>
#include <libsuskmhal/util/km-params.hpp>
#include <libsuskmhal/keymaster-types-c.h>
#include <hidl/HidlSupport.h>
#include <android/hardware/keymaster/4.0/types.h>
#include <ctime>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ostream>
#include <iostream>
#include <cstdbool>
#include <semaphore.h>

namespace suskeymaster {
namespace cli {
namespace hidl_ops {

using namespace ::android::hardware::keymaster::V4_0;
using ::android::hardware::hidl_vec;

int generate_key(HidlSusKeymaster4& hal, Algorithm alg,
        hidl_vec<KeyParameter> const& in_key_params,
        hidl_vec<uint8_t> &out)
{
    hidl_vec<KeyParameter> params(in_key_params);
    if (alg == Algorithm::EC) {
        kmhal::util::init_default_params(params, {
            { Tag::ALGORITHM, Algorithm::EC },
            { Tag::DIGEST, { Digest::SHA_2_256 } },
            { Tag::EC_CURVE, EcCurve::P_256 },
            { Tag::PURPOSE, { KeyPurpose::SIGN, KeyPurpose::VERIFY } },
            { Tag::NO_AUTH_REQUIRED, true }
        });
    } else if (alg == Algorithm::RSA) {
        kmhal::util::init_default_params(params, {
            { Tag::ALGORITHM, Algorithm::RSA },
            { Tag::DIGEST, { Digest::SHA_2_256 } },
            /* Only 2048-bit keys are guaranteed to be supported
             * by both TEE and STRONGBOX devices */
            { Tag::KEY_SIZE, 2048 },
            { Tag::PADDING, { PaddingMode::RSA_PKCS1_1_5_SIGN } },
            { Tag::RSA_PUBLIC_EXPONENT, 65537 },
            { Tag::PURPOSE, { KeyPurpose::SIGN, KeyPurpose::VERIFY } },
            { Tag::NO_AUTH_REQUIRED, true }
        });
    } else {
        std::cerr << "Unsupported algorithm: " << static_cast<int32_t>(alg) <<
            " (" << toString(alg) << ")" << std::endl;
        return -1;
    }

    KeyCharacteristics c;
    ErrorCode e = hal.generateKey(params, out, c);
    if (e != ErrorCode::OK) {
        std::cerr << "generateKey operation failed: "
            << static_cast<int32_t>(e) << " (" << toString(e) << ")" << std::endl;
        return 1;
    }

    return 0;
}

int attest_key(HidlSusKeymaster4& hal, const hidl_vec<uint8_t>& key,
        hidl_vec<KeyParameter> const& in_attest_params)
{
    hidl_vec<KeyParameter> params = in_attest_params;

    static const uint8_t ch[] = "suskeymaster TEST ATTESTATION CHALLENGE";
    static const size_t ch_len = sizeof(ch) - 1;
    static const uint8_t app_id[] = "suskeymaster TEST ATTESTATION APPLICATION ID";
    static const size_t app_id_len = sizeof(app_id) - 1;
    kmhal::util::init_default_params(params, {
        { Tag::ATTESTATION_CHALLENGE, hidl_vec<uint8_t>(ch, ch + ch_len) },
        { Tag::ATTESTATION_APPLICATION_ID, hidl_vec<uint8_t>(app_id, app_id + app_id_len) }
    });

    hidl_vec<hidl_vec<uint8_t>> cert_chain = {};

    ErrorCode e = hal.attestKey(key, params, cert_chain);
    if (e != ErrorCode::OK) {
        std::cerr << "attestKey operation failed: "
            << static_cast<int32_t>(e) << " (" << toString(e) << ")" << std::endl;
        return 1;
    }

    std::cout << "Successfully generated KeyMaster key attestation" << std::endl;

    return transact::server::verify_attestation(cert_chain);
}

} /* namespace hidl_ops */
} /* namespace cli */
} /* namespace suskeymaster */
