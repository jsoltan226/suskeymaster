#include "cli.hpp"
#include "hidl-hal.hpp"
#include <core/vector.h>
#include <libsuscertmod/key-desc.h>
#include <libsuscertmod/leaf-cert.h>
#include <libsuscertmod/keymaster-types.h>
#include <libgenericutil/util.h>
#include <libgenericutil/atomic-wrapper.h>
#include <android/hardware/keymaster/4.0/types.h>
#include <android/hardware/keymaster/4.0/IKeymasterDevice.h>
#include <hidl/HidlSupport.h>
#include <unordered_map>
#include <utils/StrongPointer.h>
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

using namespace ::android::hardware::keymaster::V4_0;
using ::android::hardware::hidl_vec;

static void init_attest_key_params(hidl_vec<KeyParameter>& params);

int generate_key(HidlSusKeymaster4& hal, Algorithm alg,
        hidl_vec<KeyParameter> const& in_key_params,
        hidl_vec<uint8_t> &out)
{
    hidl_vec<KeyParameter> params(in_key_params);
    if (alg == Algorithm::EC) {
        std::unordered_map<Tag, struct defaults_with_flags> ec_defaults = {
            { Tag::ALGORITHM, { { to_u32(Algorithm::EC) }, 0 },  },
            { Tag::DIGEST, { { to_u32(Digest::SHA_2_256) }, 0 } },
            { Tag::EC_CURVE, { { to_u32(EcCurve::P_256) }, 0 } },
            { Tag::PURPOSE, { { to_u32(KeyPurpose::SIGN), to_u32(KeyPurpose::VERIFY) }, 0 } },
            { Tag::NO_AUTH_REQUIRED, { { 1 }, 0 } },
        };
        init_default_params(ec_defaults, params);
    } else if (alg == Algorithm::RSA) {
        std::unordered_map<Tag, struct defaults_with_flags> rsa_defaults = {
            { Tag::ALGORITHM, { { to_u32(Algorithm::RSA) }, 0 } },
            { Tag::DIGEST, { { to_u32(Digest::SHA_2_256) }, 0 } },
            /* Only 2048-bit keys are guaranteed to be supported
             * by both TEE and STRONGBOX devices */
            { Tag::KEY_SIZE, { { 2048 }, 0 } },
            { Tag::PADDING, { { to_u32(PaddingMode::RSA_PKCS1_1_5_SIGN) }, 0 } },
            { Tag::RSA_PUBLIC_EXPONENT, { { 65537 }, 0 } },
            { Tag::PURPOSE, { { to_u32(KeyPurpose::SIGN), to_u32(KeyPurpose::VERIFY) }, 0 } },
            { Tag::NO_AUTH_REQUIRED, { { 1 }, 0 } },
        };
        init_default_params(rsa_defaults, params);
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
    init_attest_key_params(params);

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

static void init_attest_key_params(hidl_vec<KeyParameter>& params)
{
    bool set_att_challenge = true, set_att_application_id = true;

    for (auto const& kp : params) {
        if (kp.tag == Tag::ATTESTATION_CHALLENGE)
            set_att_challenge = false;
        else if (kp.tag == Tag::ATTESTATION_APPLICATION_ID)
            set_att_application_id = false;
    }

    if (set_att_challenge) {
        static const uint8_t challenge[] = "suskeymaster TEST ATTESTATION CHALLENGE";
        static const size_t challenge_len = sizeof(challenge) - 1;

        params.resize(params.size() + 1);
        params[params.size() - 1].tag = Tag::ATTESTATION_CHALLENGE;
        params[params.size() - 1].blob = hidl_vec<uint8_t>(
                challenge, challenge + challenge_len
        );
    }

    if (set_att_application_id) {
        static const uint8_t att_application_id[] = "suskeymaster TEST APPLICATION ID";
        static const size_t att_application_id_len = sizeof(att_application_id) - 1;

        params.resize(params.size() + 1);
        params[params.size() - 1].tag = Tag::ATTESTATION_APPLICATION_ID;
        params[params.size() - 1].blob = hidl_vec<uint8_t>(
                att_application_id, att_application_id + att_application_id_len
        );
    }
}

} /* namespace cli */
} /* namespace suskeymaster */
