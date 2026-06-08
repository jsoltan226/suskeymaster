#define OPENSSL_API_COMPAT 0x10002000L
#include "cli.hpp"
#include <libsuskmhal/suskmhal.hpp>
#include <libsuskmhal/keymaster-types-c.h>
#include <libsuskmhal/util/km-params.hpp>
#include <libsuskmhal/transport/aosp-hidl-support.hpp>
#include <cstdio>
#include <vector>
#include <iostream>
#include <semaphore.h>
#include <openssl/rand.h>

namespace suskeymaster {
namespace cli {
namespace transact {
namespace client {

using namespace kmhal::generic;

static void init_attest_key_params(std::vector<KeyParameter>& params);

int generate_and_attest_wrapping_key(SusKMHal& hal,
    std::vector<u8>& out_wrapping_blob, std::vector<u8>& out_wrapping_pubkey,
    std::vector<std::vector<u8>> * out_cert_chain,
    std::vector<KeyParameter> const& in_gen_params
)
{
    bool is_rsa = true;
    for (auto const& kp : in_gen_params) {
        if (kp.tag == Tag::ALGORITHM) {
            is_rsa = kp.f.algorithm == Algorithm::RSA;
            break;
        }
    }
    std::vector<KeyParameter> params(in_gen_params);
    if (is_rsa) {
        kmhal::util::init_default_params(params, {
            { Tag::ALGORITHM, Algorithm::RSA },
            { Tag::PURPOSE, { KeyPurpose::WRAP_KEY, KeyPurpose::ENCRYPT, KeyPurpose::DECRYPT } },
            { Tag::KEY_SIZE, 2048 },
            { Tag::RSA_PUBLIC_EXPONENT, 65537 },
            { Tag::DIGEST, { Digest::SHA_2_256 } },
            { Tag::PADDING, { PaddingMode::RSA_OAEP } },
            { Tag::NO_AUTH_REQUIRED, true }
        });
    }

    /* Generate the wrapping RSA-2048 key */
    KeyCharacteristics kc;
    ErrorCode e = hal.generateKey(params, out_wrapping_blob, kc);
    if (e != ErrorCode::OK) {
        std::cerr << "Failed to generate the wrapping key: "
            << static_cast<i32>(e) << " (" << toString(e) << ")" << std::endl;
        return 1;
    }
    std::cout << "Successfully generated wrapping key" << std::endl;

    /* Export the public part */
    if (hal_ops::export_key(hal, out_wrapping_blob, params, out_wrapping_pubkey)) {
        std::cerr << "Failed to export the wrapping public key" << std::endl;
        return 1;
    }
    std::cout << "Successfully exported the wrapping public key" << std::endl;

    if (out_cert_chain == nullptr) {
        std::cerr << "WARNING: not attesting the generated wrapping key" << std::endl;
        std::cout << "Successfully generated the wrapping key!" << std::endl;
        return 0;
    }

    /* (optionally) Generate an attestation for the wrapping key */
    init_attest_key_params(params);
    e = hal.attestKey(out_wrapping_blob, params, *out_cert_chain);
    if (e != ErrorCode::OK) {
        std::cerr << "Failed to attest the wrapping key: "
            << static_cast<i32>(e) << " (" << toString(e) << ")" << std::endl;
        return 1;
    }

    std::cout << "Successfully generated and attested the wrapping key!" << std::endl;
    return 0;
}

int import_wrapped_key(SusKMHal& hal, std::vector<u8> const& in_wrapped_data,
        std::vector<u8> const& in_masking_key, std::vector<u8> const& in_wrapping_blob,
        std::vector<KeyParameter> const& in_unwrapping_params, std::vector<u8>& out_key_blob
)
{
    std::vector<KeyParameter> params(in_unwrapping_params);
    kmhal::util::init_default_params(params, {
        { Tag::DIGEST, { Digest::SHA_2_256 } },
        { Tag::PADDING, { PaddingMode::RSA_OAEP } }
    });

    KeyCharacteristics kc;
    ErrorCode e = hal.importWrappedKey(in_wrapped_data, in_wrapping_blob,
                in_masking_key, params, 0, 0, out_key_blob, kc);
    if (e != ErrorCode::OK) {
        std::cerr << "importWrappedKey operation failed: "
            << static_cast<i32>(e) << " (" << toString(e) << ")" << std::endl;
        return 1;
    }
    std::cout << "Successfully imported wrapped key" << std::endl;

    return 0;
}

static void init_attest_key_params(std::vector<KeyParameter>& params)
{
    enum {
        PARAM_ATTESTATION_CHALLENGE, PARAM_ATTESTATION_APPLICATION_ID,
        PARAM_MAX_
    };
    params.resize(PARAM_MAX_);

    static const u8 challenge[] = "suskeymaster TEST ATTESTATION CHALLENGE";
    static const size_t challenge_len = sizeof(challenge) - 1;

    params[PARAM_ATTESTATION_CHALLENGE].tag = Tag::ATTESTATION_CHALLENGE;
    params[PARAM_ATTESTATION_CHALLENGE].blob = std::vector<u8>(
            challenge, challenge + challenge_len
    );

    static const u8 att_application_id[] = "suskeymaster TEST APPLICATION ID";
    static const size_t att_application_id_len = sizeof(att_application_id) - 1;

    params[PARAM_ATTESTATION_APPLICATION_ID].tag = Tag::ATTESTATION_APPLICATION_ID;
    params[PARAM_ATTESTATION_APPLICATION_ID].blob = std::vector<u8>(
            att_application_id, att_application_id + att_application_id_len
    );
}

} /* namespace client */
} /* namespace transact */
} /* namespace cli */
} /* namespace suskeymaster */
