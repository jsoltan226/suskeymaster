#include "cli.hpp"
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
#include <mutex>
#include <cstdio>
#include <cstdarg>
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
using ::android::sp;

static std::mutex g_master_mutex;

static sem_t g_sem = {};
static _Atomic int g_sem_inited = false;

static void pr_err(const char *fmt, ...)
{
    va_list vlist;
    va_start(vlist, fmt);
    vfprintf(stderr, fmt, vlist);
    putchar('\n');
    va_end(vlist);
}

static void init_attest_key_params(hidl_vec<KeyParameter>& params);

static ErrorCode g_generate_key_error = ErrorCode::UNKNOWN_ERROR;
static hidl_vec<uint8_t> g_generate_key_output = {};
static void generate_key_cb(
        ErrorCode error,
        hidl_vec<unsigned char> const& out_key,
        KeyCharacteristics const& out_characteristics
)
{
    (void) out_characteristics;

    if (!util::do_atomic_load_int(&g_sem_inited)) {
        std::cerr << "FATAL ERROR: Global semaphore not initialized!" << std::endl;
        std::abort();
    }

    g_generate_key_error = error;
    if (error == ErrorCode::OK)
        g_generate_key_output = out_key;

    util::try_post_g_sem(&g_sem, &g_sem_inited, pr_err);
}

static ErrorCode g_attest_key_error = ErrorCode::UNKNOWN_ERROR;
static hidl_vec<hidl_vec<uint8_t>> g_attest_cert_chain = {};
static void attest_key_cb(
        ErrorCode error,
        hidl_vec<hidl_vec<uint8_t>> const& cert_chain
)
{
    if (!util::do_atomic_load_int(&g_sem_inited)) {
        std::cerr << "FATAL ERROR: Global semaphore not initialized!" << std::endl;
        std::abort();
    }

    g_attest_key_error = error;
    if (error == ErrorCode::OK) {
        if (cert_chain.size() == 0) {
            std::cerr << "FATAL ERROR: Returned cert chain's size is 0!" << std::endl;
            std::abort();
        }
        g_attest_cert_chain = cert_chain;
    }

    util::try_post_g_sem(&g_sem, &g_sem_inited, pr_err);
}

int generate_key(sp<IKeymasterDevice> hal, Algorithm alg,
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

    struct ::timespec ts;
    //struct timespec *const &tsp = reinterpret_cast<struct timespec *>(&ts);
    if (util::prepare_timeout(&ts, 2, pr_err))
        return -1;

    bool ok = false;
    {
        std::lock_guard<std::mutex> lock(g_master_mutex);

        g_generate_key_error = ErrorCode::UNKNOWN_ERROR;
        g_generate_key_output = {};

        if (util::try_init_g_sem(&g_sem, &g_sem_inited, pr_err)) goto out;

        hal->generateKey(params, generate_key_cb);

        if (util::wait_on_sem(&g_sem, "generateKey operation", &ts, pr_err)) goto out;

        if (g_generate_key_error != ErrorCode::OK) {
            std::cerr << "generateKey operation failed: "
                << static_cast<int32_t>(g_generate_key_error) <<
                " (" << toString(g_generate_key_error) << ")" << std::endl;
            goto out;
        }

        out = g_generate_key_output;
        std::cout << "Successfully generated " << toString(alg) << " key" << std::endl;
        ok = true;

out:
        util::destroy_g_sem(&g_sem, &g_sem_inited, pr_err);
    }

    return ok ? 0 : 1;
}

int attest_key(sp<IKeymasterDevice> hal, const hidl_vec<uint8_t>& key,
        hidl_vec<KeyParameter> const& in_attest_params)
{
    hidl_vec<KeyParameter> params = in_attest_params;
    init_attest_key_params(params);

    struct timespec ts;
    if (util::prepare_timeout(&ts, 5, pr_err))
        return -1;

    VECTOR(u8) leaf_cert = vector_new(u8);
    hidl_vec<hidl_vec<uint8_t>> cert_chain = {};

    bool ok = false;
    {
        std::lock_guard<std::mutex> lock(g_master_mutex);

        g_attest_key_error = ErrorCode::UNKNOWN_ERROR;
        g_attest_cert_chain = {};

        if (util::try_init_g_sem(&g_sem, &g_sem_inited, pr_err))
            goto out;

        hal->attestKey(key, params, attest_key_cb);

        if (util::wait_on_sem(&g_sem, "attestKey operation", &ts, pr_err))
            goto out;

        if (g_attest_key_error != ErrorCode::OK) {
            std::cerr << "attestKey operation failed: "
                << static_cast<int32_t>(g_attest_key_error) <<
                " (" << toString(g_attest_key_error) << ")" << std::endl;
            goto out;
        }

        ok = true;

        cert_chain.resize(g_attest_cert_chain.size());
        for (uint32_t i = 0; i < g_attest_cert_chain.size(); i++) {
            cert_chain.data()[i] = hidl_vec<uint8_t>(g_attest_cert_chain.data()[i]);
        }
        g_attest_cert_chain = {};

out:
        util::destroy_g_sem(&g_sem, &g_sem_inited, pr_err);
    }

    if (!ok) {
        std::cerr << "Failed to generate a key attestation" << std::endl;
        vector_destroy(&leaf_cert);
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
