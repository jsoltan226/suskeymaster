#include "cli.hpp"
#include <libgenericutil/util.h>
#include <libgenericutil/atomic-wrapper.h>
#include <android/hardware/keymaster/4.0/types.h>
#include <android/hardware/keymaster/4.0/IKeymasterDevice.h>
#include <mutex>
#include <cstdio>
#include <cstdarg>
#include <iostream>
#include <unordered_map>
#include <semaphore.h>
#include <openssl/rand.h>

namespace suskeymaster {
namespace cli {
namespace transact {
namespace client {

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
        pr_err("FATAL ERROR: Global semaphore not initialized!");
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

static ErrorCode g_import_wrapped_key_error = ErrorCode::UNKNOWN_ERROR;
static hidl_vec<uint8_t> g_import_wrapped_key_out_keyblob = {};
static void import_wrapped_key_cb(
        ErrorCode error,
        hidl_vec<uint8_t> const& key_blob,
        KeyCharacteristics const& key_characteristics
)
{
    (void) key_characteristics;

    if (!util::do_atomic_load_int(&g_sem_inited)) {
        pr_err("FATAL ERROR: Global semaphore not initialized!");
        std::abort();
    }

    g_import_wrapped_key_error = error;
    if (error == ErrorCode::OK)
        g_import_wrapped_key_out_keyblob = key_blob;

    util::try_post_g_sem(&g_sem, &g_sem_inited, pr_err);
}

int generate_and_attest_wrapping_key(sp<IKeymasterDevice> hal,
    hidl_vec<uint8_t>& out_wrapping_blob, hidl_vec<uint8_t>& out_wrapping_pubkey,
    hidl_vec<hidl_vec<uint8_t>> * out_cert_chain, hidl_vec<KeyParameter> const& in_gen_params
)
{
    struct ::timespec ts;
    struct timespec *const tsp = reinterpret_cast<struct timespec *>(&ts);

    bool is_rsa = true;
    for (auto const& kp : in_gen_params) {
        if (kp.tag == Tag::ALGORITHM) {
            is_rsa = kp.f.algorithm == Algorithm::RSA;
            break;
        }
    }
    hidl_vec<KeyParameter> params(in_gen_params);
    if (is_rsa) {
        std::unordered_map<Tag, struct defaults_with_flags> defaults = {
            { Tag::ALGORITHM, { { to_u32(Algorithm::RSA) }, 0 } },
            { Tag::PURPOSE, { {
                to_u32(KeyPurpose::WRAP_KEY),
                to_u32(KeyPurpose::WRAP_KEY),
                to_u32(KeyPurpose::WRAP_KEY)
            }, 0 } },
            { Tag::KEY_SIZE, { { 2048 }, 0 } },
            { Tag::RSA_PUBLIC_EXPONENT, { { 65537 }, 0 } },
            { Tag::DIGEST, { { to_u32(Digest::SHA_2_256) }, 0 } },
            { Tag::PADDING, { { to_u32(PaddingMode::RSA_OAEP) }, 0 } },
            { Tag::NO_AUTH_REQUIRED, { { 1 }, 0 } }
        };
        init_default_params(defaults, params);
    }

    /* Generate the wrapping RSA-2048 key */
    bool ok = false;
    {
        std::lock_guard<std::mutex> lock(g_master_mutex);

        g_generate_key_error = ErrorCode::UNKNOWN_ERROR;
        g_generate_key_output = {};

        if (util::try_init_g_sem(&g_sem, &g_sem_inited, pr_err)) goto out_generate;
        if (util::prepare_timeout(tsp, 4, pr_err)) goto out_generate;

        hal->generateKey(params, generate_key_cb);

        if (util::wait_on_sem(&g_sem, "wrapping key generateKey", tsp, pr_err)) goto out_generate;

        if (g_generate_key_error != ErrorCode::OK) {
            std::cerr << "Failed to generate the wrapping key: "
                << static_cast<int32_t>(g_generate_key_error) <<
                " (" << toString(g_generate_key_error) << ")" << std::endl;
            goto out_generate;
        }

        out_wrapping_blob = g_generate_key_output;
        std::cout << "Successfully generated wrapping key" << std::endl;
        ok = true;

out_generate:
        util::destroy_g_sem(&g_sem, &g_sem_inited, pr_err);
    }

    /* Export the public part */
    if (::suskeymaster::cli::export_key(hal, out_wrapping_blob, out_wrapping_pubkey)) {
        std::cerr << "Failed to export the wrapping public key" << std::endl;
        return 1;
    }
    std::cout << "Successfully exported the wrapping public key" << std::endl;

    if (!ok) {
        std::cerr << "Failed to generate the wrapping key" << std::endl;
        return 1;
    }

    if (out_cert_chain == nullptr) {
        std::cerr << "WARNING: not attesting the generated wrapping key" << std::endl;
        std::cout << "Successfully generated the wrapping key!" << std::endl;
        return 0;
    }

    /* (optionally) Generate an attestation for the wrapping key */
    init_attest_key_params(params);
    ok = false;
    {
        std::lock_guard<std::mutex> lock(g_master_mutex);

        g_attest_key_error = ErrorCode::UNKNOWN_ERROR;
        g_attest_cert_chain = {};

        if (util::try_init_g_sem(&g_sem, &g_sem_inited, pr_err)) goto out_attest;
        if (util::prepare_timeout(tsp, 4, pr_err)) goto out_attest;

        hal->attestKey(out_wrapping_blob, params, attest_key_cb);

        if (util::wait_on_sem(&g_sem, "wrapping key attestKey", tsp, pr_err)) goto out_attest;

        if (g_attest_key_error != ErrorCode::OK) {
            std::cerr << "Failed to attest the wrapping key: "
                << static_cast<int32_t>(g_attest_key_error) <<
                " (" << toString(g_attest_key_error) << ")" << std::endl;
            goto out_attest;
        }

        *out_cert_chain = hidl_vec(g_attest_cert_chain);
        std::cout << "Successfully attested the wrapping key" << std::endl;
        ok = true;

out_attest:
        util::destroy_g_sem(&g_sem, &g_sem_inited, pr_err);
    }

    if (!ok) {
        std::cerr << "Failed to attest the wrapping key" << std::endl;
        return 1;
    }

    std::cout << "Successfully generated and attested the wrapping key!" << std::endl;
    return 0;
}

int import_wrapped_key(sp<IKeymasterDevice> hal, hidl_vec<uint8_t> const& in_wrapped_data,
        hidl_vec<uint8_t> const& in_masking_key, hidl_vec<uint8_t> const& in_wrapping_blob,
        hidl_vec<KeyParameter> const& in_unwrapping_params, hidl_vec<uint8_t>& out_key_blob
)
{
    hidl_vec<KeyParameter> params(in_unwrapping_params);
    std::unordered_map<Tag, struct defaults_with_flags> defaults = {
        { Tag::DIGEST, { { to_u32(Digest::SHA_2_256) }, 0 } },
        { Tag::PADDING, { { to_u32(PaddingMode::RSA_OAEP) }, 0 } }
    };
    init_default_params(defaults, params);

    bool ok = false;
    struct ::timespec ts;
    struct timespec *const tsp = reinterpret_cast<struct timespec *>(&ts);
    {
        std::lock_guard<std::mutex> lock(g_master_mutex);

        g_import_wrapped_key_error = ErrorCode::UNKNOWN_ERROR;
        g_import_wrapped_key_out_keyblob = {};

        if (util::prepare_timeout(tsp, 4, pr_err)) goto out;
        if (util::try_init_g_sem(&g_sem, &g_sem_inited, pr_err)) goto out;

        hal->importWrappedKey(in_wrapped_data, in_wrapping_blob,
                in_masking_key, params, 0, 0, import_wrapped_key_cb);

        if (util::wait_on_sem(&g_sem, "importWrappedKey operation", tsp, pr_err))
            goto out;

        if (g_import_wrapped_key_error != ErrorCode::OK) {
            std::cerr << "importWrappedKey operation failed: "
                << static_cast<int32_t>(g_import_wrapped_key_error) <<
                " (" << toString(g_import_wrapped_key_error) << ")" << std::endl;
            goto out;
        }

        std::cout << "Successfully imported wrapped key" << std::endl;
        out_key_blob = g_import_wrapped_key_out_keyblob;
        ok = true;
out:
        util::destroy_g_sem(&g_sem, &g_sem_inited, pr_err);
    }

    if (!ok) {
        std::cerr << "Failed to import wrapped key" << std::endl;
        return 1;
    }

    return 0;
}

static void init_attest_key_params(hidl_vec<KeyParameter>& params)
{
    enum {
        PARAM_ATTESTATION_CHALLENGE, PARAM_ATTESTATION_APPLICATION_ID,
        PARAM_MAX_
    };
    params.resize(PARAM_MAX_);

    static const uint8_t *const challenge = reinterpret_cast<const uint8_t *>
        ("suskeymaster TEST ATTESTATION CHALLENGE");
    static const size_t challenge_len = sizeof(challenge) - 1;

    params[PARAM_ATTESTATION_CHALLENGE].tag = Tag::ATTESTATION_CHALLENGE;
    params[PARAM_ATTESTATION_CHALLENGE].blob = hidl_vec<uint8_t>(
            challenge, challenge + challenge_len
    );

    static const uint8_t *const att_application_id = reinterpret_cast<const uint8_t *>
        ("suskeymaster TEST APPLICATION ID");
    static const size_t att_application_id_len = sizeof(att_application_id) - 1;

    params[PARAM_ATTESTATION_APPLICATION_ID].tag = Tag::ATTESTATION_APPLICATION_ID;
    params[PARAM_ATTESTATION_APPLICATION_ID].blob = hidl_vec<uint8_t>(
            att_application_id, att_application_id + att_application_id_len
    );
}

} /* namespace client */
} /* namespace transact */
} /* namespace cli */
} /* namespace suskeymaster */
