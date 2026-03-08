#include "android/hardware/keymaster/4.0/types.h"
#include "suskeymaster.hpp"
#include <libgenericutil/util.h>
#include <libgenericutil/atomic-wrapper.h>
#include <android/hardware/keymaster/4.0/IKeymasterDevice.h>
#include <mutex>
#include <cstdio>
#include <cstdarg>
#include <iostream>
#include <semaphore.h>
#include <openssl/rand.h>

namespace suskeymaster {

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

static void init_rsa_gen_params(hidl_vec<KeyParameter>& params);
static void init_attest_key_params(hidl_vec<KeyParameter>& params);

static void init_unwrapping_params(hidl_vec<KeyParameter>& params);

static ErrorCode g_generate_key_error = ErrorCode::UNKNOWN_ERROR;
static hidl_vec<uint8_t> g_generate_key_output = {};

static void generate_key_cb(
        ErrorCode error,
        hidl_vec<unsigned char> const& out_key,
        KeyCharacteristics const& out_characteristics
)
{
    (void) out_characteristics;

    if (!util_atomic_load_int(&g_sem_inited)) {
        std::cerr << "FATAL ERROR: Global semaphore not initialized!" << std::endl;
        std::abort();
    }

    g_generate_key_error = error;
    if (error == ErrorCode::OK)
        g_generate_key_output = out_key;

    try_post_g_sem(&g_sem, &g_sem_inited, pr_err);
}

static ErrorCode g_attest_key_error = ErrorCode::UNKNOWN_ERROR;
static hidl_vec<hidl_vec<uint8_t>> g_attest_cert_chain = {};
static void attest_key_cb(
        ErrorCode error,
        hidl_vec<hidl_vec<uint8_t>> const& cert_chain
)
{
    if (!util_atomic_load_int(&g_sem_inited)) {
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

    try_post_g_sem(&g_sem, &g_sem_inited, pr_err);
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

    if (!util_atomic_load_int(&g_sem_inited)) {
        pr_err("FATAL ERROR: Global semaphore not initialized!");
        std::abort();
    }

    g_import_wrapped_key_error = error;
    if (error == ErrorCode::OK)
        g_import_wrapped_key_out_keyblob = key_blob;

    try_post_g_sem(&g_sem, &g_sem_inited, pr_err);
}

int transact_c_generate_and_attest_wrapping_key(sp<IKeymasterDevice> hal,
    hidl_vec<uint8_t>& out_wrapping_blob, hidl_vec<uint8_t>& out_wrapping_pubkey,
    hidl_vec<hidl_vec<uint8_t>> * out_cert_chain)
{
    hidl_vec<KeyParameter> params;
    init_rsa_gen_params(params);

    struct ::timespec ts;
    struct timespec *const tsp = reinterpret_cast<struct timespec *>(&ts);

    /* Generate the wrapping RSA-2048 key */
    bool ok = false;
    {
        std::lock_guard<std::mutex> lock(g_master_mutex);

        g_generate_key_error = ErrorCode::UNKNOWN_ERROR;
        g_generate_key_output = {};

        if (try_init_g_sem(&g_sem, &g_sem_inited, pr_err)) goto out_generate;
        if (prepare_timeout(tsp, 4, pr_err)) goto out_generate;

        hal->generateKey(params, generate_key_cb);

        if (wait_on_sem(&g_sem, "wrapping key generateKey", tsp, pr_err)) goto out_generate;

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
        destroy_g_sem(&g_sem, &g_sem_inited, pr_err);
    }

    /* Export the public part */
    if (suskeymaster::export_key(hal, out_wrapping_blob, out_wrapping_pubkey)) {
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

        if (try_init_g_sem(&g_sem, &g_sem_inited, pr_err)) goto out_attest;
        if (prepare_timeout(tsp, 4, pr_err)) goto out_attest;

        hal->attestKey(out_wrapping_blob, params, attest_key_cb);

        if (wait_on_sem(&g_sem, "wrapping key attestKey", tsp, pr_err)) goto out_attest;

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
        destroy_g_sem(&g_sem, &g_sem_inited, pr_err);
    }

    if (!ok) {
        std::cerr << "Failed to attest the wrapping key" << std::endl;
        return 1;
    }

    std::cout << "Successfully generated and attested the wrapping key!" << std::endl;
    return 0;
}

int transact_c_import_wrapped_key(sp<IKeymasterDevice> hal,
        hidl_vec<uint8_t> const& in_wrapped_data, hidl_vec<uint8_t> const& in_wrapping_blob,
        hidl_vec<uint8_t>& out_key_blob)
{
    hidl_vec<uint8_t> masking_key(32);
    if (RAND_bytes(masking_key.data(), masking_key.size()) == 0) {
        std::cerr << "Failed to generate the random masking key" << std::endl;
        return 1;
    }

    hidl_vec<KeyParameter> params;
    init_unwrapping_params(params);

    bool ok = false;
    struct ::timespec ts;
    struct timespec *const tsp = reinterpret_cast<struct timespec *>(&ts);
    {
        std::lock_guard<std::mutex> lock(g_master_mutex);

        g_import_wrapped_key_error = ErrorCode::UNKNOWN_ERROR;
        g_import_wrapped_key_out_keyblob = {};

        if (prepare_timeout(tsp, 4, pr_err)) goto out;
        if (try_init_g_sem(&g_sem, &g_sem_inited, pr_err)) goto out;

        hal->importWrappedKey(in_wrapped_data, in_wrapping_blob,
                masking_key, params, 0, 0, import_wrapped_key_cb);

        if (wait_on_sem(&g_sem, "importWrappedKey operation", tsp, pr_err))
            goto out;

        if (g_import_wrapped_key_error != ErrorCode::OK) {
            std::cerr << "importWrappedKey operation failed: "
                << static_cast<int32_t>(g_import_wrapped_key_error) <<
                " (" << toString(g_import_wrapped_key_error) << ")" << std::endl;
            goto out;
        }

        std::cout << "Successfully imported wrapped key" << std::endl;
        ok = true;
out:
        destroy_g_sem(&g_sem, &g_sem_inited, pr_err);
    }

    if (!ok) {
        std::cerr << "Failed to import wrapped key" << std::endl;
        return 1;
    }

    return 0;
}

static void init_rsa_gen_params(hidl_vec<KeyParameter>& params)
{
    enum {
        PARAM_PURPOSE_WRAP, PARAM_PURPOSE_ENCRYPT, PARAM_PURPOSE_DECRYPT,
        PARAM_ALGORITHM,
        PARAM_KEY_SIZE,
        PARAM_PUBLIC_EXPONENT,
        PARAM_DIGEST,
        PARAM_PADDING,
        PARAM_NO_AUTH_REQUIRED,
        PARAM_APPLICATION_ID,
        PARAM_MAX_
    };
    params.resize(PARAM_MAX_);

    params[PARAM_PURPOSE_WRAP].tag = Tag::PURPOSE;
    params[PARAM_PURPOSE_WRAP].f.purpose = KeyPurpose::WRAP_KEY;
    params[PARAM_PURPOSE_ENCRYPT].tag = Tag::PURPOSE;
    params[PARAM_PURPOSE_ENCRYPT].f.purpose = KeyPurpose::ENCRYPT;
    params[PARAM_PURPOSE_DECRYPT].tag = Tag::PURPOSE;
    params[PARAM_PURPOSE_DECRYPT].f.purpose = KeyPurpose::DECRYPT;

    params[PARAM_ALGORITHM].tag = Tag::ALGORITHM;
    params[PARAM_ALGORITHM].f.algorithm = Algorithm::RSA;
    params[PARAM_KEY_SIZE].tag = Tag::KEY_SIZE;
    params[PARAM_KEY_SIZE].f.longInteger = 2048;
    params[PARAM_PUBLIC_EXPONENT].tag = Tag::RSA_PUBLIC_EXPONENT;
    params[PARAM_PUBLIC_EXPONENT].f.longInteger = 65537;

    params[PARAM_DIGEST].tag = Tag::DIGEST;
    params[PARAM_DIGEST].f.digest = Digest::SHA_2_256;
    params[PARAM_PADDING].tag = Tag::PADDING;
    params[PARAM_PADDING].f.paddingMode = PaddingMode::RSA_OAEP;
    params[PARAM_NO_AUTH_REQUIRED].tag = Tag::NO_AUTH_REQUIRED;
    params[PARAM_NO_AUTH_REQUIRED].f.boolValue = true;

    params[PARAM_APPLICATION_ID].tag = Tag::APPLICATION_ID;
    params[PARAM_APPLICATION_ID].blob = get_sus_application_id();
}

static void init_attest_key_params(hidl_vec<KeyParameter>& params)
{
    enum {
        PARAM_ATTESTATION_CHALLENGE, PARAM_ATTESTATION_APPLICATION_ID,
        PARAM_APPLICATION_ID,
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

    params[PARAM_APPLICATION_ID].tag = Tag::APPLICATION_ID;
    params[PARAM_APPLICATION_ID].blob = get_sus_application_id();
}

static void init_unwrapping_params(hidl_vec<KeyParameter>& params)
{
    enum {
        PARAM_DIGEST,
        PARAM_PADDING,
        PARAM_APPLICATION_ID,
        PARAM_MAX_
    };
    params.resize(PARAM_MAX_);

    params[PARAM_DIGEST].tag = Tag::DIGEST;
    params[PARAM_DIGEST].f.digest = Digest::SHA_2_256;
    params[PARAM_PADDING].tag = Tag::PADDING;
    params[PARAM_PADDING].f.paddingMode = PaddingMode::RSA_OAEP;

    params[PARAM_APPLICATION_ID].tag = Tag::APPLICATION_ID;
    params[PARAM_APPLICATION_ID].blob = get_sus_application_id();
}

} /* namespace suskeymaster */
