#include "suskeymaster.hpp"
#include <core/vector.h>
#include <libsuscertmod/key-desc.h>
#include <libsuscertmod/leaf-cert.h>
#include <libsuscertmod/keymaster-types.h>
#include <libgenericutil/util.h>
#include <libgenericutil/atomic-wrapper.h>
#include <android/hardware/keymaster/4.0/types.h>
#include <android/hardware/keymaster/4.0/IKeymasterDevice.h>
#include <hidl/HidlSupport.h>
#include <utils/StrongPointer.h>
#include <ctime>
#include <mutex>
#include <cstdio>
#include <cstdarg>
#include <cstdlib>
#include <cstring>
#include <ostream>
#include <fstream>
#include <iostream>
#include <cstdbool>
#include <semaphore.h>
#include <openssl/err.h>

namespace suskeymaster {

using namespace ::android::hardware::keymaster::V4_0;
using ::android::hardware::hidl_vec;
using ::android::sp;

static std::mutex g_master_mutex;

static sem_t g_sem = {};
static _Atomic int g_sem_inited = false;

static void pr_info(const char *fmt, ...)
{
    va_list vlist;
    va_start(vlist, fmt);
    vfprintf(stdout, fmt, vlist);
    putchar('\n');
    va_end(vlist);
}

static void pr_err(const char *fmt, ...)
{
    va_list vlist;
    va_start(vlist, fmt);
    vfprintf(stderr, fmt, vlist);
    putchar('\n');
    va_end(vlist);
}

static void init_ec_gen_params(hidl_vec<KeyParameter>& params);
static void init_rsa_gen_params(hidl_vec<KeyParameter>& params);

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
static hidl_vec<uint8_t> g_attest_leaf_cert = {};
static void attest_key_cb(
        ErrorCode error,
        hidl_vec<hidl_vec<uint8_t>> const& cert_chain
)
{
    if (!util_atomic_load_int(&g_sem_inited)) {
        std::cerr << "FATAL ERROR: Global semaphore not initialized!" << std::endl;
        std::abort();
    }

    g_attest_key_error = error;
    if (error == ErrorCode::OK) {
        if (cert_chain.size() == 0) {
            std::cerr << "FATAL ERROR: Returned cert chain's size is 0!" << std::endl;
            std::abort();
        }
        g_attest_leaf_cert = cert_chain[0];
    }

    try_post_g_sem(&g_sem, &g_sem_inited, pr_err);
}

static int openssl_err_print_cb(const char *msg, size_t size, void *userdata)
{
    (void) size;
    (void) userdata;
    std::cerr << msg;
    return 1;
}
static void print_openssl_errors(void)
{
    std::cerr << "BEGIN OPENSSL ERRORS" << std::endl;
    ERR_print_errors_cb(openssl_err_print_cb, NULL);
    std::cerr << "END OPENSSL ERRORS" << std::endl;
}

static int write_file(const char *path, const hidl_vec<uint8_t>& in, const char *name)
{
    std::ofstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "Failed to open " << name << " \"" << path << "\": "
            << errno << " (" << std::strerror(errno) << ")" << std::endl;
        return 1;
    }

    file.write(reinterpret_cast<const char *>(in.data()), in.size());
    if (file.fail()) {
        std::cerr << "Failed to write " << name << " \"" << path << "\" : "
            << errno << " (" << std::strerror(errno) << ")" << std::endl;
        return 1;
    }
    file.close();

    std::cout << "Successfully wrote " << name << " \"" << path << "\"" << std::endl;
    return 0;
}

int generate_key(sp<IKeymasterDevice> hal, Algorithm alg, hidl_vec<uint8_t> &out)
{
    hidl_vec<KeyParameter> params;
    if (alg == Algorithm::EC)
        init_ec_gen_params(params);
    else if (alg == Algorithm::RSA)
        init_rsa_gen_params(params);
    else {
        std::cerr << "Unsupported algorithm: " << static_cast<int32_t>(alg) <<
            " (" << toString(alg) << ")" << std::endl;
        return -1;
    }

    struct ::timespec ts;
    struct timespec *const tsp = reinterpret_cast<struct timespec *>(&ts);
    if (prepare_timeout(tsp, 2, pr_err))
        return -1;

    bool ok = false;
    {
        std::lock_guard<std::mutex> lock(g_master_mutex);

        g_generate_key_error = ErrorCode::UNKNOWN_ERROR;
        g_generate_key_output = {};

        if (try_init_g_sem(&g_sem, &g_sem_inited, pr_err)) goto out;

        hal->generateKey(params, generate_key_cb);

        if (wait_on_sem(&g_sem, "generateKey operation", tsp, pr_err)) goto out;

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
        destroy_g_sem(&g_sem, &g_sem_inited, pr_err);
    }

    return ok ? 0 : 1;
}

int attest_key(sp<IKeymasterDevice> hal, const hidl_vec<uint8_t>& key)
{
    hidl_vec<KeyParameter> params;
    init_attest_key_params(params);

    struct ::timespec ts;
    struct timespec *const tsp = reinterpret_cast<struct timespec *>(&ts);
    if (prepare_timeout(tsp, 5, pr_err))
        return -1;

    VECTOR(u8) leaf_cert = vector_new(u8);

    bool ok = false;
    {
        std::lock_guard<std::mutex> lock(g_master_mutex);

        g_attest_key_error = ErrorCode::UNKNOWN_ERROR;
        g_attest_leaf_cert = {};

        if (try_init_g_sem(&g_sem, &g_sem_inited, pr_err))
            goto out;

        hal->attestKey(key, params, attest_key_cb);

        if (wait_on_sem(&g_sem, "attestKey operation", tsp, pr_err))
            goto out;

        if (g_attest_key_error != ErrorCode::OK) {
            std::cerr << "attestKey operation failed: "
                << static_cast<int32_t>(g_attest_key_error) <<
                " (" << toString(g_attest_key_error) << ")" << std::endl;
            goto out;
        }

        vector_resize(&leaf_cert, g_attest_leaf_cert.size());
        std::memcpy(leaf_cert, g_attest_leaf_cert.data(), g_attest_leaf_cert.size());
        ok = true;

out:
        destroy_g_sem(&g_sem, &g_sem_inited, pr_err);
    }

    if (!ok) {
        std::cerr << "Failed to generate a key attestation" << std::endl;
        vector_destroy(&leaf_cert);
        return 1;
    }
    std::cout << "Successfully generated KeyMaster key attestation" << std::endl;

    struct KM_KeyDescription_v3 *km_desc = NULL;
    if (leaf_cert_parse(leaf_cert, NULL, NULL, &km_desc)) {
        std::cerr << "Failed to parse the leaf certificate" << std::endl;
        print_openssl_errors();
        hidl_vec<uint8_t> hidl_leaf_cert;
        hidl_leaf_cert.setToExternal(leaf_cert, vector_size(leaf_cert), false);
        (void) write_file("failed-leaf-cert.der", hidl_leaf_cert, "failed attestation DER");
        vector_destroy(&leaf_cert);
        return 1;
    }
    vector_destroy(&leaf_cert);

    key_desc_dump(km_desc, pr_info);
    key_desc_destroy(&km_desc);

    return 0;
}

static void init_ec_gen_params(hidl_vec<KeyParameter>& params)
{
    enum {
        PARAM_ALGOR, PARAM_DIGEST,
        PARAM_EC_CURVE,
        PARAM_PURPOSE_SIGN, PARAM_PURPOSE_VERIFY, PARAM_NO_AUTH_REQUIRED,
        /*PARAM_APPLICATION_ID,*/
        PARAM_MAX_
    };
    params.resize(PARAM_MAX_);

    params[PARAM_ALGOR].tag = Tag::ALGORITHM;
    params[PARAM_ALGOR].f.algorithm = Algorithm::EC;
    params[PARAM_DIGEST].tag = Tag::DIGEST;
    params[PARAM_DIGEST].f.digest = Digest::SHA_2_256;

    params[PARAM_EC_CURVE].tag = Tag::EC_CURVE;
    params[PARAM_EC_CURVE].f.ecCurve = EcCurve::P_256;

    params[PARAM_PURPOSE_SIGN].tag = Tag::PURPOSE;
    params[PARAM_PURPOSE_SIGN].f.purpose = KeyPurpose::SIGN;
    params[PARAM_PURPOSE_VERIFY].tag = Tag::PURPOSE;
    params[PARAM_PURPOSE_VERIFY].f.purpose = KeyPurpose::VERIFY;
    params[PARAM_NO_AUTH_REQUIRED].tag = Tag::NO_AUTH_REQUIRED;
    params[PARAM_NO_AUTH_REQUIRED].f.boolValue = true;

    /*
    params[PARAM_APPLICATION_ID].tag = Tag::APPLICATION_ID;
    params[PARAM_APPLICATION_ID].blob = get_sus_application_id();
    */
}

static void init_rsa_gen_params(hidl_vec<KeyParameter>& params)
{
    enum {
        PARAM_ALGOR, PARAM_DIGEST,
        PARAM_KEY_SIZE, PARAM_PADDING, PARAM_RSA_EXP,
        PARAM_PURPOSE_SIGN, PARAM_PURPOSE_VERIFY, PARAM_NO_AUTH_REQUIRED,
        /*PARAM_APPLICATION_ID,*/
        PARAM_MAX_
    };
    params.resize(PARAM_MAX_);

    params[PARAM_ALGOR].tag = Tag::ALGORITHM;
    params[PARAM_ALGOR].f.algorithm = Algorithm::RSA;
    params[PARAM_DIGEST].tag = Tag::DIGEST;
    params[PARAM_DIGEST].f.digest = Digest::SHA_2_256;

    params[PARAM_KEY_SIZE].tag = Tag::KEY_SIZE;
    /* Only 2048-bit keys are guaranteed to be supported by both TEE and STRONGBOX devices */
    params[PARAM_KEY_SIZE].f.integer = 2048;
    params[PARAM_PADDING].tag = Tag::PADDING;
    params[PARAM_PADDING].f.paddingMode = PaddingMode::RSA_PKCS1_1_5_SIGN;
    params[PARAM_RSA_EXP].tag = Tag::RSA_PUBLIC_EXPONENT;
    params[PARAM_RSA_EXP].f.longInteger = 65537;

    params[PARAM_PURPOSE_SIGN].tag = Tag::PURPOSE;
    params[PARAM_PURPOSE_SIGN].f.purpose = KeyPurpose::SIGN;
    params[PARAM_PURPOSE_VERIFY].tag = Tag::PURPOSE;
    params[PARAM_PURPOSE_VERIFY].f.purpose = KeyPurpose::VERIFY;
    params[PARAM_NO_AUTH_REQUIRED].tag = Tag::NO_AUTH_REQUIRED;
    params[PARAM_NO_AUTH_REQUIRED].f.boolValue = true;

    /*
    params[PARAM_APPLICATION_ID].tag = Tag::APPLICATION_ID;
    params[PARAM_APPLICATION_ID].blob = get_sus_application_id();
    */
}

static void init_attest_key_params(hidl_vec<KeyParameter>& params)
{
    enum {
        PARAM_ATTESTATION_CHALLENGE, PARAM_ATTESTATION_APPLICATION_ID,
        /*PARAM_APPLICATION_ID,*/
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

    /*
    params[PARAM_APPLICATION_ID].tag = Tag::APPLICATION_ID;
    params[PARAM_APPLICATION_ID].blob = get_sus_application_id();
    */
}

} /* namespace suskeymaster */
