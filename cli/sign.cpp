#include "suskeymaster.hpp"
#include <libgenericutil/util.h>
#include <libgenericutil/atomic-wrapper.h>
#include <utils/StrongPointer.h>
#include <android/hardware/keymaster/4.0/types.h>
#include <android/hardware/keymaster/4.0/IKeymasterDevice.h>
#include <mutex>
#include <ctime>
#include <cstdio>
#include <cstdarg>
#include <iostream>
#include <semaphore.h>

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

static ErrorCode g_get_key_characteristics_error = ErrorCode::UNKNOWN_ERROR;
static Algorithm g_key_type;
static void get_key_characteristics_cb(
        ErrorCode error,
        const KeyCharacteristics& key_characteristics
)
{
    if (!util_atomic_load_int(&g_sem_inited)) {
        std::cerr << "FATAL ERROR: Global semaphore not initialized!" << std::endl;
        std::abort();
    }

    if (error == ErrorCode::OK) {
        for (const auto& kp : key_characteristics.hardwareEnforced) {
            if (kp.tag == Tag::ALGORITHM) {
                g_key_type = kp.f.algorithm;
                goto found;
            }
        }

        std::cerr << "WARNING: Tag::ALGORITHM not found in hardwareEnforced auth list; "
            << "trying in softwareEnforced..." << std::endl;

        for (const auto& kp : key_characteristics.softwareEnforced) {
            if (kp.tag == Tag::ALGORITHM) {
                g_key_type = kp.f.algorithm;
                goto found;
            }
        }

        std::cerr << "Tag::ALGORITHM not found!" << std::endl;
        error = ErrorCode::INVALID_KEY_BLOB;
    }

/* failure: */
    g_get_key_characteristics_error = error;
    try_post_g_sem(&g_sem, &g_sem_inited, pr_err);
    return;

found:
    g_get_key_characteristics_error = error;
    std::cout << "Key type is: " << toString(g_key_type) << std::endl;
    try_post_g_sem(&g_sem, &g_sem_inited, pr_err);
}

static ErrorCode g_begin_error = ErrorCode::UNKNOWN_ERROR;
static uint64_t g_operation_handle = 0;
static void begin_cb(
        ErrorCode error,
        const hidl_vec<KeyParameter>& out_params,
        uint64_t operation_handle
)
{
    (void) out_params;

    if (!util_atomic_load_int(&g_sem_inited)) {
        std::cerr << "FATAL ERROR: Global semaphore not initialized!" << std::endl;
        std::abort();
    }

    if (error == ErrorCode::OK)
        g_operation_handle = operation_handle;

    g_begin_error = error;
    try_post_g_sem(&g_sem, &g_sem_inited, pr_err);
}

static ErrorCode g_finish_error = ErrorCode::UNKNOWN_ERROR;
static hidl_vec<uint8_t> g_out_sig = {};
static void finish_cb(
        ErrorCode error,
        const hidl_vec<KeyParameter>& out_params,
        const hidl_vec<uint8_t>& output
)
{
    (void) out_params;

    if (!util_atomic_load_int(&g_sem_inited)) {
        std::cerr << "FATAL ERROR: Global semaphore not initialized!" << std::endl;
        std::abort();
    }

    g_operation_handle = 0;

    if (error == ErrorCode::OK)
        g_out_sig = output;

    g_finish_error = error;
    try_post_g_sem(&g_sem, &g_sem_inited, pr_err);
}

static void init_ec_params(hidl_vec<KeyParameter>& params)
{
    enum {
        PARAM_APPLICATION_ID,
        PARAM_DIGEST,
        PARAM_MAX_
    };
    params.resize(PARAM_MAX_);

    params[PARAM_APPLICATION_ID].tag = Tag::APPLICATION_ID;
    params[PARAM_APPLICATION_ID].blob = get_sus_application_id();
    params[PARAM_DIGEST].tag = Tag::DIGEST;
    params[PARAM_DIGEST].f.digest = Digest::SHA_2_256;
}

static void init_rsa_params(hidl_vec<KeyParameter>& params)
{
    enum {
        PARAM_APPLICATION_ID,
        PARAM_DIGEST,
        PARAM_PADDING_MODE,
        PARAM_MAX_
    };
    params.resize(PARAM_MAX_);

    params[PARAM_APPLICATION_ID].tag = Tag::APPLICATION_ID;
    params[PARAM_APPLICATION_ID].blob = get_sus_application_id();

    params[PARAM_DIGEST].tag = Tag::DIGEST;
    params[PARAM_DIGEST].f.digest = Digest::SHA_2_256;

    params[PARAM_PADDING_MODE].tag = Tag::PADDING;
    params[PARAM_PADDING_MODE].f.paddingMode = PaddingMode::RSA_PKCS1_1_5_SIGN;
}

int sign(sp<IKeymasterDevice> hal,
        const hidl_vec<uint8_t>& message, const hidl_vec<uint8_t>& key,
        hidl_vec<uint8_t>& out)
{
    bool ok = false;
    g_master_mutex.lock();
    {
        g_begin_error = ErrorCode::UNKNOWN_ERROR;
        g_operation_handle = 0;
        g_finish_error = ErrorCode::UNKNOWN_ERROR;
        g_out_sig = {};

        struct ::timespec ts = { };
        struct timespec *const tsp = reinterpret_cast<struct timespec *>(&ts);
        hidl_vec<KeyParameter> params;
        int begin_timeout_s = 0, finish_timeout_s = 0;

        if (try_init_g_sem(&g_sem, &g_sem_inited, pr_err))
            goto out;

        /* Determine the key's algorithm (EC or RSA) */
        if (prepare_timeout(tsp, 1, pr_err)) goto out;
        hal->getKeyCharacteristics(key, get_sus_application_id(), {}, get_key_characteristics_cb);
        if (wait_on_sem(&g_sem, "getKeyCharacteristics operation", tsp, pr_err)) goto out;

        if (g_get_key_characteristics_error != ErrorCode::OK) {
            pr_err("Couldn't get the signing key's characteristics: %d (%s)",
                    static_cast<int>(g_get_key_characteristics_error),
                    toString(g_get_key_characteristics_error).c_str()
            );
            goto out;
        } else if (g_key_type != Algorithm::EC && g_key_type != Algorithm::RSA) {
            pr_err("Unsupported signing key algorithm: %d (%s)",
                    static_cast<int>(g_key_type), toString(g_key_type).c_str());
            goto out;
        }

        if (g_key_type == Algorithm::RSA) {
            begin_timeout_s = 2;
            finish_timeout_s = 6;
            init_rsa_params(params);
        } else /* if (g_key_type == Algorithm::EC) */ {
            begin_timeout_s = 1;
            finish_timeout_s = 2;
            init_ec_params(params);
        }

        /* Initialize the operation */
        if (prepare_timeout(tsp, begin_timeout_s, pr_err)) goto out;
        hal->begin(KeyPurpose::SIGN, key, params, {}, begin_cb);
        if (wait_on_sem(&g_sem, "BEGIN operation", tsp, pr_err)) goto out;

        if (g_begin_error != ErrorCode::OK) {
            pr_err("BEGIN operation failed: %d (%s)",
                    static_cast<int>(g_begin_error), toString(g_begin_error).c_str());
            goto out;
        }

        /* Finalize (actually perform) the operation */
        if (prepare_timeout(tsp, finish_timeout_s, pr_err)) goto out;
        hal->finish(g_operation_handle, {}, message, {}, {}, {}, finish_cb);
        if (wait_on_sem(&g_sem, "FINISH operation", tsp, pr_err)) goto out;

        if (g_finish_error != ErrorCode::OK) {
            pr_err("FINISH operation failed: %d (%s)",
                    static_cast<int>(g_finish_error), toString(g_finish_error).c_str());
            goto out;
        }

        out = g_out_sig;
        ok = true;

out:
        destroy_g_sem(&g_sem, &g_sem_inited, pr_err);
    }
    g_master_mutex.unlock();

    if (!ok) {
        std::cerr << "Failed to sign message with provided key" << std::endl;
        return 1;
    } else {
        std::cout << "Signing operation OK" << std::endl;
        return 0;
    }
}

} /* namespace suskeymaster */
