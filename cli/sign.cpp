#include "suskeymaster.hpp"
#include <libgenericutil/util.h>
#include <utils/StrongPointer.h>
#include <android/hardware/keymaster/4.0/types.h>
#include <android/hardware/keymaster/4.0/IKeymasterDevice.h>
#include <mutex>
#include <ctime>
#include <cstdio>
#include <cstdarg>
#include <iostream>
#include <semaphore.h>
#include <stdatomic.h>

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

static ErrorCode g_begin_error = ErrorCode::UNKNOWN_ERROR;
static uint64_t g_operation_handle = 0;
static void begin_cb(
        ErrorCode error,
        const hidl_vec<KeyParameter>& out_params,
        uint64_t operation_handle
)
{
    (void) out_params;

    if (::atomic_load(&g_sem_inited)) {
        std::cerr << "FATAL ERROR: Global semaphore not initialized!" << std::endl;
        std::abort();
    }

    if (error == ErrorCode::OK)
        g_operation_handle = operation_handle;

    util::try_post_g_sem(&g_sem, &g_sem_inited, pr_err);
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

    if (!::atomic_load(&g_sem_inited)) {
        std::cerr << "FATAL ERROR: Global semaphore not initialized!" << std::endl;
        std::abort();
    }

    g_operation_handle = 0;

    if (error == ErrorCode::OK)
        g_out_sig = output;

    util::try_post_g_sem(&g_sem, &g_sem_inited, pr_err);
}

int sign(sp<IKeymasterDevice> hal,
        const hidl_vec<uint8_t>& message, const hidl_vec<uint8_t>& key,
        hidl_vec<uint8_t>& out)
{
    static const uint8_t *const application_id =
        reinterpret_cast<const uint8_t *>("suskeymaster");
    static const uint8_t *const application_id_end =
        application_id + sizeof(application_id) - 1;

    hidl_vec<KeyParameter> params(2);
    params[0].tag = Tag::DIGEST;
    params[0].f.digest = Digest::SHA_2_256;
    params[1].tag = Tag::APPLICATION_ID;
    params[1].blob = hidl_vec<uint8_t>(application_id, application_id_end);

    bool ok = false;
    g_master_mutex.lock();
    {
        g_begin_error = ErrorCode::UNKNOWN_ERROR;
        g_operation_handle = 0;
        g_finish_error = ErrorCode::UNKNOWN_ERROR;
        g_out_sig = {};
        struct ::timespec ts = { };
        struct timespec *const tsp = reinterpret_cast<struct timespec *>(&ts);

        if (util::try_init_g_sem(&g_sem, &g_sem_inited, pr_err))
            goto out;

        if (util::prepare_timeout(tsp, 2, pr_err)) goto out;
        hal->begin(KeyPurpose::SIGN, key, params, {}, begin_cb);
        if (util::wait_on_sem(&g_sem, "BEGIN operation", tsp, pr_err)) goto out;

        if (g_begin_error != ErrorCode::OK) {
            pr_err("BEGIN operation failed: %d (%s)",
                    static_cast<int>(g_begin_error), toString(g_begin_error).c_str());
            goto out;
        }

        if (util::prepare_timeout(tsp, 2, pr_err)) goto out;
        hal->finish(g_operation_handle, {}, message, {}, {}, {}, finish_cb);
        if (util::wait_on_sem(&g_sem, "FINISH operation", tsp, pr_err)) goto out;

        if (g_finish_error != ErrorCode::OK) {
            pr_err("FINISH operation failed: %d (%s)",
                    static_cast<int>(g_begin_error), toString(g_begin_error).c_str());
            goto out;
        }

        out = g_out_sig;
        ok = true;

out:
        util::destroy_g_sem(&g_sem, &g_sem_inited, pr_err);
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
