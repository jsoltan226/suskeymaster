#include "suskeymaster.hpp"
#include <libgenericutil/util.h>
#include <libgenericutil/atomic-wrapper.h>
#include <android/hardware/keymaster/4.0/types.h>
#include <android/hardware/keymaster/4.0/IKeymasterDevice.h>
#include <utils/StrongPointer.h>
#include <ctime>
#include <mutex>
#include <cstdio>
#include <cstdarg>
#include <cstdbool>
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

static ErrorCode g_import_key_error = ErrorCode::UNKNOWN_ERROR;
static hidl_vec<uint8_t> g_import_key_output = {};
static void import_key_cb(
        ErrorCode error,
        hidl_vec<uint8_t> const& out_key,
        const KeyCharacteristics& out_characteristics
)
{
    (void) out_characteristics;

    if (!util_atomic_load_int(&g_sem_inited)) {
        std::cerr << "FATAL ERROR: Global semaphore not initialized!" << std::endl;
        std::abort();
    }

    g_import_key_error = error;
    if (error == ErrorCode::OK)
        g_import_key_output = out_key;

    try_post_g_sem(&g_sem, &g_sem_inited, pr_err);
}

static ErrorCode g_export_key_error = ErrorCode::UNKNOWN_ERROR;
static hidl_vec<uint8_t> g_export_key_output = {};
static void export_key_cb(
        ErrorCode error,
        hidl_vec<uint8_t> const& out_key_material
)
{
    if (!util_atomic_load_int(&g_sem_inited)) {
        std::cerr << "FATAL ERROR: Global semaphore not initialized!" << std::endl;
        std::abort();
    }

    g_export_key_error = error;
    if (error == ErrorCode::OK)
        g_export_key_output = out_key_material;

    try_post_g_sem(&g_sem, &g_sem_inited, pr_err);
}


int import_key(sp<IKeymasterDevice> hal,
        const hidl_vec<uint8_t>& priv_pkcs8, Algorithm alg,
        hidl_vec<uint8_t>& out
)
{
    if (alg != Algorithm::EC && alg != Algorithm::RSA) {
        std::cerr << "Unsupported key algorithm: "
            << static_cast<int32_t>(alg) << " (" << toString(alg) << ")" << std::endl;
        return -1;
    }

    struct ::timespec ts;
    struct timespec *const tsp = reinterpret_cast<struct timespec *>(&ts);

    if (prepare_timeout(tsp, 2, pr_err))
        return -1;

    hidl_vec<KeyParameter> params(2);
    params[0].tag = Tag::APPLICATION_ID;
    params[0].blob = get_sus_application_id();
    params[1].tag = Tag::ALGORITHM;
    params[1].f.algorithm = alg;

    bool ok = false;
    g_master_mutex.lock();
    {
        g_import_key_error = ErrorCode::UNKNOWN_ERROR;
        g_import_key_output = {};

        if (try_init_g_sem(&g_sem, &g_sem_inited, pr_err))
            goto out;

        hal->importKey(params, KeyFormat::PKCS8, priv_pkcs8, import_key_cb);

        if (wait_on_sem(&g_sem, "importKey operation", tsp, pr_err))
            goto out;

        if (g_import_key_error != ErrorCode::OK) {
            std::cerr << "importKey operation failed: "
                << static_cast<int32_t>(g_import_key_error) <<
                " (" << toString(g_import_key_error) << ")" << std::endl;
            goto out;
        }

        out = g_import_key_output;
        std::cout << "Successfully imported an " << toString(alg)
            << " private key into KeyMaster" << std::endl;
        ok = true;
out:
        destroy_g_sem(&g_sem, &g_sem_inited, pr_err);
    }
    g_master_mutex.unlock();

    return ok ? 0 : 1;
}

int export_key(sp<IKeymasterDevice> hal,
        const hidl_vec<uint8_t>& key, hidl_vec<uint8_t>& out_public_key_x509)
{
    struct ::timespec ts;
    struct timespec *const tsp = reinterpret_cast<struct timespec *>(&ts);

    if (prepare_timeout(tsp, 2, pr_err))
        return -1;

    bool ok = false;
    g_master_mutex.lock();
    {
        g_export_key_error = ErrorCode::UNKNOWN_ERROR;
        g_export_key_output = {};

        if (try_init_g_sem(&g_sem, &g_sem_inited, pr_err))
            goto out;

        hal->exportKey(KeyFormat::X509, key, get_sus_application_id(), {}, export_key_cb);

        if (wait_on_sem(&g_sem, "exportKey operation", tsp, pr_err))
            goto out;

        if (g_export_key_error != ErrorCode::OK) {
            std::cerr << "exportKey operation failed: "
                << static_cast<int32_t>(g_export_key_error) <<
                " (" << toString(g_export_key_error) << ")" << std::endl;
            goto out;
        }

        out_public_key_x509 = g_export_key_output;
        std::cout << "Successfully exported public key from KeyMaster" << std::endl;
        ok = true;

out:
        destroy_g_sem(&g_sem, &g_sem_inited, pr_err);
    }
    g_master_mutex.unlock();

    return ok ? 0 : 1;
}

} /* namespace suskeymaster */
