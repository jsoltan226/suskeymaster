#include "cli.hpp"
#include <libgenericutil/util.h>
#include <libgenericutil/atomic-wrapper.h>
#include <android/hardware/keymaster/4.0/types.h>
#include <android/hardware/keymaster/4.0/IKeymasterDevice.h>
#include <unordered_map>
#include <utils/StrongPointer.h>
#include <ctime>
#include <mutex>
#include <cstdio>
#include <cstdarg>
#include <cstdbool>
#include <iostream>
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

static ErrorCode g_import_key_error = ErrorCode::UNKNOWN_ERROR;
static hidl_vec<uint8_t> g_import_key_output = {};
static void import_key_cb(
        ErrorCode error,
        hidl_vec<uint8_t> const& out_key,
        const KeyCharacteristics& out_characteristics
)
{
    (void) out_characteristics;

    if (!util::do_atomic_load_int(&g_sem_inited)) {
        std::cerr << "FATAL ERROR: Global semaphore not initialized!" << std::endl;
        std::abort();
    }

    g_import_key_error = error;
    if (error == ErrorCode::OK)
        g_import_key_output = out_key;

    util::try_post_g_sem(&g_sem, &g_sem_inited, pr_err);
}

static ErrorCode g_export_key_error = ErrorCode::UNKNOWN_ERROR;
static hidl_vec<uint8_t> g_export_key_output = {};
static void export_key_cb(
        ErrorCode error,
        hidl_vec<uint8_t> const& out_key_material
)
{
    if (!util::do_atomic_load_int(&g_sem_inited)) {
        std::cerr << "FATAL ERROR: Global semaphore not initialized!" << std::endl;
        std::abort();
    }

    g_export_key_error = error;
    if (error == ErrorCode::OK)
        g_export_key_output = out_key_material;

    util::try_post_g_sem(&g_sem, &g_sem_inited, pr_err);
}


int import_key(sp<IKeymasterDevice> hal, hidl_vec<uint8_t> const& priv_pkcs8,
        Algorithm alg, hidl_vec<KeyParameter> const& in_import_params,
        hidl_vec<uint8_t>& out_keyblob
)
{
    if (alg != Algorithm::EC && alg != Algorithm::RSA) {
        std::cerr << "Unsupported key algorithm: "
            << static_cast<int32_t>(alg) << " (" << toString(alg) << ")" << std::endl;
        return -1;
    }

    struct ::timespec ts;
    struct timespec *const tsp = reinterpret_cast<struct timespec *>(&ts);

    if (util::prepare_timeout(tsp, 2, pr_err))
        return -1;

    std::unordered_map<Tag, struct defaults_with_flags> defaults = {
        { Tag::ALGORITHM, { { to_u32(alg) }, 0 } }
    };
    hidl_vec<KeyParameter> params(in_import_params);
    init_default_params(defaults, params);

    bool ok = false;
    {
        std::lock_guard<std::mutex> lock(g_master_mutex);

        g_import_key_error = ErrorCode::UNKNOWN_ERROR;
        g_import_key_output = {};

        if (util::try_init_g_sem(&g_sem, &g_sem_inited, pr_err))
            goto out;

        hal->importKey(params, KeyFormat::PKCS8, priv_pkcs8, import_key_cb);

        if (util::wait_on_sem(&g_sem, "importKey operation", tsp, pr_err))
            goto out;

        if (g_import_key_error != ErrorCode::OK) {
            std::cerr << "importKey operation failed: "
                << static_cast<int32_t>(g_import_key_error) <<
                " (" << toString(g_import_key_error) << ")" << std::endl;
            goto out;
        }

        out_keyblob = g_import_key_output;
        std::cout << "Successfully imported an " << toString(alg)
            << " private key into KeyMaster" << std::endl;
        ok = true;
out:
        util::destroy_g_sem(&g_sem, &g_sem_inited, pr_err);
    }

    return ok ? 0 : 1;
}

int export_key(sp<IKeymasterDevice> hal,
        const hidl_vec<uint8_t>& key, hidl_vec<uint8_t>& out_public_key_x509)
{
    struct ::timespec ts;
    struct timespec *const tsp = reinterpret_cast<struct timespec *>(&ts);

    if (util::prepare_timeout(tsp, 2, pr_err))
        return -1;

    bool ok = false;
    {
        std::lock_guard<std::mutex> lock(g_master_mutex);

        g_export_key_error = ErrorCode::UNKNOWN_ERROR;
        g_export_key_output = {};

        if (util::try_init_g_sem(&g_sem, &g_sem_inited, pr_err))
            goto out;

        hal->exportKey(KeyFormat::X509, key, get_sus_application_id(), {}, export_key_cb);

        if (util::wait_on_sem(&g_sem, "exportKey operation", tsp, pr_err))
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
        util::destroy_g_sem(&g_sem, &g_sem_inited, pr_err);
    }

    return ok ? 0 : 1;
}

} /* namespace cli */
} /* namespace suskeymaster */
