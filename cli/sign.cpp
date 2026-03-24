#include "cli.hpp"
#include <cstdlib>
#include <libgenericutil/util.h>
#include <libgenericutil/atomic-wrapper.h>
#include <libsuscertmod/keymaster-types.h>
#include <libsuscertmod/key-desc.h>
#include <unordered_map>
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

static void pr_info(const char *fmt, ...)
{
    va_list vlist;
    va_start(vlist, fmt);
    vfprintf(stdout, fmt, vlist);
    putchar('\n');
    va_end(vlist);
}

static ErrorCode g_get_key_characteristics_error = ErrorCode::UNKNOWN_ERROR;
static KeyCharacteristics g_out_characteristics;
static void get_key_characteristics_cb(
        ErrorCode error,
        const KeyCharacteristics& key_characteristics
)
{
    if (!util::do_atomic_load_int(&g_sem_inited)) {
        std::cerr << "FATAL ERROR: Global semaphore not initialized!" << std::endl;
        std::abort();
    }

    g_get_key_characteristics_error = error;
    if (error == ErrorCode::OK) {
        g_out_characteristics = key_characteristics;
    }
    util::try_post_g_sem(&g_sem, &g_sem_inited, pr_err);
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

    if (!util::do_atomic_load_int(&g_sem_inited)) {
        std::cerr << "FATAL ERROR: Global semaphore not initialized!" << std::endl;
        std::abort();
    }

    if (error == ErrorCode::OK)
        g_operation_handle = operation_handle;

    g_begin_error = error;
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

    if (!util::do_atomic_load_int(&g_sem_inited)) {
        std::cerr << "FATAL ERROR: Global semaphore not initialized!" << std::endl;
        std::abort();
    }

    g_operation_handle = 0;

    if (error == ErrorCode::OK)
        g_out_sig = output;

    g_finish_error = error;
    util::try_post_g_sem(&g_sem, &g_sem_inited, pr_err);
}

int sign(sp<IKeymasterDevice> hal,
        const hidl_vec<uint8_t>& message, const hidl_vec<uint8_t>& key,
        const hidl_vec<KeyParameter>& in_sign_params, hidl_vec<uint8_t>& out)
{
    hidl_vec<uint8_t> app_id = {};
    hidl_vec<uint8_t> app_data = {};
    for (auto const& kp : in_sign_params) {
        if (kp.tag == Tag::APPLICATION_ID) {
            app_id = kp.blob;
        } else if (kp.tag == Tag::APPLICATION_DATA) {
            app_data = kp.blob;
        }
    }

    hidl_vec<KeyParameter> params = in_sign_params;

    bool ok = false;
    {
        std::lock_guard<std::mutex> lock(g_master_mutex);

        g_begin_error = ErrorCode::UNKNOWN_ERROR;
        g_operation_handle = 0;
        g_finish_error = ErrorCode::UNKNOWN_ERROR;
        g_out_sig = {};

        struct ::timespec ts = { };
        struct timespec *const tsp = reinterpret_cast<struct timespec *>(&ts);
        Algorithm key_type;
        bool found = false;
        int begin_timeout_s = 0, finish_timeout_s = 0;

        if (util::try_init_g_sem(&g_sem, &g_sem_inited, pr_err))
            goto out;

        /* Determine the key's algorithm (EC or RSA) */
        if (util::prepare_timeout(tsp, 1, pr_err)) goto out;
        hal->getKeyCharacteristics(key, app_id, app_data, get_key_characteristics_cb);
        if (util::wait_on_sem(&g_sem, "getKeyCharacteristics operation", tsp, pr_err)) goto out;

        if (g_get_key_characteristics_error != ErrorCode::OK) {
            pr_err("Couldn't get the signing key's characteristics: %d (%s)",
                    static_cast<int>(g_get_key_characteristics_error),
                    toString(g_get_key_characteristics_error).c_str()
            );
            goto out;
        }

        for (auto const& kp : g_out_characteristics.hardwareEnforced) {
            if (kp.tag == Tag::ALGORITHM) {
                found = true;
                key_type = kp.f.algorithm;
                break;
            }
        }
        if (!found) {
            std::cerr << "No ALGORITHM tag in key characteristics!" << std::endl;
            goto out;
        } else if (key_type != Algorithm::EC && key_type != Algorithm::RSA) {
            pr_err("Unsupported signing key algorithm: %d (%s)",
                    static_cast<int>(key_type), toString(key_type).c_str());
        }

        if (key_type == Algorithm::RSA) {
            begin_timeout_s = 2;
            finish_timeout_s = 6;
            std::unordered_map<Tag, struct defaults_with_flags> rsa_defaults = {
                { Tag::DIGEST, { { to_u32(Digest::SHA_2_256) }, 0 } },
                { Tag::PADDING, { { to_u32(PaddingMode::RSA_PKCS1_1_5_SIGN) }, 0 } }
            };
            init_default_params(rsa_defaults, params);
        } else /* if (g_key_type == Algorithm::EC) */ {
            begin_timeout_s = 1;
            finish_timeout_s = 2;
            std::unordered_map<Tag, struct defaults_with_flags> ec_defaults = {
                { Tag::DIGEST, { { to_u32(Digest::SHA_2_256) }, 0 } }
            };
            init_default_params(ec_defaults, params);
        }

        /* Initialize the operation */
        if (util::prepare_timeout(tsp, begin_timeout_s, pr_err)) goto out;
        hal->begin(KeyPurpose::SIGN, key, params, {}, begin_cb);
        if (util::wait_on_sem(&g_sem, "BEGIN operation", tsp, pr_err)) goto out;

        if (g_begin_error != ErrorCode::OK) {
            pr_err("BEGIN operation failed: %d (%s)",
                    static_cast<int>(g_begin_error), toString(g_begin_error).c_str());
            goto out;
        }

        /* Finalize (actually perform) the operation */
        params = in_sign_params;
        if (util::prepare_timeout(tsp, finish_timeout_s, pr_err)) goto out;
        hal->finish(g_operation_handle, params, message, {}, {}, {}, finish_cb);
        if (util::wait_on_sem(&g_sem, "FINISH operation", tsp, pr_err)) goto out;

        if (g_finish_error != ErrorCode::OK) {
            pr_err("FINISH operation failed: %d (%s)",
                    static_cast<int>(g_finish_error), toString(g_finish_error).c_str());
            goto out;
        }

        out = g_out_sig;
        ok = true;

out:
        util::destroy_g_sem(&g_sem, &g_sem_inited, pr_err);
    }

    if (!ok) {
        std::cerr << "Failed to sign message with provided key" << std::endl;
        return 1;
    } else {
        std::cout << "Signing operation OK" << std::endl;
        return 0;
    }
}

int get_key_characteristics(
    ::android::sp<::android::hardware::keymaster::V4_0::IKeymasterDevice>   hal,
    ::android::hardware::hidl_vec<uint8_t> const&                           key,
    ::android::hardware::hidl_vec
        <::android::hardware::keymaster::V4_0::KeyParameter> const&         in_application_id_data
)
{
    hidl_vec<uint8_t> application_id;
    hidl_vec<uint8_t> application_data;
    for (auto const& kp : in_application_id_data) {
        if (kp.tag == Tag::APPLICATION_ID)
            application_id = kp.blob;
        else if (kp.tag == Tag::APPLICATION_DATA)
            application_data = kp.blob;
    }

    KeyCharacteristics key_characteristics;

    bool ok = false;
    {
        std::lock_guard<std::mutex> lock(g_master_mutex);

        g_get_key_characteristics_error = ErrorCode::UNKNOWN_ERROR;

        struct ::timespec ts = { };

        if (util::try_init_g_sem(&g_sem, &g_sem_inited, pr_err))
            goto out;

        if (util::prepare_timeout(&ts, 1, pr_err)) goto out;
        hal->getKeyCharacteristics(key, application_id, application_data,
                get_key_characteristics_cb);
        if (util::wait_on_sem(&g_sem, "getKeyCharacteristics operation", &ts, pr_err)) goto out;

        if (g_get_key_characteristics_error != ErrorCode::OK) {
            pr_err("Couldn't get the key's characteristics: %d (%s)",
                    static_cast<int>(g_get_key_characteristics_error),
                    toString(g_get_key_characteristics_error).c_str()
            );
            goto out;
        }

        key_characteristics = g_out_characteristics;
        ok = true;
out:;
    }
    if (!ok) {
        std::cerr << "Failed to get the key's characteristics" << std::endl;
        return EXIT_FAILURE;
    }

    struct certmod::KM_KeyDescription_v3 *key_desc = certmod::key_desc_new();
    if (key_desc == NULL) {
        std::cerr << "Failed to allocate a new key description" << std::endl;
        return EXIT_FAILURE;
    }

    key_params_2_auth_list(key_characteristics.softwareEnforced,
            &key_desc->softwareEnforced);
    key_params_2_auth_list(key_characteristics.hardwareEnforced,
            &key_desc->hardwareEnforced);
    certmod::key_desc_dump(key_desc, pr_info);
    key_desc_destroy(&key_desc);

    return EXIT_SUCCESS;
}

} /* namespace cli */
} /* namespace suskeymaster */
