#include "suscertsign.h"
#include "keybox.h"
#include <core/vector.h>
#include <libgenericutil/util.h>
#include <libgenericutil/cert-types.h>
#include <libgenericutil/atomic-wrapper.h>
#include <android/log.h>
#include <android/hardware/keymaster/4.0/types.h>
#include <android/hardware/keymaster/4.0/IKeymasterDevice.h>
#include <utils/StrongPointer.h>
#include <ctime>
#include <mutex>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <cstdarg>
#include <semaphore.h>

using ::android::hardware::hidl_vec;
using namespace ::android::hardware::keymaster::V4_0;
using namespace suskeymaster;

static void pr_err(const char *fmt, ...)
{
    va_list vlist;
    va_start(vlist, fmt);
    __android_log_vprint(ANDROID_LOG_ERROR, "certsign", fmt, vlist);
    va_end(vlist);
}

static void init_ec_params(hidl_vec<KeyParameter>& params);
static void init_rsa_params(hidl_vec<KeyParameter>& params);

static std::mutex g_mutex;

static sem_t g_sem = {};
static _Atomic int g_sem_inited = false;

static ErrorCode g_begin_error = ErrorCode::UNKNOWN_ERROR;
static uint64_t g_operation_handle = 0;
static void begin_cb(
        ErrorCode error,
        const hidl_vec<KeyParameter>& out_params,
        uint64_t operation_handle
);

static ErrorCode g_finish_error = ErrorCode::UNKNOWN_ERROR;
static unsigned char *g_out_sig = NULL;
static unsigned long g_out_sig_len = 0;
static void finish_cb(
        ErrorCode error,
        const hidl_vec<KeyParameter>& out_params,
        const hidl_vec<uint8_t>& output
);

extern "C" int sus_cert_sign(unsigned char *tbs_der, unsigned long tbs_der_len,
        unsigned char **out_sig, unsigned long *out_sig_len,
        enum sus_key_variant variant)
{
    if (tbs_der == NULL || out_sig == NULL) {
        pr_err("Invalid parameters!");
        return -1;
    }

    ::android::sp<IKeymasterDevice> hal = IKeymasterDevice::tryGetService("default");
    if (hal == nullptr || !hal->ping().isOk()) {
        pr_err("Couldn't get a handle to the running KeyMaster HAL");
        return -1;
    }

    hidl_vec<uint8_t> tbs_hidl;
    tbs_hidl.setToExternal(tbs_der, tbs_der_len, false);

    hidl_vec<uint8_t> keyblob_hidl;
    hidl_vec<KeyParameter> params_hidl;

    const struct keybox *keybox = NULL;
    const VECTOR(u8) keyblob = NULL;

    if (keybox_read_lock_current(&keybox)) {
        pr_err("Failed to retrieve the current keybox");
        return -1;
    }
    {
        keyblob = keybox_get_wrapped_key(keybox, variant);
        if (keyblob == NULL) {
            keybox_unlock_current(&keybox);
            pr_err("Failed to retrieve the key blob from the current keybox");
            return -1;
        }

        keyblob_hidl.resize(vector_size(keyblob));
        std::memcpy(keyblob_hidl.data(), keyblob, vector_size(keyblob));
        keyblob = NULL;
    }
    keybox_unlock_current(&keybox);

    if (variant == SUS_KEY_RSA)
        init_rsa_params(params_hidl);
    else
        init_ec_params(params_hidl);

    bool ok = false;
    unsigned char *ret = NULL;
    unsigned long ret_len = 0;

    g_mutex.lock();
    {
        g_begin_error = ErrorCode::UNKNOWN_ERROR;
        g_operation_handle = 0;
        g_finish_error = ErrorCode::UNKNOWN_ERROR;
        g_out_sig = NULL;
        g_out_sig_len = 0;
        struct ::timespec ts = { };
        util_atomic_store_int(&g_sem_inited, false);

        if (try_init_g_sem(&g_sem, &g_sem_inited, pr_err))
            goto out;

        if (prepare_timeout(&ts, 1, pr_err)) goto out;
        hal->begin(KeyPurpose::SIGN, keyblob_hidl, params_hidl, {}, begin_cb);
        if (wait_on_sem(&g_sem, "BEGIN operation", &ts, pr_err)) goto out;

        if (g_begin_error != ErrorCode::OK) {
            pr_err("BEGIN operation failed: %d (%s)",
                    static_cast<int>(g_begin_error), toString(g_begin_error).c_str());
            goto out;
        }

        if (prepare_timeout(&ts, 2, pr_err)) goto out;
        hal->finish(g_operation_handle, {}, tbs_hidl, {}, {}, {}, finish_cb);
        if (wait_on_sem(&g_sem, "FINISH operation", &ts, pr_err)) goto out;

        if (g_finish_error != ErrorCode::OK) {
            pr_err("FINISH operation failed: %d (%s)",
                    static_cast<int>(g_begin_error), toString(g_begin_error).c_str());
            goto out;
        }

        ret = g_out_sig;
        ret_len = g_out_sig_len;
        ok = true;

out:
        destroy_g_sem(&g_sem, &g_sem_inited, pr_err);
    }
    g_mutex.unlock();
    if (!ok) {
        pr_err("KeyMaster SIGN operation failed");
        return 1;
    }

    *out_sig = ret;
    *out_sig_len = ret_len;

    __android_log_print(ANDROID_LOG_INFO, "certsign",
            "Successfully signed %s cert",
            variant == SUS_KEY_EC ? "ECDSA" : "RSA");
    return 0;
}

static void init_ec_params(hidl_vec<KeyParameter>& params)
{
    enum {
        PARAM_APPLICATION_ID,
        PARAM_DIGEST,
        PARAM_MAX_
    };
    params.resize(PARAM_MAX_);

    static const unsigned char application_id_val[] = "suskeymaster";
    static const size_t application_id_val_length = sizeof(application_id_val) - 1;
    params[PARAM_APPLICATION_ID].tag = Tag::APPLICATION_ID;
    params[PARAM_APPLICATION_ID].blob = hidl_vec<uint8_t>(
            application_id_val,
            application_id_val + application_id_val_length
    );

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

    static const unsigned char application_id_val[] = "suskeymaster";
    static const size_t application_id_val_length = sizeof(application_id_val) - 1;
    params[PARAM_APPLICATION_ID].tag = Tag::APPLICATION_ID;
    params[PARAM_APPLICATION_ID].blob = hidl_vec<uint8_t>(
            application_id_val,
            application_id_val + application_id_val_length
    );

    params[PARAM_DIGEST].tag = Tag::DIGEST;
    params[PARAM_DIGEST].f.digest = Digest::SHA_2_256;

    params[PARAM_PADDING_MODE].tag = Tag::PADDING;
    params[PARAM_PADDING_MODE].f.paddingMode = PaddingMode::RSA_PKCS1_1_5_SIGN;
}

static void begin_cb(
        ErrorCode error,
        const hidl_vec<KeyParameter>& out_params,
        uint64_t operation_handle
)
{
    (void) out_params;

    g_begin_error = error;
    if (error == ErrorCode::OK)
        g_operation_handle = operation_handle;

    try_post_g_sem(&g_sem, &g_sem_inited, pr_err);
}

static void finish_cb(
        ErrorCode error,
        const hidl_vec<KeyParameter>& out_params,
        const hidl_vec<uint8_t>& output
)
{
    (void) out_params;

    g_finish_error = error;
    if (error != ErrorCode::OK)
        goto err;

    if (output.size() == 0) {
        pr_err("%s: output size is 0!", __func__);
        g_finish_error = ErrorCode::INVALID_ARGUMENT;
        goto err;
    }

    g_out_sig = (unsigned char *)malloc(output.size());
    if (g_out_sig == NULL) {
        pr_err("%s: malloc(%lu) for g_out_sig failed!", __func__, output.size());
        g_finish_error = ErrorCode::MEMORY_ALLOCATION_FAILED;
        goto err;
    }
    g_out_sig_len = (unsigned long)output.size();

    std::memcpy(g_out_sig, output.data(), output.size());

err:

    try_post_g_sem(&g_sem, &g_sem_inited, pr_err);
}
