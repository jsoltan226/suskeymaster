#include "suscertsign.h"
#include "keys.h"
#include "certs.h"
#include <core/vector.h>
#include <libgenericutil/util.h>
#include <libgenericutil/cert-types.h>
#include <android/log.h>
#include <android/hardware/keymaster/4.0/IKeymasterDevice.h>
#include <utils/StrongPointer.h>
#include <ctime>
#include <mutex>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <cstdarg>
#include <semaphore.h>
#include <stdatomic.h>

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
    if (variant == SUS_KEY_RSA) {
        keyblob_hidl.resize(sus_sign_rsa_wrapped_blob_bin_len);
        std::memcpy(keyblob_hidl.data(), sus_sign_rsa_wrapped_blob_bin,
                sus_sign_rsa_wrapped_blob_bin_len);
    } else {
        keyblob_hidl.resize(sus_sign_ec_wrapped_blob_bin_len);
        std::memcpy(keyblob_hidl.data(), sus_sign_ec_wrapped_blob_bin,
                sus_sign_ec_wrapped_blob_bin_len);
    }

    hidl_vec<KeyParameter> params_hidl;
    enum {
        PARAM_APPLICATION_ID,
        PARAM_DIGEST,
        PARAM_MAX_
    };
    params_hidl.resize(PARAM_MAX_);

    static const unsigned char application_id_val[] = "suskeymaster";
    static const size_t application_id_val_length = sizeof(application_id_val) - 1;
    params_hidl[PARAM_APPLICATION_ID].tag = Tag::APPLICATION_ID;
    params_hidl[PARAM_APPLICATION_ID].blob = hidl_vec<uint8_t>(
            application_id_val,
            application_id_val + application_id_val_length
    );

    params_hidl[PARAM_DIGEST].tag = Tag::DIGEST;
    params_hidl[PARAM_DIGEST].f.digest = Digest::SHA_2_256;

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
        ::atomic_store(&g_sem_inited, false);

        if (util::try_init_g_sem(&g_sem, &g_sem_inited, pr_err))
            goto out;

        if (util::prepare_timeout(&ts, 1, pr_err)) goto out;
        hal->begin(KeyPurpose::SIGN, keyblob_hidl, params_hidl, {}, begin_cb);
        if (util::wait_on_sem(&g_sem, "BEGIN operation", &ts, pr_err)) goto out;

        if (g_begin_error != ErrorCode::OK) {
            pr_err("BEGIN operation failed: %d (%s)",
                    static_cast<int>(g_begin_error), toString(g_begin_error).c_str());
            goto out;
        }

        if (util::prepare_timeout(&ts, 2, pr_err)) goto out;
        hal->finish(g_operation_handle, {}, tbs_hidl, {}, {}, {}, finish_cb);
        if (util::wait_on_sem(&g_sem, "FINISH operation", &ts, pr_err)) goto out;

        if (g_finish_error != ErrorCode::OK) {
            pr_err("FINISH operation failed: %d (%s)",
                    static_cast<int>(g_begin_error), toString(g_begin_error).c_str());
            goto out;
        }

        ret = g_out_sig;
        ret_len = g_out_sig_len;
        ok = true;

out:
        util::destroy_g_sem(&g_sem, &g_sem_inited, pr_err);
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

extern "C" VECTOR(VECTOR(u8 const) const) sus_cert_sign_retrieve_chain(enum sus_key_variant variant)
{
    switch (variant) {
    case SUS_KEY_EC:
        return cert_chain_ec;
    case SUS_KEY_RSA:
        return cert_chain_rsa;
    default:
        __android_log_print(ANDROID_LOG_ERROR, "certsign",
                "Invalid key variant: %d", variant);
        return NULL;
    }
}

extern "C" int sus_cert_sign_retrieve_chain_data(enum sus_key_variant variant,
    const char **out_top_issuer_serial, i64 *out_not_after)
{
    switch (variant) {
    case SUS_KEY_EC:
        if (out_top_issuer_serial != NULL)
            *out_top_issuer_serial = cert_chain_ec_top_issuer_serial;
        if (out_not_after != NULL)
            *out_not_after = cert_chain_ec_not_after;
        return 0;
    case SUS_KEY_RSA:
        if (out_top_issuer_serial != NULL)
            *out_top_issuer_serial = cert_chain_rsa_top_issuer_serial;
        if (out_not_after != NULL)
            *out_not_after = cert_chain_rsa_not_after;
        return 0;
    default:
        __android_log_print(ANDROID_LOG_ERROR, "certsign",
                "Invalid key variant: %d", variant);
        return 1;
    }
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

    util::try_post_g_sem(&g_sem, &g_sem_inited, pr_err);
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

    util::try_post_g_sem(&g_sem, &g_sem_inited, pr_err);
}
