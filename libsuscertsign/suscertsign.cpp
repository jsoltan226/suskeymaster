#include "suscertsign.h"
#include "keys.h"
#include <ctime>
#include <cerrno>
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <semaphore.h>
#include <android/log.h>
#include <android/hardware/keymaster/4.0/IKeymasterDevice.h>
#include <utils/StrongPointer.h>

using ::android::hardware::hidl_vec;
using namespace ::android::hardware::keymaster::V4_0;

static std::mutex g_mutex;

static sem_t g_sem = {};
static std::atomic<bool> g_sem_inited = false;

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

static int prepare_timeout(struct timespec *ts, int offset_seconds);
static int wait_on_sem(sem_t *sem, const char *name, const struct timespec *ts);
static void try_post_g_sem(void);

extern "C" int sus_cert_sign(unsigned char *tbs_der, unsigned long tbs_der_len,
        unsigned char **out_sig, unsigned long *out_sig_len, int ec_or_rsa)
{
    if (tbs_der == NULL || out_sig == NULL) {
        __android_log_print(ANDROID_LOG_ERROR, "certsign", "Invalid parameters!");
        return -1;
    }

    ::android::sp<IKeymasterDevice> hal = IKeymasterDevice::tryGetService("default");
    if (hal == nullptr || !hal->ping().isOk()) {
        __android_log_print(ANDROID_LOG_ERROR, "certsign",
                "Couldn't get a handle to the running KeyMaster HAL");
        return -1;
    }

    hidl_vec<uint8_t> tbs_hidl;
    tbs_hidl.setToExternal(tbs_der, tbs_der_len, false);

    hidl_vec<uint8_t> keyblob_hidl;
    if (ec_or_rsa == SUS_CERT_SIGN_RSA) {
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
        struct timespec ts = { };
        std::atomic_store(&g_sem_inited, false);

        if (sem_init(&g_sem, false, 0)) {
            __android_log_print(ANDROID_LOG_ERROR, "certsign",
                    "Failed to initialize the global semaphore: %d (%s)",
                    errno, std::strerror(errno));
            goto out;
        }
        std::atomic_store(&g_sem_inited, true);

        if (prepare_timeout(&ts, 1)) goto out;
        hal->begin(KeyPurpose::SIGN, keyblob_hidl, params_hidl, {}, begin_cb);
        if (wait_on_sem(&g_sem, "BEGIN operation", &ts)) goto out;

        if (g_begin_error != ErrorCode::OK) {
            __android_log_print(ANDROID_LOG_ERROR, "certsign",
                    "BEGIN operation failed: %d", static_cast<int>(g_begin_error));
            goto out;
        }

        if (prepare_timeout(&ts, 2)) goto out;
        hal->finish(g_operation_handle, {}, tbs_hidl, {}, {}, {}, finish_cb);
        if (wait_on_sem(&g_sem, "FINISH operation", &ts)) goto out;

        if (g_finish_error != ErrorCode::OK) {
            __android_log_print(ANDROID_LOG_ERROR, "certsign",
                    "FINISH operation failed: %d", static_cast<int>(g_finish_error));
            goto out;
        }

        ret = g_out_sig;
        ret_len = g_out_sig_len;
        ok = true;

out:
        if (std::atomic_exchange(&g_sem_inited, false)) {
            if (sem_destroy(&g_sem)) {
                __android_log_print(ANDROID_LOG_ERROR, "certsign",
                        "Failed to destroy the global semaphore: %d (%s)",
                        errno, std::strerror(errno));
            }
        }
    }
    g_mutex.unlock();
    if (!ok) {
        __android_log_print(ANDROID_LOG_ERROR, "certsign",
                "KeyMaster SIGN operation failed");
        return 1;
    }

    *out_sig = ret;
    *out_sig_len = ret_len;

    __android_log_print(ANDROID_LOG_INFO, "certsign",
            "Successfully signed %s cert",
            ec_or_rsa == SUS_CERT_SIGN_EC ? "ECDSA" : "RSA");
    return 0;
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

    try_post_g_sem();
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
        __android_log_print(ANDROID_LOG_ERROR, "certsign",
                "%s: output size is 0!", __func__);
        g_finish_error = ErrorCode::INVALID_ARGUMENT;
        goto err;
    }

    g_out_sig = (unsigned char *)malloc(output.size());
    if (g_out_sig == NULL) {
        __android_log_print(ANDROID_LOG_ERROR, "certsign",
                "%s: malloc(%lu) failed!",
                __func__, output.size());
        g_finish_error = ErrorCode::MEMORY_ALLOCATION_FAILED;
        goto err;
    }
    g_out_sig_len = (unsigned long)output.size();

    std::memcpy(g_out_sig, output.data(), output.size());

err:

    try_post_g_sem();
}

static int prepare_timeout(struct timespec *ts, int offset_seconds)
{
    memset(ts, 0, sizeof(struct timespec));

    if (clock_gettime(CLOCK_REALTIME, ts)) {
        __android_log_print(ANDROID_LOG_ERROR, "certsign",
                "Couldn't get the current time: %d (%s)",
                errno, std::strerror(errno));
        return 1;
    }

    ts->tv_sec += offset_seconds;

    return 0;
}

static int wait_on_sem(sem_t *sem, const char *name, const struct timespec *ts)
{
    int rc = 0;
    do {
        rc = sem_timedwait(sem, ts);
    } while (rc != 0 && errno == EINTR);

    if (rc != 0 && errno == ETIMEDOUT) {
        __android_log_print(ANDROID_LOG_ERROR, "certsign",
                "Timed out while waiting for %s!", name);
        return 1;
    } else if (rc != 0) {
        __android_log_print(ANDROID_LOG_ERROR, "certsign",
                "Failed to wait on the %s semaphore: %d (%s)",
                name, errno, std::strerror(errno));
        return 1;
    }

    return 0;
}

static void try_post_g_sem(void)
{
    if (!atomic_load(&g_sem_inited)) {
        __android_log_print(ANDROID_LOG_ERROR, "certsign",
                "Attempt to post the global semaphore while not initialized!");
        return;
    }

    if (sem_post(&g_sem)) {
        __android_log_print(ANDROID_LOG_ERROR, "certsign",
                "Failed to post the global semaphore: %d (%s)",
                errno, std::strerror(errno));
        return;
    }
}
