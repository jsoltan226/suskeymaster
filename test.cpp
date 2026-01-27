#include <android/hardware/keymaster/4.0/IKeymasterDevice.h>
#include <android/log.h>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <atomic>
#include <ios>
#include <fstream>
#include <semaphore.h>
#include "skeymaster.h"
#include <utils/StrongPointer.h>
#include <libsuskeymaster/handler.hpp>
#include <openssl/evp.h>
#include <openssl/asn1.h>

using namespace ::android::hardware::keymaster::V4_0;
using namespace ::android::hardware;

static sem_t g_sem;
static std::atomic<bool> g_sem_initialized = false;
static std::atomic<bool> g_sem_waiting = false;

static ErrorCode g_gen_error = ErrorCode::UNKNOWN_ERROR;
static hidl_vec<uint8_t> g_gen_key = { };
static KeyCharacteristics g_gen_characteristics = { };

static ErrorCode g_attest_error = ErrorCode::UNKNOWN_ERROR;
static hidl_vec<hidl_vec<uint8_t>> g_attest_cert_chain = { { } };

static ErrorCode g_begin_error = ErrorCode::UNKNOWN_ERROR;
static hidl_vec<KeyParameter> g_begin_out_params = { };
static uint64_t g_operation_handle = 0;

static ErrorCode g_update_error = ErrorCode::UNKNOWN_ERROR;
static uint32_t g_update_input_consumed = 0;
static hidl_vec<KeyParameter> g_update_out_params = { };
static hidl_vec<uint8_t> g_update_output = { };

static ErrorCode g_finish_error = ErrorCode::UNKNOWN_ERROR;
static hidl_vec<KeyParameter> g_finish_out_params = { };
static hidl_vec<uint8_t> g_finish_output = { };

static ErrorCode g_import_key_error = ErrorCode::UNKNOWN_ERROR;
static hidl_vec<uint8_t> g_import_key_output = { };
static KeyCharacteristics g_import_key_characteristics = { };

static ErrorCode g_export_key_error = ErrorCode::UNKNOWN_ERROR;
static hidl_vec<uint8_t> g_export_key_output = { };

static int initialize_generate_key_params(hidl_vec<KeyParameter>& params);
static int initialize_attest_key_params(hidl_vec<KeyParameter>& params);

static int initialize_ec_import_params(hidl_vec<KeyParameter>& params);
static int initialize_rsa_import_params(hidl_vec<KeyParameter>& params);

static int initialize_sign_params(hidl_vec<KeyParameter>& params);

static int test1_attest_direct(void);
static int test2_attest_binder(void);

static int test3_import_binder(void);
static int test4_sign_binder(void);
static int test5_export_binder(void);

static void dump_certs(const hidl_vec<hidl_vec<uint8_t>>& cert_chain,
        const char *file_prefix);

void generate_key_cb(
        ErrorCode error,
        hidl_vec<unsigned char> const& out_key,
        KeyCharacteristics const& out_characteristics)
{
    __android_log_print(ANDROID_LOG_INFO, "test", "Generate key cb called: %d!\n",
            (int32_t)error);

    if (!std::atomic_load(&g_sem_initialized))
        __android_log_print(ANDROID_LOG_FATAL, "test", "Semaphore not initialized!\n");

    if (!std::atomic_load(&g_sem_waiting))
        __android_log_print(ANDROID_LOG_FATAL, "test", "Main thread is not waiting!\n");

    g_gen_error = error;
    g_gen_key = out_key;
    g_gen_characteristics = out_characteristics;
    if (sem_post(&g_sem)) {
        __android_log_print(ANDROID_LOG_FATAL, "test",
                "Failed to post the semaphore (%d: %s) - impossible outcome!",
                errno, strerror(errno));
    }
}

void attest_key_cb(
        ErrorCode error,
        const hidl_vec<hidl_vec<uint8_t>>& certChain)
{
    __android_log_print(ANDROID_LOG_INFO, "test", "Attest key cb called: %d!\n",
            (int32_t)error);

    if (!std::atomic_load(&g_sem_initialized))
        __android_log_print(ANDROID_LOG_FATAL, "test", "Semaphore not initialized!\n");

    if (!std::atomic_load(&g_sem_waiting))
        __android_log_print(ANDROID_LOG_FATAL, "test", "Main thread is not waiting!\n");

    g_attest_error = error;
    g_attest_cert_chain = certChain;
    if (sem_post(&g_sem)) {
        __android_log_print(ANDROID_LOG_FATAL, "test",
                "Failed to post the semaphore (%d: %s) - impossible outcome!",
                errno, strerror(errno));
    }
}

void begin_cb(
        ErrorCode error,
        const hidl_vec<KeyParameter>& out_params,
        uint64_t operation_handle)
{
    __android_log_print(ANDROID_LOG_INFO, "test", "Begin cb called: %d!\n",
            (int32_t)error);

    if (!std::atomic_load(&g_sem_initialized))
        __android_log_print(ANDROID_LOG_FATAL, "test", "Semaphore not initialized!\n");

    if (!std::atomic_load(&g_sem_waiting))
        __android_log_print(ANDROID_LOG_FATAL, "test", "Main thread is not waiting!\n");

    g_begin_error = error;
    if (error != ErrorCode::OK) {
        __android_log_print(ANDROID_LOG_ERROR, "test", "begin operation failed!\n");
        if (sem_post(&g_sem)) {
            __android_log_print(ANDROID_LOG_FATAL, "test",
                    "Failed to post the semaphore (%d: %s) - impossible outcome!",
                    errno, strerror(errno));
        }
        return;
    }

    g_begin_out_params = out_params;
    g_operation_handle = operation_handle;

    if (sem_post(&g_sem)) {
        __android_log_print(ANDROID_LOG_FATAL, "test",
                "Failed to post the semaphore (%d: %s) - impossible outcome!",
                errno, strerror(errno));
    }
}

void update_cb(
        ErrorCode error,
        uint32_t input_consumed,
        const hidl_vec<KeyParameter>& out_params,
        const hidl_vec<uint8_t>& output)
{
    __android_log_print(ANDROID_LOG_INFO, "test", "Update cb called: %d!\n",
            (int32_t)error);

    if (!std::atomic_load(&g_sem_initialized))
        __android_log_print(ANDROID_LOG_FATAL, "test", "Semaphore not initialized!\n");

    if (!std::atomic_load(&g_sem_waiting))
        __android_log_print(ANDROID_LOG_FATAL, "test", "Main thread is not waiting!\n");

    g_update_error = error;
    if (error != ErrorCode::OK) {
        g_operation_handle = 0;
        __android_log_print(ANDROID_LOG_ERROR, "test", "update operation failed!\n");
        if (sem_post(&g_sem)) {
            __android_log_print(ANDROID_LOG_FATAL, "test",
                    "Failed to post the semaphore (%d: %s) - impossible outcome!",
                    errno, strerror(errno));
        }
        return;
    }

    g_update_input_consumed = input_consumed;
    g_update_out_params = out_params;
    g_update_output = output;

    if (sem_post(&g_sem)) {
        __android_log_print(ANDROID_LOG_FATAL, "test",
                "Failed to post the semaphore (%d: %s) - impossible outcome!",
                errno, strerror(errno));
    }
}

void finish_cb(
        ErrorCode error,
        const hidl_vec<KeyParameter>& out_params,
        const hidl_vec<uint8_t>& output
)
{
    __android_log_print(ANDROID_LOG_INFO, "test", "Finish cb called: %d!\n",
            (int32_t)error);

    if (!std::atomic_load(&g_sem_initialized))
        __android_log_print(ANDROID_LOG_FATAL, "test", "Semaphore not initialized!\n");

    if (!std::atomic_load(&g_sem_waiting))
        __android_log_print(ANDROID_LOG_FATAL, "test", "Main thread is not waiting!\n");

    g_operation_handle = 0;

    g_finish_error = error;
    if (error != ErrorCode::OK) {
        __android_log_print(ANDROID_LOG_ERROR, "test", "finish operation failed!\n");
        if (sem_post(&g_sem)) {
            __android_log_print(ANDROID_LOG_FATAL, "test",
                    "Failed to post the semaphore (%d: %s) - impossible outcome!",
                    errno, strerror(errno));
        }
        return;
    }

    g_finish_out_params = out_params;
    g_finish_output = output;

    if (sem_post(&g_sem)) {
        __android_log_print(ANDROID_LOG_FATAL, "test",
                "Failed to post the semaphore (%d: %s) - impossible outcome!",
                errno, strerror(errno));
    }
}

void import_key_cb(
        ErrorCode error,
        const hidl_vec<uint8_t>& key_blob,
        const KeyCharacteristics& key_characteristics
)
{
    __android_log_print(ANDROID_LOG_INFO, "test", "Import key cb called: %d!\n",
            (int32_t)error);

    if (!std::atomic_load(&g_sem_initialized))
        __android_log_print(ANDROID_LOG_FATAL, "test", "Semaphore not initialized!\n");

    if (!std::atomic_load(&g_sem_waiting))
        __android_log_print(ANDROID_LOG_FATAL, "test", "Main thread is not waiting!\n");

    g_import_key_error = error;
    if (error != ErrorCode::OK) {
        __android_log_print(ANDROID_LOG_ERROR, "test", "import key operation failed!\n");
        if (sem_post(&g_sem)) {
            __android_log_print(ANDROID_LOG_FATAL, "test",
                    "Failed to post the semaphore (%d: %s) - impossible outcome!",
                    errno, strerror(errno));
        }
        return;
    }

    g_import_key_output = key_blob;
    g_import_key_characteristics = key_characteristics;

    if (sem_post(&g_sem)) {
        __android_log_print(ANDROID_LOG_FATAL, "test",
                "Failed to post the semaphore (%d: %s) - impossible outcome!",
                errno, strerror(errno));
    }
}

void export_key_cb(
        ErrorCode error,
        const hidl_vec<uint8_t>& key_material
)
{
    __android_log_print(ANDROID_LOG_INFO, "test", "Export key cb called: %d!\n",
            (int32_t)error);

    if (!std::atomic_load(&g_sem_initialized))
        __android_log_print(ANDROID_LOG_FATAL, "test", "Semaphore not initialized!\n");

    if (!std::atomic_load(&g_sem_waiting))
        __android_log_print(ANDROID_LOG_FATAL, "test", "Main thread is not waiting!\n");

    g_export_key_error = error;
    if (error != ErrorCode::OK) {
        __android_log_print(ANDROID_LOG_ERROR, "test", "export key operation failed!\n");
        if (sem_post(&g_sem)) {
            __android_log_print(ANDROID_LOG_FATAL, "test",
                    "Failed to post the semaphore (%d: %s) - impossible outcome!",
                    errno, strerror(errno));
        }
        return;
    }

    g_export_key_output = key_material;
    if (sem_post(&g_sem)) {
        __android_log_print(ANDROID_LOG_FATAL, "test",
                "Failed to post the semaphore (%d: %s) - impossible outcome!",
                errno, strerror(errno));
    }
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return test2_attest_binder();

    const int testno = strtoul(argv[1], NULL, 0);
    switch (testno) {
    case 1: return test1_attest_direct();
    case 2: return test2_attest_binder();
    case 3: return test3_import_binder();
    case 4: return test4_sign_binder();
    case 5: return test5_export_binder();
    default:
            return test2_attest_binder();
    }
}

static int initialize_generate_key_params(hidl_vec<KeyParameter>& params)
{
    enum {
        PARAM_ALGOR, PARAM_EC_CURVE, PARAM_DIGEST,
        PARAM_PURPOSE_SIGN, PARAM_PURPOSE_VERIFY, PARAM_NO_AUTH_REQUIRED,
        PARAM_MAX_
    };
    params.resize(PARAM_MAX_);
    if (params.size() != PARAM_MAX_) {
        __android_log_print(ANDROID_LOG_ERROR, "test",
                "Failed to resize the generateKey param vector!\n");
        return 1;
    }

    params[PARAM_ALGOR].tag = Tag::ALGORITHM;
    params[PARAM_ALGOR].f.algorithm = Algorithm::EC;
    params[PARAM_EC_CURVE].tag = Tag::EC_CURVE;
    params[PARAM_EC_CURVE].f.ecCurve = EcCurve::P_256;
    params[PARAM_DIGEST].tag = Tag::DIGEST;
    params[PARAM_DIGEST].f.digest = Digest::SHA_2_256;

    params[PARAM_PURPOSE_SIGN].tag = Tag::PURPOSE;
    params[PARAM_PURPOSE_SIGN].f.purpose = KeyPurpose::SIGN;
    params[PARAM_PURPOSE_VERIFY].tag = Tag::PURPOSE;
    params[PARAM_PURPOSE_VERIFY].f.purpose = KeyPurpose::VERIFY;
    params[PARAM_NO_AUTH_REQUIRED].tag = Tag::NO_AUTH_REQUIRED;
    params[PARAM_NO_AUTH_REQUIRED].f.boolValue = true;

    return 0;
}

static int initialize_attest_key_params(hidl_vec<KeyParameter>& params)
{
    enum {
        PARAM_CHALLENGE, PARAM_ATTESTATION_APPLICATION_ID,
        PARAM_MAX_
    };
    params.resize(PARAM_MAX_);
    if (params.size() != PARAM_MAX_) {
        __android_log_print(ANDROID_LOG_ERROR, "test",
                "Failed to resize the attestKey param vector!\n");
        return 1;
    }

    static const unsigned char challenge_val[] = "ATTESTATION CHALLENGE";
    static const size_t challenge_val_length = sizeof(challenge_val) - 1;
    params[PARAM_CHALLENGE].tag = Tag::ATTESTATION_CHALLENGE;
    params[PARAM_CHALLENGE].blob = hidl_vec<uint8_t>(
            challenge_val,
            challenge_val + challenge_val_length
    );
    if (params[PARAM_CHALLENGE].blob.size() != challenge_val_length) {
        __android_log_print(ANDROID_LOG_ERROR, "test",
                "Failed to create the challenge blob!\n");
        return 1;
    }

    static const unsigned char application_id_val[] = "TEST ATTESTATION APPLICATION ID";
    static const size_t application_id_val_length = sizeof(application_id_val) - 1;
    params[PARAM_ATTESTATION_APPLICATION_ID].tag = Tag::ATTESTATION_APPLICATION_ID;
    params[PARAM_ATTESTATION_APPLICATION_ID].blob = hidl_vec<uint8_t>(
            application_id_val,
            application_id_val + application_id_val_length
    );
    if (params[PARAM_ATTESTATION_APPLICATION_ID].blob.size() != application_id_val_length) {
        __android_log_print(ANDROID_LOG_ERROR, "test",
                "Failed to create the attestation application ID blob!\n");
        return 1;
    }

    return 0;
}

static int __attribute__((unused)) initialize_ec_import_params(hidl_vec<KeyParameter>& params)
{
    enum {
        PARAM_APPLICATION_ID,
        PARAM_ALGORITHM,
        PARAM_EC_CURVE,
        PARAM_PURPOSE,
        PARAM_DIGEST,
        PARAM_MAX_
    };

    params.resize(PARAM_MAX_);
    if (params.size() != PARAM_MAX_) {
        __android_log_print(ANDROID_LOG_ERROR, "test",
                "Failed to resize the EC import key param vector!\n");
        return 1;
    }

    static const unsigned char application_id_val[] = "suskeymaster";
    static const size_t application_id_val_length = sizeof(application_id_val) - 1;
    params[PARAM_APPLICATION_ID].tag = Tag::APPLICATION_ID;
    params[PARAM_APPLICATION_ID].blob = hidl_vec<uint8_t>(
            application_id_val,
            application_id_val + application_id_val_length
    );
    if (params[PARAM_APPLICATION_ID].blob.size() != application_id_val_length) {
        __android_log_print(ANDROID_LOG_ERROR, "test",
                "Failed to create the application ID blob!\n");
        return 1;
    }

    params[PARAM_ALGORITHM].tag = Tag::ALGORITHM;
    params[PARAM_ALGORITHM].f.algorithm = Algorithm::EC;

    params[PARAM_EC_CURVE].tag = Tag::EC_CURVE;
    params[PARAM_EC_CURVE].f.ecCurve = EcCurve::P_256;

    params[PARAM_PURPOSE].tag = Tag::PURPOSE;
    params[PARAM_PURPOSE].f.purpose = KeyPurpose::SIGN;

    params[PARAM_DIGEST].tag = Tag::DIGEST;
    params[PARAM_DIGEST].f.digest = Digest::SHA_2_256;

    return 0;
}

static int initialize_rsa_import_params(hidl_vec<KeyParameter>& params)
{
    enum {
        PARAM_APPLICATION_ID,
        PARAM_ALGORITHM,
        PARAM_PADDING,
        PARAM_PURPOSE,
        PARAM_DIGEST,
        PARAM_MAX_
    };

    params.resize(PARAM_MAX_);
    if (params.size() != PARAM_MAX_) {
        __android_log_print(ANDROID_LOG_ERROR, "test",
                "Failed to resize the RSA import key param vector!\n");
        return 1;
    }

    static const unsigned char application_id_val[] = "suskeymaster";
    static const size_t application_id_val_length = sizeof(application_id_val) - 1;
    params[PARAM_APPLICATION_ID].tag = Tag::APPLICATION_ID;
    params[PARAM_APPLICATION_ID].blob = hidl_vec<uint8_t>(
            application_id_val,
            application_id_val + application_id_val_length
    );
    if (params[PARAM_APPLICATION_ID].blob.size() != application_id_val_length) {
        __android_log_print(ANDROID_LOG_ERROR, "test",
                "Failed to create the application ID blob!\n");
        return 1;
    }

    params[PARAM_ALGORITHM].tag = Tag::ALGORITHM;
    params[PARAM_ALGORITHM].f.algorithm = Algorithm::RSA;

    params[PARAM_PADDING].tag = Tag::PADDING;
    params[PARAM_PADDING].f.paddingMode = PaddingMode::RSA_PKCS1_1_5_SIGN;

    params[PARAM_PURPOSE].tag = Tag::PURPOSE;
    params[PARAM_PURPOSE].f.purpose = KeyPurpose::SIGN;

    params[PARAM_DIGEST].tag = Tag::DIGEST;
    params[PARAM_DIGEST].f.digest = Digest::SHA_2_256;

    return 0;
}

static int initialize_sign_params(hidl_vec<KeyParameter>& params)
{
    enum {
        PARAM_APPLICATION_ID,
        PARAM_DIGEST,
        PARAM_MAX_
    };

    params.resize(PARAM_MAX_);
    if (params.size() != PARAM_MAX_) {
        __android_log_print(ANDROID_LOG_ERROR, "test",
                "Failed to resize the sign param vector!\n");
        return 1;
    }

    params[PARAM_DIGEST].tag = Tag::DIGEST;
    params[PARAM_DIGEST].f.digest = Digest::SHA_2_256;

    static const unsigned char application_id_val[] = "suskeymaster";
    static const size_t application_id_val_length = sizeof(application_id_val) - 1;
    params[PARAM_APPLICATION_ID].tag = Tag::APPLICATION_ID;
    params[PARAM_APPLICATION_ID].blob = hidl_vec<uint8_t>(
            application_id_val,
            application_id_val + application_id_val_length
    );
    if (params[PARAM_APPLICATION_ID].blob.size() != application_id_val_length) {
        __android_log_print(ANDROID_LOG_ERROR, "test",
                "Failed to create the application ID blob!\n");
        return 1;
    }

    return 0;
}

#define goto_err(str) do { errmsg = str; goto err; } while (0)

static int test1_attest_direct(void)
{
    int ret = EXIT_SUCCESS;
    SKeymaster4Device *dev = nullptr;
    const char *errmsg = "N/A";

    __android_log_print(ANDROID_LOG_INFO, "test1", "TEST 1 START\n");

    goto_err("test 1 is not implemented!");

    dev = SKeymaster4_CreateDevice(SecurityLevel::TRUSTED_ENVIRONMENT);
    if (dev == nullptr)
        goto_err("Failed to create the SKeymaster4 device!");

    ret = test2_attest_binder();
    goto out;

err:
    __android_log_print(ANDROID_LOG_ERROR, "test1", "TEST 1 FAILED: %s", errmsg);

out:

    if (dev != nullptr) {
        SKeymaster4_DeleteDestroy(dev);
        dev = nullptr;
    }

    __android_log_print(ANDROID_LOG_INFO, "test1", "TEST 1 END\n");

    return ret;
}

static int test2_attest_binder(void)
{
    int ret = EXIT_SUCCESS;
    hidl_vec<KeyParameter> gen_key_params = {};
    hidl_vec<KeyParameter> attest_key_params = {};
    ::android::sp<IKeymasterDevice> hal = nullptr;
    IKeymasterDevice::generateKey_cb gen_cb = generate_key_cb;
    IKeymasterDevice::attestKey_cb attest_cb = attest_key_cb;
    struct timespec ts = { };
    int rc = 0;
    const char *errmsg = "N/A";

    __android_log_print(ANDROID_LOG_INFO, "test2", "TEST 2 START\n");

    hal = IKeymasterDevice::getService();
    if (hal == nullptr || !hal->ping().isOk())
        goto_err("KeyMaster HAL not available!");

    if (sem_init(&g_sem, false, 0))
        goto_err("Failed to init the semaphore!");

    std::atomic_store(&g_sem_initialized, true);

    /* Generate key and wait for signal from callback */

    if (initialize_generate_key_params(gen_key_params))
        goto_err("Failed to initialize the keygen params!");


    if (clock_gettime(CLOCK_REALTIME, &ts))
        __android_log_print(ANDROID_LOG_FATAL, "test2",
                "Couldn't get the current time: %d (%s)", errno, strerror(errno));

    ts.tv_sec += 2; /* Set a timeout of 2 seconds */

    std::atomic_store(&g_sem_waiting, true);
    hal->generateKey(gen_key_params, generate_key_cb);

    do {
        rc = sem_timedwait(&g_sem, &ts);
    } while (rc == -1 && errno == EINTR);
    if (rc == -1 && errno == ETIMEDOUT) {
        ret = EXIT_FAILURE;
        goto_err("Timed out waiting for signal from keygen callback!\n");
    } else if (rc == -1) {
        __android_log_print(ANDROID_LOG_FATAL, "test2",
                "Unexpected error while waiting from signal from keygen callback: %d (%s)\n",
                errno, strerror(errno));
    }
    std::atomic_store(&g_sem_waiting, false);

    __android_log_print(ANDROID_LOG_INFO, "test2",
            "GENERATE KEY RET: %d", (int32_t)g_gen_error);
    if (g_gen_error != ErrorCode::OK)
        goto_err("Failed to generate the attested key!");


    /* Attest the key (and wait for signal from callback) */

    if (initialize_attest_key_params(attest_key_params))
        goto_err("Failed to initialize the attestation params!");


    memset(&ts, 0, sizeof(struct timespec));
    if (clock_gettime(CLOCK_REALTIME, &ts))
        __android_log_print(ANDROID_LOG_FATAL, "test2",
                "Couldn't get the current time: %d (%s)", errno, strerror(errno));
    ts.tv_sec += 2;

    std::atomic_store(&g_sem_waiting, true);
    hal->attestKey(g_gen_key, attest_key_params, attest_key_cb);

    rc = 0;
    do {
        rc = sem_timedwait(&g_sem, &ts);
    } while (rc == -1 && errno == EINTR);
    if (rc == -1 && errno == ETIMEDOUT) {
        ret = EXIT_FAILURE;
        goto_err("Timed out waiting for signal from attest callback!\n");
    } else if (rc == -1) {
        __android_log_print(ANDROID_LOG_FATAL, "test2",
                "Unexpected error while waiting from signal from attest callback: %d (%s)\n",
                errno, strerror(errno));
    }
    std::atomic_store(&g_sem_waiting, false);

    __android_log_print(ANDROID_LOG_INFO, "test2", "ATTEST KEY RET: %d", (int32_t)g_attest_error);
    if (g_attest_error != ErrorCode::OK)
        goto_err("Failed to attest the key!");

    dump_certs(g_attest_cert_chain, "out_original");

    if (libsuskeymaster::sus_keymaster_hack_cert_chain(g_attest_cert_chain))
        goto_err("Failed to hack the cert chain!");

    dump_certs(g_attest_cert_chain, "out_hacked");

    goto out;

err:
    __android_log_print(ANDROID_LOG_ERROR, "test2", "TEST 2 FAILED: %s", errmsg);

    out:

    if (std::atomic_exchange(&g_sem_initialized, false) && sem_destroy(&g_sem)) {
        __android_log_print(ANDROID_LOG_FATAL, "test2",
                "Failed to destroy the semaphore: %d (%s)",
                errno, strerror(errno));
    }

    __android_log_print(ANDROID_LOG_INFO, "test2", "TEST 2 END\n");

    return ret;
}

static int test3_import_binder(void)
{
    if (sem_init(&g_sem, false, 0)) {
        __android_log_print(ANDROID_LOG_ERROR, "test3", "Failed to init the semaphore!");
        return EXIT_FAILURE;
    }
    std::atomic_store(&g_sem_initialized, true);

    ::android::sp<IKeymasterDevice> hal = IKeymasterDevice::getService();
    if (hal == nullptr || !hal->ping().isOk()) {
        __android_log_print(ANDROID_LOG_ERROR, "test3", "Keymaster HAL service not available");
        return EXIT_FAILURE;
    }
    int rc = 0;
    struct timespec ts;

    /* First import the EC key */

    std::ifstream ec_pkcs8_file("ec-private-pkcs8.bin", std::ios::binary | std::ios::ate);
    if (!ec_pkcs8_file.is_open()) {
        __android_log_print(ANDROID_LOG_ERROR, "test3", "Failed to open the EC key file: %s",
                std::strerror(errno));
        return EXIT_FAILURE;
    }
    std::streamsize ec_pkcs8_size = ec_pkcs8_file.tellg();
    ec_pkcs8_file.seekg(0, std::ios::beg);

    hidl_vec<uint8_t> ec_pkcs8(ec_pkcs8_size);
    if (!ec_pkcs8_file.read(reinterpret_cast<char *>(ec_pkcs8.data()), ec_pkcs8_size)) {
        __android_log_print(ANDROID_LOG_ERROR, "test3", "Failed to read the EC private key: %s",
                std::strerror(errno));
        return EXIT_FAILURE;
    }

    __android_log_print(ANDROID_LOG_INFO, "test3", "ec_pkcs8_size: %d",
            static_cast<int32_t>(ec_pkcs8_size));

    hidl_vec<KeyParameter> import_ec_params;
    if (initialize_ec_import_params(import_ec_params)) {
        __android_log_print(ANDROID_LOG_ERROR, "test3",
                "Failed to initialize the EC key import parameters");
        return EXIT_FAILURE;
    }

    std::atomic_store(&g_sem_waiting, true);
    hal->importKey(import_ec_params, KeyFormat::PKCS8, ec_pkcs8, import_key_cb);

    memset(&ts, 0, sizeof(struct timespec));
    if (clock_gettime(CLOCK_REALTIME, &ts))
        __android_log_print(ANDROID_LOG_FATAL, "test3",
                "Couldn't get the current time: %d (%s)", errno, strerror(errno));
    ts.tv_sec += 2;

    rc = 0;
    do {
        rc = sem_timedwait(&g_sem, &ts);
    } while (rc == -1 && errno == EINTR);
    if (rc == -1 && errno == ETIMEDOUT) {
        __android_log_print(ANDROID_LOG_ERROR, "test3",
                "Timed out waiting for signal from import key callback!\n");
        return EXIT_FAILURE;
    } else if (rc == -1) {
        __android_log_print(ANDROID_LOG_FATAL, "test3",
                "Unexpected error while waiting from signal from import key callback: %d (%s)\n",
                errno, strerror(errno));
    }
    std::atomic_store(&g_sem_waiting, false);

    if (g_import_key_error != ErrorCode::OK) {
        __android_log_print(ANDROID_LOG_ERROR, "test3", "Failed to import the EC key: %d",
                static_cast<int32_t>(g_import_key_error));
        return EXIT_FAILURE;
    }

    std::ofstream ec_blob_file("ec-wrapped-blob.bin", std::ios::binary | std::ios::ate);
    if (!ec_blob_file.is_open()) {
        __android_log_print(ANDROID_LOG_ERROR, "test3",
                "Failed to open the EC blob output file: %s", std::strerror(errno));
        return EXIT_FAILURE;
    }

    if (!ec_blob_file.write(reinterpret_cast<char *>(g_import_key_output.data()),
                g_import_key_output.size()))
    {
        __android_log_print(ANDROID_LOG_ERROR, "test3", "Failed to write the EC blob: %s",
                std::strerror(errno));
        return EXIT_FAILURE;
    }
    ec_blob_file.close();
    __android_log_print(ANDROID_LOG_INFO, "test3", "Wrote EC blob to ec-wrapped-blob.bin");

    /* Now do the RSA one */
    std::ifstream rsa_pkcs8_file("rsa-private-pkcs8.bin", std::ios::binary | std::ios::ate);
    if (!rsa_pkcs8_file.is_open()) {
        __android_log_print(ANDROID_LOG_ERROR, "test3", "Failed to open the RSA key file: %s",
                std::strerror(errno));
        return EXIT_FAILURE;
    }
    std::streamsize rsa_pkcs8_size = rsa_pkcs8_file.tellg();
    rsa_pkcs8_file.seekg(0, std::ios::beg);

    hidl_vec<uint8_t> rsa_pkcs8(rsa_pkcs8_size);

    __android_log_print(ANDROID_LOG_INFO, "test3", "rsa_pkcs8_size: %d",
            static_cast<int32_t>(rsa_pkcs8_size));

    if (!rsa_pkcs8_file.read(reinterpret_cast<char *>(rsa_pkcs8.data()), rsa_pkcs8_size)) {
        __android_log_print(ANDROID_LOG_ERROR, "test3", "Failed to read the RSA private key: %s",
                std::strerror(errno));
        return EXIT_FAILURE;
    }

    hidl_vec<KeyParameter> rsa_import_params;
    if (initialize_rsa_import_params(rsa_import_params)) {
        __android_log_print(ANDROID_LOG_ERROR, "test3",
                "Failed to initialize the RSA key import parameters");
        return EXIT_FAILURE;
    }

    std::atomic_store(&g_sem_waiting, true);
    hal->importKey(rsa_import_params, KeyFormat::PKCS8, rsa_pkcs8, import_key_cb);

    memset(&ts, 0, sizeof(struct timespec));
    if (clock_gettime(CLOCK_REALTIME, &ts))
        __android_log_print(ANDROID_LOG_FATAL, "test3",
                "Couldn't get the current time: %d (%s)", errno, strerror(errno));
    ts.tv_sec += 2;

    rc = 0;
    do {
        rc = sem_timedwait(&g_sem, &ts);
    } while (rc == -1 && errno == EINTR);
    if (rc == -1 && errno == ETIMEDOUT) {
        __android_log_print(ANDROID_LOG_ERROR, "test3",
                "Timed out waiting for signal from import key callback!\n");
        return EXIT_FAILURE;
    } else if (rc == -1) {
        __android_log_print(ANDROID_LOG_FATAL, "test3",
                "Unexpected error while waiting from signal from import key callback: %d (%s)\n",
                errno, strerror(errno));
    }
    std::atomic_store(&g_sem_waiting, false);

    if (g_import_key_error != ErrorCode::OK) {
        __android_log_print(ANDROID_LOG_ERROR, "test3", "Failed to import the RSA key: %d",
                static_cast<int32_t>(g_import_key_error));
        return EXIT_FAILURE;
    }

    std::ofstream rsa_blob_file("rsa-wrapped-blob.bin", std::ios::binary | std::ios::ate);
    if (!rsa_blob_file.is_open()) {
        __android_log_print(ANDROID_LOG_ERROR, "test3",
                "Failed to open the RSA blob output file: %s", std::strerror(errno));
        return EXIT_FAILURE;
    }

    if (!rsa_blob_file.write(reinterpret_cast<char *>(g_import_key_output.data()),
                g_import_key_output.size()))
    {
        __android_log_print(ANDROID_LOG_ERROR, "test3",
                "Failed to write the RSA blob: %s", std::strerror(errno));
        return EXIT_FAILURE;
    }
    rsa_blob_file.close();

    __android_log_print(ANDROID_LOG_INFO, "test3", "Wrote RSA blob to rsa-wrapped-blob.bin");
    return EXIT_SUCCESS;
}

static int test4_sign_binder(void)
{
    if (sem_init(&g_sem, false, 0)) {
        __android_log_print(ANDROID_LOG_ERROR, "test4", "Failed to init the semaphore!");
        return EXIT_FAILURE;
    }
    std::atomic_store(&g_sem_initialized, true);

    std::ifstream in("message.txt");
    if (!in.is_open()) {
        __android_log_print(ANDROID_LOG_ERROR, "test4", "Failed to open message.txt: %s",
                std::strerror(errno));
        return EXIT_FAILURE;
    }
    in.seekg(0, std::ios::beg);
    std::streamsize in_size = in.tellg();

    hidl_vec<uint8_t> message;
    message.resize(in_size);

    if (!in.read(reinterpret_cast<char *>(message.data()), in_size)) {
        __android_log_print(ANDROID_LOG_ERROR, "test4", "Failed to read the message: %s",
                std::strerror(errno));
        return EXIT_FAILURE;
    }
    in.close();

    std::ifstream wrapped_key("key.bin", std::ios::binary | std::ios::ate);
    if (!wrapped_key.is_open()) {
        __android_log_print(ANDROID_LOG_ERROR, "test4", "Failed to open key.bin: %s",
                std::strerror(errno));
        return EXIT_FAILURE;
    }
    std::streamsize key_file_size = wrapped_key.tellg();
    wrapped_key.seekg(0, std::ios::beg);

    hidl_vec<uint8_t> key_blob;
    key_blob.resize(key_file_size);

    if (!wrapped_key.read(reinterpret_cast<char *>(key_blob.data()), key_file_size)) {
        __android_log_print(ANDROID_LOG_ERROR, "test4", "Failed to read the wrapped key: %s",
                std::strerror(errno));
        return EXIT_FAILURE;
    }
    wrapped_key.close();

    ::android::sp<IKeymasterDevice> hal = IKeymasterDevice::getService();
    if (hal == nullptr || !hal->ping().isOk()) {
        __android_log_print(ANDROID_LOG_ERROR, "test4", "Keymaster HAL service not available!");
        return EXIT_FAILURE;
    }

    hidl_vec<KeyParameter> params;
    if (initialize_sign_params(params)) {
        __android_log_print(ANDROID_LOG_ERROR, "test4", "Failed to initialize the sign params!");
        return EXIT_FAILURE;
    }

    std::atomic_store(&g_sem_waiting, true);
    hal->begin(KeyPurpose::SIGN, key_blob, params, {}, begin_cb);

    struct timespec ts;
    memset(&ts, 0, sizeof(struct timespec));
    if (clock_gettime(CLOCK_REALTIME, &ts))
        __android_log_print(ANDROID_LOG_FATAL, "test4",
                "Couldn't get the current time: %d (%s)", errno, strerror(errno));
    ts.tv_sec += 2;

    int rc = 0;
    do {
        rc = sem_timedwait(&g_sem, &ts);
    } while (rc == -1 && errno == EINTR);
    if (rc == -1 && errno == ETIMEDOUT) {
        __android_log_print(ANDROID_LOG_ERROR, "test4",
                "Timed out waiting for signal from begin callback!\n");
        return EXIT_FAILURE;
    } else if (rc == -1) {
        __android_log_print(ANDROID_LOG_FATAL, "test4",
                "Unexpected error while waiting from signal from begin callback: %d (%s)\n",
                errno, strerror(errno));
    }
    std::atomic_store(&g_sem_waiting, false);

    if (g_begin_error != ErrorCode::OK) {
        __android_log_print(ANDROID_LOG_ERROR, "test4",
                "begin operation failed: %d\n", (int32_t)g_begin_error);
        return EXIT_FAILURE;
    }

    std::atomic_store(&g_sem_waiting, true);
    hal->finish(g_operation_handle, {}, message, {}, {}, {}, finish_cb);

    memset(&ts, 0, sizeof(struct timespec));
    if (clock_gettime(CLOCK_REALTIME, &ts))
        __android_log_print(ANDROID_LOG_FATAL, "test4",
                "Couldn't get the current time: %d (%s)", errno, strerror(errno));
    ts.tv_sec += 2;

    rc = 0;
    do {
        rc = sem_timedwait(&g_sem, &ts);
    } while (rc == -1 && errno == EINTR);
    if (rc == -1 && errno == ETIMEDOUT) {
        __android_log_print(ANDROID_LOG_ERROR, "test4",
                "Timed out waiting for signal from finish callback!\n");
        return EXIT_FAILURE;
    } else if (rc == -1) {
        __android_log_print(ANDROID_LOG_FATAL, "test4",
                "Unexpected error while waiting from signal from finish callback: %d (%s)\n",
                errno, strerror(errno));
    }
    std::atomic_store(&g_sem_waiting, false);

    if (g_finish_error != ErrorCode::OK) {
        __android_log_print(ANDROID_LOG_ERROR, "test4",
                "finish operation failed: %d\n", (int32_t)g_finish_error);
        return EXIT_FAILURE;
    }


    std::ofstream out("signature.bin", std::ios::binary | std::ios::ate);
    if (!out.is_open()) {
        __android_log_print(ANDROID_LOG_ERROR, "test4", "Failed to open signature.bin: %s",
                std::strerror(errno));
        return EXIT_FAILURE;
    }

    if (!out.write(reinterpret_cast<char *>(g_finish_output.data()), g_finish_output.size())) {
        __android_log_print(ANDROID_LOG_ERROR, "test4", "Failed to write the signature: %s",
                std::strerror(errno));
        return EXIT_FAILURE;
    }

    out.close();

    __android_log_print(ANDROID_LOG_INFO, "test4", "Wrote signature (%lu bytes) to signature.bin",
            g_finish_output.size());

    return EXIT_SUCCESS;
}

static int test5_export_binder(void)
{
    if (sem_init(&g_sem, false, 0)) {
        __android_log_print(ANDROID_LOG_ERROR, "test5", "Failed to init the semaphore!");
        return EXIT_FAILURE;
    }
    std::atomic_store(&g_sem_initialized, true);

    std::ifstream wrapped_key("key.bin", std::ios::binary | std::ios::ate);
    if (!wrapped_key.is_open()) {
        __android_log_print(ANDROID_LOG_ERROR, "test5", "Failed to open key.bin: %s",
                std::strerror(errno));
        return EXIT_FAILURE;
    }
    std::streamsize key_file_size = wrapped_key.tellg();
    wrapped_key.seekg(0, std::ios::beg);

    hidl_vec<uint8_t> key_blob;
    key_blob.resize(key_file_size);

    if (!wrapped_key.read(reinterpret_cast<char *>(key_blob.data()), key_file_size)) {
        __android_log_print(ANDROID_LOG_ERROR, "test4", "Failed to read the wrapped key: %s",
                std::strerror(errno));
        return EXIT_FAILURE;
    }
    wrapped_key.close();

    ::android::sp<IKeymasterDevice> hal = IKeymasterDevice::getService();
    if (hal == nullptr || !hal->ping().isOk()) {
        __android_log_print(ANDROID_LOG_ERROR, "test5", "Keymaster HAL service not available");
        return EXIT_FAILURE;
    }

    std::atomic_store(&g_sem_waiting, true);

    hidl_vec<uint8_t> application_id;
    application_id.resize(sizeof("suskeymaster") - 1);
    std::memcpy(application_id.data(), "suskeymaster", sizeof("suskeymaster") - 1);

    hal->exportKey(KeyFormat::X509, key_blob, application_id, {}, export_key_cb);

    struct timespec ts;
    memset(&ts, 0, sizeof(struct timespec));
    if (clock_gettime(CLOCK_REALTIME, &ts))
        __android_log_print(ANDROID_LOG_FATAL, "test5",
                "Couldn't get the current time: %d (%s)", errno, strerror(errno));
    ts.tv_sec += 2;

    int rc = 0;
    do {
        rc = sem_timedwait(&g_sem, &ts);
    } while (rc == -1 && errno == EINTR);
    if (rc == -1 && errno == ETIMEDOUT) {
        __android_log_print(ANDROID_LOG_ERROR, "test5",
                "Timed out waiting for signal from export key callback!\n");
        return EXIT_FAILURE;
    } else if (rc == -1) {
        __android_log_print(ANDROID_LOG_FATAL, "test5",
                "Unexpected error while waiting from signal from export key callback: %d (%s)\n",
                errno, strerror(errno));
    }
    std::atomic_store(&g_sem_waiting, false);

    if (g_export_key_error != ErrorCode::OK) {
        __android_log_print(ANDROID_LOG_ERROR, "test5",
                "Failed to export the public key: %d\n",
                static_cast<int32_t>(g_export_key_error)
        );
        return EXIT_FAILURE;
    }

    std::ofstream out("pubkey.x509", std::ios::binary | std::ios::ate);
    if (!out.is_open()) {
        __android_log_print(ANDROID_LOG_ERROR, "test5", "Failed to open pubkey.x509: %s",
                std::strerror(errno));
        return EXIT_FAILURE;
    }

    if (!out.write(reinterpret_cast<char *>(g_export_key_output.data()),
                g_export_key_output.size()))
    {
        __android_log_print(ANDROID_LOG_ERROR, "test5", "Failed to write the public key: %s",
                std::strerror(errno));
        return EXIT_FAILURE;
    }

    out.close();

    __android_log_print(ANDROID_LOG_INFO, "test5", "Wrote public key (%lu bytes) to pubkey.x509",
            g_export_key_output.size());
    return EXIT_SUCCESS;
}

static void dump_certs(const hidl_vec<hidl_vec<uint8_t>>& cert_chain,
        const char *file_prefix)
{
    char filename_buf[64] = { 0 };
    uint32_t i = 0;
    for (; i < cert_chain.size(); i++) {
        memset(filename_buf, 0, 64);
        int ret = std::snprintf(filename_buf, 64, "%s_cert_%d.der", file_prefix, i);
        if (ret < 0 || ret >= 64) {
            __android_log_print(ANDROID_LOG_ERROR, "test",
                    "snprintf failed for cert no %d, not dumping!", i);
            continue;
        }

        std::ofstream out(filename_buf, std::ios::binary);
        out.write(reinterpret_cast<const char *>(cert_chain[i].data()), cert_chain[i].size());
        if (!out) {
            __android_log_print(ANDROID_LOG_ERROR, "test",
                    "Failed to cert %d to file \"%s\"!", i, filename_buf);
            continue;
        }

        out.close();
        __android_log_print(ANDROID_LOG_INFO, "test", "Dumped cert to \"%s\"", filename_buf);
    }
}
