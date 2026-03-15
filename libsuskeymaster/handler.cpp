#define HIDL_DISABLE_INSTRUMENTATION
#include "handler.hpp"
#include <core/int.h>
#include <core/vector.h>
#include <libgenericutil/cert-types.h>
#include <libsuscertmod/certmod.h>
#include <libsuscertsign/keybox.h>
#include <libsuscertsign/suscertsign.h>
#include <android/log.h>
#include <android/hardware/keymaster/4.0/types.h>
#include <android/hardware/keymaster/4.0/IKeymasterDevice.h>
#include <cstdint>
#include <cstring>

using namespace ::android::hardware;
using namespace ::android::hardware::keymaster::V4_0;

namespace suskeymaster {

extern "C" void call_attest_cb(void *_this, void *err, void *certChain) {
    void *callable;
    void **vtable;
    void (*operator_fn)(void *, void *, void *);

    __asm__ __volatile__(
        "ldr %[callable], [%[_this], #0x20] \n"
        : [callable] "=r"(callable)
        : [_this] "r"(_this)
        : "memory"
    );

    if (!callable)
        return;

    __asm__ __volatile__(
        "ldr %[vtable], [%[callable]] \n"
        : [vtable] "=r"(vtable)
        : [callable] "r"(callable)
        : "memory"
    );

    __asm__ __volatile__(
        "ldr %[operator_fn], [%[vtable], #0x30] \n"
        : [operator_fn] "=r"(operator_fn)
        : [vtable] "r"(vtable)
        : "memory"
    );

    operator_fn(callable, err, certChain);
}

extern "C" void sus_attest_cb(
        void * _this,
        void * _err,
        void * _certChain
)
{
    hidl_vec<hidl_vec<uint8_t>> tmp_cert_chain = { };

    const ErrorCode err = *(reinterpret_cast<ErrorCode *>(_err));
    const hidl_vec<hidl_vec<uint8_t>>& certChain =
        *reinterpret_cast<const hidl_vec<hidl_vec<uint8_t>> *>(_certChain);

    __android_log_print(ANDROID_LOG_INFO, "SUS", "Hello from %s!\n", __func__);
    __android_log_print(ANDROID_LOG_INFO, "SUS", "err = 0x%.8x (%s), certChain = 0x%.8lx\n",
            static_cast<int32_t>(err), toString(err).c_str(),
            reinterpret_cast<unsigned long>(_certChain)
    );

    if (err != ErrorCode::OK)
        goto failure;

    tmp_cert_chain = certChain;
    if (sus_keymaster_hack_cert_chain(tmp_cert_chain)) {
        __android_log_print(ANDROID_LOG_ERROR, "SUS", "Failed to hack the cert chain!");
        goto failure;
    }
    call_attest_cb(_this, _err, &tmp_cert_chain);
    return;

failure:
    /* In case of failure, just send back the original cert chain */
    __android_log_print(ANDROID_LOG_WARN, "SUS", "Returning original cert chain");
    call_attest_cb(_this, _err, _certChain);
}

int sus_keymaster_hack_cert_chain(hidl_vec<hidl_vec<uint8_t>>& cert_chain)
{
    __android_log_print(ANDROID_LOG_INFO, "SUS", "Hello from %s!", __func__);

    if (cert_chain.size() == 0) {
        __android_log_print(ANDROID_LOG_ERROR, "SUS", "Cert chain size is 0!");
        return -1;
    }

    __android_log_print(ANDROID_LOG_INFO, "SUS", "cert0: size: 0x%lx, first 8 bytes: 0x%.8llx",
            cert_chain[0].size(), *(unsigned long long *)(cert_chain[0].data()));

    VECTOR(u8) old_leaf = vector_new(u8);
    vector_resize(&old_leaf, cert_chain[0].size());
    std::memcpy(old_leaf, cert_chain[0].data(), cert_chain[0].size());

    /* Get the new leaf & chain */

    enum util::sus_key_variant variant = util::SUS_KEY_INVALID_;
    VECTOR(u8) new_leaf = NULL;
    if (certmod::sus_cert_generate_leaf(old_leaf, &variant, &new_leaf)) {
        __android_log_print(ANDROID_LOG_ERROR, "SUS", "Failed to hack the leaf cert!");
        vector_destroy(&old_leaf);
        return 1;
    }

    vector_destroy(&old_leaf);

    const struct certsign::keybox *kb = NULL;
    if (certsign::keybox_read_lock_current(&kb)) {
        __android_log_print(ANDROID_LOG_ERROR, "SUS", "Failed to get the current keybox!");
        vector_destroy(&new_leaf);
        return 1;
    }
    {

        VECTOR(VECTOR(u8 const) const) new_chain =
            certsign::keybox_get_cert_chain(kb, variant);
        if (vector_size(new_chain) == 0) {
            __android_log_print(ANDROID_LOG_ERROR, "SUS", "Failed to get the new chain!");
            goto kb_out_err;
        }

        /* Resize the output vector */

        /* Number of certificates in chain + leaf */
        const u32 new_chain_len = vector_size(new_chain) + 1;
        cert_chain.resize(new_chain_len);
        if (cert_chain.size() != new_chain_len) {
            __android_log_print(ANDROID_LOG_ERROR, "SUS",
                    "Failed to resize the new cert chain vector!\n");
            goto kb_out_err;
        }

        /* Copy the leaf */

        const u32 new_leaf_size = vector_size(new_leaf);
        cert_chain[0].resize(new_leaf_size);
        if (cert_chain[0].size() != new_leaf_size) {
            __android_log_print(ANDROID_LOG_ERROR, "SUS", "Failed to resize the new leaf cert!\n");
            goto kb_out_err;
        }

        std::memcpy(cert_chain[0].data(), new_leaf, new_leaf_size);
        vector_destroy(&new_leaf);

        /* Copy the rest of the chain */

        for (u32 i = 0; i < new_chain_len - 1; i++) {
            const u32 new_sz = vector_size(new_chain[i]);

            cert_chain[i + 1].resize(new_sz);
            if (cert_chain[i + 1].size() != new_sz) {
                __android_log_print(ANDROID_LOG_ERROR, "SUS",
                        "Failed to resize cert no %d!\n", i + 1);
                goto kb_out_err;
            }

            std::memcpy(cert_chain[i + 1].data(), new_chain[i], new_sz);
        }

    }
    certsign::keybox_unlock_current(&kb);

    __android_log_print(ANDROID_LOG_INFO, "SUS", "Successfully hacked the cert chain!");
    return 0;

kb_out_err:
    certsign::keybox_unlock_current(&kb);
    vector_destroy(&new_leaf);
    return 1;
}

} /* namespace suskeymaster */
