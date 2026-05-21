#define HIDL_DISABLE_INSTRUMENTATION
#include "certsign.h"
#include "keybox.h"
#include "certmod.h"
#include <libsuskmhal/hidl/hidl-hal.hpp>
#include <libsuskmhal/util/keymaster-types-c.h>
#include <core/int.h>
#include <core/log.h>
#include <core/util.h>
#include <core/vector.h>
#include <string.h>
#include <hidl/HidlSupport.h>
#include <android/hardware/keymaster/generic/types.h>

#define MODULE_NAME "certsign"

using namespace ::android::hardware;
using namespace ::android::hardware::keymaster::generic;
using namespace ::suskeymaster::kmhal::hidl;

static std::unique_ptr<HidlSusKeymaster> get_hal(void);
static int get_keyblob_from_current_keybox(enum sus_key_variant variant,
        hidl_vec<uint8_t>& out);
static hidl_vec<KeyParameter> init_params(enum sus_key_variant variant);

extern "C" {

i32 sus_cert_sign(VECTOR(u8 const) tbs_der, VECTOR(u8) *out_sig,
        enum sus_key_variant variant)
{
    if (tbs_der == NULL || out_sig == NULL ||
            variant <= SUS_KEY_INVALID_ || variant >= SUS_KEY_MAX_)
    {
        s_log_error("Invalid parameters!");
        return -1;
    }

    ErrorCode e = ErrorCode::UNKNOWN_ERROR;
    hidl_vec<uint8_t> keyblob;
    hidl_vec<KeyParameter> params;
    std::unique_ptr<HidlSusKeymaster> hal = nullptr;

    /* Prepare what's needed */
    if (get_keyblob_from_current_keybox(variant, keyblob))
        goto_error("Couldn't get keyblob from current keybox!");

    params = init_params(variant);
    {
        hal = get_hal();
        if ((hal = get_hal()) == nullptr)
            goto_error("Couldn't obtain a handle to the Keymaster HAL service");

        uint64_t op_handle = 0;

        /* Do the HIDL transactions for a SIGN operation (begin + finish) */

        if (hal == NULL)
            goto_error("Couldn't obtain a handle to the keymaster HAL");

        hidl_vec<KeyParameter> dummy;
        e = hal->begin(KeyPurpose::SIGN, keyblob, params, {}, dummy, op_handle);
        if (e != ErrorCode::OK)
            goto_error("BEGIN operation failed: %u (%s)",
                    (uint32_t)e, KM_ErrorCode_toString((uint32_t)e));

        hidl_vec<uint8_t> tbs_der_vec(vector_size(tbs_der));
        memcpy(tbs_der_vec.data(), tbs_der, vector_size(tbs_der));

        hidl_vec<uint8_t> sig_vec;
        e = hal->finish(op_handle, {}, tbs_der_vec, {}, {}, {}, dummy, sig_vec);
        if (e != ErrorCode::OK)
            goto_error("FINISH operation failed: %u (%s)",
                    (uint32_t)e, KM_ErrorCode_toString((uint32_t)e));

        *out_sig = vector_new(u8);
        vector_resize(out_sig, sig_vec.size());
        memcpy(*out_sig, sig_vec.data(), sig_vec.size());
    }

    s_log_info("Successfully signed %s cert",
            variant == SUS_KEY_EC ? "ECDSA" : "RSA");
    return 0;

err:
    s_log_info("Failed to sign %s cert",
            variant == SUS_KEY_EC ? "ECDSA" : "RSA");
    return 1;
}

} /* extern "C" */

static std::unique_ptr<HidlSusKeymaster> get_hal(void)
{
    std::unique_ptr<HidlSusKeymaster> ret = nullptr;

#ifndef SUSKEYMASTER_HAL_DISABLE_4_1
    ret = std::make_unique<HidlSusKeymaster4_1>();
    if (ret && ret->isHALOk())
        return ret;
#endif /* SUSKEYMASTER_HAL_DISABLE_4_1 */

#ifndef SUSKEYMASTER_HAL_DISABLE_4_0
    ret = std::make_unique<HidlSusKeymaster4_0>();
    if (ret && ret->isHALOk())
        return ret;
#endif /* SUSKEYMASTER_HAL_DISABLE_4_0 */

#ifndef SUSKEYMASTER_HAL_DISABLE_3_0
    ret = std::make_unique<HidlSusKeymaster3_0>();
    if (ret && ret->isHALOk())
        return ret;
#endif /* SUSKEYMASTER_HAL_DISABLE_3_0 */

    return ret;
}

static int get_keyblob_from_current_keybox(enum sus_key_variant variant,
        hidl_vec<uint8_t>& out)
{
    const struct keybox *keybox = NULL;
    int ret = 0;

    if (keybox_read_lock_current(&keybox)) {
        s_log_error("Failed to retrieve the current keybox");
        return 1;
    }
    {
        const VECTOR(u8) tmp = NULL;

        tmp = keybox_get_keyblob(keybox, variant);
        if (tmp == NULL) {
            s_log_error("Failed to retrieve the key blob "
                    "from the current keybox");
            ret = 1;
            goto out;
        }

        out.resize(vector_size(tmp));
        memcpy(out.data(), tmp, vector_size(tmp));
        ret = 0;
    }
out:
    keybox_unlock_current(&keybox);
    return ret;
}

static hidl_vec<KeyParameter> init_params(enum sus_key_variant variant)
{
    hidl_vec<KeyParameter> ret(variant == SUS_KEY_RSA ? 2 : 1);
    ret[0].tag = Tag::DIGEST;
    ret[0].f.digest = Digest::SHA_2_256;

    if (variant == SUS_KEY_RSA) {
        ret[1].tag = Tag::PADDING;
        ret[1].f.paddingMode = PaddingMode::RSA_PKCS1_1_5_SIGN;
    }

    return ret;
}
