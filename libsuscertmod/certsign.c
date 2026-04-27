#include "certsign.h"
#include "keybox.h"
#include "certmod.h"
#include <libsuskmhal/hidl/hidl-hal-c.h>
#include <libsuskmhal/util/keymaster-types-c.h>
#include <core/int.h>
#include <core/log.h>
#include <core/util.h>
#include <core/vector.h>

#define MODULE_NAME "certsign"

static struct hidl_suskeymaster * get_hal(void);
static VECTOR(u8) get_keyblob_from_current_keybox(enum sus_key_variant variant);
static VECTOR(struct KM_KeyParameter) init_params(enum sus_key_variant variant);

i32 sus_cert_sign(VECTOR(u8 const) tbs_der, VECTOR(u8) *out_sig,
        enum sus_key_variant variant)
{
    if (tbs_der == NULL || out_sig == NULL ||
            variant <= SUS_KEY_INVALID_ || variant >= SUS_KEY_MAX_)
    {
        s_log_error("Invalid parameters!");
        return -1;
    }

    VECTOR(u8) keyblob = NULL;
    VECTOR(struct KM_KeyParameter) params = NULL;

    struct hidl_suskeymaster *hidl_km = NULL;
    uint64_t op_handle = 0;
    enum KM_ErrorCode e = KM_ERR_UNKNOWN_ERROR;

    /* Prepare what's needed */
    keyblob = get_keyblob_from_current_keybox(variant);
    if (keyblob == NULL)
        goto_error("Couldn't get keyblob from current keybox!");

    params = init_params(variant); /* Always succeeds */


    /* Do the HIDL transactions for a SIGN operation (begin + finish) */
    hidl_km = get_hal();
    if (hidl_km == NULL)
        goto_error("Couldn't obtain a handle to the keymaster HAL");

    e = hidl_suskeymaster_begin(hidl_km, KM_PURPOSE_SIGN,
            keyblob, params, NULL, NULL, &op_handle);
    if (e != KM_OK)
        goto_error("BEGIN operation failed: %d (%s)",
                e, KM_ErrorCode_toString(e));

    e = hidl_suskeymaster_finish(hidl_km, op_handle, NULL, tbs_der,
            NULL, NULL, NULL, NULL, out_sig);
    if (e != KM_OK)
        goto_error("FINISH operation failed: %d (%s)",
                e, KM_ErrorCode_toString(e));

    op_handle = 0;
    hidl_suskeymaster_destroy(&hidl_km);
    km_destroy_key_parameters(&params);
    vector_destroy(&keyblob);

    s_log_info("Successfully signed %s cert",
            variant == SUS_KEY_EC ? "ECDSA" : "RSA");
    return 0;

err:
    op_handle = 0;
    hidl_suskeymaster_destroy(&hidl_km);
    km_destroy_key_parameters(&params);
    vector_destroy(&keyblob);

    s_log_info("Failed to sign %s cert",
            variant == SUS_KEY_EC ? "ECDSA" : "RSA");
    return 1;
}

static struct hidl_suskeymaster * get_hal(void)
{
    struct hidl_suskeymaster *new_hal = NULL;

#if 0
    new_hal = hidl_suskeymaster4_1_new();
    if (new_hal != NULL)
        return new_hal;
#endif /* 0 */

    new_hal = hidl_suskeymaster4_0_new();
    if (new_hal != NULL)
        return new_hal;

#if 0
    new_hal = hidl_suskeymaster3_0_new();
    if (new_hal != NULL)
        return new_hal;
#endif /* 0 */

    return NULL;
}

static VECTOR(u8) get_keyblob_from_current_keybox(enum sus_key_variant variant)
{
    VECTOR(u8) ret = NULL;
    const struct keybox *keybox = NULL;

    if (keybox_read_lock_current(&keybox)) {
        s_log_error("Failed to retrieve the current keybox");
        return NULL;
    }
    {
        const VECTOR(u8) tmp = NULL;

        tmp = keybox_get_keyblob(keybox, variant);
        if (tmp == NULL) {
            keybox_unlock_current(&keybox);
            s_log_error("Failed to retrieve the key blob "
                    "from the current keybox");
            return NULL;
        }

        ret = (u8 *)vector_clone(tmp);
    }
    keybox_unlock_current(&keybox);

    return ret;
}

static VECTOR(struct KM_KeyParameter) init_params(enum sus_key_variant variant)
{
    VECTOR(struct KM_KeyParameter) params = vector_new(struct KM_KeyParameter);

    vector_push_back(&params, (struct KM_KeyParameter) {
            .tag = KM_TAG_DIGEST,
            .f.digest = KM_DIGEST_SHA_2_256
    });
    if (variant == SUS_KEY_RSA) {
        vector_push_back(&params, (struct KM_KeyParameter) {
                .tag = KM_TAG_PADDING,
                .f.paddingMode = KM_PADDING_RSA_PKCS1_1_5_SIGN,
        });
    }

    return params;
}
