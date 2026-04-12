#define _GNU_SOURCE
#define OPENSSL_API_COMPAT 0x10002000L
#include "certmod.h"
#include "key-desc.h"
#include "leaf-cert.h"
#include "mod-params.h"
#include "samsung-sus-indata.h"
#include <core/int.h>
#include <core/log.h>
#include <core/util.h>
#include <core/math.h>
#include <core/vector.h>
#include <libsuskmhal/keymaster-types-c.h>
#include <time.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <pthread.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>
#include <openssl/core_names.h>

#define MODULE_NAME "certmod"

static void print_openssl_errors(void);

static void mod_root_of_trust(struct KM_RootOfTrust_v3 *rot);
static void mod_patch_levels(struct KM_AuthorizationList_v3 *al,
        const char *al_name);

static void mod_key_desc(struct KM_KeyDescription_v3 *desc);

static void key_desc_dump_log_proc(const char *fmt, ...)
{
    va_list vlist;
    va_start(vlist, fmt);
    s_logv(S_LOG_INFO, "key-desc", fmt, vlist);
    va_end(vlist);
}

#ifdef SUSKEYMASTER_ENABLE_SAMSUNG_SEND_INDATA
i32 sus_cert_generate_leaf(const VECTOR(u8) old_leaf,
        bool *out_is_sus_send_indata,
        enum sus_key_variant *out_variant, VECTOR(u8) *out_new_leaf)
#else
i32 sus_cert_generate_leaf(const VECTOR(u8) old_leaf,
        enum sus_key_variant *out_variant, VECTOR(u8) *out_new_leaf)
#endif /* SUSKEYMASTER_ENABLE_SAMSUNG_SEND_INDATA */
{
    if (old_leaf == NULL || out_new_leaf == NULL
#ifdef SUSKEYMASTER_ENABLE_SAMSUNG_SEND_INDATA
        || out_is_sus_send_indata == NULL
#endif /* SUSKEYMASTER_ENABLE_SAMSUNG_SEND_INDATA */
    ) {
        s_log_error("Invalid parameters");
        return -1;
    }

    bool ok = false;

    if (out_variant != NULL)
        *out_variant = SUS_KEY_INVALID_;
    *out_new_leaf = NULL;
#ifdef SUSKEYMASTER_ENABLE_SAMSUNG_SEND_INDATA
    *out_is_sus_send_indata = false;
#endif /* SUSKEYMASTER_ENABLE_SAMSUNG_SEND_INDATA */

    EVP_PKEY *attested_pubkey = NULL;
    struct KM_KeyDescription_v3 *km_desc = NULL;
    enum sus_key_variant variant = SUS_KEY_INVALID_;
    unsigned char *tmp_out_buf = NULL;
    VECTOR(u8) out = NULL;

    if (leaf_cert_parse(old_leaf, &variant, &attested_pubkey, &km_desc))
        goto_error("Failed to parse the provided leaf certificate!");
    s_log_info("Successfully parsed leaf cert");

#ifdef SUSKEYMASTER_ENABLE_SAMSUNG_SEND_INDATA
    if ((vector_size(km_desc->attestationChallenge)
            == g_send_indata_att_challenge_len) &&
        !memcmp(km_desc->attestationChallenge, g_send_indata_att_challenge,
                g_send_indata_att_challenge_len))
    {
        *out_is_sus_send_indata = true;
        if (vector_size(km_desc->softwareEnforced.attestationApplicationId)
                == 0)
            goto_error("Missing `softwareEnforced.attestationApplicationId` "
                    "while is_sus_send_indata = true");

        *out_new_leaf =
            vector_clone(km_desc->softwareEnforced.attestationApplicationId);
        ok = true;
        goto err;
    }
#endif /* SUSKEYMASTER_ENABLE_SAMSUNG_SEND_INDATA */

    key_desc_dump(km_desc, key_desc_dump_log_proc);
    mod_key_desc(km_desc);
    key_desc_dump(km_desc, key_desc_dump_log_proc);

    if (leaf_cert_gen(&out, variant, attested_pubkey, km_desc))
        goto_error("Failed to generate a new leaf certificate!");

    *out_new_leaf = out;
    *out_variant = variant;
    s_log_info("Successfully generated a new leaf certificate :)");

    ok = true;

err:
    if (tmp_out_buf != NULL) {
        OPENSSL_free(tmp_out_buf);
        tmp_out_buf = NULL;
    }

    if (km_desc != NULL)
        key_desc_destroy(&km_desc);

    if (attested_pubkey != NULL) {
        EVP_PKEY_free(attested_pubkey);
        attested_pubkey = NULL;
    }

    if (!ok) {
        print_openssl_errors();
        return 1;
    } else {
        s_log_info("Successfully generated new leaf certificate");
        return 0;
    }
}

static int openssl_err_print_cb(const char *msg, size_t size, void *userdata)
{
    (void) size;
    (void) userdata;
    s_log_error("%s", msg);
    return 1;
}
static void print_openssl_errors(void)
{
    s_log_error("BEGIN OPENSSL ERRORS");
    ERR_print_errors_cb(openssl_err_print_cb, NULL);
    s_log_error("END OPENSSL ERRORS");
}

static void mod_key_desc(struct KM_KeyDescription_v3 *desc)
{
    /** Top-level Key Description modifications */

    /* Set security levels */
#ifdef MOD_KEYDESC_ATTESTATION_SEC_LVL
    if (desc->attestationSecurityLevel != MOD_KEYDESC_ATTESTATION_SEC_LVL) {
        s_log_info("attestationSecurityLevel: %d -> %d",
            desc->attestationSecurityLevel, MOD_KEYDESC_ATTESTATION_SEC_LVL);
        desc->attestationSecurityLevel = MOD_KEYDESC_ATTESTATION_SEC_LVL;
    }
#endif /* MOD_KEYDESC_ATTESTATION_SEC_LVL */
#ifdef MOD_KEYDESC_KEYMASTER_SEC_LVL
    if (desc->keymasterSecurityLevel != MOD_KEYDESC_KEYMASTER_SEC_LVL) {
        s_log_info("keymasterSecurityLevel: %d -> %d",
                desc->keymasterSecurityLevel, MOD_KEYDESC_KEYMASTER_SEC_LVL);
        desc->keymasterSecurityLevel = MOD_KEYDESC_KEYMASTER_SEC_LVL;
    }
#endif /* MOD_KEYDESC_KEYMASTER_SEC_LVL */

    /** Authorization list modifications **/

    /* Set root of trust */
    if (desc->softwareEnforced.__rootOfTrust_present) {
        s_log_info("Mod softwareEnforced root of trust");
        mod_root_of_trust(&desc->softwareEnforced.rootOfTrust);
    }
    if (desc->hardwareEnforced.__rootOfTrust_present) {
        s_log_info("Mod hardwareEnforced root of trust");
        mod_root_of_trust(&desc->hardwareEnforced.rootOfTrust);
    }

    /* Set patch levels */
    mod_patch_levels(&desc->softwareEnforced, "softwareEnforced");
    mod_patch_levels(&desc->hardwareEnforced, "hardwareEnforced");
}

static void mod_root_of_trust(struct KM_RootOfTrust_v3 *rot)
{
    /* Set the verified boot key */
#ifdef MOD_AUTHLIST_ROT_VERIFIED_BOOT_KEY
    s_log_info("%s: set verified boot key", __func__);
    vector_resize(&rot->verifiedBootKey,
            sizeof(MOD_AUTHLIST_ROT_VERIFIED_BOOT_KEY));
    memcpy(rot->verifiedBootKey, &MOD_AUTHLIST_ROT_VERIFIED_BOOT_KEY,
            sizeof(MOD_AUTHLIST_ROT_VERIFIED_BOOT_KEY));
#endif /* MOD_AUTHLIST_ROT_VERIFIED_BOOT_KEY */

    /* Set `deviceLocked` */
#ifdef MOD_AUTHLIST_ROT_DEVICE_LOCKED
    if (rot->deviceLocked != MOD_AUTHLIST_ROT_DEVICE_LOCKED) {
        s_log_info("%s: deviceLocked: %d -> %d", __func__,
                rot->deviceLocked, MOD_AUTHLIST_ROT_DEVICE_LOCKED);
        rot->deviceLocked = MOD_AUTHLIST_ROT_DEVICE_LOCKED;
    }
#endif /* MOD_AUTHLIST_ROT_VB_STATE */

    /* Set verified boot state */
#ifdef MOD_AUTHLIST_ROT_VB_STATE
    if (rot->verifiedBootState != MOD_AUTHLIST_ROT_VB_STATE) {
        s_log_info("%s: verifiedBootState: %d -> %d", __func__,
                rot->verifiedBootState, MOD_AUTHLIST_ROT_VB_STATE);
        rot->verifiedBootState = MOD_AUTHLIST_ROT_VB_STATE;
    }
#endif /* MOD_AUTHLIST_ROT_VB_STATE */

#ifdef MOD_AUTHLIST_ROT_VERIFIED_BOOT_HASH
    s_log_info("%s: set verified boot hash", __func__);
    vector_resize(&rot->verifiedBootHash,
            sizeof(MOD_AUTHLIST_ROT_VERIFIED_BOOT_HASH));
    memcpy(rot->verifiedBootHash, &MOD_AUTHLIST_ROT_VERIFIED_BOOT_HASH,
            sizeof(MOD_AUTHLIST_ROT_VERIFIED_BOOT_HASH));
#endif /* MOD_AUTHLIST_ROT_VERIFIED_BOOT_HASH */
}

static void mod_patch_levels(struct KM_AuthorizationList_v3 *al,
        const char *al_name)
{
#ifdef MOD_AUTHLIST_OS_VERSION
    if (al->__osVersion_present && al->osVersion != MOD_AUTHLIST_OS_VERSION) {
        s_log_info("%s.osVersion: %llu -> %llu", al_name,
                (unsigned long long)al->osVersion,
                (unsigned long long)MOD_AUTHLIST_OS_VERSION
        );
        al->osVersion = MOD_AUTHLIST_OS_VERSION;
    }
#endif /* MOD_AUTHLIST_OS_VERSION */

#ifdef MOD_AUTHLIST_OS_PATCH_LEVEL
    if (al->__osPatchLevel_present &&
                al->osPatchLevel != MOD_AUTHLIST_OS_PATCH_LEVEL)
    {
        s_log_info("%s.osPatchLevel: %llu -> %llu", al_name,
                (unsigned long long)al->osPatchLevel,
                (unsigned long long)MOD_AUTHLIST_OS_PATCH_LEVEL
        );
        al->osPatchLevel = MOD_AUTHLIST_OS_PATCH_LEVEL;
    }
#endif /* MOD_AUTHLIST_OS_PATCH_LEVEL */

#ifdef MOD_AUTHLIST_VENDOR_PATCH_LEVEL
    if (al->__vendorPatchLevel_present &&
            al->vendorPatchLevel != MOD_AUTHLIST_VENDOR_PATCH_LEVEL)
    {
        s_log_info("%s.vendorPatchLevel: %llu -> %llu", al_name,
                (unsigned long long)al->vendorPatchLevel,
                (unsigned long long)MOD_AUTHLIST_VENDOR_PATCH_LEVEL
        );
        al->vendorPatchLevel = MOD_AUTHLIST_VENDOR_PATCH_LEVEL;
    }
#endif /* MOD_AUTHLIST_VENDOR_PATCH_LEVEL */

#ifdef MOD_AUTHLIST_BOOT_PATCH_LEVEL
    if (al->__bootPatchLevel_present &&
            al->bootPatchLevel != MOD_AUTHLIST_BOOT_PATCH_LEVEL)
    {
        s_log_info("%s.bootPatchLevel: %llu -> %llu", al_name,
                (unsigned long long)al->bootPatchLevel,
                (unsigned long long)MOD_AUTHLIST_BOOT_PATCH_LEVEL
        );
        al->bootPatchLevel = MOD_AUTHLIST_BOOT_PATCH_LEVEL;
    }
#endif /* MOD_AUTHLIST_BOOT_PATCH_LEVEL */
}
