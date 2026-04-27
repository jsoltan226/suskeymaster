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
#include <libsuskmhal/util/keymaster-types-c.h>
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

static int mod_root_of_trust(KM_ROOT_OF_TRUST_V3 *rot);
static int mod_patch_levels(KM_PARAM_LIST *al,
        const char *al_name);

static int mod_key_desc(KM_KEY_DESC_V3 *desc);

static void key_desc_dump_log_proc(const char *fmt, ...)
{
    va_list vlist;
    va_start(vlist, fmt);
    s_logv(S_LOG_INFO, "key-desc", fmt, vlist);
    va_end(vlist);
}

i32 sus_cert_generate_leaf(const VECTOR(u8) old_leaf,
        bool *out_is_sus_send_indata,
        enum sus_key_variant *out_variant, VECTOR(u8) *out_new_leaf)
{
    if (old_leaf == NULL || out_new_leaf == NULL
        || out_is_sus_send_indata == NULL
    ) {
        s_log_error("Invalid parameters");
        return -1;
    }

    bool ok = false;

    if (out_variant != NULL)
        *out_variant = SUS_KEY_INVALID_;
    *out_new_leaf = NULL;
    *out_is_sus_send_indata = false;

    EVP_PKEY *attested_pubkey = NULL;
    KM_KEY_DESC_V3 *km_desc = NULL;
    enum sus_key_variant variant = SUS_KEY_INVALID_;
    unsigned char *tmp_out_buf = NULL;
    VECTOR(u8) out = NULL;

    int ch_len = 0;
    const unsigned char *ch_data = NULL;

    if (leaf_cert_parse(old_leaf, &variant, &attested_pubkey, &km_desc))
        goto_error("Failed to parse the provided leaf certificate!");
    s_log_info("Successfully parsed leaf cert");

    if (km_desc->attestationChallenge == NULL ||
        ((ch_len = ASN1_STRING_length(km_desc->attestationChallenge)) <= 0) ||
        ((ch_data = ASN1_STRING_get0_data(km_desc->attestationChallenge))
                == NULL)
    ) {
        goto_error("Missing or invalid attestationChallenge "
                "in key description!");
    }
#ifdef SUSKEYMASTER_ENABLE_SAMSUNG_SEND_INDATA
    if ((unsigned int)ch_len == g_send_indata_att_challenge_len &&
        !memcmp(ch_data, g_send_indata_att_challenge, ch_len))
    {
        *out_is_sus_send_indata = true;
        const ASN1_OCTET_STRING *att_app_id = NULL;

        int len = 0;
        const unsigned char *data = NULL;

        if (
            (km_desc->softwareEnforced == NULL) ||
            (att_app_id =
                km_desc->softwareEnforced->attestationApplicationId) == NULL ||

            (len = ASN1_STRING_length(att_app_id)) <= 0 ||
            (data = ASN1_STRING_get0_data(att_app_id)) == NULL)
        {
            goto_error("Missing `softwareEnforced.attestationApplicationId` "
                    "while is_sus_send_indata = true");
        }

        *out_new_leaf = vector_new(u8);
        vector_resize(out_new_leaf, len);
        memcpy(*out_new_leaf, data, len);
        ok = true;
        goto err;
    }
#endif /* SUSKEYMASTER_ENABLE_SAMSUNG_SEND_INDATA */

    key_desc_dump(key_desc_dump_log_proc, NULL, km_desc, 0, false);
    if (mod_key_desc(km_desc))
        goto_error("Failed to modify the key description");
    key_desc_dump(key_desc_dump_log_proc, NULL, km_desc, 0, false);

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

    if (km_desc != NULL) {
        KM_KEY_DESC_V3_free(km_desc);
        km_desc = NULL;
    }

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

static int mod_key_desc(KM_KEY_DESC_V3 *desc)
{
    /** Top-level Key Description modifications */
    int64_t e = 0LL;

    /* Set security levels */

    if (desc->attestationSecurityLevel == NULL) {
        s_log_error("attestationSecurityLevel is NULL!");
        return 1;
    }
    if (!ASN1_ENUMERATED_get_int64(&e, desc->attestationSecurityLevel)) {
        s_log_error("Failed to get the ASN.1 ENUMERATED value of "
                "desc->attestationSecurityLevel");
        return 1;
    }
    e &= 0x00000000FFFFFFFF;
#ifdef MOD_KEYDESC_ATTESTATION_SEC_LVL
    s_log_info("attestationSecurityLevel: %lld -> %lld",
        (long long int)e, (long long int)MOD_KEYDESC_ATTESTATION_SEC_LVL);
    if (e != MOD_KEYDESC_ATTESTATION_SEC_LVL) {
        e = (int64_t)MOD_KEYDESC_ATTESTATION_SEC_LVL;
        if (!ASN1_ENUMERATED_set_int64(desc->attestationSecurityLevel,
                    (int64_t)MOD_KEYDESC_ATTESTATION_SEC_LVL))
        {
            s_log_error("Failed to set the ASN.1 ENUMERATED value of "
                    "desc->attestationSecurityLevel");
            return 1;
        }
    }
#else
    s_log_info("attestationSecurityLevel: %lld (left unchanged)",
            (long long int)i);
#endif /* MOD_KEYDESC_ATTESTATION_SEC_LVL */

    if (desc->keymasterSecurityLevel == NULL) {
        s_log_error("keymasterSecurityLevel is NULL!");
        return 1;
    }
#ifdef MOD_KEYDESC_KEYMASTER_SEC_LVL
    if (!ASN1_ENUMERATED_get_int64(&e, desc->keymasterSecurityLevel)) {
        s_log_error("Failed to get the ASN.1 ENUMERATED value of "
                "desc->keymasterSecurityLevel");
        return 1;
    }
    e &= 0x00000000FFFFFFFF;
    s_log_info("keymasterSecurityLevel: %lld -> %lld",
        (long long int)e, (long long int)MOD_KEYDESC_KEYMASTER_SEC_LVL);
    if (e != MOD_KEYDESC_ATTESTATION_SEC_LVL) {
        e = (int64_t)MOD_KEYDESC_ATTESTATION_SEC_LVL;
        if (!ASN1_ENUMERATED_set_int64(desc->keymasterSecurityLevel, e)) {
            s_log_error("Failed to set the ASN.1 ENUMERATED value of "
                    "desc->keymasterSecurityLevel");
            return 1;
        }
    }
#endif /* MOD_KEYDESC_KEYMASTER_SEC_LVL */

    /** Authorization list modifications **/

    if (desc->softwareEnforced == NULL) {
        s_log_error("softwareEnforced auth list is NULL!");
        return 1;
    }
    if (desc->hardwareEnforced == NULL) {
        s_log_error("hardwareEnforced auth list is NULL!");
        return 1;
    }

    /* Set root of trust */
    if (desc->hardwareEnforced->rootOfTrust != NULL) {
        s_log_info("Mod hardwareEnforced root of trust");

        if (mod_root_of_trust(desc->hardwareEnforced->rootOfTrust)) {
            s_log_error("Failed to mod the hardwareEnforced root of trust");
            return 1;
        }
    }

    /* Set patch levels */
    if (mod_patch_levels(desc->softwareEnforced, "softwareEnforced")) {
        s_log_error("Failed to mod the softwareEnforced patch levels");
        return 1;
    }
    if (mod_patch_levels(desc->hardwareEnforced, "hardwareEnforced")) {
        s_log_error("Failed to mod the hardwareEnforced patch levels");
        return 1;
    }

    return 0;
}

static int mod_root_of_trust(KM_ROOT_OF_TRUST_V3 *rot)
{
    int64_t i = 0;

    /* Set the verified boot key */
    if (rot->verifiedBootKey == NULL) {
        s_log_error("verifiedBootKey is NULL!");
        return 1;
    }
#ifdef MOD_AUTHLIST_ROT_VERIFIED_BOOT_KEY
    s_log_info("%s: set verified boot key", __func__);
    if (!ASN1_OCTET_STRING_set(rot->verifiedBootKey,
                MOD_AUTHLIST_ROT_VERIFIED_BOOT_KEY,
                sizeof(MOD_AUTHLIST_ROT_VERIFIED_BOOT_KEY)))
    {
        s_log_error("Failed to set the OCTET_STRING value of "
                "verifiedBootKey");
        return 1;
    }
#else
    s_log_info("%s: verifiedBootKey: left unchanged", __func__);
#endif /* MOD_AUTHLIST_ROT_VERIFIED_BOOT_KEY */

    /* Set `deviceLocked` */
#ifdef MOD_AUTHLIST_ROT_DEVICE_LOCKED
    if (rot->deviceLocked != MOD_AUTHLIST_ROT_DEVICE_LOCKED) {
        s_log_info("%s: deviceLocked: %d -> %d", __func__,
                rot->deviceLocked, MOD_AUTHLIST_ROT_DEVICE_LOCKED);
        rot->deviceLocked = MOD_AUTHLIST_ROT_DEVICE_LOCKED;
    }
#else
    s_log_info("%s: deviceLocked: %d (left unchanged)",
            __func__, rot->deviceLocked);
#endif /* MOD_AUTHLIST_ROT_DEVICE_LOCKED */

    /* Set verified boot state */
    if (rot->verifiedBootState == NULL) {
        s_log_error("verifiedBootState is NULL!");
        return 1;
    }
    if (!ASN1_ENUMERATED_get_int64(&i, rot->verifiedBootState)) {
        s_log_error("Failed to get the ASN.1 ENUMERATED value of "
                "verifiedBootState");
        return 1;
    }
    i &= 0x00000000FFFFFFFF;
#ifdef MOD_AUTHLIST_ROT_VB_STATE
    s_log_info("%s: verifiedBootState: %lld -> %lld", __func__,
            (long long int)i, (long long int)MOD_AUTHLIST_ROT_VB_STATE);
    if (i != (int64_t)MOD_AUTHLIST_ROT_VB_STATE) {
        i = (int64_t)MOD_AUTHLIST_ROT_VB_STATE;
        if (!ASN1_ENUMERATED_set_int64(rot->verifiedBootState, i)) {
            s_log_error("Failed to set the ASN.1 ENUMERATED value of "
                    "verifiedBootState");
            return 1;
        }
    }
#else
    s_log_info("%s: verifiedBootState: %lld (left unchanged)", __func__,
            (long long int)i);
#endif /* MOD_AUTHLIST_ROT_VB_STATE */

    /* Set verified boot hash */
    if (rot->verifiedBootHash == NULL) {
        s_log_error("verifiedBootHash is NULL!");
        return 1;
    }
#ifdef MOD_AUTHLIST_ROT_VERIFIED_BOOT_HASH
    s_log_info("%s: set verified boot hash", __func__);
    if (!ASN1_OCTET_STRING_set(rot->verifiedBootHash,
                MOD_AUTHLIST_ROT_VERIFIED_BOOT_HASH,
                sizeof(MOD_AUTHLIST_ROT_VERIFIED_BOOT_HASH)))
    {
        s_log_error("Failed to set the OCTET_STRING value of "
                "verifiedBootHash");
        return 1;
    }
#else
    s_log_info("%s: verifiedBootHash: (left unchanged)", __func__);
#endif /* MOD_AUTHLIST_ROT_VERIFIED_BOOT_HASH */

    return 0;
}

static int mod_patch_levels(KM_PARAM_LIST *al, const char *al_name)
{
    uint64_t i = 0;

    if (al->osVersion != NULL) {
        if (!ASN1_INTEGER_get_uint64(&i, al->osVersion)) {
            s_log_error("Failed to get the ASN.1 INTEGER value of "
                    "%s.osVersion", al_name);
            return 1;
        }
        i &= 0x00000000FFFFFFFF;

#ifdef MOD_AUTHLIST_OS_VERSION
        s_log_info("%s.osVersion: %llu -> %llu", al_name,
                (long long unsigned)i,
                (long long unsigned)MOD_AUTHLIST_OS_VERSION
        );
        i = (uint64_t)MOD_AUTHLIST_OS_VERSION;
        if (!ASN1_INTEGER_set_uint64(al->osVersion, i)) {
            s_log_error("Failed to set the ASN.1 INTEGER value of "
                    "%s.osVersion", al_name);
            return 1;
        }
#else
        s_log_info("%s.osVersion: %llu (left unchanged)", al_name, i);
#endif /* MOD_AUTHLIST_OS_VERSION */
    }

    if (al->osPatchLevel != NULL) {
        if (!ASN1_INTEGER_get_uint64(&i, al->osPatchLevel)) {
            s_log_error("Failed to get the ASN.1 INTEGER value of "
                    "%s.osPatchLevel", al_name);
            return 1;
        }
        i &= 0x00000000FFFFFFFF;

#ifdef MOD_AUTHLIST_OS_PATCH_LEVEL
        s_log_info("%s.osPatchLevel: %llu -> %llu", al_name,
                (long long unsigned)i,
                (long long unsigned)MOD_AUTHLIST_OS_PATCH_LEVEL
        );
        i = (uint64_t)MOD_AUTHLIST_OS_PATCH_LEVEL;
        if (!ASN1_INTEGER_set_uint64(al->osPatchLevel, i)) {
            s_log_error("Failed to set the ASN.1 INTEGER value of "
                    "%s.osPatchLevel", al_name);
            return 1;
        }
#else
        s_log_info("%s.osPatchLevel: %llu (left unchanged)", al_name, i);
#endif /* MOD_AUTHLIST_OS_PATCH_LEVEL */
    }

    if (al->vendorPatchLevel != NULL) {
        if (!ASN1_INTEGER_get_uint64(&i, al->vendorPatchLevel)) {
            s_log_error("Failed to get the ASN.1 INTEGER value of "
                    "%s.vendorPatchLevel", al_name);
            return 1;
        }
        i &= 0x00000000FFFFFFFF;

#ifdef MOD_AUTHLIST_VENDOR_PATCH_LEVEL
        s_log_info("%s.vendorPatchLevel: %llu -> %llu", al_name,
                (long long unsigned)i,
                (long long unsigned)MOD_AUTHLIST_VENDOR_PATCH_LEVEL
        );
        i = (uint64_t)MOD_AUTHLIST_VENDOR_PATCH_LEVEL;
        if (!ASN1_INTEGER_set_uint64(al->vendorPatchLevel, i)) {
            s_log_error("Failed to set the ASN.1 INTEGER value of "
                    "%s.vendorPatchLevel", al_name);
            return 1;
        }
#else
        s_log_info("%s.vendorPatchLevel: %llu (left unchanged)", al_name, i);
#endif /* MOD_AUTHLIST_VENDOR_PATCH_LEVEL */
    }

    if (al->bootPatchLevel != NULL) {
        if (!ASN1_INTEGER_get_uint64(&i, al->bootPatchLevel)) {
            s_log_error("Failed to get the ASN.1 INTEGER value of "
                    "%s.bootPatchLevel", al_name);
            return 1;
        }
        i &= 0x00000000FFFFFFFF;

#ifdef MOD_AUTHLIST_BOOT_PATCH_LEVEL
        s_log_info("%s.bootPatchLevel: %llu -> %llu", al_name,
                (long long unsigned)i,
                (long long unsigned)MOD_AUTHLIST_BOOT_PATCH_LEVEL
        );
        i = (uint64_t)MOD_AUTHLIST_BOOT_PATCH_LEVEL;
        if (!ASN1_INTEGER_set_uint64(al->bootPatchLevel, i)) {
            s_log_error("Failed to set the ASN.1 INTEGER value of "
                    "%s.bootPatchLevel", al_name);
            return 1;
        }
#else
        s_log_info("%s.bootPatchLevel: %llu (left unchanged)", al_name, i);
#endif /* MOD_AUTHLIST_BOOT_PATCH_LEVEL */
    }

    return 0;
}
