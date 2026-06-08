#ifndef SUSKEYMASTER_BUILD_HOST

#include "aidl-util.h"
#include "binder.h"
#include "parcel.h"
#include "status.h"
#include "txn-util.h"
#include <core/int.h>
#include <core/log.h>
#include <core/util.h>
#include <uchar.h>
#include <stddef.h>
#include <inttypes.h>
#ifdef SUSKEYMASTER_BUILD_ANDROID
#include <sys/system_properties.h>
#endif /* SUSKEYMASTER_BUILD_ANDROID */

#define MODULE_NAME "aidl-util"

#define SERVICEMANAGER_HANDLE 0

/* From "frameworks/native/libs/binder/Parcel.cpp" */
#define STRICT_MODE_PENALTY_GATHER  (INT32_C(1) << 31)
#define UNSET_WORK_SOURCE           INT32_C(-1)

#ifdef SUSKEYMASTER_BUILD_ANDROID
static void prop_read_cb(void *, const char *, const char *, u32);
#endif /* SUSKEYMASTER_BUILD_ANDROID */

static int read_handle(const struct kmhal_parcel *parcel,
                       size_t *offset_p, u32 *out_handle);

enum kmhal_aidl_tx_header_type
kmhal_aidl_get_tx_header_type(struct kmhal_binder_ctx *binder)
{
    if (!kmhal_binder_ctx_ok(binder)) {
        s_log_error("%s: Invalid binder device context!", __func__);
        return AIDL_HEADER_UNKNOWN;
    }

#ifdef SUSKEYMASTER_BUILD_ANDROID
    const struct prop_info *pi = __system_property_find("ro.bootmode");
    if (pi == NULL)
        goto not_recovery;

    bool recovery = false;
    __system_property_read_callback(pi, prop_read_cb, &recovery);
    s_log_trace("%s: recovery: %d", __func__, recovery);
    if (recovery)
        return AIDL_HEADER_RECOVERY;

not_recovery:
#endif /* SUSKEYMASTER_BUILD_ANDROID */

    switch (kmhal_binder_get_domain(binder)) {
        case KMHAL_BINDER_DEV_BINDER: return AIDL_HEADER_SYSTEM;
        case KMHAL_BINDER_DEV_VNDBINDER: return AIDL_HEADER_VENDOR;
        case KMHAL_BINDER_DEV_HWBINDER:
            s_log_error("%s: Binder device domain is hwbinder, "
                    "which is for HIDL, not AIDL", __func__);
            return AIDL_HEADER_UNKNOWN;
        default:
            s_log_error("%s: Couldn't get binder device domain", __func__);
            return AIDL_HEADER_UNKNOWN;
    }
}

void kmhal_aidl_write_tx_header(struct kmhal_parcel *parcel,
                                enum kmhal_aidl_tx_header_type type,
                                const char16_t *iface_token)
{
    const u32 strict_mode_policy = (u32)STRICT_MODE_PENALTY_GATHER;
    const u32 work_source = (u32)UNSET_WORK_SOURCE;
    const u32 header_type = (u32)type;

    kmhal_parcel_write_u32(parcel, strict_mode_policy);
    kmhal_parcel_write_u32(parcel, work_source);
    kmhal_parcel_write_u32(parcel, header_type);
    kmhal_parcel_write_aidl_string16(parcel, iface_token);
}

int kmhal_aidl_parse_rx_parcelable_header(struct kmhal_parcel *p, size_t *off_p,
                                          size_t *out_start_off,
                                          i32 *out_parcelable_size)
{
    i32 stability = 0;
    i32 parcelable_size = 0;

    if (kmhal_parcel_read_u32(p, off_p, (u32 *)&stability)) {
        s_log_error("Failed to read the wire stability");
        return 1;
    }

    s_log_trace("Parcelable stability: %s", !!stability ? "VINTF" : "LOCAL");

    *out_start_off = *off_p;

    if (kmhal_parcel_read_u32(p, off_p, (u32 *)&parcelable_size)) {
        s_log_error("Failed to read the parcelable size");
        return 1;
    }
    s_log_trace("Parcelable payload size: %"PRIi32, (i32)parcelable_size);
    if (parcelable_size < 0) {
        s_log_error("Invalid parcelable size");
        return 1;
    }

    *out_parcelable_size = parcelable_size;
    return 0;
}

void kmhal_aidl_manager_write_acquire(struct kmhal_binder_txn *txn)
{
    kmhal_binder_write_increfs(txn, SERVICEMANAGER_HANDLE);
    kmhal_binder_write_acquire(txn, SERVICEMANAGER_HANDLE);
}

void kmhal_aidl_manager_write_release(struct kmhal_binder_txn *txn)
{
    kmhal_binder_write_release(txn, SERVICEMANAGER_HANDLE);
    kmhal_binder_write_decrefs(txn, SERVICEMANAGER_HANDLE);
}

enum kmhal_android_status
kmhal_aidl_manager_get(struct kmhal_binder_ctx *binder,
                       struct kmhal_binder_txn **txn_p,
                       enum kmhal_aidl_tx_header_type hdr_type,

                       const char *in_fqname,
                       const char *in_instname,

                       u32 *out_handle)
{
    u_check_params(kmhal_binder_ctx_ok(binder) && txn_p != NULL);
    u_check_params(in_fqname != NULL && in_instname != NULL);
    u_check_params(out_handle != NULL);

    enum kmhal_android_status ret = UNKNOWN_ERROR;
    struct kmhal_parcel *parcel = NULL;

    struct kmhal_binder_txn_args_out reply = { 0 };
    u32 handle = (u32)-1;

    const int fqinstname_len =
        strlen(in_fqname) + 1 /* '/' */ + strlen(in_instname);
    char *fqinstname_str = NULL;

    fqinstname_str = malloc(fqinstname_len + 1 /* '\0' */);
    if (fqinstname_str == NULL) {
        ret = NO_MEMORY;
        goto_error("Failed to allocate the fqname string");
    }
    {
        int r;
        if ((r = snprintf(fqinstname_str, fqinstname_len + 1,
                    "%s/%s", in_fqname, in_instname))
                != fqinstname_len)
        {
            s_log_fatal("Invalid return value of snprintf: %d (expected %d)",
                    r, fqinstname_len);
        }
    }

    if ((ret = kmhal_util_check_allocate_txn_tmps(txn_p, &parcel)) != OK)
        goto err;

    kmhal_aidl_write_tx_header(parcel, hdr_type, u"android.os.IServiceManager");
    /* args */
    {
        kmhal_parcel_write_convert_aidl_string16(parcel, fqinstname_str);
    }

    /* We have to call `INCREFS` and `ACQUIRE` on the returned handle
     * before writing the FREE_BUFFER command */
    kmhal_parcel_pack(*txn_p, parcel, 0, 1, 0);
    ret = kmhal_util_transact_and_unpack(binder, txn_p,
            &parcel, &reply, false, true);
    if (ret != OK)
        goto err;

    /* Read the returned handle... */
    size_t off = KMHAL_PARCEL_DATA_START_OFFSET;
    if (read_handle(parcel, &off, &handle)) {
        ret = BAD_VALUE;
        goto err;
    }

    /* ...and immediately acquire it
     * (queue the commands in the next transaction) */
    kmhal_binder_write_increfs(*txn_p, handle);
    kmhal_binder_write_acquire(*txn_p, handle);

    /* only now can we queue the FREE_BUFFER command for the current reply */
    kmhal_binder_write_free_reply(*txn_p, reply.data_buf);

    *out_handle = handle;
    kmhal_parcel_destroy(&parcel);
    ret = OK;

err:
    if (ret != OK) {
        s_log_error(
                "android.os.IServiceManager.getService(\"%s\"): ret: %d (%s)",
                fqinstname_str != NULL ? fqinstname_str : "<N/A>",
                ret, kmhal_android_status_toString(ret)
        );
        kmhal_util_destroy_txn_tmps(txn_p, &parcel);
    }

    if (fqinstname_str != NULL) {
        free(fqinstname_str);
        fqinstname_str = NULL;
    }

    return ret;
}

enum kmhal_android_status
kmhal_aidl_ping(struct kmhal_binder_ctx *binder,
                struct kmhal_binder_txn **txn_p,
                u32 handle)
{
    u_check_params(kmhal_binder_ctx_ok(binder) && txn_p != NULL);
    enum kmhal_android_status ret = UNKNOWN_ERROR;
    struct kmhal_parcel *parcel = NULL;

    if ((ret = kmhal_util_check_allocate_txn_tmps(txn_p, &parcel)) != OK)
        goto err;

    kmhal_parcel_pack(*txn_p, parcel, handle, AIDL_PING_TRANSACTION, 0);

    ret = kmhal_util_transact_and_unpack(binder, txn_p, &parcel, NULL, 1, 1);

err:
    if (ret != OK)
        kmhal_util_destroy_txn_tmps(txn_p, &parcel);
    else
        kmhal_parcel_destroy(&parcel);

    return ret;
}

enum kmhal_android_status
kmhal_aidl_get_interface_version(struct kmhal_binder_ctx *binder,
                                 struct kmhal_binder_txn **txn_p,
                                 enum kmhal_aidl_tx_header_type hdr_type,
                                 const char16_t *interface_token,

                                 u32 in_handle,

                                 i32 *out_interface_version)
{
    u_check_params(kmhal_binder_ctx_ok(binder) && txn_p != NULL);
    u_check_params(out_interface_version != NULL);

    enum kmhal_android_status ret = UNKNOWN_ERROR;
    struct kmhal_parcel *parcel = NULL;

    if ((ret = kmhal_util_check_allocate_txn_tmps(txn_p, &parcel)) != OK)
        goto err;

    kmhal_aidl_write_tx_header(parcel, hdr_type, interface_token);

    kmhal_parcel_pack(*txn_p, parcel, in_handle,
            AIDL_META_CMD_GET_INTERFACE_VERSION, 0);

    if ((ret = kmhal_util_transact_and_unpack(binder, txn_p,
                    &parcel, NULL, 1, 1)) != OK)
        goto err;

    size_t off = KMHAL_PARCEL_DATA_START_OFFSET;
    if (kmhal_parcel_read_u32(parcel, &off, (u32 *)out_interface_version)) {
        ret = BAD_VALUE;
        goto_error("Failed to read the returned interface version");
    }

err:
    if (ret != OK)
        kmhal_util_destroy_txn_tmps(txn_p, &parcel);
    else
        kmhal_parcel_destroy(&parcel);

    return ret;
}

#ifdef SUSKEYMASTER_BUILD_ANDROID
static void prop_read_cb(void *cookie, const char *name,
                         const char *value, u32 serial)
{
    (void) name;
    (void) serial;

    if (!strncmp(value, "recovery", sizeof("recovery") - 1)) {
        *(bool *)cookie = true;
    }
}
#endif /* SUSKEYMASTER_BUILD_ANDROID */

static int read_handle(const struct kmhal_parcel *parcel,
                       size_t *offset_p, u32 *out_handle)
{
    struct flat_binder_object flat_binder_obj;

    if (kmhal_parcel_read_handle(parcel, offset_p, &flat_binder_obj)) {
        s_log_error("Failed to read the flat_binder_object (handle) "
                "from the reply");
        return 1;
    }

    if (out_handle != NULL)
        *out_handle = flat_binder_obj.handle;
    return 0;
}

#endif /* SUSKEYMASTER_BUILD_HOST */
