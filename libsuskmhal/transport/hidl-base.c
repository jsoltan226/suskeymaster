#include "hidl-base.h"
#include "binder.h"
#include "status.h"
#include "parcel.h"
#include "txn-util.h"
#include "hidl-types.h"
#include <core/log.h>
#include <core/util.h>
#include <string.h>
#include <linux/android/binder.h>

#define MODULE_NAME "hidl-base"

enum kmhal_android_status
kmhal_hidl_base_ping(struct kmhal_binder_ctx *binder,
                     struct kmhal_binder_txn **txn_p,
                     u32 handle)
{
    u_check_params(kmhal_binder_ctx_ok(binder) && txn_p != NULL);

    enum kmhal_android_status ret = UNKNOWN_ERROR;
    struct kmhal_parcel *parcel = NULL;
    struct kmhal_binder_txn_args_out reply = { 0 };

    if ((ret = kmhal_util_check_allocate_txn_tmps(txn_p, &parcel)) != OK)
        goto err;

    kmhal_parcel_write_cstring(parcel, KMHAL_HIDL_BASE_FQNAME);

    kmhal_parcel_pack(*txn_p, parcel, handle, HIDL_PING_TRANSACTION, true);

    if (kmhal_binder_do_write_read_ioctl(binder, txn_p)) {
        (void) kmhal_parcel_unpack(&parcel, NULL);
        ret = FAILED_TRANSACTION;
        goto_error("The binder WRITE_READ ioctl failed");
    }

    if (kmhal_parcel_unpack(&parcel, &reply) ||
            reply.status != KMHAL_BINDER_TXN_OK)
    {
        ret = FAILED_TRANSACTION;
        goto_error("Failed to unpack the transaction result");
    }

    if (reply.data_size < sizeof(i32) || reply.data_buf == NULL) {
        ret = BAD_VALUE;
        goto_error("Received data buffer too small or invalid");
    }

    {
        i32 status = 0;
        memcpy(&status, reply.data_buf, sizeof(i32));

        if (status != 0 && !(reply.flags & TF_STATUS_CODE))
            s_log_warn("Received non-zero status code (%d - %s) "
                    "without TF_STATUS_CODE flag set",
                    status, kmhal_android_status_toString(status));

        ret = status;
    }

err:
    kmhal_util_destroy_txn_tmps(txn_p, &parcel);
    return ret;
}

enum kmhal_android_status
kmhal_hidl_base_get_descriptor(struct kmhal_binder_ctx *binder,
                               struct kmhal_binder_txn **txn_p,
                               u32 handle,
                               const struct kmhal_hidl_string **out_p)
{
    u_check_params(kmhal_binder_ctx_ok(binder) && txn_p != NULL);

    enum kmhal_android_status ret = UNKNOWN_ERROR;
    struct kmhal_parcel *parcel = NULL;

    if ((ret = kmhal_util_check_allocate_txn_tmps(txn_p, &parcel)) != OK)
        goto err;

    kmhal_parcel_write_cstring(parcel, KMHAL_HIDL_BASE_FQNAME);

    kmhal_parcel_pack(*txn_p, parcel, handle,
            HIDL_GET_DESCRIPTOR_TRANSACTION, true);

    if ((ret = kmhal_util_transact_and_unpack(binder, txn_p,
                &parcel, NULL, true, false)) != OK)
    {
        ret = FAILED_TRANSACTION;
        goto_error("The binder trasaction failed");
    }

    {
        size_t off = KMHAL_PARCEL_DATA_START_OFFSET;

        if (kmhal_hidl_string_read(out_p, parcel, &off, NULL)) {
            ret = BAD_VALUE;
            goto_error("Failed to read the returned HIDL string");
        }
    }
    ret = OK;

err:
    if (ret != OK)
        kmhal_util_destroy_txn_tmps(txn_p, &parcel);
    else
        kmhal_parcel_destroy(&parcel);

    return ret;
}
