#include "hidl-txn-util.h"
#include "binder.h"
#include "status.h"
#include "parcel.h"
#include <core/log.h>
#include <string.h>
#include <inttypes.h>
#include <linux/android/binder.h>

#define MODULE_NAME "hidl-txn-util"

enum kmhal_android_status
kmhal_hidl_util_check_allocate_txn_tmps(struct kmhal_binder_txn **txn_p,
                                        struct kmhal_parcel **parcel_p)
{
    if (txn_p != NULL && *txn_p == NULL) {
        *txn_p = kmhal_binder_txn_new();
        if (*txn_p == NULL) {
            s_log_error("Failed to allocate a new binder transaction struct");
            return NO_MEMORY;
        }
    }

    if (parcel_p != NULL && *parcel_p == NULL) {
        *parcel_p = kmhal_parcel_new();
        if (*parcel_p == NULL) {
            s_log_error("Failed to allocate a new parcel");
            return NO_MEMORY;
        }
    }

    return OK;
}

enum kmhal_android_status kmhal_hidl_util_transact_and_unpack(
        struct kmhal_binder_ctx *binder,
        struct kmhal_binder_txn **txn_p,
        struct kmhal_parcel **parcel_p,
        struct kmhal_binder_txn_args_out *out_reply,
        bool write_free_reply
)
{
    enum kmhal_android_status ret = UNKNOWN_ERROR;
    struct kmhal_binder_txn_args_out reply;

    if (!kmhal_binder_ctx_ok(binder)) {
        s_log_error("Invalid binder device context");
        return UNEXPECTED_NULL;
    } else if (txn_p == NULL || *txn_p == NULL) {
        s_log_error("Binder transaction context is NULL");
        return UNEXPECTED_NULL;
    } else if (parcel_p == NULL || *parcel_p == NULL) {
        s_log_error("Parcel is NULL");
        return UNEXPECTED_NULL;
    }

    if (kmhal_binder_do_write_read_ioctl(binder, txn_p)) {
        (void) kmhal_parcel_unpack(parcel_p, NULL);
        s_log_error("Binder WRITE_READ ioctl failed");
        return FAILED_TRANSACTION;
    }

    if (kmhal_parcel_unpack(parcel_p, &reply)) {
        s_log_error("Failed to unpack parcel after transaction");
        return FAILED_TRANSACTION;
    } else if (reply.status != KMHAL_BINDER_TXN_OK) {
        s_log_error("Reply status is not OK");
        return FAILED_TRANSACTION;
    } else if (reply.flags & TF_STATUS_CODE) {
        i32 status = UNKNOWN_ERROR;
        if (reply.data_size < sizeof(i32)) {
            s_log_error("Got status code but data buffer too small");
            return UNKNOWN_ERROR;
        }
        memcpy(&status, reply.data_buf, sizeof(i32));

        s_log_error("Got status code: %"PRIi32" (%s)",
                status, kmhal_android_status_toString(status));
        return kmhal_android_status_prune(status);
    }

    if ((ret = kmhal_hidl_util_check_allocate_txn_tmps(txn_p, NULL)) != OK)
        return ret;

    if (write_free_reply)
        kmhal_binder_write_free_reply(*txn_p, reply.data_buf);

    if ((*parcel_p = kmhal_parcel_new_from_reply(&reply)) == NULL) {
        s_log_error("Failed to initialize a new parcel from the reply");
        return BAD_VALUE;
    }

    if (out_reply != NULL)
        memcpy(out_reply, &reply, sizeof(reply));

    return OK;
}

void kmhal_hidl_util_destroy_txn_tmps(struct kmhal_binder_txn **txn_p,
                                      struct kmhal_parcel **parcel_p)
{
    kmhal_binder_txn_destroy(txn_p);
    kmhal_parcel_destroy(parcel_p);
}
