#include "hidl-manager.h"
#include "binder.h"
#include "hidl-base.h"
#include "hidl-types.h"
#include "hidl-parcel.h"
#include "hidl-txn-util.h"
#include <core/log.h>
#include <core/util.h>
#include <inttypes.h>
#include <linux/android/binder.h>
#include <string.h>

#define MODULE_NAME "hidl-manager"

#define MGR_BINDER_HANDLE 0

#define MGR_1_0_FQNAME "android.hidl.manager@1.0::IServiceManager"
#define MGR_1_1_FQNAME "android.hidl.manager@1.1::IServiceManager"
#define MGR_1_2_FQNAME "android.hidl.manager@1.2::IServiceManager"

/* See `system/libhidl/transport/manager/1.0/IServiceManager.hal` */
#define MGR_CMD_GET 1
#define MGR_CMD_ADD 2
#define MGR_CMD_GET_TRANSPORT 3
#define MGR_CMD_LIST 4
#define MGR_CMD_LIST_BY_INTERFACE 5
#define MGR_CMD_REGISTER_FOR_NOTIFICATIONS 6
#define MGR_CMD_DEBUG_DUMP 7
#define MGR_CMD_REGISTER_PASSTHROUGH_CLIENT 8


static int read_hidl_vec_of_hidl_string(
        const struct kmhal_hidl_parcel *parcel,
        size_t *offset_p,
        const KMHAL_HIDL_VEC_OF_STRUCT(kmhal_hidl_string) **out_p
);

static int read_handle(const struct kmhal_hidl_parcel *parcel,
        size_t *offset_p, u32 *out_handle);

void kmhal_hidl_manager_write_acquire(struct kmhal_binder_transaction *txn)
{
    u_check_params(txn != NULL);

    kmhal_binder_write_increfs(txn, MGR_BINDER_HANDLE);
    kmhal_binder_write_acquire(txn, MGR_BINDER_HANDLE);
}

void kmhal_hidl_manager_write_release(
        struct kmhal_binder_transaction *txn
)
{
    kmhal_binder_write_release(txn, MGR_BINDER_HANDLE);
    kmhal_binder_write_decrefs(txn, MGR_BINDER_HANDLE);
}

enum kmhal_hidl_android_status
kmhal_hidl_manager_get(struct kmhal_binder_ctx *binder,
                       struct kmhal_binder_transaction **txn_p,

                       const char *in_interface_name,
                       const char *in_instance_name,

                       u32 *out_handle)
{
    u_check_params(kmhal_binder_ctx_ok(binder) && txn_p != NULL);
    u_check_params(in_interface_name != NULL && in_instance_name != NULL);

    enum kmhal_hidl_android_status ret = UNKNOWN_ERROR;
    struct kmhal_hidl_parcel *parcel = NULL;

    const struct kmhal_hidl_string
    iface_hstr = {
        .buffer = in_interface_name,
        .length = strlen(in_interface_name),
        .owns_buffer = false
    },
    inst_hstr = {
        .buffer = in_instance_name,
        .length = strlen(in_instance_name),
        .owns_buffer = false
    };

    struct kmhal_binder_tr_sg_args_out reply = { 0 };
    u32 handle = (u32)-1;

    if ((ret = kmhal_hidl_util_check_allocate_txn_tmps(txn_p, &parcel)) != OK)
        goto err;

    kmhal_hidl_parcel_write_cstring(parcel, MGR_1_0_FQNAME);

    {
        kmhal_hidl_string_write(parcel, &iface_hstr,
                KMHAL_HIDL_PARCEL_OBJ_INVALID, 0, 0);

        kmhal_hidl_string_write(parcel, &inst_hstr,
                KMHAL_HIDL_PARCEL_OBJ_INVALID, 0, 0);
    }

    /* We have to call `INCREFS` and `ACQUIRE` on the returned handle
     * before writing the FREE_BUFFER command */
    kmhal_hidl_parcel_pack(*txn_p, parcel, MGR_BINDER_HANDLE, MGR_CMD_GET);
    ret = kmhal_hidl_util_transact_and_unpack(binder, txn_p,
            &parcel, &reply, false);
    if (ret != OK)
        goto err;

    /* Read the returned handle... */
    size_t off = KMHAL_HIDL_PARCEL_DATA_START_OFFSET;
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

    if (out_handle != NULL) *out_handle = handle;
    kmhal_hidl_parcel_destroy(&parcel);
    ret = OK;

err:
    if (ret != OK) {
        s_log_error(MGR_1_0_FQNAME"::get(\"%s\", \"%s\"): ret: %d (%s)",
                in_interface_name, in_instance_name,
                ret, kmhal_hidl_android_status_toString(ret)
        );
        kmhal_hidl_util_destroy_txn_tmps(txn_p, &parcel);
    }

    return ret;
}

enum kmhal_hidl_android_status kmhal_hidl_manager_list(
        struct kmhal_binder_ctx *binder,
        struct kmhal_binder_transaction **txn_p,

        const KMHAL_HIDL_VEC_OF_STRUCT(kmhal_hidl_string) **out_fqInstanceNames
)
{
    u_check_params(kmhal_binder_ctx_ok(binder) && txn_p != NULL);

    enum kmhal_hidl_android_status ret = UNKNOWN_ERROR;
    struct kmhal_hidl_parcel *parcel = NULL;

    if ((ret = kmhal_hidl_util_check_allocate_txn_tmps(txn_p, &parcel)) != OK)
        goto err;

    kmhal_hidl_parcel_write_cstring(parcel, MGR_1_0_FQNAME);

    kmhal_hidl_parcel_pack(*txn_p, parcel, MGR_BINDER_HANDLE, MGR_CMD_LIST);
    ret = kmhal_hidl_util_transact_and_unpack(binder, txn_p,
            &parcel, NULL, true);
    if (ret != OK)
        goto err;

    /* Read the returned hidl_vec<hidl_string> */
    size_t offset = KMHAL_HIDL_PARCEL_DATA_START_OFFSET;
    if (read_hidl_vec_of_hidl_string(parcel, &offset, out_fqInstanceNames)) {
        ret = BAD_VALUE;
        goto_error("Failed to parse the reply");
    }

    kmhal_hidl_parcel_destroy(&parcel);
    ret = OK;

err:
    if (ret != OK) {
        s_log_error(MGR_1_0_FQNAME"::list(): ret: %d (%s)",
                ret, kmhal_hidl_android_status_toString(ret));
        kmhal_hidl_util_destroy_txn_tmps(txn_p, &parcel);
    }

    return ret;
}

enum kmhal_hidl_android_status kmhal_hidl_manager_list_by_interface(
        struct kmhal_binder_ctx *binder,
        struct kmhal_binder_transaction **txn_p,

        const char *in_interface_name,

        const KMHAL_HIDL_VEC_OF_STRUCT(kmhal_hidl_string) **out_instanceNames
)
{
    u_check_params(kmhal_binder_ctx_ok(binder) && txn_p != NULL);
    u_check_params(in_interface_name != NULL);

    enum kmhal_hidl_android_status ret = UNKNOWN_ERROR;
    struct kmhal_hidl_parcel *parcel = NULL;

    const struct kmhal_hidl_string iface_hstr = {
        .buffer = in_interface_name,
        .length = strlen(in_interface_name),
        .owns_buffer = false
    };

    if ((ret = kmhal_hidl_util_check_allocate_txn_tmps(txn_p, &parcel)) != OK)
        goto err;

    kmhal_hidl_parcel_write_cstring(parcel, MGR_1_0_FQNAME);

    {
        kmhal_hidl_string_write(parcel, &iface_hstr,
                KMHAL_HIDL_PARCEL_OBJ_INVALID, 0, 0);
    }

    kmhal_hidl_parcel_pack(*txn_p, parcel, MGR_BINDER_HANDLE,
            MGR_CMD_LIST_BY_INTERFACE);

    ret = kmhal_hidl_util_transact_and_unpack(binder, txn_p,
            &parcel, NULL, true);
    if (ret != OK)
        goto err;

    /* Read the returned hidl_vec<hidl_string> */
    size_t offset = KMHAL_HIDL_PARCEL_DATA_START_OFFSET;
    if (read_hidl_vec_of_hidl_string(parcel, &offset, out_instanceNames)) {
        ret = BAD_VALUE;
        goto_error("Failed to parse the reply");
    }

    kmhal_hidl_parcel_destroy(&parcel);
    ret = OK;

err:
    if (ret != OK) {
        s_log_error(MGR_1_0_FQNAME"::listByInterface(\"%s\"): ret: %d (%s)",
            in_interface_name, ret, kmhal_hidl_android_status_toString(ret));
        kmhal_hidl_util_destroy_txn_tmps(txn_p, &parcel);
    }

    return ret;
}

static int read_hidl_vec_of_hidl_string(
        const struct kmhal_hidl_parcel *parcel,
        size_t *offset_p,
        const KMHAL_HIDL_VEC_OF_STRUCT(kmhal_hidl_string) **out_p
)
{
    kmhal_hidl_parcel_obj_t vec_bytes_ref;
    const KMHAL_HIDL_VEC_OF_STRUCT(kmhal_hidl_string) *vec = NULL;

    if (kmhal_hidl_vec_of_read(struct kmhal_hidl_string,
                KMHAL_HIDL_VECP_TO_GENERIC(&vec), parcel,
                offset_p, &vec_bytes_ref))
    {
        s_log_error("Failed to read the returned HIDL vec");
        return 1;
    }

    for (u32 i = 0; i < vec->size; i++) {
        const size_t parent_offset = i * sizeof(struct kmhal_hidl_string);

        if (kmhal_hidl_string_read_embedded(NULL, NULL, parcel, offset_p,
                    &vec->buffer[i], vec_bytes_ref, parent_offset))
        {
            s_log_error("Failed to read embedded HIDL string @ idx %"PRIu32, i);
            return 1;
        }
    }

    *out_p = vec;
    return 0;
}

static int read_handle(const struct kmhal_hidl_parcel *parcel,
        size_t *offset_p, u32 *out_handle)
{
    struct flat_binder_object flat_binder_obj;

    if (kmhal_hidl_parcel_read_handle(parcel, offset_p, &flat_binder_obj)) {
        s_log_error("Failed to read the flat_binder_object (handle) "
                "from the reply");
        return 1;
    }

    if (out_handle != NULL)
        *out_handle = flat_binder_obj.handle;
    return 0;
}
