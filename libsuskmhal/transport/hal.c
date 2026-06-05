#ifndef SUSKEYMASTER_BUILD_HOST

#include "hal.h"
#include "binder.h"
#include "status.h"
#include "parcel.h"
#include "txn-util.h"
#include "hidl-base.h"
#include "hidl-manager.h"
#include <core/log.h>
#include <core/util.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdatomic.h>
#include <linux/android/binder.h>

#define MODULE_NAME "hidl-hal"

struct kmhal_sp {
    _Atomic bool initialized_;

    bool aidl;

    struct kmhal_binder_ctx *binder;
    bool owns_binder;

    struct kmhal_binder_txn *txn;

    bool manager_acquired;
    u32 handle;
    bool owns_handle;

    const char *fqname;
    const char *instname;

    char16_t *aidl_fqname16;
};

static struct kmhal_sp *
sp_new_get_common(const char *fqname, const char *instname,
                  struct kmhal_binder_ctx *opt_existing_binder,
                  bool owns_existing_binder, bool aidl);

/* From "frameworks/native/libs/binder/Parcel.cpp" */
#define STRICT_MODE_PENALTY_GATHER  (INT32_C(1) << 31)
#define UNSET_WORK_SOURCE           INT32_C(-1)
enum aidl_header_type {
    AIDL_HEADER_UNKNOWN = B_PACK_CHARS('U', 'N', 'K', 'N'),
    AIDL_HEADER_SYSTEM = B_PACK_CHARS('S', 'Y', 'S', 'T'),
    AIDL_HEADER_VENDOR = B_PACK_CHARS('V', 'N', 'D', 'R'),
    AIDL_HEADER_RECOVERY = B_PACK_CHARS('R', 'E', 'C', 'O'),
};
static void kmhal_aidl_write_txn_header(struct kmhal_parcel *parcel,
                                        enum aidl_header_type hdr,
                                        const char16_t *iface_token);

static int kmhal_aidl_parse_reply_header(struct kmhal_parcel *p, size_t *off_p,
                                         size_t *out_start_off,
                                         i32 *out_parcelable_size);

static void kmhal_aidl_manager_write_release(struct kmhal_binder_txn *txn);

static int do_aidl_hal_get(struct kmhal_sp *hal);
static int do_hidl_hal_get(struct kmhal_sp *hal);

static enum kmhal_android_status
validate_arg_descs(const struct kmhal_arg_write_desc *in_args, u32 n_in_args,
                   struct kmhal_arg_parse_desc *out_args, u32 n_out_args);

struct kmhal_sp * kmhal_sp_new_empty(void)
{
    struct kmhal_sp *ret = NULL;

    ret = calloc(1, sizeof(struct kmhal_sp));
    if (ret == NULL) {
        s_log_error("Failed to allocate a new HAL strong pointer struct");
        return NULL;
    }
    atomic_store(&ret->initialized_, false);
    ret->aidl = false;
    ret->binder = NULL;
    ret->owns_binder = false;
    ret->txn = NULL;
    ret->manager_acquired = false;
    ret->handle = (u32)-1;
    ret->owns_handle = false;
    ret->fqname = NULL;
    ret->instname = NULL;
    ret->aidl_fqname16 = NULL;
    atomic_store(&ret->initialized_, true);

    return ret;
}

struct kmhal_sp *
kmhal_hidl_sp_new_get(const char *fqname, const char *instname,
                      struct kmhal_binder_ctx *opt_existing_binder,
                      bool owns_existing_binder)
{
    return sp_new_get_common(fqname, instname,
            opt_existing_binder, owns_existing_binder, false);
}

struct kmhal_sp *
kmhal_aidl_sp_new_get(const char *fqname, const char *instname,
                      struct kmhal_binder_ctx *opt_existing_binder,
                      bool owns_existing_binder)
{
    return sp_new_get_common(fqname, instname,
            opt_existing_binder, owns_existing_binder, true);
}

void kmhal_sp_destroy(struct kmhal_sp **hal_p)
{
    if (hal_p == NULL || *hal_p == NULL)
        return;

    struct kmhal_sp *const hal = *hal_p;

    if (!atomic_exchange(&hal->initialized_, false))
        return;

    if (hal->aidl_fqname16 != NULL) {
        free(hal->aidl_fqname16);
        hal->aidl_fqname16 = NULL;
    }
    hal->instname = NULL;
    hal->fqname = NULL;

    bool do_final_transaction = false;
    if (hal->txn != NULL)
        do_final_transaction = true;

    if (hal->handle != (u32)-1 && hal->owns_handle) {
        if (kmhal_util_check_allocate_txn_tmps(&hal->txn, NULL) != OK) {
            s_log_error("Failed to allocate a new binder transaction; "
                    "not dropping HAL handle reference");
            goto skip_binder_refs;
        }

        kmhal_binder_write_release(hal->txn, hal->handle);
        kmhal_binder_write_decrefs(hal->txn, hal->handle);
        do_final_transaction = true;
    }
    hal->handle = (u32)-1;
    hal->owns_handle = false;

    if (hal->manager_acquired) {
        if (kmhal_util_check_allocate_txn_tmps(&hal->txn, NULL) != OK) {
            s_log_error("Failed to allocate a new binder transaction; "
                    "not dropping manager handle reference");
            goto skip_binder_refs;
        }

        if (hal->aidl)
            kmhal_aidl_manager_write_release(hal->txn);
        else
            kmhal_hidl_manager_write_release(hal->txn);
        do_final_transaction = true;
    }
    hal->manager_acquired = false;

    if (do_final_transaction) {
        if (hal->binder == NULL || hal->txn == NULL) {
            s_log_error("Cannot execute queued commands due to "
                    "uninitialized binder driver and transaction contexts");
            goto skip_binder_refs;
        }

        if (kmhal_binder_do_write_read_ioctl(hal->binder, &hal->txn)) {
            s_log_error("Failed to perform the final transaction "
                    "to flush the remaining queued commands and "
                    "drop all the acquired binder references");
        }
    }
    kmhal_binder_txn_destroy(&hal->txn);

skip_binder_refs:

    if (hal->owns_binder) {
        hal->owns_binder = false;
        if (hal->binder != NULL)
            kmhal_binder_close(&hal->binder);
    }
    hal->binder = NULL;

    free(hal);
    *hal_p = NULL;
}

enum kmhal_android_status
kmhal_ping(struct kmhal_sp *hal)
{
    if (hal == NULL || !atomic_load(&hal->initialized_)) {
        s_log_error("HAL is invalid or NULL");
        return UNEXPECTED_NULL;
    }

    return kmhal_hidl_base_ping(hal->binder, &hal->txn, hal->handle);
}

enum kmhal_android_status
kmhal_call(struct kmhal_sp *hal, u32 cmd,
           const struct kmhal_arg_write_desc *in_args, u32 n_in_args,
           struct kmhal_arg_parse_desc *out_args, u32 n_out_args)
{
    u_check_params(hal != NULL);
    enum kmhal_android_status ret = UNKNOWN_ERROR;

    if ((ret = validate_arg_descs(in_args, n_in_args, out_args, n_out_args))
            != OK)
        goto_error("Invalid argument descriptors");

    struct kmhal_parcel *parcel = NULL;
    if ((ret = kmhal_util_check_allocate_txn_tmps(&hal->txn, &parcel)))
        goto_error("Failed to allocate temporary transaction resources");

    /* Write the parcel header */
    if (hal->aidl)
        kmhal_aidl_write_txn_header(parcel,
                AIDL_HEADER_SYSTEM, hal->aidl_fqname16);
    else
        kmhal_parcel_write_cstring(parcel, hal->fqname);

    /* Serialize the arguments */
    for (u32 i = 0; i < n_in_args; i++) {
        const struct kmhal_arg_write_desc *const a = &in_args[i];

        switch (a->type) {
        case KMHAL_ARG_PRIMITIVE: {
            const struct kmhal_arg_write_primitive *const p = &a->arg.p;
            p->proc(parcel, p->val, p->size);
            break;
        }
        case KMHAL_ARG_BUFFER_OBJECT: {
            const struct kmhal_arg_write_buffer_obj *const b = &a->arg.b;
            b->proc(parcel, b->data, b->size);
            break;
        }
        case KMHAL_ARG_INLINE_DATA: {
            const struct kmhal_arg_write_inline_data *const i = &a->arg.i;
            i->proc(parcel, i->data);
            break;
        }
        default: s_log_fatal("Impossible outcome");
        }
    }
    kmhal_parcel_pack(hal->txn, parcel, hal->handle, cmd, true);

    /* Transact */
    if ((ret = kmhal_util_transact_and_unpack(hal->binder, &hal->txn, &parcel,
                NULL, true, false)) != OK)
        goto_error("Binder HIDL transaction failed");

    /* Deserialize the returned values */
    size_t off = KMHAL_PARCEL_DATA_START_OFFSET;
    for (u32 i = 0; i < n_out_args; i++) {
        const struct kmhal_arg_parse_desc *const a = &out_args[i];

        /* AIDL parcelables all have headers,
         * while HIDL objects are just written one after the other */
        size_t aidl_start_off = 0;
        i32 aidl_parcelable_size = 0;
        if (hal->aidl && kmhal_aidl_parse_reply_header(parcel, &off,
                    &aidl_start_off, &aidl_parcelable_size))
        {
            ret = BAD_TYPE;
            goto_error("Failed to read arg no %"PRIu32" \"%s\"'s "
                    "AIDL parcelable header from the reply", i, a->name);
        }

        int r = -1;
        switch (a->type) {
        case KMHAL_ARG_PRIMITIVE: {
            const struct kmhal_arg_parse_primitive *const p = &a->arg.p;
            r = p->proc(parcel, &off, p->out, p->size);
            break;
        }
        case KMHAL_ARG_BUFFER_OBJECT: {
            const struct kmhal_arg_parse_buffer_obj *const b = &a->arg.b;
            r = b->proc(parcel, &off, b->out_p, b->exp_out_size);
            break;
        }
        case KMHAL_ARG_INLINE_DATA: {
            const struct kmhal_arg_parse_inline_data *const i = &a->arg.i;
            r = i->proc(parcel, &off, i->out, i->size);
            break;
        }
        default: s_log_fatal("Impossible outcome");
        }
        if (r != 0) {
            ret = BAD_VALUE;
            goto_error("Failed to parse arg no %u \"%s\" from the reply",
                    i, a->name);
        }

        /* If AIDL, validate that previously parsed parcelable header */
        if (hal->aidl && off - aidl_start_off != (size_t)aidl_parcelable_size) {
            ret = BAD_TYPE;
            goto_error("AIDL parcelable size mismatch in arg no "
                    "%"PRIu32" (\"%s\")", i, a->name);
        }
    }

    ret = OK;

err:
    if (ret != OK)
        kmhal_util_destroy_txn_tmps(&hal->txn, &parcel);
    else
        kmhal_parcel_destroy(&parcel);

    return ret;
}

void kmhal_arg_write_u32(struct kmhal_parcel *p, u64 val, size_t size)
{
    u_check_params(size == sizeof(u32) && val <= UINT32_MAX);
    kmhal_parcel_write_u32(p, (u32)val);
}

void kmhal_arg_write_u64(struct kmhal_parcel *p, u64 val, size_t size)
{
    u_check_params(size == sizeof(u64));
    kmhal_parcel_write_u64(p, val);
}

int kmhal_arg_parse_u32(const struct kmhal_parcel *p, size_t *off_p,
                        void *out, size_t size)
{
    if (size != sizeof(u32) || out == NULL) {
        s_log_error("%s: Invalid parameters", __func__);
        return -1;
    }

    return kmhal_parcel_read_u32(p, off_p, out);
}

int kmhal_arg_parse_u64(const struct kmhal_parcel *p, size_t *off_p,
                        void *out, size_t size)
{
    if (size != sizeof(u32) || out == NULL) {
        s_log_error("%s: Invalid parameters", __func__);
        return -1;
    }

    return kmhal_parcel_read_u64(p, off_p, out);
}

struct kmhal_binder_ctx *
kmhal_get_binder(struct kmhal_sp *hal,
                          bool *opt_out_owns_binder)
{
    u_check_params(hal != NULL && atomic_load(&hal->initialized_));
    if (opt_out_owns_binder != NULL) *opt_out_owns_binder = hal->owns_binder;
    return hal->binder;
}

void kmhal_set_binder(struct kmhal_sp *hal,
                               struct kmhal_binder_ctx *binder,
                               bool owns_binder)
{
    u_check_params(hal != NULL && atomic_load(&hal->initialized_));

    if (hal->binder != NULL && hal->owns_binder)
        kmhal_binder_close(&hal->binder);

    hal->binder = binder;
    hal->owns_binder = owns_binder;
}

u32 kmhal_get_handle(const struct kmhal_sp *hal,
        bool *opt_out_owns_handle)
{
    u_check_params(hal != NULL && atomic_load(&hal->initialized_));
    if (opt_out_owns_handle != NULL) *opt_out_owns_handle = hal->owns_handle;
    return hal->handle;
}

void kmhal_set_handle(struct kmhal_sp *hal,
                               u32 handle, bool owns_handle)
{
    u_check_params(hal != NULL && atomic_load(&hal->initialized_));

    if (hal->handle != (u32)-1 && hal->owns_handle) {
        if (kmhal_util_check_allocate_txn_tmps(&hal->txn, NULL) != OK) {
            s_log_error("Failed to allocate a new binder transaction; "
                    "not dropping existing HAL handle reference");
        } else {
            kmhal_binder_write_release(hal->txn, hal->handle);
            kmhal_binder_write_decrefs(hal->txn, hal->handle);
        }
    }

    hal->handle = handle;
    hal->owns_handle = owns_handle;
}

const char * kmhal_get_fqname(const struct kmhal_sp *hal)
{
    u_check_params(hal != NULL && atomic_load(&hal->initialized_));
    return hal->fqname;
}

void kmhal_set_fqname(struct kmhal_sp *hal,
                               const char *fqname)
{
    u_check_params(hal != NULL && atomic_load(&hal->initialized_));
    hal->fqname = fqname;
}

const char * kmhal_get_instname(const struct kmhal_sp *hal)
{
    u_check_params(hal != NULL && atomic_load(&hal->initialized_));
    return hal->instname;
}

void kmhal_set_instname(struct kmhal_sp *hal,
                                 const char *instname)
{
    u_check_params(hal != NULL && atomic_load(&hal->initialized_));
    hal->instname = instname;
}

static struct kmhal_sp *
sp_new_get_common(const char *fqname, const char *instname,
                  struct kmhal_binder_ctx *opt_existing_binder,
                  bool owns_existing_binder, bool aidl)
{
    u_check_params(fqname != NULL && instname != NULL);

    struct kmhal_sp *ret = NULL;

    ret = kmhal_sp_new_empty();
    if (ret == NULL)
        goto err;

    ret->aidl = aidl;

    if (opt_existing_binder == NULL) {
        ret->binder = kmhal_binder_open(aidl ? KMHAL_BINDER_DEV_BINDER :
                                               KMHAL_BINDER_DEV_HWBINDER);
        if (ret->binder == NULL)
            goto_error("Failed to open binder device");
        ret->owns_binder = true;
    } else {
        ret->binder = opt_existing_binder;
        ret->owns_binder = owns_existing_binder;
    }

    ret->fqname = fqname;
    ret->instname = instname;
    if (aidl) {
        const size_t nchars = strlen(fqname) + 1;
        ret->aidl_fqname16 = calloc(nchars, sizeof(char16_t));
        if (ret->aidl_fqname16 == NULL)
            goto_error("Failed to allocate the AIDL UTF-16 fqname string");

        for (size_t i = 0; i < nchars; i++)
            ret->aidl_fqname16[i] = INT16_C(0x00FF) & fqname[i];
    }

    if (kmhal_util_check_allocate_txn_tmps(&ret->txn, NULL) != OK)
        goto err;

    if (aidl && do_aidl_hal_get(ret))
        goto err;
    else if (do_hidl_hal_get(ret))
        goto err;

    ret->owns_handle = true;

    return ret;

err:
    if (ret != NULL)
        kmhal_sp_destroy(&ret);

    return NULL;
}

static void kmhal_aidl_write_txn_header(struct kmhal_parcel *parcel,
                                        enum aidl_header_type hdr,
                                        const char16_t *iface_token)
{
    const u32 strict_mode_policy = STRICT_MODE_PENALTY_GATHER;
    const u32 work_source = UNSET_WORK_SOURCE;
    const u32 header = hdr;

    kmhal_parcel_write_u32(parcel, strict_mode_policy);
    kmhal_parcel_write_u32(parcel, work_source);
    kmhal_parcel_write_u32(parcel, header);
    kmhal_parcel_write_aidl_string16(parcel, iface_token);

}

static int kmhal_aidl_parse_reply_header(struct kmhal_parcel *p, size_t *off_p,
                                         size_t *out_start_off,
                                         i32 *out_parcelable_size)
{
    u32 stability = 0;
    u32 parcelable_size = 0;

    if (kmhal_parcel_read_u32(p, off_p, &stability)) {
        s_log_error("Failed to read the wire stability");
        return 1;
    }

    s_log_debug("Parcelable stability: %s",
            !!stability ? "VINTF" : "LOCAL");

    *out_start_off = *off_p;

    if (kmhal_parcel_read_u32(p, off_p, &parcelable_size)) {
        s_log_error("Failed to read the parcelable size");
        return 1;
    }
    s_log_debug("Parcelable payload size: %"PRIi32,
            (i32)parcelable_size);
    if (parcelable_size < 0) {
        s_log_error("Invalid parcelable size");
        return 1;
    }

    *out_parcelable_size = parcelable_size;
    return 0;
}

static void kmhal_aidl_manager_write_acquire(struct kmhal_binder_txn *txn)
{
    kmhal_binder_write_increfs(txn, 0);
    kmhal_binder_write_acquire(txn, 0);
}

static void kmhal_aidl_manager_write_release(struct kmhal_binder_txn *txn)
{
    kmhal_binder_write_release(txn, 0);
    kmhal_binder_write_decrefs(txn, 0);
}

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

static enum kmhal_android_status
kmhal_aidl_manager_get(struct kmhal_binder_ctx *binder,
                       struct kmhal_binder_txn **txn_p,

                       const char *in_interface_name,
                       const char *in_instance_name,

                       u32 *out_handle)
{
    u_check_params(kmhal_binder_ctx_ok(binder) && txn_p != NULL);
    u_check_params(in_interface_name != NULL && in_instance_name != NULL);

    enum kmhal_android_status ret = UNKNOWN_ERROR;
    struct kmhal_parcel *parcel = NULL;

    struct kmhal_binder_txn_args_out reply = { 0 };
    u32 handle = (u32)-1;

    const int fqname_len =
        strlen(in_interface_name) + 1 /* '/' */ + strlen(in_instance_name);
    char *fqname_str = NULL;

    fqname_str = malloc(fqname_len + 1 /* '\0' */);
    if (fqname_str == NULL) {
        ret = NO_MEMORY;
        goto_error("Failed to allocate the fqname string");
    }
    {
        int r;
    if ((r = snprintf(fqname_str, fqname_len + 1,
                "%s/%s", in_interface_name, in_instance_name))
            != fqname_len)
    {
        s_log_fatal("Invalid return value of snprintf: %d (%d)", r, fqname_len);
    }
    }

    if ((ret = kmhal_util_check_allocate_txn_tmps(txn_p, &parcel)) != OK)
        goto err;

    kmhal_aidl_write_txn_header(parcel, AIDL_HEADER_SYSTEM, u"android.os.IServiceManager");
    /* args */
    {
        kmhal_parcel_write_convert_aidl_string16(parcel, fqname_str);
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

    if (out_handle != NULL) *out_handle = handle;
    kmhal_parcel_destroy(&parcel);
    ret = OK;

err:
    if (ret != OK) {
        s_log_error("android.os.IServiceManager::getService(\"%s\"): ret: %d (%s)",
                fqname_str != NULL ? fqname_str : "<N/A>",
                ret, kmhal_android_status_toString(ret)
        );
        kmhal_util_destroy_txn_tmps(txn_p, &parcel);
    }

    if (fqname_str != NULL) {
        free(fqname_str);
        fqname_str = NULL;
    }

    return ret;
}

static int do_aidl_hal_get(struct kmhal_sp *hal)
{
    kmhal_aidl_manager_write_acquire(hal->txn);
    if (kmhal_binder_do_write_read_ioctl(hal->binder, &hal->txn)) {
        s_log_error("Binder acquire transactions on servicemanager failed");
        return 1;
    }
    hal->manager_acquired = true;

    if (kmhal_aidl_manager_get(hal->binder, &hal->txn,
                hal->fqname, hal->instname, &hal->handle) != OK)
    {
        s_log_error("Failed to getService() a handle to the HAL");
        return 1;
    } else if (hal->handle == 0) {
        /* In AIDL we only really try to get the service once,
         * so this should be an error message */
        s_log_error("No handle received");
        return 1;
    }

    return 0;
}

static int do_hidl_hal_get(struct kmhal_sp *hal)
{
    kmhal_hidl_manager_write_acquire(hal->txn);
    if (kmhal_binder_do_write_read_ioctl(hal->binder, &hal->txn)) {
        s_log_error("Binder acquire transactions on hwservicemanager failed");
        return 1;
    }
    hal->manager_acquired = true;

    if (kmhal_hidl_manager_get(hal->binder, &hal->txn,
                hal->fqname, hal->instname, &hal->handle) != OK)
    {
        s_log_error("Failed to get() a handle to the HIDL HAL");
        return 1;
    } else if (hal->handle == 0) {
        /* This error is expected when getting the wrong version,
         * so we might need to call this function multiple times
         * before we get the correct one, therefore we might
         * not want this error spammed */
        s_log_verbose("No handle received");
        return 1;
    }

    return 0;
}

static enum kmhal_android_status
validate_arg_descs(const struct kmhal_arg_write_desc *in_args,
                   u32 n_in_args,
                   struct kmhal_arg_parse_desc *out_args,
                   u32 n_out_args)
{
    if (in_args == NULL && n_in_args > 0) {
        s_log_error("in_args is NULL but n_in_args > 0");
        return UNEXPECTED_NULL;
    }
    if (out_args == NULL && n_out_args > 0) {
        s_log_error("out_args is NULL but n_out_args > 0");
        return UNEXPECTED_NULL;
    }

    enum kmhal_android_status ret = OK;
    for (u32 i = 0; i < n_in_args; i++) {
        const struct kmhal_arg_write_desc *const arg = &in_args[i];

        if (arg->name == NULL) {
            s_log_error("In arg %u: name is NULL", i);
            ret = UNEXPECTED_NULL;
        }

        switch (arg->type) {
        case KMHAL_ARG_PRIMITIVE:
            if (arg->arg.p.proc == NULL) {
                s_log_error("In primitive arg %u (\"%s\"): proc is NULL",
                        i, arg->name);
                ret = UNEXPECTED_NULL;
            }
            break;
        case KMHAL_ARG_BUFFER_OBJECT:
            if (arg->arg.b.proc == NULL) {
                s_log_error("In buffer_obj arg %u (\"%s\"): proc is NULL",
                        i, arg->name);
                ret = UNEXPECTED_NULL;
            }
            if (arg->arg.b.data == NULL && arg->arg.b.size > 0) {
                s_log_error("In buffer_obj arg %u (\"%s\"): "
                        "data is NULL while size > 0", i, arg->name);
                ret = UNEXPECTED_NULL;
            }
            break;
        case KMHAL_ARG_INLINE_DATA:
            if (arg->arg.i.proc == NULL) {
                s_log_error("In inline_data arg %u (\"%s\"): proc is NULL",
                        i, arg->name);
                ret = UNEXPECTED_NULL;
            }
            break;
        default:
            s_log_error("In arg %u (\"%s\"): Invalid arg type %d",
                    i, arg->name, arg->type);
            ret = BAD_TYPE;
        }
    }

    for (u32 i = 0; i < n_out_args; i++) {
        const struct kmhal_arg_parse_desc *const arg = &out_args[i];

        if (arg->name == NULL) {
            s_log_error("Out arg %u: name is NULL", i);
            ret = UNEXPECTED_NULL;
        }

        switch (arg->type) {
        case KMHAL_ARG_PRIMITIVE:
            if (arg->arg.p.proc == NULL) {
                s_log_error("Out primitive arg %u (\"%s\"): proc is NULL",
                        i, arg->name);
                ret = UNEXPECTED_NULL;
            }
            if (arg->arg.p.out == NULL && arg->arg.p.size > 0) {
                s_log_error("Out primitive arg %u (\"%s\"): "
                        "out pointer is NULL while size > 0", i, arg->name);
                ret = UNEXPECTED_NULL;
            }
            break;
        case KMHAL_ARG_BUFFER_OBJECT:
            if (arg->arg.b.proc == NULL) {
                s_log_error("Out buffer_obj arg %u (\"%s\"): proc is NULL",
                        i, arg->name);
                ret = UNEXPECTED_NULL;
            }
            if (arg->arg.b.out_p == NULL && arg->arg.b.exp_out_size > 0) {
                s_log_error("Out buffer_obj arg %u (\"%s\"): "
                        "out pointer is NULL while exp_out_size > 0",
                        i, arg->name);
                ret = UNEXPECTED_NULL;
            } else if (arg->arg.b.out_p != NULL && *arg->arg.b.out_p != NULL) {
                s_log_warn("Out buffer_obj arg %u (\"%s\"): "
                        "`*out_p` not initialized to NULL, initializing...",
                        i, arg->name);
                *arg->arg.b.out_p = NULL;
            }
            break;
        case KMHAL_ARG_INLINE_DATA:
            if (arg->arg.i.proc == NULL) {
                s_log_error("Out inline_data arg %u (\"%s\"): proc is NULL",
                        i, arg->name);
                ret = UNEXPECTED_NULL;
            }
            if (arg->arg.i.out == NULL && arg->arg.i.size > 0) {
                s_log_error("Out inline_data arg %u (\"%s\"): "
                        "out pointer is NULL while size > 0", i, arg->name);
                ret = UNEXPECTED_NULL;
            }
            break;
        default:
            s_log_error("Out arg %u (\"%s\"): Invalid arg type %d",
                    i, arg->name, arg->type);
            ret = BAD_TYPE;
        }
    }

    return ret;
}

#endif /* SUSKEYMASTER_BUILD_HOST */
