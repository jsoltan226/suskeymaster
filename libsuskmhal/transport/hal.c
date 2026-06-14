#ifndef SUSKEYMASTER_BUILD_HOST

#include "hal.h"
#include "binder.h"
#include "status.h"
#include "parcel.h"
#include "txn-util.h"
#include "aidl-util.h"
#include "hidl-base.h"
#include "hidl-manager.h"
#include <core/log.h>
#include <core/util.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdatomic.h>
#include <linux/android/binder.h>

#define MODULE_NAME "hal"

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
    enum kmhal_aidl_tx_header_type aidl_tx_hdr_type;
};

static struct kmhal_sp *
sp_new_get_common(const char *fqname, const char *instname,
                  struct kmhal_binder_ctx *opt_existing_binder,
                  bool owns_existing_binder, bool aidl);

static int do_aidl_hal_get_handle(struct kmhal_sp *hal);
static int do_hidl_hal_get_handle(struct kmhal_sp *hal);

static enum kmhal_android_status
validate_arg_descs(const struct kmhal_arg_write_desc *in_args, u32 n_in_args,
                   struct kmhal_arg_parse_desc *out_args, u32 n_out_args);

struct kmhal_sp * kmhal_sp_new_empty(bool aidl)
{
    struct kmhal_sp *ret = NULL;

    ret = calloc(1, sizeof(struct kmhal_sp));
    if (ret == NULL) {
        s_log_error("Failed to allocate a new HAL strong pointer struct");
        return NULL;
    }
    atomic_store(&ret->initialized_, false);
    ret->aidl = aidl;
    ret->binder = NULL;
    ret->owns_binder = false;
    ret->txn = NULL;
    ret->manager_acquired = false;
    ret->handle = (u32)-1;
    ret->owns_handle = false;
    ret->fqname = NULL;
    ret->instname = NULL;
    ret->aidl_fqname16 = NULL;
    ret->aidl_tx_hdr_type = AIDL_HEADER_UNKNOWN;
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

    hal->aidl_tx_hdr_type = AIDL_HEADER_UNKNOWN;
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

    if (hal->aidl)
        return kmhal_aidl_ping(hal->binder, &hal->txn, hal->handle);
    else
        return kmhal_hidl_base_ping(hal->binder, &hal->txn, hal->handle);
}

enum kmhal_android_status
kmhal_get_aidl_interface_version(struct kmhal_sp *hal,
                                 i32 *out_interface_version)
{
    if (hal == NULL || !atomic_load(&hal->initialized_)) {
        s_log_error("HAL is invalid or NULL");
        return UNEXPECTED_NULL;
    } else if (!hal->aidl) {
        s_log_error("Not an AIDL HAL!");
        return BAD_TYPE;
    }

    i32 tmp = 0;
    enum kmhal_android_status ret = UNKNOWN_ERROR;
    ret = kmhal_aidl_get_interface_version(hal->binder, &hal->txn,
            hal->aidl_tx_hdr_type, hal->aidl_fqname16, hal->handle, &tmp);
    if (ret != OK) {
        s_log_error("%s.getInterfaceVersion: ret: %d (%s)",
                hal->fqname, ret, kmhal_android_status_toString(ret));
        return ret;
    }

    if (out_interface_version != NULL)
        *out_interface_version = tmp;
    return OK;
}

enum kmhal_android_status
kmhal_call(struct kmhal_sp *hal, u32 cmd,
           const struct kmhal_arg_write_desc *in_args, u32 n_in_args,
           struct kmhal_arg_parse_desc *out_args, u32 n_out_args,
           u32 *out_aidl_svc_specific_error_code)
{
    u_check_params(hal != NULL);
    enum kmhal_android_status ret = UNKNOWN_ERROR;
    struct kmhal_binder_txn_args_out reply = { 0 };
    struct kmhal_parcel *parcel = NULL;
    bool got_handle = false;

    if (out_aidl_svc_specific_error_code != NULL)
        *out_aidl_svc_specific_error_code = 0;

    if ((ret = validate_arg_descs(in_args, n_in_args, out_args, n_out_args))
            != OK)
        goto_error("Invalid argument descriptors");

    if ((ret = kmhal_util_check_allocate_txn_tmps(&hal->txn, &parcel)))
        goto_error("Failed to allocate temporary transaction resources");

    /* Write the parcel header */
    if (hal->aidl)
        kmhal_aidl_write_tx_header(parcel,
                AIDL_HEADER_SYSTEM, hal->aidl_fqname16);
    else
        kmhal_parcel_write_cstring(parcel, hal->fqname);

    /* Serialize the arguments */
    for (u32 i = 0; i < n_in_args; i++) {
        const struct kmhal_arg_write_desc *const a = &in_args[i];

        switch (a->type) {
        case KMHAL_ARG_PRIMITIVE: {
            const struct kmhal_arg_write_primitive *const p = &a->arg.p;
            s_log_trace("writing primitive arg %"PRIu32" (\"%s\"); "
                    "val: 0x%"PRIx64", size: %zu", i, a->name, p->val, p->size);
            p->proc(parcel, p->val, p->size);
            break;
        }
        case KMHAL_ARG_BUFFER_OBJECT: {
            const struct kmhal_arg_write_buffer_obj *const b = &a->arg.b;
            s_log_trace("writing buffer obj arg %"PRIu32" (\"%s\"); "
                    "data: %p, size: %zu", i, a->name, b->data, b->size);
            b->proc(parcel, b->data, b->size);
            break;
        }
        case KMHAL_ARG_INLINE_DATA_WITH_HANDLE:
        case KMHAL_ARG_INLINE_DATA: {
            s_log_trace("writing inline data arg %"PRIu32" (\"%s\"); data: %p",
                    i, a->name, a->arg.i.data);
            const struct kmhal_arg_write_inline_data *const i = &a->arg.i;
            i->proc(parcel, i->data);
            break;
        }
        default: s_log_fatal("Impossible outcome");
        }
    }
    kmhal_parcel_pack(hal->txn, parcel, hal->handle, cmd, hal->aidl ? 0 : 1);

    /* Transact */
    ret = kmhal_util_transact_and_unpack(hal->binder, &hal->txn, &parcel,
                &reply, false, hal->aidl, out_aidl_svc_specific_error_code);
    if (ret != OK) {
        if (out_aidl_svc_specific_error_code &&
                *out_aidl_svc_specific_error_code != 0)
        {
            /* Got service specific code; let the caller handle this */
            ret = OK;
            goto err;
        }

        goto_error("Binder transaction failed");
    }

    /* Deserialize the returned values */
    size_t off = KMHAL_PARCEL_DATA_START_OFFSET;
    for (u32 i = 0; i < n_out_args; i++) {
        const struct kmhal_arg_parse_desc *const a = &out_args[i];

        int r = -1;
        switch (a->type) {
        case KMHAL_ARG_PRIMITIVE: {
            const struct kmhal_arg_parse_primitive *const p = &a->arg.p;
            s_log_trace("Reading primitive arg %"PRIu32" (\"%s\"); off: %zu; "
                    " out: %p, size: %zu", i, a->name, off, p->out, p->size);
            r = p->proc(parcel, &off, p->out, p->size);
            break;
        }
        case KMHAL_ARG_BUFFER_OBJECT: {
            const struct kmhal_arg_parse_buffer_obj *const b = &a->arg.b;
            s_log_trace("Reading buffer obj arg %"PRIu32" (\"%s\"); off: %zu; "
                    " out_p: %p, exp_out_size: %zu", i, a->name, off,
                    b->out_p, b->exp_out_size);
            r = b->proc(parcel, &off, b->out_p, b->exp_out_size);
            break;
        }
        case KMHAL_ARG_INLINE_DATA: {
            s_log_trace("Reading inline data arg %"PRIu32" (\"%s\"); off: %zu; "
                    " out: %p, size: %zu", i, a->name, off,
                    a->arg.i.out, a->arg.i.size);
            const struct kmhal_arg_parse_inline_data *const i = &a->arg.i;
            r = i->proc(parcel, &off, i->out, i->size);
            break;
        }
        case KMHAL_ARG_INLINE_DATA_WITH_HANDLE: {
            s_log_trace("Reading inline data (with handle) arg "
                    "%"PRIu32" (\"%s\"); off: %zu; "
                    " out: %p, size: %zu", i, a->name, off,
                    a->arg.i.out, a->arg.i.size);

            const struct kmhal_arg_parse_inline_data_with_handle *const ih =
                &a->arg.ih;
            u32 handle = UINT32_MAX;
            r = ih->proc(parcel, &off, &handle, ih->out, ih->size);
            if (r == 0 && handle != UINT32_MAX) {
                s_log_trace("Incref()ing handle %"PRIu32, handle);
                kmhal_binder_write_increfs(hal->txn, handle);
                kmhal_binder_write_acquire(hal->txn, handle);
                got_handle = true;
            }
            break;
        }
        default: s_log_fatal("Impossible outcome");
        }
        if (r != 0) {
            ret = BAD_VALUE;
            goto_error("Failed to parse arg no %u \"%s\" from the reply",
                    i, a->name);
        }
    }

    ret = OK;

err:
    if (reply.status != KMHAL_BINDER_TXN_UNINITIALIZED) {
        kmhal_binder_write_free_reply(hal->txn, reply.data_buf);
        memset(&reply, 0, sizeof(reply));
    }
    if (got_handle) {
        got_handle = false;
        /* Since we have no guarantee that noone will start using the handle
         * immediately after this call without acquiring it,
         * we must do that right now */
        if (kmhal_binder_do_write_read_ioctl(hal->binder, &hal->txn)) {
            s_log_error("Failed to perform binder transaction");
            ret = FAILED_TRANSACTION;
        }
        if ((ret = kmhal_util_check_allocate_txn_tmps(&hal->txn, NULL)) != OK) {
            s_log_error("Failed to allocate new binder transaction context");
        }
    }

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
    if (size != sizeof(u64) || out == NULL) {
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
    if (hal->aidl)
        hal->aidl_tx_hdr_type = kmhal_aidl_get_tx_header_type(hal->binder);
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

void kmhal_set_fqname(struct kmhal_sp *hal, const char *fqname)
{
    u_check_params(hal != NULL && atomic_load(&hal->initialized_));

    hal->fqname = fqname;

    if (hal->aidl) {
        if (hal->aidl_fqname16 != NULL) {
            free(hal->aidl_fqname16);
            hal->aidl_fqname16 = NULL;
        }

        const size_t nchars = strlen(fqname) + 1;
        hal->aidl_fqname16 = calloc(nchars, sizeof(char16_t));
        if (hal->aidl_fqname16 == NULL)
            s_log_fatal("Failed to allocate the AIDL UTF-16 fqname string");

        for (size_t i = 0; i < nchars; i++)
            hal->aidl_fqname16[i] = INT16_C(0x00FF) & fqname[i];
    }
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

    ret = kmhal_sp_new_empty(aidl);
    if (ret == NULL)
        goto err;

    if (opt_existing_binder == NULL) {
        struct kmhal_binder_ctx *binder = kmhal_binder_open(aidl ?
                KMHAL_BINDER_DEV_BINDER : KMHAL_BINDER_DEV_HWBINDER);
        if (binder == NULL)
            goto_error("Failed to open binder device");

        kmhal_set_binder(ret, binder, true);
    } else {
        kmhal_set_binder(ret, opt_existing_binder, owns_existing_binder);
    }

    kmhal_set_fqname(ret, fqname);
    kmhal_set_instname(ret, instname);

    if (kmhal_util_check_allocate_txn_tmps(&ret->txn, NULL) != OK)
        goto err;

    if (aidl && do_aidl_hal_get_handle(ret))
        goto err;
    else if (!aidl && do_hidl_hal_get_handle(ret))
        goto err;

    return ret;

err:
    if (ret != NULL)
        kmhal_sp_destroy(&ret);

    return NULL;
}

static int do_aidl_hal_get_handle(struct kmhal_sp *hal)
{
    kmhal_aidl_manager_write_acquire(hal->txn);
    if (kmhal_binder_do_write_read_ioctl(hal->binder, &hal->txn)) {
        s_log_error("Binder acquire transactions on servicemanager failed");
        return 1;
    }
    hal->manager_acquired = true;

    enum kmhal_android_status s = kmhal_aidl_manager_get(hal->binder,
            &hal->txn, hal->aidl_tx_hdr_type, hal->fqname, hal->instname,
            &hal->handle);
    if (s != OK && s != PERMISSION_DENIED) {
        s_log_error("Failed to getService() a handle to the AIDL HAL");
        return 1;
    } else if (hal->handle == 0 || s == PERMISSION_DENIED) {
        /* This error is expected when getting the wrong version,
         * so we might need to call this function multiple times
         * before we get the correct one, therefore don't spam this error */
        s_log_verbose("No handle received");
        return 1;
    }

    return 0;
}

static int do_hidl_hal_get_handle(struct kmhal_sp *hal)
{
    kmhal_hidl_manager_write_acquire(hal->txn);
    if (kmhal_binder_do_write_read_ioctl(hal->binder, &hal->txn)) {
        s_log_error("Binder acquire transactions on hwservicemanager failed");
        return 1;
    }
    hal->manager_acquired = true;

    u32 handle = 0;
    enum kmhal_android_status s = kmhal_hidl_manager_get(hal->binder,
                            &hal->txn, hal->fqname, hal->instname, &handle);
    if (handle == 0 || s == PERMISSION_DENIED) {
        /* This error is expected when getting the wrong version,
         * so we might need to call this function multiple times
         * before we get the correct one, therefore don't spam this error */
        s_log_verbose("No handle received");
        return 1;
    } else if (s != OK) {
        s_log_error("Failed to get() a handle to the HIDL HAL");
        return 1;
    }

    kmhal_set_handle(hal, handle, true);
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
        case KMHAL_ARG_INLINE_DATA_WITH_HANDLE:
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
        case KMHAL_ARG_INLINE_DATA_WITH_HANDLE:
            if (arg->arg.i.proc == NULL) {
                s_log_error("Out inline_data (with handle) arg %u (\"%s\"): "
                        "proc is NULL", i, arg->name);
                ret = UNEXPECTED_NULL;
            }
            if (arg->arg.i.out == NULL && arg->arg.i.size > 0) {
                s_log_error("Out inline_data (with handle) arg %u (\"%s\"): "
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
