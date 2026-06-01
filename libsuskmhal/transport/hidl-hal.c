#include "binder.h"
#include "status.h"
#include "parcel.h"
#include "hidl-hal.h"
#include "hidl-base.h"
#include "hidl-manager.h"
#include "hidl-txn-util.h"
#include <core/log.h>
#include <core/util.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdatomic.h>
#include <linux/android/binder.h>

#define MODULE_NAME "hidl-hal"

struct kmhal_hidl_hal_sp {
    _Atomic bool initialized_;

    struct kmhal_binder_ctx *binder;
    bool owns_binder;

    struct kmhal_binder_txn *txn;

    bool manager_acquired;
    u32 handle;
    bool owns_handle;

    const char *fqname;
    const char *instname;
};

static enum kmhal_android_status
validate_arg_descs(const struct kmhal_hidl_hal_arg_write_desc *in_args,
                   u32 n_in_args,
                   struct kmhal_hidl_hal_arg_parse_desc *out_args,
                   u32 n_out_args);

struct kmhal_hidl_hal_sp * kmhal_hidl_hal_sp_new_empty(void)
{
    struct kmhal_hidl_hal_sp *ret = NULL;

    ret = calloc(1, sizeof(struct kmhal_hidl_hal_sp));
    if (ret == NULL) {
        s_log_error("Failed to allocate a new HAL strong pointer struct");
        return NULL;
    }
    atomic_store(&ret->initialized_, false);
    ret->binder = NULL;
    ret->owns_binder = false;
    ret->txn = NULL;
    ret->manager_acquired = false;
    ret->handle = (u32)-1;
    ret->owns_handle = false;
    ret->fqname = NULL;
    ret->instname = NULL;
    atomic_store(&ret->initialized_, true);

    return ret;
}

struct kmhal_hidl_hal_sp *
kmhal_hidl_hal_sp_new_get(const char *fqname, const char *instname,
                          struct kmhal_binder_ctx *opt_existing_binder,
                          bool owns_existing_binder)
{
    u_check_params(fqname != NULL && instname != NULL);

    struct kmhal_hidl_hal_sp *ret = NULL;

    ret = kmhal_hidl_hal_sp_new_empty();
    if (ret == NULL)
        goto err;

    if (opt_existing_binder == NULL) {
        ret->binder = kmhal_binder_open(KMHAL_BINDER_DEV_HWBINDER);
        if (ret->binder == NULL)
            goto_error("Failed to open hardware binder device");
        ret->owns_binder = true;
    } else {
        ret->binder = opt_existing_binder;
        ret->owns_binder = owns_existing_binder;
    }

    ret->fqname = fqname;
    ret->instname = instname;

    if (kmhal_hidl_util_check_allocate_txn_tmps(&ret->txn, NULL) != OK)
        goto err;

    kmhal_hidl_manager_write_acquire(ret->txn);
    if (kmhal_binder_do_write_read_ioctl(ret->binder, &ret->txn))
        goto_error("Binder acquire transactions on service manager failed");
    ret->manager_acquired = true;

    if (kmhal_hidl_manager_get(ret->binder, &ret->txn,
                ret->fqname, ret->instname, &ret->handle))
        goto_error("Failed to get() a handle to the HAL");
    else if (ret->handle == 0) {
        /* This error is expected when getting the wrong version,
         * so we might need to call this function multiple times
         * before we get the correct one, therefore we might
         * not want this error spammed */
        s_log_verbose("Invalid handle received");
        goto err;
    }
    ret->owns_handle = true;

    return ret;

err:
    if (ret != NULL)
        kmhal_hidl_hal_sp_destroy(&ret);

    return NULL;
}

void kmhal_hidl_hal_sp_destroy(struct kmhal_hidl_hal_sp **hal_p)
{
    if (hal_p == NULL || *hal_p == NULL)
        return;

    struct kmhal_hidl_hal_sp *const hal = *hal_p;

    if (!atomic_exchange(&hal->initialized_, false))
        return;

    hal->instname = NULL;
    hal->fqname = NULL;

    bool do_final_transaction = false;
    if (hal->txn != NULL)
        do_final_transaction = true;

    if (hal->handle != (u32)-1 && hal->owns_handle) {
        if (kmhal_hidl_util_check_allocate_txn_tmps(&hal->txn, NULL) != OK) {
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
        if (kmhal_hidl_util_check_allocate_txn_tmps(&hal->txn, NULL) != OK) {
            s_log_error("Failed to allocate a new binder transaction; "
                    "not dropping manager handle reference");
            goto skip_binder_refs;
        }

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
kmhal_hidl_hal_ping(struct kmhal_hidl_hal_sp *hal)
{
    if (hal == NULL || !atomic_load(&hal->initialized_)) {
        s_log_error("HAL is invalid or NULL");
        return UNEXPECTED_NULL;
    }

    return kmhal_hidl_base_ping(hal->binder, &hal->txn, hal->handle);
}

enum kmhal_android_status
kmhal_hidl_hal_call(struct kmhal_hidl_hal_sp *hal, u32 cmd,
                    const struct kmhal_hidl_hal_arg_write_desc *in_args,
                    u32 n_in_args,
                    struct kmhal_hidl_hal_arg_parse_desc *out_args,
                    u32 n_out_args)
{
    u_check_params(hal != NULL);
    enum kmhal_android_status ret = UNKNOWN_ERROR;

    if ((ret = validate_arg_descs(in_args, n_in_args, out_args, n_out_args))
            != OK)
        goto_error("Invalid argument descriptors");

    struct kmhal_parcel *p = NULL;
    kmhal_hidl_util_check_allocate_txn_tmps(&hal->txn, &p);

    kmhal_parcel_write_cstring(p, hal->fqname);
    for (u32 i = 0; i < n_in_args; i++) {
        const struct kmhal_hidl_hal_arg_write_desc *const arg = &in_args[i];
        if (arg->size == 0)
            continue;

        arg->write_proc(p, arg->data, arg->size);
    }
    kmhal_parcel_pack(hal->txn, p, hal->handle, cmd, true);

    if ((ret = kmhal_hidl_util_transact_and_unpack(hal->binder, &hal->txn, &p,
                NULL, true)) != OK)
        goto_error("Binder HIDL transaction failed");

    size_t off = KMHAL_PARCEL_HIDL_DATA_START_OFFSET;
    for (u32 i = 0; i < n_out_args; i++) {
        const struct kmhal_hidl_hal_arg_parse_desc *const arg = &out_args[i];

        if (arg->parse_proc(p, &off, arg->out_p, arg->out_size)) {
            ret = BAD_VALUE;
            goto_error("Failed to parse arg no %u \"%s\" from the reply",
                    i, arg->name);
        }
    }

err:
    kmhal_parcel_destroy(&p);
    return ret;
}

struct kmhal_binder_ctx *
kmhal_hidl_hal_get_binder(struct kmhal_hidl_hal_sp *hal,
                          bool *opt_out_owns_binder)
{
    u_check_params(hal != NULL && atomic_load(&hal->initialized_));
    if (opt_out_owns_binder != NULL) *opt_out_owns_binder = hal->owns_binder;
    return hal->binder;
}

void kmhal_hidl_hal_set_binder(struct kmhal_hidl_hal_sp *hal,
                               struct kmhal_binder_ctx *binder,
                               bool owns_binder)
{
    u_check_params(hal != NULL && atomic_load(&hal->initialized_));

    if (hal->binder != NULL && hal->owns_binder)
        kmhal_binder_close(&hal->binder);

    hal->binder = binder;
    hal->owns_binder = owns_binder;
}

u32 kmhal_hidl_hal_get_handle(const struct kmhal_hidl_hal_sp *hal,
        bool *opt_out_owns_handle)
{
    u_check_params(hal != NULL && atomic_load(&hal->initialized_));
    if (opt_out_owns_handle != NULL) *opt_out_owns_handle = hal->owns_handle;
    return hal->handle;
}

void kmhal_hidl_hal_set_handle(struct kmhal_hidl_hal_sp *hal,
                               u32 handle, bool owns_handle)
{
    u_check_params(hal != NULL && atomic_load(&hal->initialized_));

    if (hal->handle != (u32)-1 && hal->owns_handle) {
        if (kmhal_hidl_util_check_allocate_txn_tmps(&hal->txn, NULL) != OK) {
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

const char * kmhal_hidl_hal_get_fqname(const struct kmhal_hidl_hal_sp *hal)
{
    u_check_params(hal != NULL && atomic_load(&hal->initialized_));
    return hal->fqname;
}

void kmhal_hidl_hal_set_fqname(struct kmhal_hidl_hal_sp *hal,
                               const char *fqname)
{
    u_check_params(hal != NULL && atomic_load(&hal->initialized_));
    hal->fqname = fqname;
}

const char * kmhal_hidl_hal_get_instname(const struct kmhal_hidl_hal_sp *hal)
{
    u_check_params(hal != NULL && atomic_load(&hal->initialized_));
    return hal->instname;
}

void kmhal_hidl_hal_set_instname(struct kmhal_hidl_hal_sp *hal,
                                 const char *instname)
{
    u_check_params(hal != NULL && atomic_load(&hal->initialized_));
    hal->instname = instname;
}

static enum kmhal_android_status
validate_arg_descs(const struct kmhal_hidl_hal_arg_write_desc *in_args,
                   u32 n_in_args,
                   struct kmhal_hidl_hal_arg_parse_desc *out_args,
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
        const struct kmhal_hidl_hal_arg_write_desc *const arg = &in_args[i];

        if (arg->name == NULL) {
            s_log_error("In arg %u: name is NULL", i);
            ret = UNEXPECTED_NULL;
        } else if (arg->write_proc == NULL) {
            s_log_error("In arg %u: write_proc is NULL", i);
            ret = UNEXPECTED_NULL;
        } else if (arg->data == NULL && arg->size > 0) {
            s_log_error("Out arg %u: data is NULL but size > 0", i);
            ret = UNEXPECTED_NULL;
        }
    }
    for (u32 i = 0; i < n_out_args; i++) {
        const struct kmhal_hidl_hal_arg_parse_desc *const arg = &out_args[i];

        if (arg->name == NULL) {
            s_log_error("Out arg %u: name is NULL", i);
            ret = UNEXPECTED_NULL;
        } else if (arg->parse_proc == NULL) {
            s_log_error("Out arg %u: parse_proc is NULL", i);
            ret = UNEXPECTED_NULL;
        } else if (arg->out_p == NULL && arg->out_size > 0) {
            s_log_error("Out arg %u: out pointer is NULL but size > 0", i);
            ret = UNEXPECTED_NULL;
        }
    }

    return ret;
}
