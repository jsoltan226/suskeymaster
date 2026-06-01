#ifndef SUSKEYMASTER_KMHAL_HIDL_HAL_H_
#define SUSKEYMASTER_KMHAL_HIDL_HAL_H_

/**
 * HIDL HAL - A wrapper around HIDL HAL handles and transactions.
 */

#include "binder.h"
#include "parcel.h"
#include "hidl-base.h"
#include "hidl-types.h"
#include <core/int.h>
#include <core/log.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Opaque reference to a HAL strong pointer and associated data */
struct kmhal_hidl_hal_sp;

/**
 * Allocates and initializes a new HAL strong pointer struct.
 * The returned struct is empty and not ready for use.
 * You are probably looking for `kmhal_hidl_hal_sp_new_get`.
 *
 * @return A new HAL strong pointer struct, or NULL on allocation failure.
 */
struct kmhal_hidl_hal_sp * kmhal_hidl_hal_sp_new_empty(void);

/**
 * Allocates a new HAL strong pointer struct, and tries to initialize
 * it with a handle to the requested HAL instance.
 *
 * @param fqname The fully qualified name of the HAL interface, e.g.
 *  "android.hardware.keymaster@3.0::IKeymasterDevice".
 *
 * @param instname The name of the HAL instance.
 *  If NULL, "default" is used.
 *
 * @param opt_existing_binder Optionally, an existing valid binder device
 *  context. If NULL, a new one will be allocated and initialized internally.
 *
 * @param owns_existing_binder Whether or not the provided binder device context
 *  should be automatically destroyed in `kmhal_hidl_hal_sp_destroy`.
 *  Ignored if `opt_existing_binder` is NULL.
 *
 * @return On success, a new HAL strong pointer initialized with a handle
 *  to the requested HAL, or NULL on failure.
 */
struct kmhal_hidl_hal_sp *
kmhal_hidl_hal_sp_new_get(const char *fqname, const char *instname,
                          struct kmhal_binder_ctx *opt_existing_binder,
                          bool owns_existing_binder);

/**
 * Destroys the HAL strong pointer struct and any associated resources.
 * Sets `*hal_p` to NULL afterwards.
 *
 * @param hal_p A pointer to the strong pointer struct to destroy
 */
void kmhal_hidl_hal_sp_destroy(struct kmhal_hidl_hal_sp **hal_p);

/**
 * Calls `kmhal_hidl_base_ping` on the HAL instance.
 *
 * @param hal The HAL instance to ping.
 *
 * @return OK if successful, anything else otherwise.
 */
enum kmhal_android_status
kmhal_hidl_hal_ping(struct kmhal_hidl_hal_sp *hal);

/**
 * A function that writes the given data type into a parcel.
 * It should abort on `size` mismatch.
 */
typedef void (*kmhal_hidl_hal_arg_write_proc_t)(struct kmhal_parcel *,
                                                const void *data, size_t size);
/**
 * Descriptor for an input argument passed to an HIDL call.
 * For example, for IKeymasterDevice::addRngEntropy
 * the `hidl_vec<uint8_t> data` would be the only argument.
 * See `kmhal_hidl_hal_call`.
 */
struct kmhal_hidl_hal_arg_write_desc {
    const char *name; /* The name of the argument. Must not be NULL. */

    /* The input data buffer, of size `size`.
     * Must not be NULL if `size` is > 0. */
    const void *data;
    size_t size; /* Size of the input data buffer `data`. */

    /* The function that performs the serialization. Must not be NULL. */
    kmhal_hidl_hal_arg_write_proc_t write_proc;
};

/**
 * A function that reads the given data type from a parcel.
 * It should return 0 on success and non-zero on failure
 * or `exp_out_size` mismatch, and write to `out` only on success.
 *
 * If the given type is a primitive type, `*out_p` should contain
 * the immediate value. Otherwise, it should contain a const pointer
 * to binder memory.
 *
 * See `kmhal_hidl_hal_call`.
 */
typedef int (*kmhal_hidl_hal_arg_parse_proc_t)(const struct kmhal_parcel *p,
                                               size_t *off_p,
                                               const void **out_p,
                                               size_t exp_out_size);
/**
 * Descriptor for an output (returned) argument from an HIDL call.
 * For example, for IKeymasterDevice::addRngEntropy
 * the returned `ErrorCode` would be the only output argument.
 * See `kmhal_hidl_hal_call`.
 */
struct kmhal_hidl_hal_arg_parse_desc {
    const char *name; /* The name of the argument. Must not be NULL. */

    /* The output pointer, of size `out_size`.
     * Must not be NULL if `out_size` is > 0. */
    const void **out_p;
    size_t out_size; /* Size of the output `*out_p`. */

    /* The function that performs the deserialization. Must not be NULL. */
    kmhal_hidl_hal_arg_parse_proc_t parse_proc;
};

/**
 * Calls a given method on a HAL using provided arguments
 * and parses the returned data.
 *
 * @param hal The HAL to transact with.
 *
 * @param cmd The command ID of the HAL method.
 *
 * @param in_args A list of descriptors of the method's arguments.
 *  Can be NULL only if the method doesn't take any arguments,
 *  in which case @n_in_args should also be set to 0.
 *
 * @param n_in_args The number of members of the @in_args array.
 *
 * @param in_args A list of descriptors of the method's return values.
 *  Can be NULL only if the method doesn't return anything,
 *  in which case @n_out_args should also be set to 0.
 *
 * @param n_out_args The number of members of the @in_args array.
 *
 * @return OK on success, anything else on failure.
 *  See `enum kmhal_android_status`.
 */
enum kmhal_android_status
kmhal_hidl_hal_call(struct kmhal_hidl_hal_sp *hal, u32 cmd,
                    const struct kmhal_hidl_hal_arg_write_desc *in_args,
                    u32 n_in_args,
                    struct kmhal_hidl_hal_arg_parse_desc *out_args,
                    u32 n_out_args);

/** Serialization and deserialization functions for common HIDL types **/

static inline void kmhal_hidl_hal_arg_write_u32(struct kmhal_parcel *p,
                                                const void *data, size_t size)
{
    if (size != sizeof(u32))
        s_abort("hidl-hal", __func__, "Invalid size");
    else if (data == NULL)
        s_abort("hidl-hal", __func__, "Data is NULL");

    kmhal_parcel_write_u32(p, *(u32 *)data);
}

static inline void kmhal_hidl_hal_arg_write_u64(struct kmhal_parcel *p,
                                                const void *data, size_t size)
{
    if (size != sizeof(u64))
        s_abort("hidl-hal", __func__, "Invalid size");
    else if (data == NULL)
        s_abort("hidl-hal", __func__, "Data is NULL");

    kmhal_parcel_write_u64(p, *(u64 *)data);
}

static inline void
kmhal_hidl_hal_arg_write_hidl_string(struct kmhal_parcel *p,
                                     const void *data,
                                     size_t size)
{
    if (size != sizeof(struct kmhal_hidl_string))
        s_abort("hidl-hal", __func__, "Invalid size");
    else if (data == NULL)
        s_abort("hidl-hal", __func__, "Data is NULL");

    kmhal_hidl_string_write(p, (const struct kmhal_hidl_string *)data,
                            KMHAL_PARCEL_OBJ_INVALID, 0, NULL);
}

static inline int
kmhal_hidl_hal_arg_parse_u32(const struct kmhal_parcel *p,
                             size_t *off_p,
                             const void **out_p, size_t out_size)
{
    if (out_size != sizeof(u32)) {
        s_log(S_LOG_ERROR, "hidl-hal", "%s: Invalid size", __func__);
        return -1;
    } else if (out_p == NULL) {
        s_log(S_LOG_ERROR, "hidl-hal", "%s: Output pointer is NULL", __func__);
        return -1;
    }

    return kmhal_parcel_read_u32(p, off_p, (u32 *)out_p);
}

static inline int
kmhal_hidl_hal_arg_parse_u64(const struct kmhal_parcel *p,
                             size_t *off_p,
                             const void **out_p, size_t out_size)
{
    if (out_size != sizeof(u64)) {
        s_log(S_LOG_ERROR, "hidl-hal", "%s: Invalid size", __func__);
        return -1;
    } else if (out_p == NULL) {
        s_log(S_LOG_ERROR, "hidl-hal", "%s: Output pointer is NULL", __func__);
        return -1;
    }

    return kmhal_parcel_read_u64(p, off_p, (u64 *)out_p);
}

static inline int
kmhal_hidl_hal_arg_parse_hidl_string(const struct kmhal_parcel *p,
                                     size_t *off_p,
                                     const void **out_p, size_t out_size)
{
    if (out_size != sizeof(struct kmhal_hidl_string)) {
        s_log(S_LOG_ERROR, "hidl-hal", "%s: Invalid size", __func__);
        return -1;
    } else if (out_p == NULL) {
        s_log(S_LOG_ERROR, "hidl-hal", "%s: Output pointer is NULL", __func__);
        return -1;
    }

    return kmhal_hidl_string_read((const struct kmhal_hidl_string **)out_p, p,
            off_p, NULL);
}

/**
 * A getter for the currently used binder device context.
 *
 * @param hal The HAL strong pointer struct.
 *
 * @param opt_out_owns_binder An optional output pointer for whether
 *  the binder device context is set to be cleaned up automatically
 *  during destruction.
 *
 * @return @hal's binder device context.
 */
struct kmhal_binder_ctx *
kmhal_hidl_hal_get_binder(struct kmhal_hidl_hal_sp *hal,
                          bool *opt_out_owns_binder);

/**
 * A setter for the binder device context.
 * If @hal already contains and owns an existing context,
 * it is destroyed before being overwritten by the new one.
 *
 * @param hal The HAL strong pointer struct.
 *
 * @param binder The new binder device context.
 *
 * @param owns_binder Whether @binder should be set to be cleaned up
 *  automatically during @hal's destruction.
 */
void kmhal_hidl_hal_set_binder(struct kmhal_hidl_hal_sp *hal,
                               struct kmhal_binder_ctx *binder,
                               bool owns_binder);

/**
 * A getter for the currently used HAL binder handle.
 *
 * @param hal The HAL strong pointer struct.
 *
 * @param opt_out_owns_handle An optional output pointer for whether
 *  the binder handle is set to be released automatically
 *  during @hal's destruction.
 *
 * @return @hal's binder device context.
 */
u32 kmhal_hidl_hal_get_handle(const struct kmhal_hidl_hal_sp *hal,
                              bool *opt_out_owns_handle);

/**
 * A setter for the HAL binder handle.
 *
 * @param hal The HAL strong pointer struct.
 * If @hal already contains and owns an existing handle,
 * the references on it are dropped before the overwrite with the new one.
 *
 * @param handle The new HAL binder handle.
 *
 * @param owns_handle Whether references to @handle should be set to be
 *  automatically dropped during @hal's destruction.
 */
void kmhal_hidl_hal_set_handle(struct kmhal_hidl_hal_sp *hal,
                               u32 handle, bool owns_handle);

/**
 * A getter for the fully qualified interface name of the HAL
 * referenced by the strong pointer struct.
 *
 * @param hal The HAL strong pointer struct.
 *
 * @return The fully qualified interface name of @hal, e.g.
 *  "android.hardware.keymaster@3.0::IKeymasterDevice".
 */
const char * kmhal_hidl_hal_get_fqname(const struct kmhal_hidl_hal_sp *hal);

/**
 * A setter for the fully qualified interface name of the HAL
 * referenced by the strong pointer struct.
 *
 * @param hal The HAL strong pointer struct.
 *
 * @param fqname The new fully qualified interface name, e.g.
 *  "android.hardware.keymaster@3.0::IKeymasterDevice".
 */
void kmhal_hidl_hal_set_fqname(struct kmhal_hidl_hal_sp *hal,
                               const char *fqname);

/**
 * A getter for the instance name of the HAL
 * referenced by the strong pointer struct.
 *
 * @param hal The HAL strong pointer struct.
 *
 * @return The instance name of @hal, e.g. "default".
 */
const char * kmhal_hidl_hal_get_instname(const struct kmhal_hidl_hal_sp *hal);

/**
 * A setter for the instance name of the HAL
 * referenced by the strong pointer struct.
 *
 * @param hal The HAL strong pointer struct.
 *
 * @param fqname The new instance name, e.g. "default".
 */
void kmhal_hidl_hal_set_instname(struct kmhal_hidl_hal_sp *hal,
                                 const char *instname);


#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* SUSKEYMASTER_KMHAL_HIDL_HAL_H_ */
