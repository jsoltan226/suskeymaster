#ifndef SUSKEYMASTER_KMHAL_HIDL_HAL_H_
#define SUSKEYMASTER_KMHAL_HIDL_HAL_H_

/**
 * HIDL HAL - A wrapper around HIDL HAL handles and transactions.
 */

#include "binderif.h"
#include <core/int.h>

#ifdef __cplusplus
namespace suskeymaster {
namespace kmhal {
namespace hidl {
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
                          struct kmhal_hidl_binder_ctx *opt_existing_binder,
                          bool owns_existing_binder);

/**
 * Destroys the HAL strong pointer struct and any associated resources.
 * Sets `*hal_p` to NULL afterwards.
 *
 * @param hal_p A pointer to the strong pointer struct to destroy
 */
void kmhal_hidl_hal_sp_destroy(struct kmhal_hidl_hal_sp **hal_p);

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
struct kmhal_hidl_binder_ctx *
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
                               struct kmhal_hidl_binder_ctx *binder,
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
} /* namespace hidl */
} /* namespace kmhal */
} /* namespace suskeymaster */
#endif /* __cplusplus */

#endif /* SUSKEYMASTER_KMHAL_HIDL_HAL_H_ */
