#ifndef SUSKEYMASTER_KMHAL_HIDL_MANAGER_H_
#define SUSKEYMASTER_KMHAL_HIDL_MANAGER_H_

/**
 * A wrapper around some of the HIDL IServiceManager calls.
 */

#include "base.h"
#include "binderif.h"
#include "hidl-types.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * Writes the INCREFS and ACQUIRE commands for the hwservicemanager handle.
 * Should be called before any transactions with the manager.
 *
 * @param txn The binder transaction context to write into.
 */
void kmhal_hidl_manager_write_acquire(
        struct kmhal_hidl_binder_transaction *txn
);

/**
 * Writes the DECREFS and RELEASE commands for the hwservicemanager handle.
 * Should be called after all transactions with the manager are completed.
 *
 * @param txn The binder transaction context to write into.
 */
void kmhal_hidl_manager_write_release(
        struct kmhal_hidl_binder_transaction *txn
);

/**
 * Calls the hwservicemanager method:
 *  `android.hidl.manager@1.0::IServiceManager::get(string fqName, string name)`
 *
 * @param binder A valid binder device context.
 *
 * @param txn_p A pointer to a binder transaction struct.
 *  If `*txn_p` is NULL, it will be automatically allocated.
 *  `*txn_p` is only destroyed and set to NULL in case of failure.
 *
 * @param in_fqName Fully qualified name of the interface to get, e.g.
 *  "android.hardware.keymaster@3.0::IKeymasterDevice".
 *
 * @param in_name Name of the instance of the interface to get, e.g.
 *  "default". May be NULL, and in that case "default" is used.
 *
 * @param out_service Output pointer for the returned handle
 *  to the requested HAL instance. May be NULL.
 *
 * @return `OK` on success, anything else means failure.
 *  See `enum kmhal_hidl_android_status`.
 */
enum kmhal_hidl_android_status kmhal_hidl_manager_get(
        struct kmhal_hidl_binder_ctx *binder,
        struct kmhal_hidl_binder_transaction **txn_p,

        const char *in_fqName,
        const char *in_name, /* Instance name */

        u32 *out_service
);

/**
 * Calls the hwservicemanager method:
 *  `android.hidl.manager@1.0::IServiceManager::list()`
 *
 * @param binder A valid binder device context.
 *
 * @param txn_p A pointer to a binder transaction struct.
 *  If `*txn_p` is NULL, it will be automatically allocated.
 *  `*txn_p` is only destroyed and set to NULL in case of failure.
 *
 * @param out_fqInstanceNames Optional output pointer for the returned
 *  `hidl_vec<hidl_string>` list of all the running HAL instances
 *  managed by hwservicemanager.
 *  Example output: {
 *      "android.frameworks.displayservice@1.0::IDisplayService/default",
 *      "android.frameworks.faceservice@1.0::IFaceHalService/faceservice",
 *      "android.frameworks.sensorservice@1.0::ISensorManager/default",
 *      "android.hardware.audio.effect@4.0::IEffectsFactory/default",
 *      "android.hardware.audio@4.0::IDevicesFactory/default",
 *      "android.hardware.bluetooth@1.0::IBluetoothHci/default",
 *      "android.hardware.camera.provider@2.4::ICameraProvider/internal/0",
 *      "android.hardware.cas@1.0::IMediaCasService/default",
 *      ...
 *  }
 *
 * @return `OK` on success, anything else means failure.
 *  See `enum kmhal_hidl_android_status`.
 */
enum kmhal_hidl_android_status kmhal_hidl_manager_list(
        struct kmhal_hidl_binder_ctx *binder,
        struct kmhal_hidl_binder_transaction **txn_p,

        const KMHAL_HIDL_VEC_OF_STRUCT(kmhal_hidl_string) **out_fqInstanceNames
);

/**
 * Calls the hwservicemanager method:
 *  `android.hidl.manager@1.0::IServiceManager::listByInterface(string fqName)`
 *
 * @param binder A valid binder device context.
 *
 * @param txn_p A pointer to a binder transaction struct.
 *  If `*txn_p` is NULL, it will be automatically allocated.
 *  `*txn_p` is only destroyed and set to NULL in case of failure.
 *
 * @param in_fqName The fully qualified interface name of the HAL whose
 *  instances to list, e.g. "android.hardware.keymaster@3.0::IKeymasterDevice"
 *
 * @param out_instanceNames Optional output pointer for the returned
 *  `hidl_vec<hidl_string>` list of all the running instances of the given HAL.
 *  Example output: { "default", "strongbox" }
 *
 * @return `OK` on success, anything else means failure.
 *  See `enum kmhal_hidl_android_status`.
 */
enum kmhal_hidl_android_status kmhal_hidl_manager_list_by_interface(
        struct kmhal_hidl_binder_ctx *binder,
        struct kmhal_hidl_binder_transaction **txn_p,

        const char *in_interface_name,

        const KMHAL_HIDL_VEC_OF_STRUCT(kmhal_hidl_string) **out_instanceNames
);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* SUSKEYMASTER_KMHAL_HIDL_MANAGER_H_ */
