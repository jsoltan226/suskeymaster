#ifndef SUSKEYMASTER_KMHAL_TRANSPORT_AIDL_UTIL_H_
#define SUSKEYMASTER_KMHAL_TRANSPORT_AIDL_UTIL_H_

#ifndef SUSKEYMASTER_BUILD_HOST

#include "binder.h"
#include "parcel.h"
#include "status.h"
#include <core/int.h>
#include <uchar.h>
#include <stddef.h>
#include <inttypes.h>
#include <linux/android/binder.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * From "frameworks/native/libs/binder/Parcel.cpp"
 *
 * This is written as part of the header of AIDL parcels
 * sent from the client to the server.
 * It is later parsed and validated on the server side
 * by `enforceInterface` or an equivalent function.
 */
enum kmhal_aidl_tx_header_type {
    /**
     * Used by system services (/dev/binder)
     */
    AIDL_HEADER_SYSTEM = B_PACK_CHARS('S', 'Y', 'S', 'T'),

    /**
     * Used by vendor services (/dev/vndbinder)
     */
    AIDL_HEADER_VENDOR = B_PACK_CHARS('V', 'N', 'D', 'R'),

    /**
     * Used in recovery mode
     */
    AIDL_HEADER_RECOVERY = B_PACK_CHARS('R', 'E', 'C', 'O'),

    /**
     * Used when the environment for which libbinder
     * was compiled is none of the above
     */
    AIDL_HEADER_UNKNOWN = B_PACK_CHARS('U', 'N', 'K', 'N'),
};

/**
 * Determine the appropriate client -> server AIDL parcel header type
 * based on the binder device and other environment signals.
 *
 * @param binder The binder device.
 *
 * @return The parcel header. See `enum aidl_tx_header_type`.
 */
enum kmhal_aidl_tx_header_type
kmhal_aidl_get_tx_header_type(struct kmhal_binder_ctx *binder);

/**
 * Serialize the client -> server AIDL parcel header.
 *
 * @param parcel The parcel to write into.
 *
 * @param type The header type.
 *  See `kmhal_aidl_get_tx_header_type` and `enum kmhal_aidl_tx_header_type`.
 *
 * @param iface_token The interface token of the AIDL service.
 */
void kmhal_aidl_write_tx_header(struct kmhal_parcel *parcel,
                                enum kmhal_aidl_tx_header_type type,
                                const char16_t *iface_token);

/**
 * Parse the header of a parcelable sent in a parcel
 * from the server to the client.
 *
 * @param p The parcel to read from.
 *
 * @param off_p Offset pointer which on successful read
 *  will be increment to point past the read header.
 *
 * @param out_start_off Output pointer for the data start offset.
 *  Used later when validating @out_parcelable_size.
 *  May be NULL.
 *
 * @param out_parcelable_size Output pointer for the parcelable size,
 *  as written in the header. Later, after deserializing the whole parcel,
 *  it should be validated using the following condition:
 *      `off > start_off && off - start_off == parcelable_size`
 *
 *  Where `off` is pointing past the end of the parsed parcelable,
 *  while `start_off` and `parcelable_size` are the respective
 *  @out_start_off and @out_parcelable_size values written by this function.
 *
 * @return 0 on success and non-zero on failure.
 */
int kmhal_aidl_parse_rx_parcelable_header(struct kmhal_parcel *p, size_t *off_p,
                                          size_t *out_start_off,
                                          i32 *out_parcelable_size);

/**
 * Writes the INCREFS and ACQUIRE commands for the servicemanager handle.
 * Should be called before any transactions with the manager.
 *
 * Equivalent to `kmhal_hidl_manager_write_acquire`.
 *
 * @param txn The binder transaction context to write into.
 */
void kmhal_aidl_manager_write_acquire(struct kmhal_binder_txn *txn);

/**
 * Writes the DECREFS and RELEASE commands for the hwservicemanager handle.
 * Should be called after all transactions with the manager are completed.
 *
 * Equivalent to `kmhal_hidl_manager_write_release`.
 *
 * @param txn The binder transaction context to write into.
 */
void kmhal_aidl_manager_write_release(struct kmhal_binder_txn *txn);

/**
 * Calls android.os.IServiceManager.getService to get a handle
 * to an AIDL service.
 *
 * @param binder The binder device context.
 *
 * @param txn_p Pointer to binder transaction context.
 *  It itself must not be NULL, but `*txn_p` may be, in which case
 *  a new transaction context will be allocated on-the-fly and written there.
 *  See `kmhal_util_check_allocate_txn_tmps`.
 *
 * @param hdr_type AIDL parcel header type.
 *  See `kmhal_aidl_get_tx_header_type`.
 *
 * @param in_fqname The fully qualified name of the service to get, e.g.
 *  "android.hardware.security.keymint.IKeyMintDevice". Must not be NULL.
 *
 * @param in_instname The service instance name, e.g. "default".
 *  Must not be NULL.
 *
 * @param out_handle Output pointer for the returned handle.
 *  Must not be NULL.
 *
 * @return OK on success, anything else on failure.
 */
enum kmhal_android_status
kmhal_aidl_manager_get(struct kmhal_binder_ctx *binder,
                       struct kmhal_binder_txn **txn_p,
                       enum kmhal_aidl_tx_header_type hdr_type,

                       const char *in_fqname,
                       const char *in_instname,

                       u32 *out_handle);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* SUSKEYMASTER_BUILD_HOST */

#endif /* SUSKEYMASTER_KMHAL_TRANSPORT_AIDL_UTIL_H_ */
