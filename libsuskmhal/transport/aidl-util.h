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

#define KMHAL_AIDL_NULL_FLAG INT32_C(0)
#define KMHAL_AIDL_PRESENT_FLAG INT32_C(1)

#define KMHAL_AIDL_NULL_FLAG_SIZE sizeof(i32)
#define KMHAL_AIDL_PRESENT_FLAG_SIZE sizeof(i32)

/**
 * Parse the header of a parcelable sent in a parcel.
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
 * @param nullable Whether it is accepted that the parcel has a nullopt
 *  value (@Nullable AIDL annotation).
 *
 * @param out_parcelable_size Output pointer for the parcelable size,
 *  as written in the header. Later, after deserializing the whole parcel,
 *  it should be validated using `kmhal_aidl_validate_parcelable_size`.
 *  If @nullable was set and the read value is a nullopt,
 *  *out_union_field_id will contain the value `UINT32_MAX`.
 *  This output pointer must not be NULL.
 *
 *  Where `off` is pointing past the end of the parsed parcelable,
 *  while `start_off` and `parcelable_size` are the respective
 *  @out_start_off and @out_parcelable_size values written by this function.
 *
 * @return 0 on success and non-zero on failure.
 */
int kmhal_aidl_parse_parcelable_header(const struct kmhal_parcel *p,
                                       size_t *off_p,
                                       size_t *out_start_off, bool nullable,
                                       i32 *out_parcelable_size);

/**
 * Validate previously parsed parcelable size
 *  (see `kmhal_aidl_parse_parcelable_header`).
 *
 * @param start The @out_start_off returned by
 *  `kmhal_aidl_parse_parcelable_header`.
 *
 * @param cur The current value of `*off_p`.
 *
 * @param parcelable_size The @out_parcelable_size returned by
 *  `kmhal_aidl_parse_parcelable_header`.
 *
 * @return 0 If the the parcelable size is valid, non-zero otherwise.
 */
int kmhal_aidl_validate_parcelable_size(size_t start, size_t cur,
                                        i32 parcelable_size);

/**
 * Parse the header of a union sent in a parcel.
 *
 * @param p The parcel to read from.
 *
 * @param off_p Offset pointer which on successful read
 *  will be increment to point past the read header.
 *
 * @param nullable Whether it is accepted that the parcel has a nullopt
 *  value (@Nullable AIDL annotation).
 *
 * @param out_union_field_id Output pointer for the union field ID.
 *  This ID represents which of the union's fields is actually used.
 *  If @nullable was set and the read value is a nullopt,
 *  *out_union_field_id will contain the value `UINT32_MAX`.
 *  This output pointer must not be NULL.
 *
 * Here's an explanation of the meaning of @out_union_field_id:
 *
 *  E.g. it's known that in the IntegerParams union,
 *  the enum KM_Digest `digest` member (ID 4) takes 4 bytes,
 *  while `longInteger` (ID 12) takes 8 bytes.
 *
 *  This is done to save space (i guess?) while serializing a union,
 *  like in this situation:
 *      union {
 *          u32 value; // ID 0
 *          u8 veryLargeBuffer[1024]; // ID 1
 *      }
 *  If we only use the `value` member,
 *  only 4 bytes will be written for it + the 4 bytes for its ID `0`.
 *
 *  Obviously, every union has its own list of IDs and the caller
 *  should interpret it accordingly.
 *
 * @return 0 on success and non-zero on failure.
 */
int kmhal_aidl_parse_union_header(const struct kmhal_parcel *p, size_t *off_p,
                                  bool nullable, u32 *out_union_field_id);

/**
 * Parse the headers of an array sent in a parcel.
 *
 * @param p The parcel to read from.
 *
 * @param off_p Offset pointer which on successful read
 *  will be increment to point past the read header.
 *
 * @param out_array_size Output pointer for the number of elements in the array.
 *  If @nullable was set and the read value is a nullopt,
 *  `*out_array_size` will contain the value `-1`.
 *  Must not be NULL.
 *
 * @return 0 on success and non-zero on failure.
 */
int kmhal_aidl_parse_array_header(const struct kmhal_parcel *p, size_t *off_p,
                                  i32 *out_array_size);

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

/* See "frameworks/native/libs/binder/include/binder/IBinder.h" in AOSP */
enum kmhal_aidl_transaction_ids {
    AIDL_FIRST_CALL_TRANSACTION = 0x00000001,
    AIDL_LAST_CALL_TRANSACTION = 0x00ffffff,

    /** AIDL "meta" transactions -
     ** special methods shared by all AIDL interfaces, similar to hidlbase **/

    /* "frameworks/native/libs/binder/ndk/ibinder.cpp",
     * "system/tools/aidl/aidl.cpp" */

    /* IDs for meta transactions. Most of the meta transactions are implemented
     * in the framework side (Binder.java or Binder.cpp).
     * But these are the ones that are auto-implemented by the AIDL compiler. */

    /* Additional meta transactions implemented by AIDL should use
     * kFirstMetaMethodId -1, -2, ...and so on. */

    /* Note: In AOSP, `*_METHOD_ID` mean offsets from
     * `AIDL_FIRST_CALL_TRANSACTION`, but here, for convenience,
     * we define them as absolute values. */
    AIDL_FIRST_META_METHOD_ID = AIDL_LAST_CALL_TRANSACTION,

    /* Reserve 100 IDs for meta methods, which is more than enough.
     * If we don't reserve, in the future, a newly added meta transaction ID
     * will have a chance to collide with the user-defined methods
     * that were added in the past. So, let's prevent users from using IDs
     * in this range from the beginning. */
    AIDL_LAST_META_METHOD_ID = AIDL_FIRST_META_METHOD_ID - 99,

    /* AIDL getInterfaceVersion */
    AIDL_META_CMD_GET_INTERFACE_VERSION = AIDL_FIRST_META_METHOD_ID,

    /* AIDL getInterfaceHash */
    AIDL_META_CMD_GET_INTERFACE_HASH = AIDL_FIRST_META_METHOD_ID - 1,

    /* Range of IDs that is allowed for user-defined methods. */
    AIDL_FIRST_USER_METHOD_ID = AIDL_FIRST_CALL_TRANSACTION,
    AIDL_LAST_USER_METHOD_ID = AIDL_LAST_META_METHOD_ID - 1,

    /** Special transaction codes **/

    AIDL_PING_TRANSACTION = B_PACK_CHARS('_', 'P', 'N', 'G'),
    AIDL_START_RECORDING_TRANSACTION = B_PACK_CHARS('_', 'S', 'R', 'D'),
    AIDL_STOP_RECORDING_TRANSACTION = B_PACK_CHARS('_', 'E', 'R', 'D'),
    AIDL_DUMP_TRANSACTION = B_PACK_CHARS('_', 'D', 'M', 'P'),
    AIDL_SHELL_COMMAND_TRANSACTION = B_PACK_CHARS('_', 'C', 'M', 'D'),
    AIDL_INTERFACE_TRANSACTION = B_PACK_CHARS('_', 'N', 'T', 'F'),
    AIDL_SYSPROPS_TRANSACTION = B_PACK_CHARS('_', 'S', 'P', 'R'),
    AIDL_EXTENSION_TRANSACTION = B_PACK_CHARS('_', 'E', 'X', 'T'),
    AIDL_DEBUG_PID_TRANSACTION = B_PACK_CHARS('_', 'P', 'I', 'D'),
    AIDL_SET_RPC_CLIENT_TRANSACTION = B_PACK_CHARS('_', 'R', 'P', 'C'),

    /* See android.os.IBinder.TWEET_TRANSACTION
     * Most importantly, messages can be anything not exceeding 130 UTF-8
     * characters, and callees should exclaim "jolly good message old boy!" */
    AIDL_TWEET_TRANSACTION = B_PACK_CHARS('_', 'T', 'W', 'T'),

    /* See android.os.IBinder.LIKE_TRANSACTION
     * Improve binder self-esteem. */
    AIDL_LIKE_TRANSACTION = B_PACK_CHARS('_', 'L', 'I', 'K'),

    /** Transaction/binder flags **/

    /* Corresponds to TF_ONE_WAY -- an asynchronous call. */
    AIDL_FLAG_ONEWAY = 0x00000001,

    /* Corresponds to TF_CLEAR_BUF -- clear transaction buffers after call
     * is made */
    AIDL_FLAG_CLEAR_BUF = 0x00000020,

    /* Private userspace flag for transaction which is being requested from
     * a vendor context. */
    AIDL_FLAG_PRIVATE_VENDOR = 0x10000000,
};

/**
 * Pings the given AIDL service.
 *
 * @param binder The binder device context.
 *
 * @param txn_p Pointer to binder transaction context.
 *  It itself must not be NULL, but `*txn_p` may be, in which case
 *  a new transaction context will be allocated on-the-fly and written there.
 *  See `kmhal_util_check_allocate_txn_tmps`.
 *
 * @param handle A handle to the service to ping.
 *
 * @return OK on success, anything else otherwise.
 */
enum kmhal_android_status
kmhal_aidl_ping(struct kmhal_binder_ctx *binder,
                struct kmhal_binder_txn **txn_p,
                u32 handle);

/**
 * Calls the special `getInterfaceVersion` method on the given AIDL service.
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
 * @param interface_token The interface token (fqname) of the service.
 *
 * @param in_handle A handle to the AIDL server
 *  whose interface version is to be queried.
 *
 * @param out_interface_version Output pointer
 *  for the returned interface version. Must not be NULL.
 *
 * @return OK on success, anything else on failure.
 */
enum kmhal_android_status
kmhal_aidl_get_interface_version(struct kmhal_binder_ctx *binder,
                                 struct kmhal_binder_txn **txn_p,
                                 enum kmhal_aidl_tx_header_type hdr_type,
                                 const char16_t *interface_token,

                                 u32 in_handle,

                                 i32 *out_interface_version);

/** Serialization/Deserialization primitives for common AIDL types
 * (see `hal.h`) **/

/**
 * See `kmhal_parcel_write_aidl_string16`.
 *
 * @param data The `const char16_t *` u'\0'-terminated UTF-16 string to write.
 */
void kmhal_aidl_write_string16(struct kmhal_parcel *parcel, const void *data);

/**
 * See `kmhal_parcel_write_convert_aidl_string16`.
 *
 * @param data The `const char *` '\0'-terminated C string
 *  to convert to `char16_t *` and then write.
 */
void kmhal_aidl_write_convert_string16(struct kmhal_parcel *parcel,
                                       const void *data);

/**
 * See `kmhal_parcel_read_aidl_string16`.
 *
 * @param out a char_16 **out_str16p; after successful conversion,
 *  a new malloc'd string (char16_t *) will be written there.
 *  The user should later free it.
 *
 * @param out_size sizeof(char16_t *).
 */
int kmhal_aidl_parse_string16(const struct kmhal_parcel *parcel, size_t *off_p,
                              void *out, size_t out_size);

/**
 * See `kmhal_parcel_read_convert_aidl_string16`.
 *
 * @param out a char **out_str8; after successful conversion,
 *  a new malloc'd string (char *) will be written there.
 *  The user should later free it.
 *
 * @param out_size sizeof(char *).
 */
int kmhal_aidl_parse_convert_string16(const struct kmhal_parcel *parcel,
                                      size_t *off_p,
                                      void *out, size_t out_size);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* SUSKEYMASTER_BUILD_HOST */

#endif /* SUSKEYMASTER_KMHAL_TRANSPORT_AIDL_UTIL_H_ */
