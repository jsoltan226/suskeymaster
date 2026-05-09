#ifndef SUSKEYMASTER_KMHAL_HIDL_PARCEL_H_
#define SUSKEYMASTER_KMHAL_HIDL_PARCEL_H_

/**
 * PARCEL - HIDL binder parcel serializer/deserializer.
 *
 * A parcel is a container used to construct the binary wire format
 * expected by the Android binder driver and HIDL services.
 *
 * This API provides a lightweight wrapper around binder transaction
 * payload serialization. It supports:
 *
 *  - Writing aligned primitive values
 *  - Writing raw byte buffers
 *  - Writing HIDL strings using `binder_buffer_object`
 *  - Tracking binder object offsets automatically
 *  - Packing the parcel into a binder scatter-gather transaction
 *  - Retrieving transaction replies
 *
 * The parcel owns all serialized data until either:
 *
 *  - `kmhal_hidl_parcel_unpack()` is called, or
 *  - `kmhal_hidl_parcel_destroy()` is called.
 *
 * A parcel may only participate in a single pending transaction
 * at a time.
 */

#include "binderif.h"
#include <core/int.h>
#include <stddef.h>
#include <linux/android/binder.h>

#ifdef __cplusplus
namespace suskeymaster {
namespace kmhal {
namespace hidl {
extern "C" {
#endif /* __cplusplus */

/**
 * Opaque parcel object.
 *
 * Internally stores:
 *  - Serialized transaction payload data
 *  - Binder object offset tables
 *  - Scatter-gather transaction state
 */
struct kmhal_hidl_parcel;

/**
 * Allocate and initialize a new parcel.
 * The returned parcel initially contains no serialized data.
 *
 * @return New parcel instance on success, NULL on allocation failure.
 */
struct kmhal_hidl_parcel * kmhal_hidl_parcel_new(void);

/**
 * Append arbitrary bytes to the parcel payload.
 *
 * Data is aligned to a 4-byte boundary as required
 * by the binder wire protocol.
 * The provided data is copied into internal parcel storage.
 *
 * @param parcel Parcel to write into.
 * @param data Input byte buffer.
 * @param len Number of bytes to write.
 * @return 0 on success, non-zero on failure.
 */
int kmhal_hidl_parcel_write_bytes(
        struct kmhal_hidl_parcel *parcel,
        const void *data,
        size_t len
);

/**
 * Append a 32-bit unsigned integer to the parcel.
 *
 * Data is serialized using native-endian binder format
 * and aligned to 4 bytes.
 *
 * @param parcel Parcel to write into.
 * @param u Value to serialize.
 * @return 0 on success, non-zero on failure.
 */
int kmhal_hidl_parcel_write_u32(
        struct kmhal_hidl_parcel *parcel,
        const u32 u
);

/**
 * Append a 64-bit unsigned integer to the parcel.
 * Data is aligned to an 8-byte boundary.
 *
 * @param parcel Parcel to write into.
 * @param u Value to serialize.
 * @return 0 on success, non-zero on failure.
 */
int kmhal_hidl_parcel_write_u64(
        struct kmhal_hidl_parcel *parcel,
        const u64 u
);

/**
 * Serialize a UTF-8 string into the parcel.
 * The string is serialized as:
 *  - Null-terminated UTF-8 string data
 *  - A corresponding `binder_buffer_object`
 *
 * Binder object offsets are registered automatically.
 *
 * String storage and object metadata are aligned
 * to 8-byte boundaries.
 *
 * The string contents are copied into parcel-owned memory.
 *
 * @param parcel Parcel to write into.
 * @param str Null-terminated UTF-8 string.
 * @return 0 on success, non-zero on failure.
 */
int kmhal_hidl_parcel_write_string(
        struct kmhal_hidl_parcel *parcel,
        const char *str
);

/**
 * Pack the parcel into a binder scatter-gather transaction.
 *
 * This function:
 *  - Finalizes binder object pointers
 *  - Registers the parcel buffer as transaction payload
 *  - Configures scatter-gather metadata
 *  - Queues a `BC_TRANSACTION_SG` command into `txn`
 *
 * After this call the parcel enters a pending transaction state
 * and must later be consumed using either:
 *  - `kmhal_hidl_parcel_unpack()`
 *  - `kmhal_hidl_parcel_destroy()`
 *
 * A parcel must not be packed multiple times simultaneously.
 *
 * @param txn Target binder transaction command buffer.
 * @param parcel Parcel containing serialized payload data.
 * @param handle Target binder object handle.
 * @param cmd Binder/HIDL transaction command ID.
 */
void kmhal_hidl_parcel_pack(
        struct kmhal_hidl_binder_transaction *txn,
        struct kmhal_hidl_parcel *parcel,
        u32 handle,
        u32 cmd
);

/**
 * Finalize and extract the result of a packed transaction,
 * destroying the parcel in the process.
 *
 * This function validates the transaction result stored
 * inside the parcel after a successful binder ioctl cycle.
 *
 * On success, the repy data is written to `out` (if `out` is not NULL).
 * In any case, `*parcel_p` is destroyed and set to NULL.
 *
 * @param parcel_p
 *      Pointer to the parcel handle. The parcel is consumed by this function.
 *
 * @param out Optional output structure receiving reply metadata. May be NULL.
 * @return
 *      0 if the transaction completed successfully,
 *      1 if the transaction failed,
 *      negative value on API misuse or invalid state.
 */
int kmhal_hidl_parcel_unpack(
        struct kmhal_hidl_parcel **parcel_p,
        struct kmhal_hidl_binder_tr_sg_args_out *out
);

/**
 * Destroy a parcel and release all associated resources.
 *
 * Warning: If the parcel still has an active pending transaction,
 * destruction may abort depending on transaction state.
 * Preferably, use `kmhal_hidl_parcel_unpack` do destroy the parcel instead.
 *
 * `*parcel_p` is set to NULL
 * @param parcel_p Pointer to parcel to be destroyed.
 */
void kmhal_hidl_parcel_destroy(
        struct kmhal_hidl_parcel **parcel_p
);

#ifdef __cplusplus
} /* extern "C" */
} /* namespace hidl */
} /* namespace kmhal */
} /* namespace suskeymaster */
#endif /* __cplusplus */

#endif /* SUSKEYMASTER_KMHAL_HIDL_PARCEL_H_ */
