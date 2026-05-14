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
#include <stdint.h>
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
 * Opaque reference to a binder object inside a parcel.
 *
 * The reference is bound to a given parcel, so it cannot be reused.
 */
typedef u32 kmhal_hidl_parcel_obj_t;
#define KMHAL_HIDL_PARCEL_OBJ_INVALID UINT32_MAX

#define KMHAL_HIDL_PARCEL_OBJ_IS_VALID(obj) \
    ((obj) != KMHAL_HIDL_PARCEL_OBJ_INVALID)

/**
 * Allocate and initialize a new empty parcel.
 * The returned parcel initially contains no serialized data.
 *
 * @return New parcel instance on success, NULL on allocation failure.
 */
struct kmhal_hidl_parcel * kmhal_hidl_parcel_new(void);

/**
 * Allocate and initailize parcel using data from a transaction reply.
 * The returned parcel is meant to be used for deserializing
 * protocol responses, but can also later be written to and resent,
 * just like a normal parcel created with `kmhal_hidl_parcel_new`.
 *
 * @param reply The reply data returned by `kmhal_hidl_parcel_unpack`
 *  with which the new parcel is to be initialized.
 *
 * @return New initialized parcel on succcess,
 *  NULL on allocation or parsing error.
 */
struct kmhal_hidl_parcel * kmhal_hidl_parcel_new_from_reply(
        const struct kmhal_hidl_binder_tr_sg_args_out *reply
);

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
 */
void kmhal_hidl_parcel_write_bytes(struct kmhal_hidl_parcel *parcel,
                                   const void *data, size_t len);

/**
 * Write arbitrary data at an arbitrary offset to the parcel payload.
 *
 * The offset doesn't have to be aligned.
 * The parcel's buffer will be grown to acommodate the data if necessary.
 *
 * @param parcel Parcel to write into.
 * @param offset The offset at which to write.
 * @param data Input byte buffer.
 * @param len Number of bytes to write.
 */
void kmhal_hidl_parcel_patch(struct kmhal_hidl_parcel *parcel,
                             size_t offset, const void *data, size_t len);

/**
 * Append a 32-bit unsigned integer to the parcel.
 *
 * Data is serialized using native-endian binder format
 * and aligned to 4 bytes.
 *
 * @param parcel Parcel to write into.
 * @param u Value to serialize.
 */
void kmhal_hidl_parcel_write_u32(struct kmhal_hidl_parcel *parcel, u32 u);

/**
 * Append a 64-bit unsigned integer to the parcel.
 * Data is aligned to an 8-byte boundary.
 *
 * @param parcel Parcel to write into.
 * @param u Value to serialize.
 */
void kmhal_hidl_parcel_write_u64(struct kmhal_hidl_parcel *parcel, u64 u);

/**
 * Serialize a UTF-8 string into the parcel.
 *
 * The string contents are copied into parcel-owned memory.
 *
 * @param parcel Parcel to write into.
 * @param str Null-terminated C string.
 */
void kmhal_hidl_parcel_write_cstring(struct kmhal_hidl_parcel *parcel,
                                     const char *str);

/**
 * Serialize a flat_binder_objcect containing `handle` into the parcel.
 *
 * @param parcel Parcel to write into.
 * @param obj A valid `struct flat_binder_objcect`.
 * @return A reference to the newly written object.
 */
kmhal_hidl_parcel_obj_t
kmhal_hidl_parcel_write_handle(struct kmhal_hidl_parcel *parcel,
                               const struct flat_binder_object *obj);

/**
 * Serialize a binder_buffer_object into the parcel.
 *
 * @param parcel Parcel to write into.
 * @param obj A valid `struct binder_buffer_object`.
 * @return A reference to the newly written object.
 */
kmhal_hidl_parcel_obj_t
kmhal_hidl_parcel_write_buffer_obj(struct kmhal_hidl_parcel *parcel,
                                   const struct binder_buffer_object *obj);

/**
 * Get the index into the offsets array of the parcel
 * that corresponds to the given object reference.
 *
 * Note: No validation is performed against `obj`'s parcel.
 *
 * @param obj The object whose index is to be retrieved.
 *
 * @return The object's index.
 */
size_t kmhal_hidl_parcel_obj_get_idx(kmhal_hidl_parcel_obj_t obj);

/**
 * Get a reference to the object at `idx` from `parcel`'s offsets array.
 *
 * @param parcel The parcel containg the object to be retrieved.
 * @param idx Index into @parcel's offsets array.
 *
 * @return A reference to the object or NULL if it doesn't exist.
 */
kmhal_hidl_parcel_obj_t
kmhal_hidl_parcel_get_obj(const struct kmhal_hidl_parcel *parcel, size_t idx);

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
void kmhal_hidl_parcel_pack(struct kmhal_hidl_binder_transaction *txn,
                            struct kmhal_hidl_parcel *parcel,
                            u32 handle, u32 cmd);

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
int kmhal_hidl_parcel_unpack(struct kmhal_hidl_parcel **parcel_p,
                             struct kmhal_hidl_binder_tr_sg_args_out *out);

/* Read arbitrary data at an arbitrary offset from the parcel's buffer.
 * The offset doesn't have to be aligned.
 *
 * @param parcel The parcel from which to read.
 * @param offset The offset at which to start reading.
 * @param out Optional output pointer. May be NULL, but why would you do that?
 * @param len The amount of data to read.
 *  If @out is not NULL, the provided buffer must be at least @len long.
 *
 * @return 0 on success, non-zero if the requested range is out of bounds.
 */
int kmhal_hidl_parcel_peek(const struct kmhal_hidl_parcel *parcel,
                           size_t offset, void *out, size_t len);

/* Read a uint32 value from the parcel's buffer.
 * The offset must be 4-byte aligned.
 *
 * @param parcel Parcel from which the value will be read.
 * @param offset 4-byte-aligned offset of the integer value.
 * @param out Output pointer, may be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
int kmhal_hidl_parcel_read_u32(const struct kmhal_hidl_parcel *parcel,
                               binder_size_t offset, u32 *out);

/* Read a uint64 value from the parcel's buffer.
 * The offset must be 4-byte aligned.
 *
 * @param parcel Parcel from which the value will be read.
 * @param offset 4-byte-aligned offset of the integer value.
 * @param out Output pointer, may be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
int kmhal_hidl_parcel_read_u64(const struct kmhal_hidl_parcel *parcel,
                               binder_size_t offset, u64 *out);

/* Read a flat_binder_object from the parcel's buffer.
 *
 * @param parcel Parcel from which the object will be read.
 * @param obj A reference to the object to read.
 *  See `kmhal_hidl_parcel_get_obj.`
 * @param out Output pointer, may be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
int kmhal_hidl_parcel_read_handle(const struct kmhal_hidl_parcel *parcel,
                                  kmhal_hidl_parcel_obj_t obj,
                                  struct flat_binder_object *out);

/* Read a binder_buffer_object from the parcel's buffer.
 *
 * @param parcel Parcel from which the object will be read.
 * @param obj A reference to the object to read.
 *  See `kmhal_hidl_parcel_get_obj.`
 * @param out Output pointer, may be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
int kmhal_hidl_parcel_read_buffer_obj(const struct kmhal_hidl_parcel *parcel,
                                      kmhal_hidl_parcel_obj_t obj,
                                      struct binder_buffer_object *out);

/**
 * Destroy a parcel and release all associated resources.
 *
 * Warning: If the parcel still has an active pending transaction,
 * destruction may abort depending on transaction state.
 * Preferably, use `kmhal_hidl_parcel_unpack` do destroy the parcel instead.
 *
 * `*parcel_p` is set to NULL.
 *
 * @param parcel_p Pointer to parcel to be destroyed.
 */
void kmhal_hidl_parcel_destroy(struct kmhal_hidl_parcel **parcel_p);

#ifdef __cplusplus
} /* extern "C" */
} /* namespace hidl */
} /* namespace kmhal */
} /* namespace suskeymaster */
#endif /* __cplusplus */

#endif /* SUSKEYMASTER_KMHAL_HIDL_PARCEL_H_ */
