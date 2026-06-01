#ifndef SUSKEYMASTER_KMHAL_PARCEL_H_
#define SUSKEYMASTER_KMHAL_PARCEL_H_

/**
 * PARCEL - HIDL & AIDL binder parcel serializer/deserializer.
 *
 * A parcel is a container used to construct the binary wire format
 * expected by the Android binder driver and HIDL or AIDL services.
 *
 * This API provides a lightweight wrapper around binder transaction
 * payload serialization. It supports:
 *
 *  - Writing aligned primitive values
 *  - Writing raw byte buffers
 *  - Tracking binder object offsets automatically
 *  - Packing the parcel into a binder scatter-gather transaction
 *  - Retrieving transaction replies
 *  - etc
 *
 * The parcel owns all serialized data until either:
 *
 *  - `kmhal_parcel_unpack()` is called, or
 *  - `kmhal_parcel_destroy()` is called.
 *
 * A parcel may only participate in a single pending transaction
 * at a time.
 */

#include "binder.h"
#include <core/int.h>
#include <uchar.h>
#include <stdint.h>
#include <stddef.h>
#include <linux/android/binder.h>

#ifdef __cplusplus
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
struct kmhal_parcel;

/**
 * Opaque reference to a binder object inside a parcel.
 *
 * The reference is bound to a given parcel, so it cannot be reused.
 */
typedef u32 kmhal_parcel_obj_t;
#define KMHAL_PARCEL_OBJ_INVALID ((kmhal_parcel_obj_t)UINT32_MAX)

#define KMHAL_PARCEL_OBJ_IS_VALID(obj) \
    ((obj) != KMHAL_PARCEL_OBJ_INVALID)

/* The first 4 bytes of an HIDL parcel are always the status code,
 * and so the actual data only starts after it,
 * while in AIDL, if there is any data returned, it is preceded by
 * an exception code which is also 4 bytes in size */
#define KMHAL_PARCEL_DATA_START_OFFSET (sizeof(u32))

/**
 * Allocate and initialize a new empty parcel.
 * The returned parcel initially contains no serialized data.
 *
 * @return New parcel instance on success, NULL on allocation failure.
 */
struct kmhal_parcel * kmhal_parcel_new(void);

/**
 * Allocate and initailize parcel using data from a transaction reply.
 * The returned parcel is meant to be used for deserializing
 * protocol responses, but can also later be written to and resent,
 * just like a normal parcel created with `kmhal_parcel_new`.
 *
 * @param reply The reply data returned by `kmhal_parcel_unpack`
 *  with which the new parcel is to be initialized.
 *
 * @return New initialized parcel on succcess,
 *  NULL on allocation or parsing error.
 */
struct kmhal_parcel *
kmhal_parcel_new_from_reply(const struct kmhal_binder_txn_args_out *reply);

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
void kmhal_parcel_write_bytes(struct kmhal_parcel *parcel,
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
void kmhal_parcel_patch(struct kmhal_parcel *parcel,
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
void kmhal_parcel_write_u32(struct kmhal_parcel *parcel, u32 u);

/**
 * Append a 64-bit unsigned integer to the parcel.
 * Data is aligned to an 8-byte boundary.
 *
 * @param parcel Parcel to write into.
 * @param u Value to serialize.
 */
void kmhal_parcel_write_u64(struct kmhal_parcel *parcel, u64 u);

/**
 * Serialize a UTF-8 string into the parcel.
 *
 * The string contents are copied into parcel-owned memory.
 *
 * @param parcel Parcel to write into.
 * @param str Null-terminated (UTF-8) C string.
 */
void kmhal_parcel_write_cstring(struct kmhal_parcel *parcel, const char *str);

/**
 * Serialize a UTF-16 string into the parcel in the AIDL format:
 * [length: i32][contents...: utf16 string]
 *
 * The string contents are copied into parcel-owned memory.
 *
 * @param parcel Parcel to write into.
 * @param str Null-terminated UTF-16 string.
 */
void kmhal_parcel_write_aidl_string16(struct kmhal_parcel *parcel,
                                      const char16_t *str16);

/**
 * Convert a UTF-8 string to UTF-16 and then serialize it into the parcel
 * in the AIDL format: [length: i32][contents...: utf16 string]
 *
 * The converted string contents are copied into parcel-owned memory.
 *
 * @param parcel Parcel to write into.
 * @param str Null-terminated (UTF-8) C string.
 */
void kmhal_parcel_write_convert_aidl_string16(struct kmhal_parcel *parcel,
                                              const char *str8);

/**
 * Serialize a flat_binder_objcect containing `handle` into the parcel.
 *
 * @param parcel Parcel to write into.
 * @param obj A valid `struct flat_binder_objcect`.
 * @return A reference to the newly written object.
 */
kmhal_parcel_obj_t
kmhal_parcel_write_handle(struct kmhal_parcel *parcel,
                          const struct flat_binder_object *obj);

/**
 * Serialize a binder_buffer_object into the parcel.
 *
 * @param parcel Parcel to write into.
 * @param obj A valid `struct binder_buffer_object`.
 * @return A reference to the newly written object.
 */
kmhal_parcel_obj_t
kmhal_parcel_write_buffer_obj(struct kmhal_parcel *parcel,
                                   const void *buffer, size_t buffer_size,
                                   u32 flags, kmhal_parcel_obj_t parent,
                                   binder_size_t parent_offset);

/**
 * Serialize an embedded binder_buffer_object into the parcel.
 *
 * This creates a binder buffer object whose contents are logically
 * embedded inside another buffer object already present in the parcel.
 *
 * Internally this emits a `binder_buffer_object` with the
 * `BINDER_BUFFER_FLAG_HAS_PARENT` flag set and records the parent-child
 * relationship expected by the binder driver.
 *
 * The embedded buffer contents are copied into parcel-owned storage.
 *
 * @param parcel Parcel to write into.
 *
 * @param buf Pointer to the embedded buffer contents.
 *
 * @param buf_size Size of the embedded buffer in bytes.
 *
 * @param parent Reference to the parent buffer object into which the
 *      embedded buffer is attached.
 *      Must refer to a valid `binder_buffer_object` already written
 *      into the same parcel.
 *
 * @param parent_offset Byte offset within the parent buffer at which
 *      the embedded object pointer resides.
 *
 * @return Reference to the newly written embedded buffer object.
 *      This function never fails non-fatally.
 */
kmhal_parcel_obj_t
kmhal_parcel_write_embedded_buffer(struct kmhal_parcel *parcel,
                                   const void *buf, size_t buf_size,
                                   kmhal_parcel_obj_t parent,
                                   binder_size_t parent_offset);

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
size_t kmhal_parcel_obj_idx(kmhal_parcel_obj_t obj);

/**
 * Get a reference to the object at `idx` from `parcel`'s offsets array.
 *
 * @param parcel The parcel containg the object to be retrieved.
 * @param idx Index into @parcel's offsets array.
 *
 * @return A reference to the object or
 *  `KMHAL_PARCEL_OBJ_INVALID` if it doesn't exist.
 */
kmhal_parcel_obj_t
kmhal_parcel_obj_get(const struct kmhal_parcel *parcel, size_t idx);

/**
 * Find an object in the parcel's list based on its offset.
 *
 * @param parcel The parcel to search in.
 *
 * @param off The offset of the object.
 *
 * @return A reference to the found object or
 *  `KMHAL_PARCEL_OBJ_INVALID` if it doesn't exist.
 */
kmhal_parcel_obj_t
kmhal_parcel_obj_find_by_offset(const struct kmhal_parcel *parcel,
                                size_t offset);

/**
 * Pack the parcel into a binder scatter-gather transaction.
 *
 * This function:
 *  - Finalizes binder object pointers
 *  - Registers the parcel buffer as transaction payload
 *  - Configures scatter-gather metadata
 *  - Queues a `BC_TRANSACTION(_SG)` command into `txn`
 *
 * After this call the parcel enters a pending transaction state
 * and must later be consumed using either:
 *  - `kmhal_parcel_unpack()`
 *  - `kmhal_parcel_destroy()`
 *
 * A parcel must not be packed multiple times simultaneously.
 *
 * @param txn Target binder transaction command buffer.
 *
 * @param parcel Parcel containing serialized payload data.
 *
 * @param handle Target binder object handle.
 *
 * @param cmd Binder/HIDL/AIDL transaction command ID.
 *
 * @param scatter_gather Whether to use `BC_TRANSACTION_SG`
 *  instead of `BC_TRANSACTION`. Set this to `1` if any buffer objects
 *  have been written into the parcel, `0` if none were written
 *  or `-1` to decide automatically.
 */
void kmhal_parcel_pack(struct kmhal_binder_txn *txn,
                       struct kmhal_parcel *parcel,
                       u32 handle, u32 cmd, int scatter_gather);

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
 *
 * @return
 *      0 if the transaction completed successfully,
 *      1 if the transaction failed,
 *      negative value on API misuse or invalid state.
 */
int kmhal_parcel_unpack(struct kmhal_parcel **parcel_p,
                        struct kmhal_binder_txn_args_out *out);

/* Read arbitrary data at an arbitrary offset from the parcel's buffer.
 * The offset doesn't have to be aligned.
 *
 * @param parcel The parcel from which to read.
 *
 * @param offset The offset at which to start reading.
 *
 * @param out Optional output pointer. May be NULL, but why would you do that?
 *
 * @param len The amount of data to read.
 *  If @out is not NULL, the provided buffer must be at least @len long.
 *
 * @return 0 on success, non-zero if the requested range is out of bounds.
 */
int kmhal_parcel_peek(const struct kmhal_parcel *parcel,
                      size_t offset, void *out, size_t len);

/* Read a uint32 value from the parcel's buffer.
 * The offset must be 4-byte aligned.
 *
 * @param parcel Parcel from which the value will be read.
 *
 * @param offset_p A pointer to the offset of the object. Must not be NULL.
 *  On success, incremented to point to after the read object.
 *  Note: The value must be 4-byte aligned.
 *
 * @param out Output pointer, may be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
int kmhal_parcel_read_u32(const struct kmhal_parcel *parcel,
                          size_t *offset_p, u32 *out);

/* Read a uint64 value from the parcel's buffer.
 * The offset must be 4-byte aligned.
 *
 * @param parcel Parcel from which the value will be read.
 *
 * @param offset_p A pointer to the offset of the object. Must not be NULL.
 *  On success, incremented to point to after the read object.
 *  Note: The value must be 4-byte aligned.
 *
 * @param out Output pointer, may be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
int kmhal_parcel_read_u64(const struct kmhal_parcel *parcel,
                          size_t *offset_p, u64 *out);

/* Read a UTF-16 string in the AIDL format from the parcel's buffer.
 * The offset must be 4-byte aligned.
 *
 * @param parcel Parcel from which the value will be read.
 *
 * @param offset_p A pointer to the offset of the object. Must not be NULL.
 *  On success, incremented to point to after the read object.
 *  Note: The value must be 4-byte aligned.
 *
 * @param out_p Pointer to output pointer. `out_p` itself may be NULL.
 *  If `*out_p` is NULL, a new string is malloced and `*out_p`
 *  is set to point to it. In that case the caller should later free `*out_p`.
 *
 * @param out_size_p Pointer to output buffer size.
 *  Cannot be NULL if `*out_p` is non-NULL
 *  (in which case `*out_size_p` should be the size of the buffer `*out_p`).
 *  After reading the string, this function will set `*out_size_p`
 *  to contain the size of the string *in bytes, including the null-terminator*.
 *
 * @return 0 on success, non-zero on failure
 *  or if the given buffer was too small.
 */
int kmhal_parcel_read_aidl_string16(const struct kmhal_parcel *parcel,
                                    size_t *offset_p,
                                    char16_t **out_p, size_t *out_size_p);

/* Read a UTF-16 string in the AIDL format from the parcel's buffer
 * and convert it to a normal UTF-8 C string.
 * The offset must be 4-byte aligned.
 *
 * @param parcel Parcel from which the value will be read.
 *
 * @param offset_p A pointer to the offset of the object. Must not be NULL.
 *  On success, incremented to point to after the read object.
 *  Note: The value must be 4-byte aligned.
 *
 * @param out_p Pointer to output pointer. `out_p` itself may be NULL.
 *  If `*out_p` is NULL, a new string is malloced and `*out_p`
 *  is set to point to it. In that case the caller should later free `*out_p`.
 *
 * @param out_size_p Pointer to output buffer size.
 *  Cannot be NULL if `*out_p` is non-NULL
 *  (in which case `*out_size_p` should be the size of the buffer `*out_p`).
 *  After reading & converting the string, this function will set `*out_size_p`
 *  to contain the size of the string IN BYTES, INCLUDING THE NULL-TERMINATOR.
 *
 * @return 0 on success, non-zero on failure
 *  or if the given buffer was too small.
 */
int kmhal_parcel_read_convert_aidl_string16(const struct kmhal_parcel *parcel,
                                            size_t *offset_p,
                                            char **out_p, size_t *out_size_p);

/* Read a flat_binder_object from the parcel's buffer.
 *
 * @param parcel Parcel from which the object will be read.
 *
 * @param offset_p A pointer to the offset of the object. Must not be NULL.
 *  On success, incremented to point to after the read object.
 *  Note: The value must be 4-byte aligned.
 *
 * @param out Output pointer, may be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
int kmhal_parcel_read_handle(const struct kmhal_parcel *parcel,
                             size_t *offset_p,
                             struct flat_binder_object *out);

/* Read a binder_buffer_object from the parcel's buffer.
 *
 * @param parcel Parcel from which the object will be read.
 *
 * @param offset_p A pointer to the offset of the object. Must not be NULL.
 *  On success, incremented to point to after the read object.
 *
 * @param exp_size The expected size of the object's buffer.
 *
 * @param exp_flags A pointer to the expected value of the object's `flags`.
 *  May be NULL.
 *
 * @param exp_parent A pointer to the expected value of the object's `parent`.
 *  May be NULL. Ignored if @exp_flags is not set to point to a value with
 *  `BINDER_BUFFER_FLAG_HAS_PARENT`.
 *
 * @param exp_parent_offset A pointer to the expected value of the object's
 *  `parent_offset`. May be NULL. Ignored if @exp_flags is not set
 *  to point to a value with `BINDER_BUFFER_FLAG_HAS_PARENT`.
 *
 * @param out Output pointer for the object's buffer. May be NULL.
 *
 * @param out_ref Output pointer for the object's reference. May be NULL.
 *
 * @return 0 on success, non-zero on failure.
 */
int kmhal_parcel_read_buffer_obj(const struct kmhal_parcel *parcel,
                                 size_t *offset_p,
                                 binder_size_t exp_size,
                                 const u32 *exp_flags,
                                 const kmhal_parcel_obj_t *exp_parent,
                                 const binder_size_t *exp_parent_offset,
                                 const void **out,
                                 kmhal_parcel_obj_t *out_ref);

/**
 * Retrieve an embedded buffer referenced by a parent buffer object.
 *
 * This resolves and validates a child `binder_buffer_object`
 * embedded within another buffer object.
 *
 * The returned buffer pointer refers directly to memory owned by
 * the parcel and remains valid until the parcel is destroyed.
 * The returned memory must not be modified.
 *
 * @param p Parcel containing the serialized objects.
 *
 * @param offset_p A pointer to the offset of the object. Must not be NULL.
 *  On success, incremented to point to after the read object.
 *
 * @param parent_ref Reference to the parent buffer object.
 *
 * @param parent_offset Byte offset within the parent object at which
 *      the embedded child buffer is expected to reside.
 *
 * @param expected_buf_size Optional expected size of the child buffer.
 *      If not NULL, the resolved child buffer size must exactly match
 *      `*expected_child_size`.
 *
 * @param out_buf Optional output pointer receiving the embedded buffer
 *      address inside parcel-owned memory.
 *
 * @param out_ref Optional output pointer receiving the resolved
 *      child object reference.
 *
 * @return 0 on success, non-zero on validation or lookup failure.
 */
int kmhal_parcel_read_embedded_buffer(const struct kmhal_parcel *p,
                                      size_t *off_p,
                                      kmhal_parcel_obj_t parent_ref,
                                      binder_size_t parent_offset,
                                      size_t expected_buf_size,
                                      const void **out_buf,
                                      kmhal_parcel_obj_t *out_ref);

/**
 * Destroy a parcel and release all associated resources.
 *
 * Warning: If the parcel still has an active pending transaction,
 * destruction may abort depending on transaction state.
 * Preferably, use `kmhal_parcel_unpack` do destroy the parcel instead.
 *
 * `*parcel_p` is set to NULL.
 *
 * @param parcel_p Pointer to parcel to be destroyed.
 */
void kmhal_parcel_destroy(struct kmhal_parcel **parcel_p);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* SUSKEYMASTER_KMHAL_PARCEL_H_ */
