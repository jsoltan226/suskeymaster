#ifndef KMHAL_HIDL_TYPES_H_
#define KMHAL_HIDL_TYPES_H_

#include "parcel.h"
#include <core/int.h>
#include <errno.h>
#include <stddef.h>

#ifdef __cplusplus
namespace suskeymaster {
namespace kmhal {
namespace hidl {
extern "C" {
#endif /* __cplusplus */

/** The C struct representation of the HIDL string type. */
struct kmhal_hidl_string {
    const char *buffer;
    u32 length;
    u32 owns_buffer;
};
_Static_assert(offsetof(struct kmhal_hidl_string, buffer) == 0,
        "Invalid offset of the buffer pointer in HIDL string");
_Static_assert(offsetof(struct kmhal_hidl_string, length) == 8,
        "Invalid offset of the length u32 in HIDL string");
_Static_assert(offsetof(struct kmhal_hidl_string, owns_buffer) == 12,
        "Invalid offset of the `owns_buffer` u32 in HIDL string");
_Static_assert(sizeof(struct kmhal_hidl_string) == 16,
        "Invalid size of the HIDL string struct");

/**
 * Write objects for an HIDL string struct and its contents into the parcel.
 * This function never fails non-fatally.
 *
 * @param parcel The parcel to write into.
 *
 * @param hstr The HIDL string object to serialize.
 *
 * @param parent Optionally, a handle to the HIDL string's parent.
 *  Pass in `KMHAL_HIDL_PARCEL_OBJ_INVALID` if unspecified.
 *
 * @param parent_offset If @parent is specified, the offset into its
 *  buffer where the @str HIDL string object lives. Otherise, ignored.
 *
 * @param out_parent_ref Optional output pointer for a reference
 *  to the newly created HIDL string struct object.
 *
 * @return A reference to the newly created HIDL string contents object.
 */
kmhal_hidl_parcel_obj_t
kmhal_hidl_string_write(struct kmhal_hidl_parcel *parcel,
                        const struct kmhal_hidl_string *hstr,
                        kmhal_hidl_parcel_obj_t parent,
                        binder_size_t parent_offset,
                        kmhal_hidl_parcel_obj_t *out_parent_ref);

/**
 * Write an object for an HIDL string's contents into the parcel.
 * This function never fails non-fatally.
 *
 * @param parcel The parcel to write into.
 *
 * @param hstr The HIDL string object for whose contents
 *  an object should be created.
 *
 * @param parent The parent object containing the @hstr HIDL string.
 *
 * @param parent_offset An offset within the parent object where the
 *  @hstr HIDL string is located.
 *
 * @return A reference to the newly created HIDL string contents object.
 */
kmhal_hidl_parcel_obj_t
kmhal_hidl_string_write_embedded(struct kmhal_hidl_parcel *parcel,
                                 const struct kmhal_hidl_string *hstr,
                                 kmhal_hidl_parcel_obj_t parent,
                                 binder_size_t parent_offset);

/**
 * Read an HIDL string object from the parcel.
 * This function reads the HIDL string struct object
 * and looks for and validates its corresponding contents (child) object.
 *
 * @param out Output pointer. May be NULL.
 *
 * @param parcel The parcel from which to read.
 *
 * @param hstr_obj_ref A reference to the HIDL string struct object.
 *
 * @param out_child_ref An optional output pointer for the HIDL string
 *  contents object (child of @hstr_obj_ref).
 *
 * @return 0 on success, non-zero on failure.
 */
int kmhal_hidl_string_read(struct kmhal_hidl_string *out,
                           const struct kmhal_hidl_parcel *parcel,
                           kmhal_hidl_parcel_obj_t hstr_obj_ref,
                           kmhal_hidl_parcel_obj_t *out_child_ref);

/**
 * Find and validate the contents object of an HIDL string.
 * Also ensures that the string is NULL-terminated.
 *
 * @param out Output pointer for the string contents. May be NULL.
 *  Technically one can use the `hstr.buffer` directly, but this
 *  function helps to ensure the integrity of the entire HIDL string
 *  and thus should be called before trusting the contents of `hstr`.
 *
 * @param out_ref Output pointer for a reference to the HIDL string
 *  contents (child) object. May be NULL.
 *
 * @param parcel The parcel from which to read.
 *
 * @param hstr A pointer to the HIDL string struct.
 *
 * @param parent_handle A reference to the object that contains @hstr.
 *
 * @param parent_offset The offset at which @hstr lives in the buffer of
 *  the parent object (referenced by @parent_handle).
 *
 * @return 0 on success, non-zero on failure.
 */
int kmhal_hidl_string_read_embedded(const char **out,
                                    kmhal_hidl_parcel_obj_t *out_ref,
                                    const struct kmhal_hidl_parcel *parcel,
                                    const struct kmhal_hidl_string *hstr,
                                    kmhal_hidl_parcel_obj_t parent_handle,
                                    size_t parent_offset,
                                    kmhal_hidl_parcel_obj_t child_hint);

/* The C struct representation of the HIDL vec type */
struct kmhal_hidl_vec {
    const void *buffer;
    u32 size; /* number of elements */
    u32 owns_buffer;
};
_Static_assert(offsetof(struct kmhal_hidl_vec, buffer) == 0,
        "Invalid offset of the buffer pointer in HIDL vec");
_Static_assert(offsetof(struct kmhal_hidl_vec, size) == 8,
        "Invalid offset of the size u32 in HIDL vec");
_Static_assert(offsetof(struct kmhal_hidl_vec, owns_buffer) == 12,
        "Invalid offset of the `owns_buffer` u32 in HIDL vec");
_Static_assert(sizeof(struct kmhal_hidl_vec) == 16,
        "Invalid size of the HIDL vec struct");

/**
 * Write objects for both the HIDL vec struct and its contents into the parcel.
 * This function never fails non-fatally.
 *
 * @param parcel The parcel to write into.
 *
 * @param vec The HIDL vec object to serialize.
 *
 * @param elem_size The size of the type @vec stores.
 *
 * @param parent Optionally, a handle to the HIDL vec's parent.
 *  Pass in `KMHAL_HIDL_PARCEL_OBJ_INVALID` if unspecified.
 *
 * @param parent_offset If @parent is specified, the offset into its
 *  buffer where the @vec HIDL vec object lives. Otherise, ignored.
 *
 * @param out_parent_ref Optional output pointer for a reference
 *  to the newly created HIDL vec struct object.
 *
 * @return A reference to the newly created HIDL vec bytes object.
 */
kmhal_hidl_parcel_obj_t
kmhal_hidl_vec_write(struct kmhal_hidl_parcel *parcel,
                     const struct kmhal_hidl_vec *vec, size_t elem_size,
                     kmhal_hidl_parcel_obj_t parent,
                     binder_size_t parent_offset,
                     kmhal_hidl_parcel_obj_t *out_parent_ref);

#define kmhal_hidl_vec_of_write(T, parcel, vec,     \
        parent, parent_offset, out_parent_ref)      \
                                                    \
    kmhal_hidl_vec_write(parcel, vec, sizeof(T),    \
            parent, parent_offset, out_parent_ref)

/**
 * Write an object for an HIDL vec's contents into the parcel.
 * This function never fails non-fatally.
 *
 * @param parcel The parcel to write into.
 *
 * @param vec The HIDL vec object for whose contents
 *  an object should be created.
 *
 * @param elem_size The size of the type @vec stores.
 *
 * @param parent The parent object that contains @vec.
 *
 * @param parent_offset The offset at which @vec lives within the parent object.
 *
 * @return A reference to the newly created HIDL vec contents object.
 */
kmhal_hidl_parcel_obj_t
kmhal_hidl_vec_write_embedded(struct kmhal_hidl_parcel *parcel,
                              const struct kmhal_hidl_vec *vec,
                              size_t elem_size,
                              kmhal_hidl_parcel_obj_t parent,
                              binder_size_t parent_offset);

#define kmhal_hidl_vec_of_write_embedded(T, parcel, vec,    \
        parent, parent_offset)                              \
                                                            \
    kmhal_hidl_vec_write_embedded(parcel, vec, sizeof(T),   \
            parent, parent_offset)

/**
 * Read an HIDL vec object from the parcel.
 * This function reads the HIDL vec struct object
 * and looks for and validates its corresponding contents (child) object.
 *
 * @param out Output pointer. May be NULL.
 *
 * @param parcel The parcel from which to read.
 *
 * @param vec_obj_ref A reference to the HIDL vec struct object.
 *
 * @param out_child_ref An optional output pointer for the HIDL vec
 *  contents object (child of @vec_obj_ref).
 *
 * @return 0 on success, non-zero on failure.
 */
int kmhal_hidl_vec_read(struct kmhal_hidl_vec *out, size_t elem_size,
                        const struct kmhal_hidl_parcel *parcel,
                        kmhal_hidl_parcel_obj_t vec_obj_ref,
                        kmhal_hidl_parcel_obj_t *out_child_ref);

#define kmhal_hidl_vec_of_read(T, out, parcel,  \
        vec_obj_ref, out_child_ref)             \
    kmhal_hidl_vec_read(out, sizeof(T), parcel, \
            vec_obj_ref, out_child_ref)

/**
 * Find and validate the contents object of an HIDL vec.
 *
 * @param out Output pointer for the vec contents. May be NULL.
 *  Technically one can use the `vec.buffer` directly, but this
 *  function helps to ensure the integrity of the entire HIDL vec
 *  and thus should be called before trusting the contents of `vec`.
 *
 * @param out_ref Output pointer for a reference to the HIDL vec
 *  contents (child) object. May be NULL.
 *
 * @param parcel The parcel from which to read.
 *
 * @param vec A pointer to the HIDL vec struct.
 *
 * @param parent_handle A reference to the object that contains @vec.
 *
 * @param parent_offset The offset at which @vec lives in the buffer of
 *  the parent object (referenced by @parent_handle).
 *
 * @return 0 on success, non-zero on failure.
 */
int kmhal_hidl_vec_read_embedded(const void **out,
                                 kmhal_hidl_parcel_obj_t *out_ref,
                                 const struct kmhal_hidl_parcel *parcel,
                                 const struct kmhal_hidl_vec *vec,
                                 size_t elem_size,
                                 kmhal_hidl_parcel_obj_t parent_handle,
                                 size_t parent_offset,
                                 kmhal_hidl_parcel_obj_t child_hint);

#define kmhal_hidl_vec_of_read_embedded(T, out, out_ref, parcel,    \
        parent_vec, parent_handle, parent_offset, child_hint)       \
                                                                    \
    kmhal_hidl_vec_read_embedded(out, out_ref, parcel, parent_vec,  \
            sizeof(T), parent_handle, parent_offset, child_hint)

/* Stolen from AOSP: system/core/libutils/include/utils/Errors.h */
enum kmhal_hidl_android_status {
    OK                  = 0,
    NO_ERROR            = OK,
    UNKNOWN_ERROR       = INT32_MIN,
    NO_MEMORY           = -ENOMEM,
    INVALID_OPERATION   = -ENOSYS,
    BAD_VALUE           = -EINVAL,
    BAD_TYPE            = (UNKNOWN_ERROR + 1),
    NAME_NOT_FOUND      = -ENOENT,
    PERMISSION_DENIED   = -EPERM,
    NO_INIT             = -ENODEV,
    ALREADY_EXISTS      = -EEXIST,
    DEAD_OBJECT         = -EPIPE,
    FAILED_TRANSACTION  = (UNKNOWN_ERROR + 2),
    BAD_INDEX           = -EOVERFLOW,
    NOT_ENOUGH_DATA     = -ENODATA,
    WOULD_BLOCK         = -EWOULDBLOCK,
    TIMED_OUT           = -ETIMEDOUT,
    UNKNOWN_TRANSACTION = -EBADMSG,
    FDS_NOT_ALLOWED     = (UNKNOWN_ERROR + 7),
    UNEXPECTED_NULL     = (UNKNOWN_ERROR + 8),
};
const char * kmhal_hidl_android_status_toString(int32_t s);

/* Also stolen from AOSP - system/libhwbinder/include/hwbinder/IBinder.h */
enum kmhal_hidl_transaction_ids {
    /* User defined transactions */

    HIDL_FIRST_CALL_TRANSACTION  = 0x00000001,
    HIDL_LAST_CALL_TRANSACTION   = 0x0effffff,

    /* HIDL reserved transaction IDs */
#define B_PACK_CHARS_USER(c1, c2, c3, c4) \
    ((((c1)<<24)) | (((c2)<<16)) | (((c3)<<8)) | (c4))
    HIDL_FIRST_HIDL_TRANSACTION  = 0x0f000000,
    HIDL_PING_TRANSACTION                     = B_PACK_CHARS_USER(0x0f, 'P', 'N', 'G'),
    HIDL_DESCRIPTOR_CHAIN_TRANSACTION         = B_PACK_CHARS_USER(0x0f, 'C', 'H', 'N'),
    HIDL_GET_DESCRIPTOR_TRANSACTION           = B_PACK_CHARS_USER(0x0f, 'D', 'S', 'C'),
    HIDL_SYSPROPS_CHANGED_TRANSACTION         = B_PACK_CHARS_USER(0x0f, 'S', 'Y', 'S'),
    HIDL_LINK_TO_DEATH_TRANSACTION            = B_PACK_CHARS_USER(0x0f, 'L', 'T', 'D'),
    HIDL_UNLINK_TO_DEATH_TRANSACTION          = B_PACK_CHARS_USER(0x0f, 'U', 'T', 'D'),
    HIDL_SET_HAL_INSTRUMENTATION_TRANSACTION  = B_PACK_CHARS_USER(0x0f, 'I', 'N', 'T'),
    HIDL_GET_REF_INFO_TRANSACTION             = B_PACK_CHARS_USER(0x0f, 'R', 'E', 'F'),
    HIDL_DEBUG_TRANSACTION                    = B_PACK_CHARS_USER(0x0f, 'D', 'B', 'G'),
    HIDL_HASH_CHAIN_TRANSACTION               = B_PACK_CHARS_USER(0x0f, 'H', 'S', 'H'),
#undef B_PACK_CHARS_USER
    HIDL_LAST_HIDL_TRANSACTION   = 0x0fffffff,

    /* Corresponds to TF_ONE_WAY -- an asynchronous call. */
    HIDL_FLAG_ONEWAY             = 0x00000001,

    /* Corresponds to TF_CLEAR_BUF --
     * clear transaction buffers after call is made */
    HIDL_FLAG_CLEAR_BUF          = 0x00000020,
};

#ifdef __cplusplus
} /* extern "C" */
} /* namespace hidl */
} /* namespace kmhal */
} /* namespace suskeymaster */
#endif /* __cplusplus */

#endif /* KMHAL_HIDL_TYPES_H_ */
