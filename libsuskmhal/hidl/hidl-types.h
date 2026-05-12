#ifndef KMHAL_HIDL_TYPES_H_
#define KMHAL_HIDL_TYPES_H_

#include <core/int.h>
#include <errno.h>
#include <stddef.h>

#ifdef __cplusplus
namespace suskeymaster {
namespace kmhal {
namespace hidl {
extern "C" {
#endif /* __cplusplus */

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

struct kmhal_hidl_vec {
    const void *buffer;
    u32 size;
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
