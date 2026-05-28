#ifndef SUSKEYMASTER_KMHAL_HIDL_BASE_H_
#define SUSKEYMASTER_KMHAL_HIDL_BASE_H_

#include "hidl-types.h"
#include <core/int.h>
#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct kmhal_hidl_hal_sp;

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
const char * kmhal_hidl_android_status_toString(i32 s);

#define KMHAL_HIDL_BASE_FQNAME "android.hidl.base@1.0::IBase"

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

enum kmhal_hidl_android_status
kmhal_hidl_base_ping(struct kmhal_binder_ctx *binder,
                     struct kmhal_binder_transaction **txn_p,
                     u32 handle);

enum kmhal_hidl_android_status
kmhal_hidl_base_get_descriptor(struct kmhal_binder_ctx *binder,
                               struct kmhal_binder_transaction **txn_p,
                               u32 handle,
                               const struct kmhal_hidl_string **out_p);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* SUSKEYMASTER_KMHAL_HIDL_BASE_H_ */
