#ifndef SUSKEYMASTER_KMHAL_TRANSPORT_STATUS_H_
#define SUSKEYMASTER_KMHAL_TRANSPORT_STATUS_H_

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <core/int.h>

/* Stolen from AOSP: system/core/libutils/include/utils/Errors.h */
enum kmhal_android_status {
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
const char * kmhal_android_status_toString(i32 s);

enum kmhal_android_status kmhal_android_status_prune(i32 s);

/* frameworks/native/libs/binder/include/binder/Status.h */
enum kmhal_aidl_exception {
    EX_NONE = 0,
    EX_SECURITY = -1,
    EX_BAD_PARCELABLE = -2,
    EX_ILLEGAL_ARGUMENT = -3,
    EX_NULL_POINTER = -4,
    EX_ILLEGAL_STATE = -5,
    EX_NETWORK_MAIN_THREAD = -6,
    EX_UNSUPPORTED_OPERATION = -7,
    EX_SERVICE_SPECIFIC = -8,
    EX_PARCELABLE = -9,
    EX_HAS_NOTED_APPOPS_REPLY_HEADER = -127,
    EX_HAS_REPLY_HEADER = -128,
    EX_TRANSACTION_FAILED = -129,
};
const char * kmhal_aidl_exception_toString(i32 ex);

enum kmhal_android_status kmhal_aidl_exception_to_android_status(i32 ex);

#endif /* SUSKEYMASTER_KMHAL_TRANSPORT_STATUS_H_ */
