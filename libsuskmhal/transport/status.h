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

#endif /* SUSKEYMASTER_KMHAL_TRANSPORT_STATUS_H_ */
