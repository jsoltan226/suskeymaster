#include "status.h"
#include <core/log.h>
#include <core/int.h>
#include <inttypes.h>

#define MODULE_NAME "android-status"

const char * kmhal_android_status_toString(i32 s)
{
    switch (s) {
    case OK: return "OK";
    case UNKNOWN_ERROR: return "UNKNOWN_ERROR";
    case NO_MEMORY: return "NO_MEMORY";
    case INVALID_OPERATION: return "INVALID_OPERATION";
    case BAD_VALUE: return "BAD_VALUE";
    case BAD_TYPE: return "BAD_TYPE";
    case NAME_NOT_FOUND: return "NAME_NOT_FOUND";
    case PERMISSION_DENIED: return "PERMISSION_DENIED";
    case NO_INIT: return "NO_INIT";
    case ALREADY_EXISTS: return "ALREADY_EXISTS";
    case DEAD_OBJECT: return "DEAD_OBJECT";
    case FAILED_TRANSACTION: return "FAILED_TRANSACTION";
    case BAD_INDEX: return "BAD_INDEX";
    case NOT_ENOUGH_DATA: return "NOT_ENOUGH_DATA";
    case WOULD_BLOCK: return "WOULD_BLOCK";
    case TIMED_OUT: return "TIMED_OUT";
    case UNKNOWN_TRANSACTION: return "UNKNOWN_TRANSACTION";
    case FDS_NOT_ALLOWED: return "FDS_NOT_ALLOWED";
    case UNEXPECTED_NULL: return "UNEXPECTED_NULL";
    default: return "(unknown)";
    }
}

enum kmhal_android_status kmhal_android_status_prune(i32 s)
{
    switch (s) {
    case OK:
    case UNKNOWN_ERROR:
    case NO_MEMORY:
    case INVALID_OPERATION:
    case BAD_VALUE:
    case BAD_TYPE:
    case NAME_NOT_FOUND:
    case PERMISSION_DENIED:
    case NO_INIT:
    case ALREADY_EXISTS:
    case DEAD_OBJECT:
    case FAILED_TRANSACTION:
    case BAD_INDEX:
    case NOT_ENOUGH_DATA:
    case WOULD_BLOCK:
    case TIMED_OUT:
    case UNKNOWN_TRANSACTION:
    case FDS_NOT_ALLOWED:
    case UNEXPECTED_NULL:
        return s;

    default:
        s_log_warn("Received unknown status %"PRIi32"; "
                "returning UNKNOWN_ERROR", s);
        return UNKNOWN_ERROR;
    }
}

const char * kmhal_aidl_exception_toString(i32 ex)
{
    switch (ex) {
    case EX_NONE: return "EX_NONE";
    case EX_SECURITY: return "EX_SECURITY";
    case EX_BAD_PARCELABLE: return "EX_BAD_PARCELABLE";
    case EX_ILLEGAL_ARGUMENT: return "EX_ILLEGAL_ARGUMENT";
    case EX_NULL_POINTER: return "EX_NULL_POINTER";
    case EX_ILLEGAL_STATE: return "EX_ILLEGAL_STATE";
    case EX_NETWORK_MAIN_THREAD: return "EX_NETWORK_MAIN_THREAD";
    case EX_UNSUPPORTED_OPERATION: return "EX_UNSUPPORTED_OPERATION";
    case EX_SERVICE_SPECIFIC: return "EX_SERVICE_SPECIFIC";
    case EX_PARCELABLE: return "EX_PARCELABLE";
    case EX_HAS_NOTED_APPOPS_REPLY_HEADER: return "EX_HAS_NOTED_APPOPS_REPLY_HEADER";
    case EX_HAS_REPLY_HEADER: return "EX_HAS_REPLY_HEADER";
    case EX_TRANSACTION_FAILED: return "EX_TRANSACTION_FAILED";
    default: return "(unknown)";
    }
}

enum kmhal_android_status kmhal_aidl_exception_to_android_status(i32 ex)
{
    switch (ex) {
    case EX_NONE: return NO_ERROR;
    case EX_SECURITY: return PERMISSION_DENIED;
    case EX_BAD_PARCELABLE: return BAD_VALUE;
    case EX_ILLEGAL_ARGUMENT: return BAD_VALUE;
    case EX_NULL_POINTER: return UNEXPECTED_NULL;
    case EX_ILLEGAL_STATE: return UNKNOWN_ERROR;
    case EX_NETWORK_MAIN_THREAD: return UNKNOWN_ERROR;
    case EX_UNSUPPORTED_OPERATION: return INVALID_OPERATION;
    case EX_SERVICE_SPECIFIC: return UNKNOWN_ERROR;
    case EX_PARCELABLE: return BAD_TYPE;
    case EX_HAS_NOTED_APPOPS_REPLY_HEADER: return UNKNOWN_ERROR;
    case EX_HAS_REPLY_HEADER: return UNKNOWN_ERROR;
    case EX_TRANSACTION_FAILED: return FAILED_TRANSACTION;
    default:
        return UNKNOWN_ERROR;
    }
}
