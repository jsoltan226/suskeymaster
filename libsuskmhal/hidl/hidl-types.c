#include "hidl-types.h"

const char * kmhal_hidl_android_status_toString(int32_t s)
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
