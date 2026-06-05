#ifndef SUSKEYMASTER_KMHAL_SERDES_AIDL_H_
#define SUSKEYMASTER_KMHAL_SERDES_AIDL_H_

#ifndef SUSKEYMASTER_BUILD_HOST

#include "parcel.h"
#include <core/int.h>
#include <core/log.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** Serialization and deserialization functions for common AIDL types **/

static inline void
kmhal_aidl_arg_write_aidl_string16(struct kmhal_parcel *p,
                                   const void *data, size_t size)
{
    (void) size;
    if (data == NULL)
        s_abort("serdes-aidl", __func__, "Data is NULL");


    kmhal_parcel_write_aidl_string16(p, (const char16_t *)data);
}

static inline void
kmhal_aidl_arg_write_convert_aidl_string16(struct kmhal_parcel *p,
                                           const void *data, size_t size)
{
    (void) size;
    if (data == NULL)
        s_abort("serdes-aidl", __func__, "Data is NULL");

    kmhal_parcel_write_convert_aidl_string16(p, (const char *)data);
}

static inline int
kmhal_aidl_arg_parse_aidl_string16(const struct kmhal_parcel *p,
                                   size_t *off_p,
                                   const void **out_p, size_t out_size)
{
    (void) out_size;
    if (out_p == NULL) {
        s_log(S_LOG_ERROR, "serdes-aidl", "%s: Output pointer is NULL", __func__);
        return -1;
    }

    return kmhal_parcel_read_aidl_string16(p, off_p, (char16_t **)out_p, NULL);
}

static inline int
kmhal_aidl_arg_parse_convert_aidl_string16(const struct kmhal_parcel *p,
                                           size_t *off_p,
                                           const void **out_p, size_t out_size)
{
    (void) out_size;
    if (out_p == NULL) {
        s_log(S_LOG_ERROR, "serdes-aidl", "%s: Output pointer is NULL", __func__);
        return -1;
    }

    return kmhal_parcel_read_convert_aidl_string16(p, off_p,
            (char **)out_p, NULL);
}

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* SUSKEYMASTER_BUILD_HOST */

#endif /* SUSKEYMASTER_KMHAL_SERDES_AIDL_H_ */
