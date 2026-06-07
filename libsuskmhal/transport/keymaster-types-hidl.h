#ifndef SUSKEYMASTER_KMHAL_HIDL_KEYMASTER_HIDL_H_
#define SUSKEYMASTER_KMHAL_HIDL_KEYMASTER_HIDL_H_

#ifndef SUSKEYMASTER_BUILD_HOST

#include "parcel.h"
#include "hidl-types.h"
#include "../keymaster-types-c.h"
#include <core/int.h>
#include <core/log.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* `KeyParameter`
 *      -> `hidl_vec<u8>` blob
 */
void write_key_parameter(struct kmhal_parcel *p, const void *data, size_t size);
int parse_key_parameter(const struct kmhal_parcel *p, size_t *off_p,
                        const void **out_p, size_t out_size);

/* `hidl_vec<KeyParameter>`
 *          ==> [ KeyParameter -> `hidl_vec<u8>` blob, ... ]
 */
void write_vec_of_key_parameter(struct kmhal_parcel *p,
                                const void *data, size_t size);
int parse_vec_of_key_parameter(const struct kmhal_parcel *p, size_t *off_p,
                              const void **out_p, size_t out_size);

/* `KeyCharacteristics`
 *      -> `hidl_vec<KeyParameter>` softwareEnforced
 *              ==> [ KeyParameter -> `hidl_vec<u8>` blob, ... ]
 *
 *      -> `hidl_vec<KeyParameter>` hardwareEnforced
 *              ==> [ KeyParameter -> `hidl_vec<u8>` blob, ... ]
 */
void write_key_characteristics(struct kmhal_parcel *p,
                               const void *data, size_t size);
int parse_key_characteristics(const struct kmhal_parcel *p, size_t *off_p,
                              const void **out_p, size_t out_size);

/* `HmacSharingParameters`
 *      -> `hidl_vec<u8>` seed
 */
void write_hmac_sharing_parameters(struct kmhal_parcel *p,
                                   const void *data, size_t size);
int parse_hmac_sharing_parameters(const struct kmhal_parcel *p, size_t *off_p,
                                 const void **out_p, size_t out_size);

/* `hidl_vec<HmacSharingParameters>`
 *          ==> [ HmacSharingParameters -> `hidl_vec<u8>` seed, ... ]
 */
void write_vec_of_hmac_sharing_parameters(struct kmhal_parcel *p,
                                          const void *data, size_t size);
int parse_vec_of_hmac_sharing_parameters(const struct kmhal_parcel *p,
                                         size_t *off_p,
                                         const void **out_p, size_t out_size);

/* `HardwareAuthToken`
 *      -> `hidl_vec<u8>` mac
 */
void write_hardware_auth_token(struct kmhal_parcel *p,
                               const void *data, size_t size);
int parse_hardware_auth_token(const struct kmhal_parcel *p, size_t *off_p,
                              const void **out_p, size_t out_size);

/* `VerificationToken`
 *      -> `hidl_vec<KeyParameter>` parametersVerified
 *              ==> [ KeyParameter -> `hidl_vec<u8>` blob, ... ]
 *      -> `hidl_vec<u8>` mac
 */
void write_verification_token(struct kmhal_parcel *p,
                              const void *data, size_t size);
int parse_verification_token(const struct kmhal_parcel *p, size_t *off_p,
                             const void **out_p, size_t out_size);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* SUSKEYMASTER_BUILD_HOST */

#endif /* SUSKEYMASTER_KMHAL_HIDL_KEYMASTER_HIDL_H_ */
