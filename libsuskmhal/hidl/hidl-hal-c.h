#ifndef SUSKEYMASTER_HIDL_HAL_C_H_
#define SUSKEYMASTER_HIDL_HAL_C_H_

#include "../util/keymaster-types-c.h"
#include <core/vector.h>
#include <stdint.h>
#include <stdbool.h>

#if (defined(__cplusplus))
extern "C" {
namespace suskeymaster {
namespace kmhal {
namespace hidl {
using namespace ::suskeymaster::kmhal::util;
#endif /* (defined(__cplusplus)) */

struct hidl_suskeymaster;


/* Allocates and initializes a new keymaster 3.0 handle.
 * Returns NULL if the HAL service could not be obtained. */
struct hidl_suskeymaster *hidl_suskeymaster3_0_new(void);

/* Allocates and initializes a new keymaster 4.0 handle.
 * Returns NULL if the HAL service could not be obtained. */
struct hidl_suskeymaster *hidl_suskeymaster4_0_new(void);

/* Allocates and initializes a new keymaster 4.1 handle.
 * Returns NULL if the HAL service could not be obtained. */
struct hidl_suskeymaster *hidl_suskeymaster4_1_new(void);

/* Destroys and frees the keymaster handle. */
void hidl_suskeymaster_destroy(struct hidl_suskeymaster **km_p);

/* Returns true if the HAL is reachable and responsive. */
bool hidl_suskeymaster_is_hal_ok(struct hidl_suskeymaster *km);

void hidl_suskeymaster_get_hardware_info(struct hidl_suskeymaster *km,
        enum KM_SecurityLevel *out_security_level,
        VECTOR(char) *out_keymaster_name,
        VECTOR(char) *out_keymaster_author_name
);

enum KM_ErrorCode hidl_suskeymaster_get_hmac_sharing_parameters(struct hidl_suskeymaster *km,
        struct KM_HmacSharingParameters *out_params
);

enum KM_ErrorCode hidl_suskeymaster_compute_shared_hmac(struct hidl_suskeymaster *km,
        VECTOR(struct KM_HmacSharingParameters const) params,

        VECTOR(u8) *out_sharing_check /* caller must vector_destroy */
);

enum KM_ErrorCode hidl_suskeymaster_verify_authorization(struct hidl_suskeymaster *km,
        uint64_t operation_handle,
        VECTOR(struct KM_KeyParameter const) params_to_verify,
        struct KM_HardwareAuthToken const *auth_token,

        struct KM_VerificationToken *out_verification_token
);

enum KM_ErrorCode hidl_suskeymaster_add_rng_entropy(struct hidl_suskeymaster *km,
        VECTOR(u8 const) data
);

enum KM_ErrorCode hidl_suskeymaster_generate_key(struct hidl_suskeymaster *km,
        VECTOR(struct KM_KeyParameter const) key_params,
        VECTOR(u8) *out_key_blob,                   /* caller must vector_destroy */
        struct KM_KeyCharacteristics *out_key_characteristics);

enum KM_ErrorCode hidl_suskeymaster_import_key(struct hidl_suskeymaster *km,
        VECTOR(struct KM_KeyParameter const) key_params,
        enum KM_KeyFormat key_format, VECTOR(u8 const) key_data,

        VECTOR(u8) *out_key_blob,
        struct KM_KeyCharacteristics *out_key_characteristics
);

enum KM_ErrorCode hidl_suskeymaster_import_wrapped_key(struct hidl_suskeymaster *km,
        VECTOR(u8 const) wrapped_key_data, VECTOR(u8 const) wrapping_key_blob,
        VECTOR(u8 const) masking_key, VECTOR(struct KM_KeyParameter const) unwrapping_params,
        uint64_t password_sid, uint64_t biometric_sid,

        VECTOR(u8) *out_key_blob,
        struct KM_KeyCharacteristics *out_key_characteristics
);

enum KM_ErrorCode hidl_suskeymaster_get_key_characteristics(struct hidl_suskeymaster *km,
        VECTOR(u8 const) key_blob, VECTOR(u8 const) app_id, VECTOR(u8 const) app_data,
        struct KM_KeyCharacteristics *out_key_characteristics
);

enum KM_ErrorCode hidl_suskeymaster_export_key(struct hidl_suskeymaster *km,
        enum KM_KeyFormat key_format, VECTOR(u8 const) key_blob,
        VECTOR(u8 const) app_id, VECTOR(u8 const) app_data,

        VECTOR(u8) *out_key_material
);

enum KM_ErrorCode hidl_suskeymaster_attest_key(struct hidl_suskeymaster *km,
        VECTOR(u8 const) key_to_attest, VECTOR(struct KM_KeyParameter const) attest_params,
        VECTOR(VECTOR(u8)) *out_cert_chain /* caller must destroy each cert + the chain */
);

enum KM_ErrorCode hidl_suskeymaster_upgrade_key(struct hidl_suskeymaster *km,
        VECTOR(u8 const) key_blob, VECTOR(struct KM_KeyParameter const) upgrade_params,
        VECTOR(u8) *out_upgraded_key_blob
);

enum KM_ErrorCode hidl_suskeymaster_delete_key(struct hidl_suskeymaster *km,
        VECTOR(u8 const) key_blob
);

enum KM_ErrorCode hidl_suskeymaster_delete_all_keys(struct hidl_suskeymaster *km);

enum KM_ErrorCode hidl_suskeymaster_destroy_attestation_ids(struct hidl_suskeymaster *km);

enum KM_ErrorCode hidl_suskeymaster_begin(struct hidl_suskeymaster *km,
        enum KM_KeyPurpose purpose, VECTOR(u8 const) key_blob,
        VECTOR(struct KM_KeyParameter const) in_params,
        struct KM_HardwareAuthToken const *auth_token,

        VECTOR(struct KM_KeyParameter) *out_params,
        uint64_t *out_operation_handle
);

enum KM_ErrorCode hidl_suskeymaster_update(struct hidl_suskeymaster *km,
        uint64_t operation_handle,
        VECTOR(struct KM_KeyParameter const) in_params, VECTOR(u8 const) input,
        struct KM_HardwareAuthToken *auth_token, struct KM_VerificationToken *verification_token,

        uint32_t *out_input_consumed,
        VECTOR(struct KM_KeyParameter) *out_params,
        VECTOR(u8) *out_output
);

enum KM_ErrorCode hidl_suskeymaster_finish(struct hidl_suskeymaster *km,
        uint64_t operation_handle, VECTOR(struct KM_KeyParameter const) in_params,
        VECTOR(u8 const) input, VECTOR(u8 const) signature,
        struct KM_HardwareAuthToken *auth_token, struct KM_VerificationToken *verification_token,

        VECTOR(struct KM_KeyParameter) *out_params,
        VECTOR(u8) *out_output
);

enum KM_ErrorCode hidl_suskeymaster_abort(struct hidl_suskeymaster *km,
        uint64_t operation_handle);

#if (defined(__cplusplus))
} /* namespace hidl */
} /* namespace kmhal */
} /* namespace suskeymaster */
} /* extern "C" */
#endif /* (defined(__cplusplus)) */

#endif /* SUSKEYMASTER_HIDL_HAL_C_H_ */
