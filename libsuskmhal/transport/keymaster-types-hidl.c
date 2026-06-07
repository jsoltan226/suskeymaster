#include "keymaster-types-hidl.h"
#include "parcel.h"
#include "hidl-types.h"
#include "../keymaster-types-c.h"
#include <core/int.h>
#include <core/log.h>
#include <core/util.h>
#include <stddef.h>

#define MODULE_NAME "keymaster-types-hidl"

void write_key_parameter(struct kmhal_parcel *p, const void *data, size_t size)
{
    u_check_params(data != NULL && size == sizeof(struct KM_KeyParameter));

    /* KeyParameter (top-level buffer obj) */
    kmhal_parcel_obj_t ref = kmhal_parcel_write_buffer_obj(p, data, size,
            0, KMHAL_PARCEL_OBJ_INVALID, 0);

    /* KeyParameter.blob (`hidl_vec<u8>`) */
    const struct KM_KeyParameter *const kp_p = data;
    kmhal_hidl_vec_write_embedded(p, (const struct kmhal_hidl_vec *)&kp_p->blob,
                sizeof(u8), ref, offsetof(struct KM_KeyParameter, blob));
}

int parse_key_parameter(const struct kmhal_parcel *p, size_t *off_p,
                        const void **out_p, size_t out_size)
{
    if (out_p == NULL || out_size != sizeof(struct KM_KeyParameter)) {
        s_log_error("%s: Invalid parameters", __func__);
        return -1;
    }

    kmhal_parcel_obj_t ref = KMHAL_PARCEL_OBJ_INVALID;

    /* KeyParameter (top-level buffer obj) */
    u32 exp_flags = 0;
    if (kmhal_parcel_read_buffer_obj(p, off_p, sizeof(struct KM_KeyParameter),
                &exp_flags, NULL, NULL, out_p, &ref))
    {
        s_log_error("Failed to read the key parameter buffer object");
        return 1;
    }
    const struct KM_KeyParameter *const kp_p = *out_p;

    /* KeyParameter.blob (`hidl_vec<u8>`) */
    if (kmhal_hidl_vec_read_embedded(NULL, NULL, p, off_p,
               (const struct kmhal_hidl_vec *)&kp_p->blob,
                sizeof(u8), ref, offsetof(struct KM_KeyParameter, blob)))
    {
        s_log_error("Failed to read KeyParameter's embedded blob HIDL vec buffer");
        return 1;
    }

    return 0;
}

void write_vec_of_key_parameter(struct kmhal_parcel *p,
                                const void *data, size_t size)
{
    u_check_params(data != NULL && size == sizeof(struct kmhal_hidl_vec));

    const struct kmhal_hidl_vec *vec_p = (const struct kmhal_hidl_vec *)data;

    /* hidl_vec<KeyParameter> (top-level buffer obj) */
    kmhal_parcel_obj_t vec_ref =
    kmhal_hidl_vec_write(p, vec_p, sizeof(struct KM_KeyParameter),
            KMHAL_PARCEL_OBJ_INVALID, 0, NULL);

    for (u32 i = 0; i < vec_p->size; i++) {
        /* hidl_vec<KeyParameter>[i].blob (`hidl_vec<u8>`) */
        const struct KM_KeyParameter *const curr =
            &((const struct KM_KeyParameter *)vec_p->buffer)[i];

        binder_size_t parent_offset = i * sizeof(struct KM_KeyParameter) +
                                        offsetof(struct KM_KeyParameter, blob);

        kmhal_hidl_vec_write_embedded(p,
                (const struct kmhal_hidl_vec *)&curr->blob,
                sizeof(u8), vec_ref, parent_offset);
    }
}

int parse_vec_of_key_parameter(const struct kmhal_parcel *p, size_t *off_p,
                              const void **out_p, size_t out_size)
{
    if (out_p == NULL || out_size != sizeof(struct kmhal_hidl_vec)) {
        s_log_error("%s: Invalid parameters", __func__);
        return -1;
    }

    kmhal_parcel_obj_t vec_ref = KMHAL_PARCEL_OBJ_INVALID;

    /* hidl_vec<KeyParameter> (top-level buffer obj) */
    if (kmhal_hidl_vec_read((const struct kmhal_hidl_vec **)out_p,
                sizeof(struct KM_KeyParameter), p, off_p, &vec_ref))
    {
        s_log_error("Failed to read the HIDL vec buffer object");
        return 1;
    }
    const struct kmhal_hidl_vec *const vec_p = *out_p;

    for (u32 i = 0; i < vec_p->size; i++) {
        /* hidl_vec<KeyParameter>[i].blob (`hidl_vec<u8>`) */

        const size_t parent_offset = i * sizeof(struct KM_KeyParameter) +
                                        offsetof(struct KM_KeyParameter, blob);

        const struct kmhal_hidl_vec *const curr_blob =
            (const struct kmhal_hidl_vec *)((const u8 *)vec_p->buffer +
                                             parent_offset);

        if (kmhal_hidl_vec_read_embedded(NULL, NULL, p, off_p,
                    curr_blob, sizeof(u8), vec_ref, parent_offset))
        {
            s_log_error("Failed to read "
                    "embedded KeyParameter's embedded blob HIDL vec buffer");
            return 1;
        }
    }

    return 0;
}

void write_key_characteristics(struct kmhal_parcel *p,
                               const void *data, size_t size)
{
    u_check_params(data != NULL &&
            size == sizeof(struct KM_KeyCharacteristics));

    /* KeyCharacteristics (top-level buffer obj) */
    kmhal_parcel_obj_t kc_ref =
    kmhal_parcel_write_buffer_obj(p, data, size,
            0, KMHAL_PARCEL_OBJ_INVALID, 0);

    const struct KM_KeyCharacteristics *const kc_p = data;

    /* KeyCharacteristics.softwareEnforced (`hidl_vec<KeyParameter>`) */
    kmhal_parcel_obj_t sw_ref =
    kmhal_hidl_vec_write_embedded(p,
            (const struct kmhal_hidl_vec *)&kc_p->softwareEnforced,
            sizeof(struct KM_KeyParameter), kc_ref,
            offsetof(struct KM_KeyCharacteristics, softwareEnforced));

    for (u32 i = 0; i < kc_p->softwareEnforced.size; i++) {
        const struct KM_KeyParameter *const curr =
            &kc_p->softwareEnforced.buffer[i];

        /* KeyCharacteristics.softwareEnforced[i].blob (`hidl_vec<u8>`) */
        kmhal_hidl_vec_write_embedded(p,
                (const struct kmhal_hidl_vec *)&curr->blob,
                sizeof(u8), sw_ref,
                i*sizeof(struct KM_KeyParameter) +
                    offsetof(struct KM_KeyParameter, blob)
        );
    }

    /* KeyCharacteristics.hardwareEnforced (`hidl_vec<KeyParameter>`) */
    kmhal_parcel_obj_t hw_ref =
    kmhal_hidl_vec_write_embedded(p,
            (const struct kmhal_hidl_vec *)&kc_p->hardwareEnforced,
            sizeof(struct KM_KeyParameter), kc_ref,
            offsetof(struct KM_KeyCharacteristics, hardwareEnforced));

    for (u32 i = 0; i < kc_p->hardwareEnforced.size; i++) {
        const struct KM_KeyParameter *const curr =
            &kc_p->hardwareEnforced.buffer[i];

        /* KeyCharacteristics.hardwareEnforced[i].blob (`hidl_vec<u8>`) */
        kmhal_hidl_vec_write_embedded(p,
                (const struct kmhal_hidl_vec *)&curr->blob,
                sizeof(u8), hw_ref,
                i*sizeof(struct KM_KeyParameter) +
                    offsetof(struct KM_KeyParameter, blob)
        );
    }
}

int parse_key_characteristics(const struct kmhal_parcel *p, size_t *off_p,
                              const void **out_p, size_t out_size)
{
    if (out_p == NULL || out_size != sizeof(struct KM_KeyCharacteristics)) {
        s_log_error("%s: Invalid parameters", __func__);
        return -1;
    }

    /**
     * `KeyCharacteristics]`: read_buffer_obj
     *  -> `hidl_vec<KeyParameter>` (softwareEnforced): hidl_vec_read_embedded
     *          ==> [ KeyParameter -> `hidl_vec<u8>` blob], ... ]
     *                                   ^ for each: hidl_vec_read_embedded
     *
     *  -> `hidl_vec<KeyParameter>` (hardwareEnforced): hidl_vec_read_embedded
     *          ==> [ KeyParameter -> `hidl_vec<u8>` blob], ... ]
     *                                   ^ for each: hidl_vec_read_embedded
     *
     *  so first, `read_buffer_obj` the top-level `KeyCharacteristics`,
     *  then, for both `softwareEnforced` and `hardwareEnforced`,
     *  which both are `hidl_vec<KeyParameter>`s:
     *      Read embedded hidl_vec<KeyParameter>;
     *          Then for each KeyParameter, read its blob
     *          (an embedded hidl_vec<u8>).
     *
     *  So:
     *      [KeyCharacteristics]: buffer obj
     *          -> [softwareEnforced]: embedded hidl_vec<KeyParameter>
     *              -> { KeyParameter, ... }
     *                      -> [blob]: embedded hidl_vec<u8>
     *
     *          -> [hardwareEnforced]: embedded hidl_vec<KeyParameter>
     *              -> { KeyParameter, ... }
     *                      -> [blob]: embedded hidl_vec<u8>
     */

    /* KeyCharacteristics (top-level buffer obj) */
    kmhal_parcel_obj_t kc_ref = KMHAL_PARCEL_OBJ_INVALID;
    u32 exp_flags = 0;
    if (kmhal_parcel_read_buffer_obj(p, off_p,
                sizeof(struct KM_KeyCharacteristics), &exp_flags,
                NULL, NULL, out_p, &kc_ref))
    {
        s_log_error("Failed to read the KeyCharacteristics buffer object");
        return 1;
    }
    const struct KM_KeyCharacteristics *const kc_p = *out_p;

    /* KeyCharacteristics.softwareEnforced (`hidl_vec<KeyParameter>`) */
    kmhal_parcel_obj_t sw_ref = KMHAL_PARCEL_OBJ_INVALID;
    if (kmhal_hidl_vec_read_embedded(NULL, &sw_ref, p, off_p,
                (const struct kmhal_hidl_vec *)&kc_p->softwareEnforced,
                sizeof(struct KM_KeyParameter), kc_ref,
                offsetof(struct KM_KeyCharacteristics, softwareEnforced)))
    {
        s_log_error("Failed to read the KeyCharacteristics "
                "embedded softwareEnforced HIDL vec buffer object");
        return 1;
    }

    for (u32 i = 0; i < kc_p->softwareEnforced.size; i++) {
        const size_t parent_offset = i*sizeof(struct KM_KeyParameter)
                                    + offsetof(struct KM_KeyParameter, blob);

        const struct kmhal_hidl_vec *curr_blob = (const struct kmhal_hidl_vec *)
                ((const u8 *)kc_p->softwareEnforced.buffer + parent_offset);

        /* KeyCharacteristics.softwareEnforced[i].blob (`hidl_vec<u8>`) */
        if (kmhal_hidl_vec_read_embedded(NULL, NULL, p, off_p,
                    curr_blob, sizeof(u8), sw_ref, parent_offset))
        {
            s_log_error("Failed to read the KeyCharacteristics "
                    "embedded softwareEnforced embedded KeyParameter's "
                    "embedded blob HIDL vec buffer object");
            return 1;
        }
    }

    /* KeyCharacteristics.hardwareEnforced (`hidl_vec<KeyParameter>`) */
    kmhal_parcel_obj_t hw_ref = KMHAL_PARCEL_OBJ_INVALID;
    if (kmhal_hidl_vec_read_embedded(NULL, &hw_ref, p, off_p,
                (const struct kmhal_hidl_vec *)&kc_p->hardwareEnforced,
                sizeof(struct KM_KeyParameter), kc_ref,
                offsetof(struct KM_KeyCharacteristics, hardwareEnforced)))
    {
        s_log_error("Failed to read the KeyCharacteristics "
                "embedded hardwareEnforced HIDL vec buffer object");
        return 1;
    }

    for (u32 i = 0; i < kc_p->hardwareEnforced.size; i++) {
        const size_t parent_offset = i*sizeof(struct KM_KeyParameter)
                                    + offsetof(struct KM_KeyParameter, blob);

        const struct kmhal_hidl_vec *curr_blob = (const struct kmhal_hidl_vec *)
                ((const u8 *)kc_p->hardwareEnforced.buffer + parent_offset);

        /* KeyCharacteristics.hardwareEnforced[i].blob (`hidl_vec<u8>`) */
        if (kmhal_hidl_vec_read_embedded(NULL, NULL, p, off_p,
                    curr_blob, sizeof(u8), hw_ref, parent_offset))
        {
            s_log_error("Failed to read the KeyCharacteristics "
                    "embedded hardwareEnforced embedded KeyParameter's "
                    "embedded blob HIDL vec buffer object");
            return 1;
        }
    }

    return 0;
}

void write_hmac_sharing_parameters(struct kmhal_parcel *p,
                                   const void *data, size_t size)
{
    u_check_params(data != NULL &&
                   size == sizeof(struct KM_HmacSharingParameters));

    /* HmacSharingParameters (top-level buffer obj) */
    kmhal_parcel_obj_t hsp_ref =
    kmhal_parcel_write_buffer_obj(p, data, size,
            0, KMHAL_PARCEL_OBJ_INVALID, 0);
    const struct KM_HmacSharingParameters *const hsp_p = data;

    /* HmacSharingParameters.seed (`hidl_vec<u8>`) */
    kmhal_hidl_vec_write_embedded(p,
            (const struct kmhal_hidl_vec *)&hsp_p->seed, sizeof(u8),
            hsp_ref, offsetof(struct KM_HmacSharingParameters, seed));
}

int parse_hmac_sharing_parameters(const struct kmhal_parcel *p, size_t *off_p,
                                 const void **out_p, size_t out_size)
{
    if (out_p == NULL || out_size != sizeof(struct KM_HmacSharingParameters)) {
        s_log_error(__func__, "Invalid parameters");
        return -1;
    }

    kmhal_parcel_obj_t hsp_ref = KMHAL_PARCEL_OBJ_INVALID;

    /* HmacSharingParameters (top-level buffer obj) */
    u32 exp_flags = 0;
    if (kmhal_parcel_read_buffer_obj(p, off_p,
                sizeof(struct KM_HmacSharingParameters),
                &exp_flags, NULL, NULL, out_p, &hsp_ref))
    {
        s_log_error("Failed to read the HmacSharingParameters buffer object");
        return 1;
    }
    const struct KM_HmacSharingParameters *const hsp_p = *out_p;

    /* HmacSharingParameters.seed (`hidl_vec<u8>`) */
    if (kmhal_hidl_vec_read_embedded(NULL, NULL, p, off_p,
                (const struct kmhal_hidl_vec *)&hsp_p->seed, sizeof(u8),
                hsp_ref, offsetof(struct KM_HmacSharingParameters, seed)))
    {
        s_log_error("Failed to read the "
                "HmacSharingParameters' embedded seed HIDL vec buffer object");
        return 1;
    }

    return 0;
}

void write_vec_of_hmac_sharing_parameters(struct kmhal_parcel *p,
                                          const void *data, size_t size)
{
    u_check_params(data != NULL || size == sizeof(struct kmhal_hidl_vec));

    const struct kmhal_hidl_vec *const vec_p = data;

    /* hidl_vec<HmacSharingParameters> (top-level buffer obj) */
    kmhal_parcel_obj_t vec_ref =
    kmhal_hidl_vec_write(p, vec_p, sizeof(struct KM_HmacSharingParameters),
            KMHAL_PARCEL_OBJ_INVALID, 0, NULL);

    for (u32 i = 0; i < vec_p->size; i++) {
        /* hidl_vec<HmacSharingParameters>[i].seed (`hidl_vec<u8>`) */
        const struct KM_HmacSharingParameters *const curr =
            &((const struct KM_HmacSharingParameters *)vec_p->buffer)[i];

        kmhal_hidl_vec_write_embedded(p,
                (const struct kmhal_hidl_vec *)&curr->seed,
                sizeof(u8), vec_ref,
                i*sizeof(struct KM_HmacSharingParameters) +
                    offsetof(struct KM_HmacSharingParameters, seed)
        );
    }
}

int parse_vec_of_hmac_sharing_parameters(const struct kmhal_parcel *p,
                                         size_t *off_p,
                                         const void **out_p, size_t out_size)
{
    if (out_p == NULL || out_size != sizeof(struct kmhal_hidl_vec)) {
        s_log_error("%s: Invalid parameters", __func__);
        return -1;
    }

    kmhal_parcel_obj_t vec_ref = KMHAL_PARCEL_OBJ_INVALID;

    /* hidl_vec<HmacSharingParameters> (top-level buffer obj) */
    if (kmhal_hidl_vec_read((const struct kmhal_hidl_vec **)out_p,
                sizeof(struct KM_HmacSharingParameters), p, off_p, &vec_ref))
    {
        s_log_error("Failed to read the HIDL vec buffer object");
        return 1;
    }
    const struct kmhal_hidl_vec *const vec_p = *out_p;

    for (u32 i = 0; i < vec_p->size; i++) {
        /* hidl_vec<HmacSharingParameters>[i].seed (`hidl_vec<u8>`) */

        const size_t parent_offset =
            i*sizeof(struct KM_HmacSharingParameters) +
                offsetof(struct KM_HmacSharingParameters, seed);

        const struct kmhal_hidl_vec *const curr_blob =
            (const struct kmhal_hidl_vec *)(
                    (const u8 *)vec_p->buffer + parent_offset
            );

        if (kmhal_hidl_vec_read_embedded(NULL, NULL, p, off_p,
                    curr_blob, sizeof(u8), vec_ref, parent_offset))
        {
            s_log_error("Failed to read embedded HmacSharingParameters' "
                        "embedded `seed` HIDL vec buffer");
            return 1;
        }
    }

    return 0;
}

void write_hardware_auth_token(struct kmhal_parcel *p,
                               const void *data, size_t size)
{
    u_check_params(data != NULL && size == sizeof(struct KM_HardwareAuthToken));

    /* HardwareAuthToken (top-level buffer obj) */
    kmhal_parcel_obj_t hat_ref =
    kmhal_parcel_write_buffer_obj(p, data, size,
            0, KMHAL_PARCEL_OBJ_INVALID, 0);

    /* HardwareAuthToken.mac (`hidl_vec<u8>`) */
    const struct KM_HardwareAuthToken *hat_p = data;
    kmhal_hidl_vec_write_embedded(p,
            (const struct kmhal_hidl_vec *)&hat_p->mac, sizeof(u8),
            hat_ref, offsetof(struct KM_HardwareAuthToken, mac));
}

int parse_hardware_auth_token(const struct kmhal_parcel *p, size_t *off_p,
                             const void **out_p, size_t out_size)
{
    if (out_p == NULL || out_size != sizeof(struct KM_HardwareAuthToken)) {
        s_log_error("%s: Invalid parameters", __func__);
        return -1;
    }

    kmhal_parcel_obj_t hat_ref = KMHAL_PARCEL_OBJ_INVALID;

    /* HardwareAuthToken (top-level buffer obj) */
    u32 exp_flags = 0;
    if (kmhal_parcel_read_buffer_obj(p, off_p,
                sizeof(struct KM_HardwareAuthToken),
                &exp_flags, NULL, NULL, out_p, &hat_ref))
    {
        s_log_error("Failed to read the HardwareAuthToken buffer object");
        return 1;
    }
    const struct KM_HardwareAuthToken *const hat_p = *out_p;

    /* HardwareAuthToken.mac (`hidl_vec<u8>`) */
    if (kmhal_hidl_vec_read_embedded(NULL, NULL, p, off_p,
                (const struct kmhal_hidl_vec *)&hat_p->mac, sizeof(u8),
                hat_ref, offsetof(struct KM_HardwareAuthToken, mac)))
    {
        s_log_error("Failed to read the "
                "HardwareAuthToken's embedded mac HIDL vec buffer object");
        return 1;
    }

    return 0;
}

void write_verification_token(struct kmhal_parcel *p,
                              const void *data, size_t size)
{
    u_check_params(data != NULL && size == sizeof(struct KM_VerificationToken));

    /* VerificationToken (top-level buffer obj) */
    kmhal_parcel_obj_t vt_ref =
    kmhal_parcel_write_buffer_obj(p, data, size,
            0, KMHAL_PARCEL_OBJ_INVALID, 0);
    const struct KM_VerificationToken *const vt_p = data;

    /* VerificationToken.parametersVerified (`hidl_vec<KeyParameter>`) */
    kmhal_parcel_obj_t pv_ref =
    kmhal_hidl_vec_write_embedded(p,
            (const struct kmhal_hidl_vec *)&vt_p->parametersVerified,
            sizeof(struct KM_KeyParameter), vt_ref,
            offsetof(struct KM_VerificationToken, parametersVerified));
    for (u32 i = 0; i < vt_p->parametersVerified.size; i++) {
        /* VerificationToken.parametersVerified[i].blob (`hidl_vec<u8>`) */

        const struct KM_KeyParameter *const curr =
            &vt_p->parametersVerified.buffer[i];

        const binder_size_t parent_offset = i*sizeof(struct KM_KeyParameter)
                                    + offsetof(struct KM_KeyParameter, blob);

        kmhal_hidl_vec_write_embedded(p,
                (const struct kmhal_hidl_vec *)&curr->blob,
                sizeof(u8), pv_ref, parent_offset);
    }

    /* VerificationToken.mac (`hidl_vec<u8>`) */
    kmhal_hidl_vec_write_embedded(p,
            (const struct kmhal_hidl_vec *)&vt_p->mac, sizeof(u8),
            vt_ref, offsetof(struct KM_HardwareAuthToken, mac));
}

int parse_verification_token(const struct kmhal_parcel *p, size_t *off_p,
                             const void **out_p, size_t out_size)
{
    if (out_p == NULL || out_size != sizeof(struct KM_VerificationToken)) {
        s_log_error("%s: Invalid parameters", __func__);
        return -1;
    }

    kmhal_parcel_obj_t vt_ref = KMHAL_PARCEL_OBJ_INVALID;

    u32 exp_flags = 0;
    if (kmhal_parcel_read_buffer_obj(p, off_p,
                sizeof(struct KM_VerificationToken),
                &exp_flags, NULL, NULL, out_p, &vt_ref))
    {
        s_log_error("Failed to read the VerificationToken buffer object");
        return 1;
    }
    const struct KM_VerificationToken *const vt_p = *out_p;

    /* VerificationToken.parametersVerified (`hidl_vec<KeyParameter>`) */
    kmhal_parcel_obj_t pv_ref = KMHAL_PARCEL_OBJ_INVALID;
    if (kmhal_hidl_vec_read_embedded(NULL, &pv_ref, p, off_p,
                (const struct kmhal_hidl_vec *)&vt_p->parametersVerified,
                sizeof(struct KM_KeyParameter),
                vt_ref,
                offsetof(struct KM_VerificationToken, parametersVerified)))
    {
        s_log_error("Failed to read the "
                "VerificationToken's embedded parametersVerified "
                "HIDL vec buffer object");
        return 1;
    }

    for (u32 i = 0; i < vt_p->parametersVerified.size; i++) {
        /* VerificationToken.parametersVerified[i].blob (`hidl_vec<u8>`) */

        const size_t parent_offset = i*sizeof(struct KM_KeyParameter)
                                    + offsetof(struct KM_KeyParameter, blob);

        const struct kmhal_hidl_vec *const curr_blob =
            (const struct kmhal_hidl_vec *)(
                (const u8 *)vt_p->parametersVerified.buffer + parent_offset
            );

        if (kmhal_hidl_vec_read_embedded(NULL, NULL, p, off_p,
                    curr_blob, sizeof(u8), pv_ref, parent_offset))
        {
            s_log_error("Failed to read the VerificationToken "
                    "embedded parametersVerified embedded KeyParameter's "
                    "embedded blob HIDL vec buffer object");
            return 1;
        }
    }


    /* VerificationToken.mac (`hidl_vec<u8>`) */
    if (kmhal_hidl_vec_read_embedded(NULL, NULL, p, off_p,
                (const struct kmhal_hidl_vec *)&vt_p->mac, sizeof(u8),
                vt_ref, offsetof(struct KM_VerificationToken, mac)))
    {
        s_log_error("Failed to read the "
                "VerificationToken's embedded mac HIDL vec buffer object");
        return 1;
    }

    return 0;
}
