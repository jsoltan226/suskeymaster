#ifndef SUSKEYMASTER_KMHAL_HIDL_KEYMASTER_HIDL_H_
#define SUSKEYMASTER_KMHAL_HIDL_KEYMASTER_HIDL_H_

#ifndef SUSKEYMASTER_BUILD_HOST

#include "hidl-types.h"
#include "hidl-parcel.h"
#include "../util/keymaster-types-c.h"
#include <core/int.h>
#include <core/log.h>
#include <cstddef>
#include <cstring>

template<typename T> void write_vec_of_primitive(struct kmhal_hidl_parcel *p,
                                                      const void *data, size_t size)
{
    if (data == NULL || size != sizeof(struct kmhal_hidl_vec))
        s_abort("keymaster-hidl-types", __func__, "Invalid parameters");

    const struct kmhal_hidl_vec *const vec_p =
        reinterpret_cast<const struct kmhal_hidl_vec *>(data);

    kmhal_hidl_vec_write(p, vec_p, sizeof(T), KMHAL_HIDL_PARCEL_OBJ_INVALID, 0, nullptr);
}

template<typename T> int read_vec_of_primitive(const struct kmhal_hidl_parcel *p,
                                               size_t *off_p,
                                               const void **out_p, size_t out_size)
{
    if (out_p == NULL || out_size != sizeof(struct kmhal_hidl_vec)) {
        s_log(S_LOG_ERROR, "keymaster-hidl-types", "%s: Invalid parameters", __func__);
        return -1;
    }

    return kmhal_hidl_vec_read(reinterpret_cast<const struct kmhal_hidl_vec **>(out_p),
            sizeof(T), p, off_p, nullptr);
}

template<typename T> void write_vec_of_vec_of_primitive(struct kmhal_hidl_parcel *p,
                                                             const void *data, size_t size)
{
    if (data == NULL || size != sizeof(struct kmhal_hidl_vec))
        s_abort("keymaster-hidl-types", __func__, "Invalid parameters");

    const struct kmhal_hidl_vec vec = *(reinterpret_cast<const struct kmhal_hidl_vec *>(data));

    kmhal_hidl_parcel_obj_t ref =
    kmhal_hidl_parcel_write_buffer_obj(p, vec.buffer, vec.size * sizeof(struct kmhal_hidl_vec), 0,
            KMHAL_HIDL_PARCEL_OBJ_INVALID, 0);

    for (u32 i = 0; i < vec.size; i++) {
        kmhal_hidl_parcel_write_embedded_buffer(p, vec.buffer,
                sizeof(T) * vec.size, ref, i * vec.size);
    }
}

template<typename T> int read_vec_of_vec_of_primitive(const struct kmhal_hidl_parcel *p,
                                                      size_t *off_p,
                                                      const void **out_p, size_t out_size)
{
    if (out_p == NULL || out_size != sizeof(struct kmhal_hidl_vec)) {
        s_log(S_LOG_ERROR, "keymaster-hidl-types", "%s: Invalid parameters", __func__);
        return -1;
    }

    const struct kmhal_hidl_vec *vec_p = nullptr;
    kmhal_hidl_parcel_obj_t ref;
    if (kmhal_hidl_vec_read(reinterpret_cast<const struct kmhal_hidl_vec **>(out_p),
                sizeof(struct kmhal_hidl_vec), p, off_p, &ref))
    {
        s_log(S_LOG_ERROR, "keymaster-hidl-types", "Failed to read the HIDL vec buffer object");
        return 1;
    }

    vec_p = reinterpret_cast<const struct kmhal_hidl_vec *>(*out_p);

    for (u32 i = 0; i < vec_p->size; i++) {
        const size_t parent_offset = i * sizeof(struct kmhal_hidl_vec);

        const struct kmhal_hidl_vec *curr = reinterpret_cast<const struct kmhal_hidl_vec *>(
            reinterpret_cast<const u8 *>(vec_p->buffer) + parent_offset
        );

        if (kmhal_hidl_vec_read_embedded(nullptr, nullptr, p, off_p,
                    curr, sizeof(T), ref, parent_offset))
        {
            s_log(S_LOG_ERROR, "keymaster-hidl-types", "Failed to read embedded HIDL vec buffer");
            return 1;
        }
    }

    return 0;
}

static inline
void write_key_parameter(struct kmhal_hidl_parcel *p,
                         const void *data, size_t size)
{
    if (data == NULL || size != sizeof(struct KM_KeyParameter))
        s_abort("keymaster-hidl-types", __func__, "Invalid parameters");

    kmhal_hidl_parcel_obj_t ref =
    kmhal_hidl_parcel_write_buffer_obj(p, data, size, 0, KMHAL_HIDL_PARCEL_OBJ_INVALID, 0);

    const struct KM_KeyParameter *const kp_p =
        reinterpret_cast<const struct KM_KeyParameter *>(data);

    kmhal_hidl_vec_write_embedded(p,
                reinterpret_cast<const struct kmhal_hidl_vec *>(&kp_p->blob),
                sizeof(uint8_t), ref, offsetof(struct KM_KeyParameter, blob));
}

static inline
int read_key_parameter(const struct kmhal_hidl_parcel *p,
                       size_t *off_p,
                       const void **out_p, size_t out_size)
{
    if (out_p == NULL || out_size != sizeof(struct KM_KeyParameter)) {
        s_log(S_LOG_ERROR, "keymaster-hidl-types", "%s: Invalid parameters", __func__);
        return -1;
    }

    kmhal_hidl_parcel_obj_t ref;

    u32 exp_flags = 0;
    if (kmhal_hidl_parcel_read_buffer_obj(p, off_p, sizeof(struct KM_KeyParameter),
                &exp_flags, nullptr, nullptr, out_p, &ref))
    {
        s_log(S_LOG_ERROR, "keymaster-hidl-types",
                "Failed to read the key parameter buffer object");
        return 1;
    }

    const struct KM_KeyParameter *const kp_p =
        reinterpret_cast<const struct KM_KeyParameter *>(*out_p);

    if (kmhal_hidl_vec_read_embedded(nullptr, nullptr, p, off_p,
                reinterpret_cast<const struct kmhal_hidl_vec *>(&kp_p->blob),
                sizeof(uint8_t), ref, offsetof(struct KM_KeyParameter, blob)))
    {
            s_log(S_LOG_ERROR, "keymaster-hidl-types",
                    "Failed to read KeyParameter's embedded blob HIDL vec buffer");
            return 1;
    }

    return 0;
}

static inline
void write_vec_of_key_parameter(struct kmhal_hidl_parcel *p,
                                const void *data, size_t size)
{
    if (data == NULL || size != sizeof(struct kmhal_hidl_vec))
        s_abort("keymaster-hidl-types", __func__, "Invalid parameters");

    const struct kmhal_hidl_vec *vec_p = reinterpret_cast<const struct kmhal_hidl_vec *>(data);

    kmhal_hidl_parcel_obj_t vec_ref =
    kmhal_hidl_vec_write(p, vec_p, sizeof(struct KM_KeyParameter),
            KMHAL_HIDL_PARCEL_OBJ_INVALID, 0, nullptr);

    for (u32 i = 0; i < vec_p->size; i++) {
        const struct KM_KeyParameter *const curr =
            &reinterpret_cast<const struct KM_KeyParameter *>(vec_p->buffer)[i];

        kmhal_hidl_vec_write_embedded(p,
                reinterpret_cast<const struct kmhal_hidl_vec *>(&curr->blob),
                sizeof(uint8_t), vec_ref,
                i*sizeof(struct KM_KeyParameter) + offsetof(struct KM_KeyParameter, blob)
        );
    }
}

static inline
int read_vec_of_key_parameter(const struct kmhal_hidl_parcel *p,
                              size_t *off_p,
                              const void **out_p, size_t out_size)
{
    if (out_p == NULL || out_size != sizeof(struct kmhal_hidl_vec)) {
        s_log(S_LOG_ERROR, "keymaster-hidl-types", "%s: Invalid parameters", __func__);
        return -1;
    }

    kmhal_hidl_parcel_obj_t vec_ref;

    if (kmhal_hidl_vec_read(reinterpret_cast<const struct kmhal_hidl_vec **>(out_p),
                sizeof(struct KM_KeyParameter), p, off_p, &vec_ref))
    {
        s_log(S_LOG_ERROR, "keymaster-hidl-types",
                "Failed to read the HIDL vec buffer object");
        return 1;
    }

    const struct kmhal_hidl_vec *const vec_p =
        reinterpret_cast<const struct kmhal_hidl_vec *>(*out_p);

    for (u32 i = 0; i < vec_p->size; i++) {
        const size_t parent_offset =
            i*sizeof(struct KM_KeyParameter) + offsetof(struct KM_KeyParameter, blob);

        const struct kmhal_hidl_vec *const curr_blob =
        reinterpret_cast<const struct kmhal_hidl_vec *>(
                reinterpret_cast<const u8 *>(vec_p->buffer) + parent_offset
        );

        if (kmhal_hidl_vec_read_embedded(nullptr, nullptr, p, off_p,
                    curr_blob, sizeof(uint8_t), vec_ref, parent_offset))
        {
                s_log(S_LOG_ERROR, "keymaster-hidl-types",
                        "Failed to read embedded KeyParameter's embedded blob HIDL vec buffer");
                return 1;
        }
    }

    return 0;
}

static inline
void write_key_characteristics(struct kmhal_hidl_parcel *p,
                               const void *data, size_t size)
{
    if (data == NULL || size != sizeof(struct KM_KeyCharacteristics))
        s_abort("keymaster-hidl-types", __func__, "Invalid parameters");

    kmhal_hidl_parcel_obj_t kc_ref =
    kmhal_hidl_parcel_write_buffer_obj(p, data, size,
            0, KMHAL_HIDL_PARCEL_OBJ_INVALID, 0);

    const struct KM_KeyCharacteristics *kc_p =
        reinterpret_cast<const struct KM_KeyCharacteristics *>(data);

    kmhal_hidl_parcel_obj_t sw_ref =
    kmhal_hidl_vec_write_embedded(p,
            reinterpret_cast<const struct kmhal_hidl_vec *>(&kc_p->softwareEnforced),
            sizeof(struct KM_KeyParameter), kc_ref,
            offsetof(struct KM_KeyCharacteristics, softwareEnforced));
    for (u32 i = 0; i < kc_p->softwareEnforced.size; i++) {
        const struct KM_KeyParameter *const curr =
            &reinterpret_cast<const struct KM_KeyParameter *>(kc_p->softwareEnforced.buffer)[i];

        kmhal_hidl_vec_write_embedded(p,
                reinterpret_cast<const struct kmhal_hidl_vec *>(&curr->blob),
                sizeof(uint8_t), sw_ref,
                i*sizeof(struct KM_KeyParameter) + offsetof(struct KM_KeyParameter, blob)
        );
    }

    kmhal_hidl_parcel_obj_t hw_ref =
    kmhal_hidl_vec_write_embedded(p,
            reinterpret_cast<const struct kmhal_hidl_vec *>(&kc_p->hardwareEnforced),
            sizeof(struct KM_KeyParameter), kc_ref,
            offsetof(struct KM_KeyCharacteristics, hardwareEnforced));
    for (u32 i = 0; i < kc_p->hardwareEnforced.size; i++) {
        const struct KM_KeyParameter *const curr =
            &reinterpret_cast<const struct KM_KeyParameter *>(kc_p->hardwareEnforced.buffer)[i];

        kmhal_hidl_vec_write_embedded(p,
                reinterpret_cast<const struct kmhal_hidl_vec *>(&curr->blob),
                sizeof(uint8_t), hw_ref,
                i*sizeof(struct KM_KeyParameter) + offsetof(struct KM_KeyParameter, blob)
        );
    }
}

static inline
int read_key_characteristics(const struct kmhal_hidl_parcel *p,
                             size_t *off_p,
                             const void **out_p, size_t out_size)
{
    if (out_p == NULL || out_size != sizeof(struct KM_KeyCharacteristics)) {
        s_log(S_LOG_ERROR, "keymaster-hidl-types", "%s: Invalid parameters", __func__);
        return -1;
    }

    kmhal_hidl_parcel_obj_t kc_ref;

    u32 exp_flags = 0;
    if (kmhal_hidl_parcel_read_buffer_obj(p, off_p, sizeof(struct KM_KeyCharacteristics),
                &exp_flags, nullptr, nullptr, out_p, &kc_ref))
    {
        s_log(S_LOG_ERROR, "keymaster-hidl-types",
                "Failed to read the KeyCharacteristics buffer object");
        return 1;
    }

    const struct KM_KeyCharacteristics *const kc_p =
        reinterpret_cast<const struct KM_KeyCharacteristics *>(*out_p);

    kmhal_hidl_parcel_obj_t sw_ref;
    if (kmhal_hidl_vec_read_embedded(nullptr, &sw_ref, p, off_p,
                reinterpret_cast<const struct kmhal_hidl_vec *>(&kc_p->softwareEnforced),
                sizeof(struct KM_KeyParameter), kc_ref,
                offsetof(struct KM_KeyCharacteristics, softwareEnforced)))
    {
        s_log(S_LOG_ERROR, "keymaster-hidl-types",
                "Failed to read the KeyCharacteristics "
                "embedded softwareEnforced HIDL vec buffer object");
        return 1;
    }

    for (u32 i = 0; i < kc_p->softwareEnforced.size; i++) {
        const size_t parent_offset =
            i*sizeof(struct KM_KeyParameter) + offsetof(struct KM_KeyParameter, blob);

        const struct kmhal_hidl_vec *curr_blob = reinterpret_cast<const struct kmhal_hidl_vec *>(
                reinterpret_cast<const u8 *>(kc_p->softwareEnforced.buffer) + parent_offset
        );

        if (kmhal_hidl_vec_read_embedded(nullptr, nullptr, p, off_p,
                    curr_blob, sizeof(uint8_t), sw_ref, parent_offset))
        {
            s_log(S_LOG_ERROR, "keymaster-hidl-types",
                    "Failed to read the KeyCharacteristics "
                    "embedded softwareEnforced embedded KeyParameter's embedded blob "
                    "HIDL vec buffer object");
            return 1;
        }
    }

    kmhal_hidl_parcel_obj_t hw_ref;
    if (kmhal_hidl_vec_read_embedded(nullptr, &hw_ref, p, off_p,
                reinterpret_cast<const struct kmhal_hidl_vec *>(&kc_p->hardwareEnforced),
                sizeof(struct KM_KeyParameter), kc_ref,
                offsetof(struct KM_KeyCharacteristics, hardwareEnforced)))
    {
        s_log(S_LOG_ERROR, "keymaster-hidl-types",
                "Failed to read the KeyCharacteristics "
                "embedded hardwareEnforced HIDL vec buffer object");
        return 1;
    }
    for (u32 i = 0; i < kc_p->hardwareEnforced.size; i++) {
        const size_t parent_offset =
            i*sizeof(struct KM_KeyParameter) + offsetof(struct KM_KeyParameter, blob);

        const struct kmhal_hidl_vec *curr_blob = reinterpret_cast<const struct kmhal_hidl_vec *>(
                reinterpret_cast<const u8 *>(kc_p->hardwareEnforced.buffer) + parent_offset
        );

        if (kmhal_hidl_vec_read_embedded(nullptr, nullptr, p, off_p,
                    curr_blob, sizeof(uint8_t), hw_ref, parent_offset))
        {
            s_log(S_LOG_ERROR, "keymaster-hidl-types",
                    "Failed to read the KeyCharacteristics "
                    "embedded hardwareEnforced embedded KeyParameter's embedded blob "
                    "HIDL vec buffer object");
            return 1;
        }
    }

    return 0;
}

static inline
void write_hmac_sharing_parameters(struct kmhal_hidl_parcel *p,
                                   const void *data, size_t size)
{
    if (data == NULL || size != sizeof(struct KM_HmacSharingParameters))
        s_abort("keymaster-hidl-types", __func__, "Invalid parameters");


    kmhal_hidl_parcel_obj_t hsp_ref =
    kmhal_hidl_parcel_write_buffer_obj(p, data, size,
            0, KMHAL_HIDL_PARCEL_OBJ_INVALID, 0);

    const struct KM_HmacSharingParameters *hsp_p =
        reinterpret_cast<const struct KM_HmacSharingParameters *>(data);
    kmhal_hidl_vec_write_embedded(p,
            reinterpret_cast<const struct kmhal_hidl_vec *>(&hsp_p->seed), sizeof(uint8_t),
            hsp_ref, offsetof(struct KM_HmacSharingParameters, seed));
}

static inline
int read_hmac_sharing_parameters(const struct kmhal_hidl_parcel *p,
                                 size_t *off_p,
                                 const void **out_p, size_t out_size)
{
    if (out_p == NULL || out_size != sizeof(struct KM_HmacSharingParameters))
        s_abort("keymaster-hidl-types", __func__, "Invalid parameters");

    kmhal_hidl_parcel_obj_t hsp_ref;

    u32 exp_flags = 0;
    if (kmhal_hidl_parcel_read_buffer_obj(p, off_p, sizeof(struct KM_HmacSharingParameters),
                &exp_flags, nullptr, nullptr, out_p, &hsp_ref))
    {
        s_log(S_LOG_ERROR, "keymaster-hidl-types",
                "Failed to read the HmacSharingParameters buffer object");
        return 1;
    }

    const struct KM_HmacSharingParameters *hsp_p =
        reinterpret_cast<const struct KM_HmacSharingParameters *>(*out_p);

    if (kmhal_hidl_vec_read_embedded(nullptr, nullptr, p, off_p,
                reinterpret_cast<const struct kmhal_hidl_vec *>(&hsp_p->seed), sizeof(uint8_t),
                hsp_ref, offsetof(struct KM_HmacSharingParameters, seed)))
    {
        s_log(S_LOG_ERROR, "keymaster-hidl-types",
                "Failed to read the HmacSharingParameters' embedded seed HIDL vec buffer object");
        return 1;
    }

    return 0;
}

static inline
void write_vec_of_hmac_sharing_parameters(struct kmhal_hidl_parcel *p,
                                          const void *data, size_t size)
{
    if (data == NULL || size != sizeof(struct kmhal_hidl_vec))
        s_abort("keymaster-hidl-types", __func__, "Invalid parameters");

    const struct kmhal_hidl_vec *vec_p = reinterpret_cast<const struct kmhal_hidl_vec *>(data);

    kmhal_hidl_parcel_obj_t vec_ref =
    kmhal_hidl_vec_write(p, vec_p, sizeof(struct KM_HmacSharingParameters),
            KMHAL_HIDL_PARCEL_OBJ_INVALID, 0, nullptr);

    for (u32 i = 0; i < vec_p->size; i++) {
        const struct KM_HmacSharingParameters *const curr =
            &reinterpret_cast<const struct KM_HmacSharingParameters *>(vec_p->buffer)[i];

        kmhal_hidl_vec_write_embedded(p,
                reinterpret_cast<const struct kmhal_hidl_vec *>(&curr->seed),
                sizeof(uint8_t), vec_ref,
                i*sizeof(struct KM_HmacSharingParameters) +
                    offsetof(struct KM_HmacSharingParameters, seed)
        );
    }
}

static inline
int read_vec_of_hmac_sharing_parameters(const struct kmhal_hidl_parcel *p,
                                        size_t *off_p,
                                        const void **out_p, size_t out_size)
{
    if (out_p == NULL || out_size != sizeof(struct kmhal_hidl_vec)) {
        s_log(S_LOG_ERROR, "keymaster-hidl-types", "%s: Invalid parameters", __func__);
        return -1;
    }

    kmhal_hidl_parcel_obj_t vec_ref;

    if (kmhal_hidl_vec_read(reinterpret_cast<const struct kmhal_hidl_vec **>(out_p),
                sizeof(struct KM_HmacSharingParameters), p, off_p, &vec_ref))
    {
        s_log(S_LOG_ERROR, "keymaster-hidl-types",
                "Failed to read the HIDL vec buffer object");
        return 1;
    }

    const struct kmhal_hidl_vec *const vec_p =
        reinterpret_cast<const struct kmhal_hidl_vec *>(*out_p);

    for (u32 i = 0; i < vec_p->size; i++) {
        const size_t parent_offset =
            i*sizeof(struct KM_HmacSharingParameters) +
                offsetof(struct KM_HmacSharingParameters, seed);

        const struct kmhal_hidl_vec *const curr_blob =
        reinterpret_cast<const struct kmhal_hidl_vec *>(
                reinterpret_cast<const u8 *>(vec_p->buffer) + parent_offset
        );

        if (kmhal_hidl_vec_read_embedded(nullptr, nullptr, p, off_p,
                    curr_blob, sizeof(uint8_t), vec_ref, parent_offset))
        {
                s_log(S_LOG_ERROR, "keymaster-hidl-types",
                        "Failed to read embedded HmacSharingParameters' "
                        "embedded seed HIDL vec buffer");
                return 1;
        }
    }

    return 0;
}

static inline
void write_hardware_auth_token(struct kmhal_hidl_parcel *p,
                               const void *data, size_t size)
{
    if (data == NULL || size != sizeof(struct KM_HardwareAuthToken))
        s_abort("keymaster-hidl-types", __func__, "Invalid parameters");


    kmhal_hidl_parcel_obj_t hat_ref =
    kmhal_hidl_parcel_write_buffer_obj(p, data, size,
            0, KMHAL_HIDL_PARCEL_OBJ_INVALID, 0);

    const struct KM_HardwareAuthToken *hat_p =
        reinterpret_cast<const struct KM_HardwareAuthToken *>(data);
    kmhal_hidl_vec_write_embedded(p,
            reinterpret_cast<const struct kmhal_hidl_vec *>(&hat_p->mac), sizeof(uint8_t),
            hat_ref, offsetof(struct KM_HardwareAuthToken, mac));
}

static inline
int read_hardware_auth_token(const struct kmhal_hidl_parcel *p,
                             size_t *off_p,
                             const void **out_p, size_t out_size)
{
    if (out_p == NULL || out_size != sizeof(struct KM_HardwareAuthToken))
        s_abort("keymaster-hidl-types", __func__, "Invalid parameters");

    kmhal_hidl_parcel_obj_t hat_ref;

    u32 exp_flags = 0;
    if (kmhal_hidl_parcel_read_buffer_obj(p, off_p, sizeof(struct KM_HardwareAuthToken),
                &exp_flags, nullptr, nullptr, out_p, &hat_ref))
    {
        s_log(S_LOG_ERROR, "keymaster-hidl-types",
                "Failed to read the HardwareAuthToken buffer object");
        return 1;
    }

    const struct KM_HardwareAuthToken *hat_p =
        reinterpret_cast<const struct KM_HardwareAuthToken *>(*out_p);

    if (kmhal_hidl_vec_read_embedded(nullptr, nullptr, p, off_p,
                reinterpret_cast<const struct kmhal_hidl_vec *>(&hat_p->mac), sizeof(uint8_t),
                hat_ref, offsetof(struct KM_HardwareAuthToken, mac)))
    {
        s_log(S_LOG_ERROR, "keymaster-hidl-types",
                "Failed to read the HardwareAuthToken's embedded mac HIDL vec buffer object");
        return 1;
    }

    return 0;
}

static inline
void write_verification_token(struct kmhal_hidl_parcel *p,
                              const void *data, size_t size)
{
    if (data == NULL || size != sizeof(struct KM_HardwareAuthToken))
        s_abort("keymaster-hidl-types", __func__, "Invalid parameters");


    kmhal_hidl_parcel_obj_t vt_ref =
    kmhal_hidl_parcel_write_buffer_obj(p, data, size,
            0, KMHAL_HIDL_PARCEL_OBJ_INVALID, 0);

    const struct KM_VerificationToken *vt_p =
        reinterpret_cast<const struct KM_VerificationToken *>(data);

    kmhal_hidl_parcel_obj_t pv_ref =
    kmhal_hidl_vec_write_embedded(p,
            reinterpret_cast<const struct kmhal_hidl_vec *>(&vt_p->parametersVerified),
            sizeof(struct KM_KeyParameter), vt_ref,
            offsetof(struct KM_VerificationToken, parametersVerified));
    for (u32 i = 0; i < vt_p->parametersVerified.size; i++) {
        const struct KM_KeyParameter *const curr =
            &reinterpret_cast<const struct KM_KeyParameter *>(vt_p->parametersVerified.buffer)[i];

        kmhal_hidl_vec_write_embedded(p,
                reinterpret_cast<const struct kmhal_hidl_vec *>(&curr->blob),
                sizeof(uint8_t), pv_ref,
                i*sizeof(struct KM_KeyParameter) + offsetof(struct KM_KeyParameter, blob)
        );
    }

    kmhal_hidl_vec_write_embedded(p,
            reinterpret_cast<const struct kmhal_hidl_vec *>(&vt_p->mac), sizeof(uint8_t),
            vt_ref, offsetof(struct KM_HardwareAuthToken, mac));
}

static inline
int read_verification_token(const struct kmhal_hidl_parcel *p,
                            size_t *off_p,
                            const void **out_p, size_t out_size)
{
    if (out_p == NULL || out_size != sizeof(struct KM_VerificationToken))
        s_abort("keymaster-hidl-types", __func__, "Invalid parameters");

    kmhal_hidl_parcel_obj_t vt_ref;

    u32 exp_flags = 0;
    if (kmhal_hidl_parcel_read_buffer_obj(p, off_p, sizeof(struct KM_VerificationToken),
                &exp_flags, nullptr, nullptr, out_p, &vt_ref))
    {
        s_log(S_LOG_ERROR, "keymaster-hidl-types",
                "Failed to read the VerificationToken buffer object");
        return 1;
    }

    const struct KM_VerificationToken *vt_p =
        reinterpret_cast<const struct KM_VerificationToken *>(*out_p);

    kmhal_hidl_parcel_obj_t pv_ref;

    if (kmhal_hidl_vec_read_embedded(nullptr, &pv_ref, p, off_p,
                reinterpret_cast<const struct kmhal_hidl_vec *>(&vt_p->mac),
                sizeof(struct KM_KeyParameter),
                vt_ref, offsetof(struct KM_VerificationToken, parametersVerified)))
    {
        s_log(S_LOG_ERROR, "keymaster-hidl-types",
                "Failed to read the VerificationToken's embedded parametersVerified "
                "HIDL vec buffer object");
        return 1;
    }

    for (u32 i = 0; i < vt_p->parametersVerified.size; i++) {
        const size_t parent_offset =
            i*sizeof(struct KM_KeyParameter) + offsetof(struct KM_KeyParameter, blob);

        const struct kmhal_hidl_vec *curr_blob = reinterpret_cast<const struct kmhal_hidl_vec *>(
                reinterpret_cast<const u8 *>(vt_p->parametersVerified.buffer) + parent_offset
        );

        if (kmhal_hidl_vec_read_embedded(nullptr, nullptr, p, off_p,
                    curr_blob, sizeof(uint8_t), pv_ref, parent_offset))
        {
            s_log(S_LOG_ERROR, "keymaster-hidl-types",
                    "Failed to read the VerificationToken "
                    "embedded parametersVerified embedded KeyParameter's embedded blob "
                    "HIDL vec buffer object");
            return 1;
        }
    }


    if (kmhal_hidl_vec_read_embedded(nullptr, nullptr, p, off_p,
                reinterpret_cast<const struct kmhal_hidl_vec *>(&vt_p->mac), sizeof(uint8_t),
                vt_ref, offsetof(struct KM_VerificationToken, mac)))
    {
        s_log(S_LOG_ERROR, "keymaster-hidl-types",
                "Failed to read the VerificationToken's embedded mac HIDL vec buffer object");
        return 1;
    }

    return 0;
}

#endif /* SUSKEYMASTER_BUILD_HOST */

#endif /* SUSKEYMASTER_KMHAL_HIDL_KEYMASTER_HIDL_H_ */
