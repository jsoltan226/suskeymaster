#include "hal.h"
#include "keymint-types-aidl.h"
#include "parcel.h"
#include "aidl-util.h"
#include <core/log.h>
#include <core/util.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <linux/android/binder.h>

#define MODULE_NAME "keymint-types-aidl"

static u32 get_aidl_integerparam_union_member_id(enum KM_Tag t);


static void write_vec_of_parcelable(struct kmhal_parcel *p,
                                    const void *vec, size_t item_size,
                                    kmhal_arg_write_inline_data_proc_t proc);
static int parse_vec_of_parcelable(const struct kmhal_parcel *p, size_t *off_p,
                                   size_t item_size,
                                   void *out, size_t out_size,
                                   kmhal_arg_parse_inline_data_proc_t proc,
                                   void (*destroy_proc)(void *));

static void destroy_vec_of_parcelable(void *vec, size_t item_size,
                                      void (*proc)(void *));

#define try_read_primitive(typename, out, field_name) do {              \
    if (kmhal_parcel_read_##typename(p, off_p, &out->field_name)) {     \
        s_log_error("Failed to read the " #field_name " " #typename);   \
        return 1;                                                       \
    }                                                                   \
} while (0)

#define try_read_vec_of(typename, out, field_name) do {                 \
    if (parse_aidl_vec_of_##typename(p, off_p, &out->field_name,        \
                sizeof(struct aidl_vec_of_##typename)))                 \
    {                                                                   \
        s_log_error("Failed to read the "                               \
                    #field_name " " #typename " vec");                  \
        return 1;                                                       \
    }                                                                   \
} while (0)

#define try_read_parcelable(typename, out, field_name) do {             \
    if (parse_aidl_##typename(p, off_p,                                 \
                &out->field_name, sizeof(struct aidl_##typename))) {    \
        s_log_error("Failed to read the "                               \
                    #field_name " " #typename " parcelable");           \
        return 1;                                                       \
    }                                                                   \
} while (0)

#define AIDL_VEC_OF_PARCELABLE_IMPL(T, name)                                   \
    void destroy_aidl_vec_of_##name(struct aidl_vec_of_##name *vec)            \
    {                                                                          \
        destroy_vec_of_parcelable(vec, sizeof(T),                              \
                                  (void (*)(void *))destroy_aidl_##name);      \
    }                                                                          \
                                                                               \
    void write_nullable_aidl_vec_of_##name(struct kmhal_parcel *p,             \
                                           const void *data)                   \
    {                                                                          \
        write_vec_of_parcelable(p, data, sizeof(T), write_aidl_##name);        \
    }                                                                          \
                                                                               \
    void write_aidl_vec_of_##name(struct kmhal_parcel *p, const void *data)    \
    {                                                                          \
        u_check_params(data != NULL);                                          \
        write_nullable_aidl_vec_of_##name(p, data);                            \
    }                                                                          \
                                                                               \
    int parse_aidl_vec_of_##name(const struct kmhal_parcel *p, size_t *off_p,  \
                                 void *out, size_t out_size)                   \
    {                                                                          \
        return parse_vec_of_parcelable(p, off_p, sizeof(T), out, out_size,     \
                parse_aidl_##name,                                             \
                (void (*)(void *))destroy_aidl_##name);                        \
    }                                                                          \

static inline binder_size_t align4(binder_size_t s);

/* from the AIDL-generated KeyParameterValue.h file */
enum aidl_KeyParameterValue_union_field_id {
    invalid = 0,
    algorithm = 1,
    blockMode = 2,
    paddingMode = 3,
    digest = 4,
    ecCurve = 5,
    origin = 6,
    keyPurpose = 7,
    hardwareAuthenticatorType = 8,
    securityLevel = 9,
    boolValue = 10,
    integer = 11,
    longInteger = 12,
    dateTime = 13,
    blob = 14,
};

void destroy_aidl_keymint_hardware_info(
        struct aidl_keymint_hardware_info *hwinfo
)
{
    if (hwinfo == NULL)
        return;

    if (hwinfo->keyMintName != NULL)
        free(hwinfo->keyMintName);

    if (hwinfo->keyMintAuthorName != NULL)
        free(hwinfo->keyMintAuthorName);

    memset(hwinfo, 0, sizeof(struct aidl_keymint_hardware_info));
}

int parse_aidl_keymint_hardware_info(const struct kmhal_parcel *p,
                                     size_t *off_p,
                                     void *out, size_t out_size)
{
    if (out == NULL || out_size != sizeof(struct aidl_keymint_hardware_info)) {
        s_log_error("%s: Invalid parameters", __func__);
        return -1;
    }

    i32 size = 0; size_t start = 0;
    if (kmhal_aidl_parse_parcelable_header(p, off_p, &start, false, &size)) {
        s_log_error("Invalid parcelable header");
        return 1;
    }

    struct aidl_keymint_hardware_info *const hwinfo = out;

    if (kmhal_arg_parse_u32(p, off_p,
                (const void **)&hwinfo->versionNumber, sizeof(i32)))
    {
        s_log_error("%s: Invalid parameters", __func__);
        return 1;
    }

    if (kmhal_arg_parse_u32(p, off_p,
                (const void **)&hwinfo->securityLevel, sizeof(u32)))
    {
        s_log_error("%s: Failed to parse the securityLevel field", __func__);
        return 1;
    }

    hwinfo->keyMintName = NULL;
    if (kmhal_parcel_read_convert_aidl_string16(p, off_p,
                &hwinfo->keyMintName, NULL))
    {
        s_log_error("%s: Failed to parse the keyMintName field", __func__);
        return 1;
    }

    hwinfo->keyMintAuthorName = NULL;
    if (kmhal_parcel_read_convert_aidl_string16(p, off_p,
                &hwinfo->keyMintAuthorName, NULL))
    {
        s_log_error("%s: Failed to parse the keyMintAuthorName field",
                __func__);
        return 1;
    }

    if (kmhal_arg_parse_u32(p, off_p,
                (const void **)&hwinfo->timestampTokenRequired, sizeof(u32)))
    {
        s_log_error("%s: Failed to parse the timestampTokenRequired field",
                __func__);
        return 1;
    }

    if (kmhal_aidl_validate_parcelable_size(start, *off_p, size)) {
        s_log_error("KeyMintHardwareInfo parcelable size mismatch");
        return 1;
    }

    return 0;
}

void destroy_aidl_vec_of_u8(struct aidl_vec_of_u8 *vec)
{
    if (vec == NULL)
        return;

    s_log_trace("%s: ptr: %p, size: %"PRIi32", owns: %d", __func__,
            vec->ptr, vec->size, vec->owns);

    if (vec->ptr != NULL && vec->owns)
        free(vec->ptr);

    memset(vec, 0, sizeof(struct aidl_vec_of_u8));
}

void write_nullable_aidl_vec_of_u8(struct kmhal_parcel *p, const void *data)
{
    if (data == NULL) {
        kmhal_parcel_write_u32(p, 0);
        return;
    }

    const struct aidl_vec_of_u8 *const vec = data;
    s_assert(vec->size >= 0, "Invalid vector size");
    if (vec->size == 0) {
        kmhal_parcel_write_u32(p, 0);
        return;
    }

    kmhal_parcel_write_u32(p, (u32)vec->size);

    kmhal_parcel_write_bytes(p, vec->ptr, (size_t)vec->size);
}

void write_aidl_vec_of_u8(struct kmhal_parcel *p, const void *data)
{
    u_check_params(data != NULL);
    write_nullable_aidl_vec_of_u8(p, data);
}

int parse_aidl_vec_of_u8(const struct kmhal_parcel *p, size_t *off_p,
                         void *out, size_t out_size)
{
    if (out == NULL || out_size != sizeof(struct aidl_vec_of_u8)) {
        s_log_error("%s: Invalid parameters", __func__);
        return -1;
    }

    struct aidl_vec_of_u8 *const vec = out;

    i32 vec_size;
    if (kmhal_aidl_parse_array_header(p, off_p, &vec_size)) {
        s_log_error("Failed to parse the vec header");
        return 1;
    }

    /* std::nullopt */
    if (vec_size <= 0) {
        vec->size = 0;
        vec->ptr = NULL;
        vec->owns = false;
        return 0;
    }

    vec->size = vec_size;
    vec->owns = false;
    vec->ptr = malloc((size_t)vec_size);
    if (vec->ptr == NULL) {
        s_log_error("Failed to malloc a vector copy");
        destroy_aidl_vec_of_u8(vec);
        return 1;
    }
    vec->owns = true;

    if (kmhal_parcel_read_bytes(p, off_p, vec->ptr, (size_t)vec_size)) {
        s_log_error("Failed to read the vector bytes from the parcel");
        destroy_aidl_vec_of_u8(vec);
        return 1;
    }

    return 0;
}

void destroy_aidl_key_parameter(struct aidl_key_parameter *kp)
{
    if (kp->blob.ptr != NULL)
        destroy_aidl_vec_of_u8(&kp->blob);
    memset(kp, 0, sizeof(struct aidl_key_parameter));
}

void write_aidl_key_parameter(struct kmhal_parcel *p, const void *data)
{
    u_check_params(data != NULL);

    const struct aidl_key_parameter *const kp = data;
    const enum KM_TagType tt = __KM_TAG_TYPE_MASK(kp->tag);

    s_log_trace("kp->tag: %d (%s)", kp->tag, KM_Tag_toString(kp->tag));

    u32 kp_parcelable_size = 0, kp_value_union_member_id = 0;
    bool kp_value_is_longInteger = false;

    kp_parcelable_size += sizeof(kp_parcelable_size);

    kp_parcelable_size += sizeof(kp->tag);

    /* the inner KeyParameterValue parcelable */
    kp_parcelable_size += KMHAL_AIDL_PRESENT_FLAG_SIZE;
    {
        kp_value_union_member_id =
            get_aidl_integerparam_union_member_id(kp->tag);

        kp_parcelable_size += sizeof(kp_value_union_member_id);

        if (tt == KM_TAG_TYPE_BYTES || tt == KM_TAG_TYPE_BIGNUM) {
            /* blob; vec<u8> */
            kp_parcelable_size += sizeof(kp->blob.size) + align4(kp->blob.size);
        } else {
            /* integerParam; size <= sizeof(u64); depends on tag */

            switch (tt) {
            case KM_TAG_TYPE_INVALID: case KM_TAG_TYPE_BOOL:
            case KM_TAG_TYPE_ENUM: case KM_TAG_TYPE_ENUM_REP:
            case KM_TAG_TYPE_UINT: case KM_TAG_TYPE_UINT_REP:
                kp_parcelable_size += sizeof(u32);
                kp_value_is_longInteger = false;
                break;
            case KM_TAG_TYPE_ULONG:
            case KM_TAG_TYPE_ULONG_REP:
            case KM_TAG_TYPE_DATE:
                kp_parcelable_size += sizeof(u64);
                kp_value_is_longInteger = true;
                break;
            default:
                s_log_fatal("Invalid tag type: 0x%08x", (unsigned int)tt);
            }
        }
    }

    kmhal_parcel_write_u32(p, KMHAL_AIDL_PRESENT_FLAG);
    kmhal_parcel_write_u32(p, kp_parcelable_size);

    kmhal_parcel_write_u32(p, (u32)kp->tag);

    {
        kmhal_parcel_write_u32(p, (u32)KMHAL_AIDL_PRESENT_FLAG);
        kmhal_parcel_write_u32(p, kp_value_union_member_id);

        if (tt == KM_TAG_TYPE_BYTES || tt == KM_TAG_TYPE_BIGNUM) {
            write_aidl_vec_of_u8(p, &kp->blob);
        } else {
            if (kp_value_is_longInteger)
                kmhal_parcel_write_u64(p, (u64)kp->integer_value.l);
            else
                kmhal_parcel_write_u32(p, (u32)kp->integer_value.i);
        }
    }
}

int parse_aidl_key_parameter(const struct kmhal_parcel *p, size_t *off_p,
                             void *out, size_t out_size)
{
    if (out == NULL || out_size != sizeof(struct aidl_key_parameter)) {
        s_log_error("%s: Invalid parameters", __func__);
        return -1;
    }

    i32 size = 0; size_t start = 0;
    if (kmhal_aidl_parse_parcelable_header(p, off_p, &start, false, &size)) {
        s_log_error("Invalid parcelable header");
        return 1;
    }

    struct aidl_key_parameter *const kp = out;
    try_read_primitive(u32, kp, tag);

    u32 kp_value_field_id = 0;
    if (kmhal_aidl_parse_union_header(p, off_p, false, &kp_value_field_id)) {
        s_log_error("Failed to parse the KeyParameterValue union header");
        return 1;
    }
    kp->integer_value.l = UINT64_C(0);
    kp->blob.ptr = NULL; kp->blob.size = 0; kp->blob.owns = false;
    switch (kp_value_field_id) {
        case invalid: case integer: case boolValue:
        case algorithm: case blockMode: case paddingMode:
        case digest: case ecCurve: case origin: case keyPurpose:
        case hardwareAuthenticatorType: case securityLevel:
            if (kmhal_parcel_read_u32(p, off_p, (u32 *)&kp->integer_value.i)) {
                s_log_error("Failed to read u32 KeyParameterValue");
                return 1;
            }
            break;
        case longInteger: case dateTime:
            if (kmhal_parcel_read_u64(p, off_p, (u64 *)&kp->integer_value.l)) {
                s_log_error("Failed to read u64 KeyParameterValue");
                return 1;
            }
            break;
        case blob:
            if (parse_aidl_vec_of_u8(p, off_p, &kp->blob, sizeof(kp->blob))) {
                s_log_error("Failed to parse blob KeyParameterValue");
                return 1;
            }
            break;
        default:
            s_log_error("Invalid AIDL KeyParameterValue union tag: %"PRIu32,
                    kp_value_field_id);
            return 1;
    }

    if (kmhal_aidl_validate_parcelable_size(start, *off_p, size)) {
        s_log_error("KeyParameter parcelable size mismatch");
        return 1;
    }

    return 0;
}

AIDL_VEC_OF_PARCELABLE_IMPL(struct aidl_key_parameter, key_parameter)

void destroy_aidl_key_characteristics(struct aidl_key_characteristics *kp)
{
    if (kp == NULL) return;

    destroy_vec_of_parcelable(&kp->authorizations,
            sizeof(struct aidl_key_parameter),
            (void (*)(void *))destroy_aidl_key_parameter);
    kp->security_level = 0;
}

void write_aidl_key_characteristics(struct kmhal_parcel *p, const void *data)
{
    u_check_params(data != NULL);

    const struct aidl_key_characteristics *const kc = data;

    kmhal_parcel_write_u32(p, KMHAL_AIDL_PRESENT_FLAG);

    const size_t start_off = kmhal_parcel_get_write_buffer_size(p);
    kmhal_parcel_write_u32(p, 0);

    kmhal_parcel_write_u32(p, kc->security_level);
    write_aidl_vec_of_key_parameter(p, &kc->authorizations);

    const size_t end_off = kmhal_parcel_get_write_buffer_size(p);
    i32 data_size = end_off - start_off;
    kmhal_parcel_patch(p, start_off, &data_size, sizeof(i32));
}

int parse_aidl_key_characteristics(const struct kmhal_parcel *p, size_t *off_p,
                                   void *out, size_t out_size)
{
    if (out == NULL || out_size != sizeof(struct aidl_key_characteristics)) {
        s_log_error("%s: Invalid parameters", __func__);
        return -1;
    }

    i32 size = 0; size_t start = 0;
    if (kmhal_aidl_parse_parcelable_header(p, off_p, &start, false, &size)) {
        s_log_error("Invalid parcelable header");
        return 1;
    }

    struct aidl_key_characteristics *const kc = out;

    try_read_primitive(u32, kc, security_level);
    try_read_vec_of(key_parameter, kc, authorizations);

    if (kmhal_aidl_validate_parcelable_size(start, *off_p, size)) {
        s_log_error("KeyCharacteristics parcelable size mismatch");
        return 1;
    }

    return 0;
}

AIDL_VEC_OF_PARCELABLE_IMPL(struct aidl_key_characteristics,
                            key_characteristics)

void destroy_aidl_certificate(struct aidl_certificate *cert)
{
    if (cert == NULL)
        return;

    destroy_aidl_vec_of_u8(&cert->encoded_certificate);
}

void write_aidl_certificate(struct kmhal_parcel *p, const void *data)
{
    u_check_params(data != NULL);

    const struct aidl_certificate *const cert = data;

    kmhal_parcel_write_u32(p, KMHAL_AIDL_PRESENT_FLAG);

    u_check_params(cert->encoded_certificate.size <
            INT32_MAX - (i32)sizeof(i32) - (i32)sizeof(i32));
    const i32 parcelable_size = sizeof(parcelable_size) +
                        sizeof(cert->encoded_certificate.size) +
                        cert->encoded_certificate.size;
    kmhal_parcel_write_u32(p, parcelable_size);

    write_aidl_vec_of_u8(p, &cert->encoded_certificate);
}

int parse_aidl_certificate(const struct kmhal_parcel *p, size_t *off_p,
                           void *out, size_t out_size)
{
    if (out == NULL || out_size != sizeof(struct aidl_certificate)) {
        s_log_error("%s: Invalid parameters", __func__);
        return -1;
    }

    i32 size = 0; size_t start = 0;
    if (kmhal_aidl_parse_parcelable_header(p, off_p, &start, false, &size)) {
        s_log_error("Invalid parcelable header");
        return 1;
    }

    struct aidl_certificate *const cert = out;

    try_read_vec_of(u8, cert, encoded_certificate);

    if (kmhal_aidl_validate_parcelable_size(start, *off_p, size)) {
        s_log_error("Certificate parcelable size mismatch");
        return 1;
    }

    return 0;
}

AIDL_VEC_OF_PARCELABLE_IMPL(struct aidl_certificate, certificate)

void destroy_aidl_key_creation_result(struct aidl_key_creation_result *cr)
{
    if (cr == NULL)
        return;

    destroy_aidl_vec_of_u8(&cr->key_blob);
    destroy_aidl_vec_of_key_characteristics(&cr->key_characteristics);
    destroy_aidl_vec_of_certificate(&cr->certificate_chain);
}

int parse_aidl_key_creation_result(const struct kmhal_parcel *p, size_t *off_p,
                                   void *out, size_t out_size)
{
    if (out == NULL || out_size != sizeof(struct aidl_key_creation_result)) {
        s_log_error("%s: Invalid parameters", __func__);
        return -1;
    }

    i32 size = 0; size_t start = 0;
    if (kmhal_aidl_parse_parcelable_header(p, off_p, &start, false, &size)) {
        s_log_error("Invalid parcelable header");
        return 1;
    }

    struct aidl_key_creation_result *const kc = out;

    try_read_vec_of(u8, kc, key_blob);
    try_read_vec_of(key_characteristics, kc, key_characteristics);
    try_read_vec_of(certificate, kc, certificate_chain);

    if (kmhal_aidl_validate_parcelable_size(start, *off_p, size)) {
        s_log_error("KeyCreationResult parcelable size mismatch");
        return 1;
    }

    return 0;
}

void destroy_aidl_hardware_auth_token(struct aidl_hardware_auth_token *hat)
{
    if (hat == NULL)
        return;

    if (hat->mac.ptr != NULL)
        destroy_aidl_vec_of_u8(&hat->mac);

    memset(hat, 0, sizeof(struct aidl_hardware_auth_token));
}

void write_nullable_aidl_hardware_auth_token(struct kmhal_parcel *p,
                                             const void *data)
{
    if (data == NULL) {
        kmhal_parcel_write_u32(p, KMHAL_AIDL_NULL_FLAG);
        return;
    }

    const struct aidl_hardware_auth_token *const hat = data;

    kmhal_parcel_write_u32(p, KMHAL_AIDL_PRESENT_FLAG);

    const size_t start_off = kmhal_parcel_get_write_buffer_size(p);
    kmhal_parcel_write_u32(p, 0);

    kmhal_parcel_write_u64(p, hat->challenge);
    kmhal_parcel_write_u64(p, hat->user_id);
    kmhal_parcel_write_u64(p, hat->authenticator_id);
    kmhal_parcel_write_u32(p, hat->authenticator_type);
    kmhal_parcel_write_u64(p, hat->timestamp);
    write_aidl_vec_of_u8(p, &hat->mac);

    const size_t end_off = kmhal_parcel_get_write_buffer_size(p);
    i32 data_size = end_off - start_off;
    kmhal_parcel_patch(p, start_off, &data_size, sizeof(i32));
}

int parse_aidl_hardware_auth_token(const struct kmhal_parcel *p, size_t *off_p,
                                   void *out, size_t out_size)
{
    if (out == NULL || out_size != sizeof(struct aidl_hardware_auth_token)) {
        s_log_error("%s: Invalid parameters", __func__);
        return -1;
    }

    i32 size = 0; size_t start = 0;
    if (kmhal_aidl_parse_parcelable_header(p, off_p, &start, false, &size)) {
        s_log_error("Invalid parcelable header");
        return 1;
    }

    struct aidl_hardware_auth_token *const hat = out;

    try_read_primitive(u64, hat, challenge);
    try_read_primitive(u64, hat, user_id);
    try_read_primitive(u64, hat, authenticator_id);
    try_read_primitive(u32, hat, authenticator_type);
    try_read_primitive(u64, hat, timestamp);
    try_read_vec_of(u8, hat, mac);

    if (kmhal_aidl_validate_parcelable_size(start, *off_p, size)) {
        s_log_error("KeyCharacteristics parcelable size mismatch");
        return 1;
    }

    return 0;
}

void destroy_aidl_begin_result(struct aidl_begin_result *res)
{
    if (res == NULL)
        return;

    destroy_aidl_vec_of_key_parameter(&res->params);
    res->challenge = 0;
    res->IKeyMintOperation_binder_handle = 0;
}

int parse_aidl_begin_result(const struct kmhal_parcel *p, size_t *off_p,
                            u32 *out_handle_to_incref,
                            void *out, size_t out_size)
{
    if (out == NULL || out_size != sizeof(struct aidl_begin_result) ||
            out_handle_to_incref == NULL)
    {
        s_log_error("%s: Invalid parameters", __func__);
        return -1;
    }
    *out_handle_to_incref = UINT32_MAX;

    i32 size = 0; size_t start = 0;
    if (kmhal_aidl_parse_parcelable_header(p, off_p, &start, false, &size)) {
        s_log_error("Invalid parcelable header");
        return 1;
    }

    struct aidl_begin_result *const res = out;

    try_read_primitive(u64, res, challenge);
    try_read_vec_of(key_parameter, res, params);

    struct flat_binder_object binder;
    if (kmhal_parcel_read_handle(p, off_p, &binder)) {
        s_log_error("Failed to read the IKeyMintOperation binder handle");
        return 1;
    }
    if (binder.handle == 0) {
        s_log_error("Invalid IKeyMintOperation binder handle");
        return 1;
    }

    res->IKeyMintOperation_binder_handle = binder.handle;
    *out_handle_to_incref = binder.handle;
    return 0;
}

/* This is AIDL's way of serializing unions.
 * Each union member is assigned an ID,
 * by which the size of the subsequent serialized data is identified.
 *
 * E.g. it's known that in the IntegerParams union,
 * the enum KM_Digest `digest` member (ID 4) takes 4 bytes,
 * while `longInteger` (ID 12) takes 8 bytes.
 *
 * This is done to save space (i guess?) while serializing a union,
 * like in this situation:
 *  union {
 *      uint32_t value; // ID 0
 *      u8 veryLargeBuffer[1024]; // ID 1
 *  }
 * If we only use the `value` member,
 * only 4 bytes will be written for it + the 4 bytes for its ID `0`
 */
static u32 get_aidl_integerparam_union_member_id(enum KM_Tag t)
{
    const enum KM_TagType tt = __KM_TAG_TYPE_MASK(t);

    switch (tt) {
    default:
    case KM_TAG_TYPE_INVALID:
        return invalid;
    case KM_TAG_TYPE_BIGNUM:
    case KM_TAG_TYPE_BYTES:
        return blob;
    case KM_TAG_TYPE_ENUM:
    case KM_TAG_TYPE_ENUM_REP:
        switch (t) {
        case KM_TAG_ALGORITHM: return algorithm;
        case KM_TAG_BLOCK_MODE: return blockMode;
        case KM_TAG_PADDING: return paddingMode;
        case KM_TAG_DIGEST: return digest;
        case KM_TAG_EC_CURVE: return ecCurve;
        case KM_TAG_ORIGIN: return origin;
        case KM_TAG_PURPOSE: return keyPurpose;
        case KM_TAG_USER_AUTH_TYPE: return hardwareAuthenticatorType;
        default: return invalid;
        }
    case KM_TAG_TYPE_UINT:
    case KM_TAG_TYPE_UINT_REP:
        return integer;
    case KM_TAG_TYPE_BOOL:
        return boolValue;
    case KM_TAG_TYPE_ULONG:
    case KM_TAG_TYPE_ULONG_REP:
        return longInteger;
    case KM_TAG_TYPE_DATE:
        return dateTime;
    }
}

static void write_vec_of_parcelable(struct kmhal_parcel *p,
                                    const void *data, size_t item_size,
                                    kmhal_arg_write_inline_data_proc_t proc)
{
    if (data == NULL) {
        kmhal_parcel_write_u32(p, 0);
        return;
    }

    const struct aidl_vec_generic *const vec = data;
    s_assert(vec->size >= 0, "Invalid vector size");
    if (vec->size == 0) {
        kmhal_parcel_write_u32(p, 0);
        return;
    }

    kmhal_parcel_write_u32(p, (u32)vec->size);

    for (i32 i = 0; i < vec->size; i++) {
        proc(p, (const u8 *)vec->ptr + i*item_size);
    }
}

static int parse_vec_of_parcelable(const struct kmhal_parcel *p, size_t *off_p,
                                   size_t item_size,
                                   void *out, size_t out_size,
                                   kmhal_arg_parse_inline_data_proc_t proc,
                                   void (*destroy_proc)(void *))
{
    s_log_trace("%s: *off_p: %zu, item_size: %zu, out_size: %zu",
            __func__, *off_p, item_size, out_size);

    if (out == NULL || out_size != sizeof(struct aidl_vec_generic)) {
        s_log_error("%s: Invalid parameters", __func__);
        return -1;
    }

    struct aidl_vec_of_u8 *const vec = out;

    i32 vec_size;
    if (kmhal_aidl_parse_array_header(p, off_p, &vec_size)) {
        s_log_error("Failed to parse the vec header");
        return 1;
    }

    s_log_trace("%s: vec_size: %"PRIi32, __func__, vec_size);

    /* std::nullopt */
    if (vec_size <= 0) {
        vec->size = 0;
        vec->ptr = NULL;
        vec->owns = false;
        return 0;
    }

    /* don't malloc(0) */
    size_t malloc_size = (size_t)vec_size * item_size;
    if (malloc_size == 0)
        malloc_size = 1;

    vec->size = vec_size;
    vec->owns = false;
    vec->ptr = malloc(malloc_size);
    if (vec->ptr == NULL) {
        s_log_error("Failed to malloc a vector copy");
        destroy_vec_of_parcelable(vec, item_size, destroy_proc);
        return 1;
    }
    vec->owns = true;

    for (i32 i = 0; i < vec_size; i++) {
        if (proc(p, off_p, (u8 *)vec->ptr + i*item_size, item_size)) {
            s_log_error("Failed to read the vector data from the parcel");
            destroy_vec_of_parcelable(vec, item_size, destroy_proc);
            return 1;
        }
    }

    return 0;
}

static void destroy_vec_of_parcelable(void *data, size_t item_size,
                                      void (*proc)(void *))
{
    u_check_params(proc != NULL);

    if (data == NULL)
        return;

    struct aidl_vec_generic *const vec = data;

    if (vec->ptr != NULL) {
        for (i32 i = 0; i < vec->size; i++)
            proc((u8 *)vec->ptr + i*item_size);

        if (vec->owns)
            free(vec->ptr);
    }

    memset(vec, 0, sizeof(struct aidl_vec_generic));
}

static inline binder_size_t align4(binder_size_t s)
{
    return (s + UINT64_C(3)) & ~UINT64_C(3);
}
