#ifndef SUSKEYMASTER_BUILD_HOST

#include "hidl-types.h"
#include "parcel.h"
#include <core/log.h>
#include <core/util.h>
#include <linux/android/binder.h>
#include <string.h>

#define MODULE_NAME "hidl-types"

kmhal_parcel_obj_t
kmhal_hidl_string_write(struct kmhal_parcel *parcel,
                        const struct kmhal_hidl_string *hstr,
                        kmhal_parcel_obj_t parent,
                        binder_size_t parent_offset,
                        kmhal_parcel_obj_t *out_parent_ref)
{
    u_check_params(parcel != NULL && hstr != NULL);

    bool has_parent = false;
    binder_size_t parent_idx = 0;
    if (KMHAL_PARCEL_OBJ_IS_VALID(parent)) {
        has_parent = true;
        parent_idx = kmhal_parcel_obj_idx(parent);
    }

    /* Write the hidl_string struct object */
    kmhal_parcel_obj_t hstr_obj_ref =
    kmhal_parcel_write_buffer_obj(parcel, hstr, sizeof(*hstr),
            has_parent ? BINDER_BUFFER_FLAG_HAS_PARENT : 0,
            has_parent ? parent_idx : 0,
            has_parent ? parent_offset : 0);

    if (out_parent_ref != NULL)
        *out_parent_ref = hstr_obj_ref;

    /* Write the string bytes object */
    return kmhal_hidl_string_write_embedded(parcel, hstr, hstr_obj_ref,
        offsetof(struct kmhal_hidl_string, buffer));
}

kmhal_parcel_obj_t
kmhal_hidl_string_write_embedded(struct kmhal_parcel *parcel,
                                 const struct kmhal_hidl_string *hstr,
                                 kmhal_parcel_obj_t parent,
                                 binder_size_t parent_offset)
{
    u_check_params(parcel != NULL && hstr != NULL);
    u_check_params(KMHAL_PARCEL_OBJ_IS_VALID(parent));

    return kmhal_parcel_write_embedded_buffer(parcel,
            hstr->buffer, hstr->length + 1, parent,
            parent_offset + offsetof(struct kmhal_hidl_string, buffer));
}

int kmhal_hidl_string_read(const struct kmhal_hidl_string **out_p,
                           const struct kmhal_parcel *parcel,
                           size_t *offset_p,
                           kmhal_parcel_obj_t *out_child_ref)
{
    u_check_params(parcel != NULL);

    const struct kmhal_hidl_string *hstr_p;
    kmhal_parcel_obj_t hstr_obj_ref;
    if (kmhal_parcel_read_buffer_obj(parcel, offset_p,
            sizeof(struct kmhal_hidl_string), NULL, NULL, NULL,
            (const void **)&hstr_p, &hstr_obj_ref))
    {
        s_log_error("Failed to read the HIDL string struct object");
        return 1;
    }

    if (kmhal_hidl_string_read_embedded(NULL,
                out_child_ref, parcel, offset_p, hstr_p, hstr_obj_ref,
                offsetof(struct kmhal_hidl_string, buffer)))
    {
        s_log_error("Failed to read the HIDL string bytes object");
        return 1;
    }

    if (out_p != NULL)
        *out_p = hstr_p;

    return 0;
}

int kmhal_hidl_string_read_embedded(const char **out,
                                    kmhal_parcel_obj_t *out_ref,
                                    const struct kmhal_parcel *parcel,
                                    size_t *offset_p,
                                    const struct kmhal_hidl_string *hstr,
                                    kmhal_parcel_obj_t parent_handle,
                                    size_t parent_offset)
{
    u_check_params(parcel != NULL && hstr != NULL &&
            KMHAL_PARCEL_OBJ_IS_VALID(parent_handle));

    const size_t expected_size = hstr->length + 1;
    const void *tmp_out = NULL;

    if (kmhal_parcel_read_embedded_buffer(parcel, offset_p, parent_handle,
                parent_offset + offsetof(struct kmhal_hidl_string, buffer),
                expected_size, &tmp_out, out_ref))
    {
        s_log_error("Failed to read the embedded HIDL string bytes");
        return 1;
    }

    if (((const char *)tmp_out)[hstr->length] != '\0') {
        s_log_error("Received an unterminated HIDL string!");
        return 1;
    }

    if (out != NULL)
        *out = (const char *)tmp_out;

    return 0;
}

kmhal_parcel_obj_t
kmhal_hidl_vec_write(struct kmhal_parcel *parcel,
                     const struct kmhal_hidl_vec *vec, size_t elem_size,
                     kmhal_parcel_obj_t parent,
                     binder_size_t parent_offset,
                     kmhal_parcel_obj_t *out_parent_ref)
{
    u_check_params(parcel != NULL && vec != NULL);

    bool has_parent = false;
    if (KMHAL_PARCEL_OBJ_IS_VALID(parent))
        has_parent = true;

    /* Write the hidl_vec struct object */
    kmhal_parcel_obj_t vec_obj_ref =
    kmhal_parcel_write_buffer_obj(parcel, vec, sizeof(*vec),
            has_parent ? BINDER_BUFFER_FLAG_HAS_PARENT : 0,
            has_parent ? parent : 0,
            has_parent ? parent_offset : 0);

    if (out_parent_ref != NULL)
        *out_parent_ref = vec_obj_ref;

    /* Write the vec bytes object */
    return kmhal_hidl_vec_write_embedded(parcel, vec, elem_size, vec_obj_ref,
            offsetof(struct kmhal_hidl_vec, buffer));
}

kmhal_parcel_obj_t
kmhal_hidl_vec_write_embedded(struct kmhal_parcel *parcel,
                              const struct kmhal_hidl_vec *vec,
                              size_t elem_size,
                              kmhal_parcel_obj_t parent,
                              binder_size_t parent_offset)
{
    u_check_params(parcel != NULL && vec != NULL);
    u_check_params(KMHAL_PARCEL_OBJ_IS_VALID(parent));
    u_check_params(vec->size * elem_size < UINT32_MAX);

    return kmhal_parcel_write_embedded_buffer(parcel,
            vec->buffer,
            vec->size * elem_size,
            parent,
            parent_offset + offsetof(struct kmhal_hidl_vec, buffer)
    );
}

int kmhal_hidl_vec_read(const struct kmhal_hidl_vec **out_p, size_t elem_size,
                        const struct kmhal_parcel *parcel,
                        size_t *offset_p,
                        kmhal_parcel_obj_t *out_child_ref)
{
    u_check_params(parcel != NULL);

    const struct kmhal_hidl_vec *vec_p;
    kmhal_parcel_obj_t vec_obj_ref;
    if (kmhal_parcel_read_buffer_obj(parcel, offset_p,
            sizeof(struct kmhal_hidl_vec), NULL, NULL, NULL,
            (const void **)&vec_p, &vec_obj_ref))
    {
        s_log_error("Failed to read the HIDL vec struct object");
        return 1;
    }

    if (kmhal_hidl_vec_read_embedded(NULL, out_child_ref, parcel, offset_p,
                vec_p, elem_size, vec_obj_ref,
                offsetof(struct kmhal_hidl_vec, buffer)))
    {
        s_log_error("Failed to read the HIDL vec bytes object");
        return 1;
    }

    if (out_p != NULL)
        *out_p = vec_p;

    return 0;
}

int kmhal_hidl_vec_read_embedded(const void **out,
                                 kmhal_parcel_obj_t *out_ref,
                                 const struct kmhal_parcel *parcel,
                                 size_t *offset_p,
                                 const struct kmhal_hidl_vec *vec,
                                 size_t elem_size,
                                 kmhal_parcel_obj_t parent_handle,
                                 size_t parent_offset)
{
    u_check_params(parcel != NULL && vec != NULL &&
            KMHAL_PARCEL_OBJ_IS_VALID(parent_handle));
    u_check_params(vec->size * elem_size < UINT32_MAX);

    if (kmhal_parcel_read_embedded_buffer(parcel, offset_p, parent_handle,
                parent_offset + offsetof(struct kmhal_hidl_vec, buffer),
                vec->size * elem_size, out, out_ref))
    {
        s_log_error("Failed to read the embedded HIDL vec bytes");
        return 1;
    }

    return 0;
}

void kmhal_hidl_arg_write_hidl_string(struct kmhal_parcel *p,
                                      const void *data, size_t size)
{
    if (size != sizeof(struct kmhal_hidl_string))
        s_abort("serdes-hidl", __func__, "Invalid size");
    else if (data == NULL)
        s_abort("serdes-hidl", __func__, "Data is NULL");

    kmhal_hidl_string_write(p, (const struct kmhal_hidl_string *)data,
                            KMHAL_PARCEL_OBJ_INVALID, 0, NULL);
}

int kmhal_hidl_arg_parse_hidl_string(const struct kmhal_parcel *p,
                                     size_t *off_p,
                                     const void **out_p, size_t out_size)
{
    if (out_size != sizeof(struct kmhal_hidl_string)) {
        s_log(S_LOG_ERROR, "serdes-hidl", "%s: Invalid size", __func__);
        return -1;
    } else if (out_p == NULL) {
        s_log(S_LOG_ERROR, "serdes-hidl", "%s: Output pointer is NULL", __func__);
        return -1;
    }

    return kmhal_hidl_string_read((const struct kmhal_hidl_string **)out_p, p,
            off_p, NULL);
}

void kmhal_hidl_arg_write_vec_of_u8(struct kmhal_parcel *p,
                                    const void *data, size_t size)
{
    u_check_params(data != NULL && size == sizeof(struct kmhal_hidl_vec));
    kmhal_hidl_vec_write(p, data, sizeof(u8),
            KMHAL_PARCEL_OBJ_INVALID, 0, NULL);
}

int kmhal_hidl_arg_parse_vec_of_u8(const struct kmhal_parcel *p,
                                   size_t *off_p,
                                   const void **out_p, size_t out_size)
{
    if (out_p == NULL || out_size != sizeof(struct kmhal_hidl_vec)) {
        s_log_error("%s: Invalid parameters", __func__);
        return -1;
    }
    return kmhal_hidl_vec_read((const struct kmhal_hidl_vec **)out_p,
            sizeof(u8), p, off_p, NULL);
}

void kmhal_hidl_arg_write_vec_of_vec_of_u8(struct kmhal_parcel *p,
                                           const void *data, size_t size)
{
    u_check_params(data != NULL && size == sizeof(struct kmhal_hidl_vec));

    const struct kmhal_hidl_vec *const vec_p =
        (const struct kmhal_hidl_vec *)data;

    kmhal_parcel_obj_t ref =
    kmhal_parcel_write_buffer_obj(p, vec_p->buffer,
                                  vec_p->size * sizeof(struct kmhal_hidl_vec),
                                  0, KMHAL_PARCEL_OBJ_INVALID, 0);

    for (u32 i = 0; i < vec_p->size; i++) {
        kmhal_parcel_write_embedded_buffer(p, vec_p->buffer,
                                           vec_p->size * sizeof(u8),
                                           ref,
                                           i * vec_p->size);
    }
}

int kmhal_hidl_arg_parse_vec_of_vec_of_u8(const struct kmhal_parcel *p,
                                          size_t *off_p,
                                          const void **out_p, size_t out_size)
{
    if (out_p == NULL || out_size != sizeof(struct kmhal_hidl_vec)) {
        s_log_error("%s: Invalid parameters", __func__);
        return -1;
    }

    const struct kmhal_hidl_vec *vec_p = NULL;
    kmhal_parcel_obj_t ref;

    if (kmhal_hidl_vec_read((const struct kmhal_hidl_vec **)out_p,
                             sizeof(struct kmhal_hidl_vec), p, off_p, &ref))
    {
        s_log_error("Failed to read the parent HIDL vec buffer object");
        return 1;
    }
    vec_p = *out_p;

    for (u32 i = 0; i < vec_p->size; i++) {
        const size_t parent_offset = i * sizeof(struct kmhal_hidl_vec);

        const struct kmhal_hidl_vec *curr_p = (const struct kmhal_hidl_vec *)
            ((const u8 *)vec_p->buffer + parent_offset);

        if (kmhal_hidl_vec_read_embedded(NULL, NULL, p, off_p,
                                         curr_p, sizeof(u8),
                                         ref, parent_offset))
        {
            s_log_error("Failed to read embedded HIDL vec");
            return 1;
        }
    }

    return 0;
}

#endif /* SUSKEYMASTER_BUILD_HOST */
