#include "hidl-types.h"
#include "hidl-parcel.h"
#include <core/log.h>
#include <core/util.h>
#include <linux/android/binder.h>
#include <string.h>

#define MODULE_NAME "hidl-types"

kmhal_hidl_parcel_obj_t
kmhal_hidl_string_write(struct kmhal_hidl_parcel *parcel,
                        const struct kmhal_hidl_string *hstr,
                        kmhal_hidl_parcel_obj_t parent,
                        binder_size_t parent_offset,
                        kmhal_hidl_parcel_obj_t *out_parent_ref)
{
    u_check_params(parcel != NULL && hstr != NULL);

    bool has_parent = false;
    binder_size_t parent_idx = 0;
    if (KMHAL_HIDL_PARCEL_OBJ_IS_VALID(parent)) {
        has_parent = true;
        parent_idx = kmhal_hidl_parcel_obj_idx(parent);
    }

    /* Write the hidl_string struct object */
    kmhal_hidl_parcel_obj_t hstr_obj_ref =
    kmhal_hidl_parcel_write_buffer_obj(parcel, hstr, sizeof(*hstr),
            has_parent ? BINDER_BUFFER_FLAG_HAS_PARENT : 0,
            has_parent ? parent_idx : 0,
            has_parent ? parent_offset : 0);

    if (out_parent_ref != NULL)
        *out_parent_ref = hstr_obj_ref;

    /* Write the string bytes object */
    return kmhal_hidl_string_write_embedded(parcel, hstr, hstr_obj_ref,
        offsetof(struct kmhal_hidl_string, buffer));
}

kmhal_hidl_parcel_obj_t
kmhal_hidl_string_write_embedded(struct kmhal_hidl_parcel *parcel,
                                 const struct kmhal_hidl_string *hstr,
                                 kmhal_hidl_parcel_obj_t parent,
                                 binder_size_t parent_offset)
{
    u_check_params(parcel != NULL && hstr != NULL);
    u_check_params(KMHAL_HIDL_PARCEL_OBJ_IS_VALID(parent));

    return kmhal_hidl_parcel_write_embedded_buffer(parcel,
            hstr->buffer, hstr->length + 1, parent,
            parent_offset + offsetof(struct kmhal_hidl_string, buffer));
}

int kmhal_hidl_string_read(const struct kmhal_hidl_string **out_p,
                           const struct kmhal_hidl_parcel *parcel,
                           size_t *offset_p,
                           kmhal_hidl_parcel_obj_t *out_child_ref)
{
    u_check_params(parcel != NULL);

    const struct kmhal_hidl_string *hstr_p;
    kmhal_hidl_parcel_obj_t hstr_obj_ref;
    if (kmhal_hidl_parcel_read_buffer_obj(parcel, offset_p,
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
                                    kmhal_hidl_parcel_obj_t *out_ref,
                                    const struct kmhal_hidl_parcel *parcel,
                                    size_t *offset_p,
                                    const struct kmhal_hidl_string *hstr,
                                    kmhal_hidl_parcel_obj_t parent_handle,
                                    size_t parent_offset)
{
    u_check_params(parcel != NULL && hstr != NULL &&
            KMHAL_HIDL_PARCEL_OBJ_IS_VALID(parent_handle));

    const size_t expected_size = hstr->length + 1;
    const void *tmp_out = NULL;

    if (kmhal_hidl_parcel_read_embedded_buffer(parcel, offset_p, parent_handle,
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

kmhal_hidl_parcel_obj_t
kmhal_hidl_vec_write(struct kmhal_hidl_parcel *parcel,
                     const struct kmhal_hidl_vec *vec, size_t elem_size,
                     kmhal_hidl_parcel_obj_t parent,
                     binder_size_t parent_offset,
                     kmhal_hidl_parcel_obj_t *out_parent_ref)
{
    u_check_params(parcel != NULL && vec != NULL);

    bool has_parent = false;
    if (KMHAL_HIDL_PARCEL_OBJ_IS_VALID(parent))
        has_parent = true;

    /* Write the hidl_vec struct object */
    kmhal_hidl_parcel_obj_t vec_obj_ref =
    kmhal_hidl_parcel_write_buffer_obj(parcel, vec, sizeof(*vec),
            has_parent ? BINDER_BUFFER_FLAG_HAS_PARENT : 0,
            has_parent ? parent : 0,
            has_parent ? parent_offset : 0);

    if (out_parent_ref != NULL)
        *out_parent_ref = vec_obj_ref;

    /* Write the vec bytes object */
    return kmhal_hidl_vec_write_embedded(parcel, vec, elem_size, vec_obj_ref,
            offsetof(struct kmhal_hidl_vec, buffer));
}

kmhal_hidl_parcel_obj_t
kmhal_hidl_vec_write_embedded(struct kmhal_hidl_parcel *parcel,
                              const struct kmhal_hidl_vec *vec,
                              size_t elem_size,
                              kmhal_hidl_parcel_obj_t parent,
                              binder_size_t parent_offset)
{
    u_check_params(parcel != NULL && vec != NULL);
    u_check_params(KMHAL_HIDL_PARCEL_OBJ_IS_VALID(parent));
    u_check_params(vec->size * elem_size < UINT32_MAX);

    return kmhal_hidl_parcel_write_embedded_buffer(parcel,
            vec->buffer,
            vec->size * elem_size,
            parent,
            parent_offset + offsetof(struct kmhal_hidl_vec, buffer)
    );
}

int kmhal_hidl_vec_read(const struct kmhal_hidl_vec **out_p, size_t elem_size,
                        const struct kmhal_hidl_parcel *parcel,
                        size_t *offset_p,
                        kmhal_hidl_parcel_obj_t *out_child_ref)
{
    u_check_params(parcel != NULL);

    const struct kmhal_hidl_vec *vec_p;
    kmhal_hidl_parcel_obj_t vec_obj_ref;
    if (kmhal_hidl_parcel_read_buffer_obj(parcel, offset_p,
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
                                 kmhal_hidl_parcel_obj_t *out_ref,
                                 const struct kmhal_hidl_parcel *parcel,
                                 size_t *offset_p,
                                 const struct kmhal_hidl_vec *vec,
                                 size_t elem_size,
                                 kmhal_hidl_parcel_obj_t parent_handle,
                                 size_t parent_offset)
{
    u_check_params(parcel != NULL && vec != NULL &&
            KMHAL_HIDL_PARCEL_OBJ_IS_VALID(parent_handle));
    u_check_params(vec->size * elem_size < UINT32_MAX);

    if (kmhal_hidl_parcel_read_embedded_buffer(parcel, offset_p, parent_handle,
                parent_offset + offsetof(struct kmhal_hidl_vec, buffer),
                vec->size * elem_size, out, out_ref))
    {
        s_log_error("Failed to read the embedded HIDL vec bytes");
        return 1;
    }

    return 0;
}
