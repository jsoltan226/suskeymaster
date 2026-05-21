#include "parcel.h"
#include "base.h"
#include "binderif.h"
#include <core/log.h>
#include <core/int.h>
#include <core/util.h>
#include <core/vector.h>
#include <core/bitfield.h>
#include <stdatomic.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <inttypes.h>
#include <linux/android/binder.h>
#include <unistd.h>

#define MODULE_NAME "hidl-parcel"

struct parcel_obj {
    struct kmhal_hidl_parcel *parcel_bp;
    size_t self_idx;

    binder_size_t off;

    binder_size_t parent, parent_offset;
    bool has_parent;
};

struct kmhal_hidl_parcel {
    _Atomic bool initialized_;

    VECTOR(u8) buffer;

    VECTOR(struct parcel_obj) objects;
    binder_size_t sg_buffers_size;

    _Atomic bool txn_pending;
    VECTOR(binder_size_t) txn_object_offsets;
    struct kmhal_hidl_binder_tr_sg_args txn_arg;
};

static void parcel_destroy__(struct kmhal_hidl_parcel **parcel_p,
        bool allow_pending_transaction);

static inline binder_size_t align4(binder_size_t s);
static inline binder_size_t align8(binder_size_t s);

static int validate_parcel_object_ref(const struct kmhal_hidl_parcel *parcel,
                                      kmhal_hidl_parcel_obj_t obj_ref);

static int validate_buffer_object(const struct kmhal_hidl_parcel *parcel,
        const struct binder_buffer_object *obj, binder_size_t size, u32 flags,
        binder_size_t parent, binder_size_t parent_offset);

static int validate_parent(const struct kmhal_hidl_parcel *parcel,
                           binder_size_t parent_idx, binder_size_t child_idx);

static int validate_reply(const struct kmhal_hidl_binder_tr_sg_args_out *r);

struct kmhal_hidl_parcel * kmhal_hidl_parcel_new(void)
{
    struct kmhal_hidl_parcel *ret = NULL;

    ret = calloc(1, sizeof(struct kmhal_hidl_parcel));
    if (ret == NULL)
        goto_error("Failed to allocate a new parcel struct");
    atomic_store(&ret->initialized_, true);

    ret->buffer = vector_new(u8);

    ret->objects = vector_new(struct parcel_obj);
    ret->sg_buffers_size = 0;

    atomic_store(&ret->txn_pending, false);
    ret->txn_object_offsets = vector_new(binder_size_t);
    ret->txn_arg = (struct kmhal_hidl_binder_tr_sg_args){ 0 };

    return ret;

err:
    if (ret != NULL)
        kmhal_hidl_parcel_destroy(&ret);

    return NULL;
}

struct kmhal_hidl_parcel * kmhal_hidl_parcel_new_from_reply(
        const struct kmhal_hidl_binder_tr_sg_args_out *reply
)
{
    (void) reply;
    struct kmhal_hidl_parcel *ret = NULL;

    if (validate_reply(reply))
        goto_error("Invalid or failed reply");

    ret = kmhal_hidl_parcel_new();
    if (ret == NULL)
        goto err;

    vector_resize(&ret->buffer, reply->data_size);
    memcpy(ret->buffer, reply->data_buf, reply->data_size);

    vector_reserve(&ret->objects, reply->offsets_count);
    for (u32 i = 0; i < reply->offsets_count; i++) {
        bool has_parent = false;
        binder_size_t parent = 0, parent_offset = 0;

        /* All offsets validated by `validate_reply` */
        struct binder_object_header hdr;
        memcpy(&hdr, (const u8 *)reply->data_buf + reply->offsets_buf[i],
                sizeof(struct binder_object_header));
        if (hdr.type == BINDER_TYPE_PTR) {
            struct binder_buffer_object obj;
            memcpy(&obj, (const u8 *)reply->data_buf + reply->offsets_buf[i],
                    sizeof(struct binder_buffer_object));

            if (obj.flags & BINDER_BUFFER_FLAG_HAS_PARENT) {
                has_parent = true;
                parent = obj.parent;
                parent_offset = obj.parent_offset;
            }

            ret->sg_buffers_size += align8(obj.length);
        }

        vector_push_back(&ret->objects, (struct parcel_obj) {
                .parcel_bp = ret,
                .self_idx = i,

                .off = reply->offsets_buf[i],

                .has_parent = has_parent,
                .parent = parent,
                .parent_offset = parent_offset,
        });
    }

    return ret;

err:
    if (ret != NULL)
        kmhal_hidl_parcel_destroy(&ret);

    return NULL;
}

void kmhal_hidl_parcel_write_bytes(struct kmhal_hidl_parcel *parcel,
        const void *data, size_t len)
{
    u_check_params(parcel != NULL && atomic_load(&parcel->initialized_) &&
            (data != NULL || len == 0) && len < UINT32_MAX);

    /* `vector_resize` already memset()s the whole thing to zero,
     * including any of our additional padding bytes */
    const size_t offset = align4(vector_size(parcel->buffer));
    s_assert(offset + len < UINT32_MAX, "Offset and length too big");

    vector_resize(&parcel->buffer, offset + len);
    memcpy(parcel->buffer + offset, data, len);
}

void kmhal_hidl_parcel_patch(struct kmhal_hidl_parcel *parcel,
                             size_t offset, const void *data, size_t len)
{
    u_check_params(parcel != NULL && atomic_load(&parcel->initialized_) &&
            (data != NULL || len == 0) &&
            offset < UINT32_MAX && len < UINT32_MAX);

    s_assert(offset + len < UINT32_MAX, "Offset and length too big");

    if (offset + len > vector_size(parcel->buffer))
        vector_resize(&parcel->buffer, offset + len);

    memcpy(parcel->buffer + offset, data, len);
}

void kmhal_hidl_parcel_write_u32(struct kmhal_hidl_parcel *parcel, u32 u)
{
    u32 u_ = u;
    kmhal_hidl_parcel_write_bytes(parcel, &u_, sizeof(u32));
}

void kmhal_hidl_parcel_write_u64(struct kmhal_hidl_parcel *parcel, u64 u)
{
    u_check_params(parcel != NULL && atomic_load(&parcel->initialized_));

    size_t off = align8(vector_size(parcel->buffer));
    s_assert(off < UINT32_MAX - sizeof(u64), "New offset too bit");

    vector_resize(&parcel->buffer, off + sizeof(u64));

    const u64 u_ = u;
    memcpy(parcel->buffer + off, &u_, sizeof(u64));
}

void kmhal_hidl_parcel_write_cstring(struct kmhal_hidl_parcel *parcel,
                                     const char *str)
{
    u_check_params(parcel != NULL && atomic_load(&parcel->initialized_) &&
            str != NULL);

    const binder_size_t str_offset = align4(vector_size(parcel->buffer));
    const size_t str_len = strlen(str),
          str_len_full = align4(str_len + sizeof((char)'\0'));

    vector_resize(&parcel->buffer, str_offset + str_len_full);
    memcpy(parcel->buffer + str_offset, str, str_len);
    parcel->buffer[str_offset + str_len] = '\0';
}

kmhal_hidl_parcel_obj_t
kmhal_hidl_parcel_write_handle(struct kmhal_hidl_parcel *parcel,
                               const struct flat_binder_object *obj)
{
    u_check_params(parcel != NULL && atomic_load(&parcel->initialized_));
    u_check_params(obj != NULL && (
            obj->hdr.type == BINDER_TYPE_BINDER ||
            obj->hdr.type == BINDER_TYPE_WEAK_BINDER ||
            obj->hdr.type == BINDER_TYPE_HANDLE ||
            obj->hdr.type == BINDER_TYPE_WEAK_HANDLE
    ));

    const binder_size_t off = align4(vector_size(parcel->buffer));
    s_assert(off < UINT32_MAX - sizeof(*obj), "New offset too big");

    vector_resize(&parcel->buffer, off + sizeof(*obj));
    memcpy(parcel->buffer + off, obj, sizeof(*obj));

    const size_t new_idx = vector_size(parcel->objects);
    vector_push_back(&parcel->objects, (struct parcel_obj) {
            .parcel_bp = parcel,
            .self_idx = new_idx,

            .off = off,

            .has_parent = false
    });

    return (kmhal_hidl_parcel_obj_t)new_idx;
}

kmhal_hidl_parcel_obj_t
kmhal_hidl_parcel_write_buffer_obj(struct kmhal_hidl_parcel *parcel,
                                   const void *buffer, size_t buffer_size,
                                   u32 flags, kmhal_hidl_parcel_obj_t parent,
                                   binder_size_t parent_offset)
{
    u_check_params(parcel != NULL && atomic_load(&parcel->initialized_));

    const size_t new_idx = vector_size(parcel->objects);

    const bool has_parent = !!(flags & BINDER_BUFFER_FLAG_HAS_PARENT);
    binder_size_t parent_idx = 0;
    if (has_parent) {
        parent_idx = (binder_size_t)parent;
        u_check_params(validate_parent(parcel, parent_idx, new_idx) == 0);
    }
    u_check_params(buffer != NULL || buffer_size == 0);

    struct binder_buffer_object obj = {
        .hdr.type = BINDER_TYPE_PTR,
        .buffer = (binder_uintptr_t)buffer,
        .length = buffer_size,
        .flags = flags,
        .parent = has_parent ? parent_idx : 0,
        .parent_offset  = has_parent ? parent_offset : 0
    };

    const size_t off = align4(vector_size(parcel->buffer));
    s_assert(off < UINT32_MAX - sizeof(obj), "New offset too big");

    vector_resize(&parcel->buffer, off + sizeof(obj));
    memcpy(parcel->buffer + off, &obj, sizeof(obj));

    if (buffer != NULL) {
        vector_push_back(&parcel->objects, (struct parcel_obj) {
                .parcel_bp = parcel,
                .self_idx = new_idx,

                .off = off,

                .has_parent = has_parent,
                .parent = obj.parent,
                .parent_offset = obj.parent_offset
        });
        parcel->sg_buffers_size += align8(obj.length);
    }

    return (kmhal_hidl_parcel_obj_t)new_idx;
}

kmhal_hidl_parcel_obj_t
kmhal_hidl_parcel_write_embedded_buffer(struct kmhal_hidl_parcel *parcel,
                                        const void *buf, size_t buf_size,
                                        kmhal_hidl_parcel_obj_t parent,
                                        binder_size_t parent_offset)
{
    u_check_params(parcel != NULL && atomic_load(&parcel->initialized_));
    u_check_params(buf != NULL || buf_size == 0);
    u_check_params(validate_parcel_object_ref(parcel, parent) == 0);

    const binder_size_t parent_idx = (binder_size_t)parent;

    return kmhal_hidl_parcel_write_buffer_obj(parcel, buf, buf_size,
            BINDER_BUFFER_FLAG_HAS_PARENT, parent_idx, parent_offset);
}

size_t kmhal_hidl_parcel_obj_idx(kmhal_hidl_parcel_obj_t obj)
{
    u_check_params(KMHAL_HIDL_PARCEL_OBJ_IS_VALID(obj));
    return (size_t)obj;
}

kmhal_hidl_parcel_obj_t
kmhal_hidl_parcel_obj_get(const struct kmhal_hidl_parcel *parcel, size_t idx)
{
    u_check_params(parcel != NULL && atomic_load(&parcel->initialized_));

    if (idx >= vector_size(parcel->objects)) {
        s_log_error("Invalid object offset index %zu", idx);
        return KMHAL_HIDL_PARCEL_OBJ_INVALID;
    }

    return (kmhal_hidl_parcel_obj_t)idx;
}

static int cmp_objs_offsets(const void *obj1_, const void *obj2_)
{
    const struct parcel_obj *const obj1 = obj1_, *const obj2 = obj2_;

    s_assert(obj1 != NULL && obj2 != NULL, "Unexpected NULL pointer(s)");
    s_assert(obj1->off < INT_MAX && obj2->off < INT_MAX, "Offset(s) too big");

    return (int)obj1->off - (int)obj2->off;
}

kmhal_hidl_parcel_obj_t
kmhal_hidl_parcel_obj_find_by_offset(const struct kmhal_hidl_parcel *parcel,
                                     size_t offset)
{
    u_check_params(parcel != NULL && atomic_load(&parcel->initialized_));

    if (vector_size(parcel->buffer) < sizeof(struct binder_buffer_object) ||
        align4(offset) > vector_size(parcel->buffer) -
            sizeof(struct binder_buffer_object))
    {
        s_log_error("Binder buffer object offset out of bounds");
        return KMHAL_HIDL_PARCEL_OBJ_INVALID;
    } else if (offset != align4(offset)) {
        s_log_error("Offset not aligned");
        return KMHAL_HIDL_PARCEL_OBJ_INVALID;
    }

    struct parcel_obj key = { .off = offset };

    struct parcel_obj *found = bsearch(&key,
            parcel->objects, vector_size(parcel->objects),
            sizeof(struct parcel_obj), cmp_objs_offsets);
    if (found == NULL) {
        /* s_log_error("Object with offset %zu not found in parcel", offset); */
        return KMHAL_HIDL_PARCEL_OBJ_INVALID;
    }

    const kmhal_hidl_parcel_obj_t r = (kmhal_hidl_parcel_obj_t)found->self_idx;
    return r;
}

void kmhal_hidl_parcel_pack(struct kmhal_hidl_binder_transaction *txn,
                            struct kmhal_hidl_parcel *parcel,
                            u32 handle, u32 cmd)
{
    u_check_params(txn != NULL &&
            parcel != NULL && atomic_load(&parcel->initialized_));

    const bool prev_pending = atomic_exchange(&parcel->txn_pending, true);
    s_assert(!prev_pending, "Attempt to queue parcel for transaction twice");

    const u32 n_objs = vector_size(parcel->objects);

    vector_clear(&parcel->txn_object_offsets);
    vector_reserve(&parcel->txn_object_offsets, n_objs);

    for (u32 i = 0; i < n_objs; i++)
        vector_push_back(&parcel->txn_object_offsets, parcel->objects[i].off);

    parcel->txn_arg = (struct kmhal_hidl_binder_tr_sg_args) {
        .in_txn = txn,
        .in_data = {
            .cmd = cmd,
            .flags = TF_ACCEPT_FDS,
            .handle = handle,
            .data_buf = parcel->buffer,
            .data_size = vector_size(parcel->buffer),
            .offsets_buf = parcel->txn_object_offsets,
            .offsets_count = n_objs,
            .sg_buffers_size = parcel->sg_buffers_size
        },
        .out_reply = {}
    };

    kmhal_hidl_binder_add_transact_sg(&parcel->txn_arg);
}

int kmhal_hidl_parcel_unpack(struct kmhal_hidl_parcel **parcel_p,
                             struct kmhal_hidl_binder_tr_sg_args_out *out)
{
    u_check_params(parcel_p != NULL && *parcel_p != NULL &&
            atomic_load(&(*parcel_p)->initialized_));
    struct kmhal_hidl_parcel *const parcel = *parcel_p;

    if (!atomic_load(&parcel->txn_pending)) {
        s_log_error("Parcel has no pending transaction to unpack!");
        return -1;
    }

    switch (parcel->txn_arg.out_reply.status) {
    case KMHAL_HIDL_BINDER_TR_SG_OK:
        break;
    default:
    case KMHAL_HIDL_BINDER_TR_SG_UNINITIALIZED:
        s_log_fatal("Transaction not even initialized, invalid state!");
    case KMHAL_HIDL_BINDER_TR_SG_PENDING:
        s_log_fatal("Transaction still pending, impossible outcome!");
    case KMHAL_HIDL_BINDER_TR_SG_FAILED:
        s_log_error("Transaction failed :(");
        parcel_destroy__(parcel_p, true);
        return 1;
    }

    if (!memcmp(&parcel->txn_arg.out_reply,
                &(struct kmhal_hidl_binder_tr_sg_args_out) { 0 },
                sizeof(struct kmhal_hidl_binder_tr_sg_args_out)))
    {
        s_log_error("The transaction didn't write anything");
        return 1;
    }

    if (out != NULL)
        memcpy(out, &parcel->txn_arg.out_reply, sizeof(*out));

    parcel_destroy__(parcel_p, true);

    return 0;
}

int kmhal_hidl_parcel_peek(const struct kmhal_hidl_parcel *parcel,
                           size_t offset, void *out, size_t len)
{
    u_check_params(parcel != NULL && atomic_load(&parcel->initialized_)
            && offset < UINT32_MAX && len < UINT32_MAX);

    if (offset > vector_size(parcel->buffer) ||
        len > vector_size(parcel->buffer) - offset)
        return 1;

    if (out)
        memcpy(out, parcel->buffer + offset, len);

    return 0;
}

int kmhal_hidl_parcel_read_u32(const struct kmhal_hidl_parcel *parcel,
                               size_t *offset_p, u32 *out)
{
    u_check_params(parcel != NULL && atomic_load(&parcel->initialized_) &&
            parcel->buffer != NULL);
    u_check_params(offset_p != NULL && *offset_p == align4(*offset_p) &&
            *offset_p < UINT32_MAX - sizeof(u32));

    if (*offset_p + sizeof(u32) > vector_size(parcel->buffer)) {
        s_log_error("Requested offset outside of parcel buffer");
        return -1;
    }

    if (out != NULL)
        memcpy(out, parcel->buffer + *offset_p, sizeof(u32));
    *offset_p += sizeof(u32);

    return 0;
}

int kmhal_hidl_parcel_read_u64(const struct kmhal_hidl_parcel *parcel,
                               size_t *offset_p, u64 *out)
{
    u_check_params(parcel != NULL && atomic_load(&parcel->initialized_) &&
            parcel->buffer != NULL);
    u_check_params(offset_p != NULL && *offset_p == align4(*offset_p) &&
            *offset_p < UINT32_MAX - sizeof(u64));

    if (*offset_p + sizeof(u64) > vector_size(parcel->buffer)) {
        s_log_error("Requested *offset_p outside of parcel buffer");
        return -1;
    }

    if (out != NULL)
        memcpy(out, parcel->buffer + *offset_p, sizeof(u64));
    *offset_p += sizeof(u64);

    return 0;
}

int kmhal_hidl_parcel_read_handle(const struct kmhal_hidl_parcel *parcel,
                                  size_t *offset_p,
                                  struct flat_binder_object *out)
{
    u_check_params(parcel != NULL && atomic_load(&parcel->initialized_) &&
            parcel->buffer != NULL);
    u_check_params(offset_p != NULL);

    const size_t off = *offset_p;
    if (vector_size(parcel->buffer) < sizeof(struct flat_binder_object) ||
        off > vector_size(parcel->buffer) - sizeof(struct flat_binder_object))
    {
        s_log_error("Flat binder object out of bounds");
        return -1;
    }

    struct flat_binder_object tmp;
    memcpy(&tmp, parcel->buffer + off, sizeof(struct flat_binder_object));
    switch (tmp.hdr.type) {
    case BINDER_TYPE_HANDLE:
    case BINDER_TYPE_WEAK_HANDLE:
    case BINDER_TYPE_BINDER:
    case BINDER_TYPE_WEAK_BINDER:
        break;
    default:
        s_log_error("Buffer type %u invalid for a handle (flat_binder_object)",
                tmp.hdr.type);
        return -1;
    }

    if (out != NULL)
        memcpy(out, &tmp, sizeof(struct flat_binder_object));
    *offset_p += sizeof(struct flat_binder_object);

    return 0;
}

int kmhal_hidl_parcel_read_buffer_obj(const struct kmhal_hidl_parcel *parcel,
                                      size_t *offset_p,
                                      binder_size_t exp_size,
                                      const u32 *exp_flags,
                                      const kmhal_hidl_parcel_obj_t *exp_parent,
                                      const binder_size_t *exp_parent_offset,
                                      const void **out,
                                      kmhal_hidl_parcel_obj_t *out_ref)
{
    u_check_params(parcel != NULL && atomic_load(&parcel->initialized_) &&
            parcel->buffer != NULL);
    u_check_params(offset_p != NULL && *offset_p < SIZE_MAX);

    const size_t off = *offset_p;
    if (vector_size(parcel->buffer) < sizeof(struct binder_buffer_object) ||
            off > vector_size(parcel->buffer) -
                sizeof(struct binder_buffer_object))
    {
        s_log_error("Offset overflows buffer!");
        return -1;
    }
    struct binder_buffer_object tmp;
    memcpy(&tmp, parcel->buffer + off, sizeof(struct binder_buffer_object));

    kmhal_hidl_parcel_obj_t ref = KMHAL_HIDL_PARCEL_OBJ_INVALID;

    u32 flags = exp_flags != NULL ? *exp_flags : tmp.flags;
    binder_size_t parent = exp_parent != NULL ? *exp_parent : tmp.parent;
    binder_size_t parent_offset = exp_parent_offset != NULL ?
        *exp_parent_offset : tmp.parent_offset;

    if (validate_buffer_object(parcel, &tmp, exp_size,
                flags, parent, parent_offset))
    {
        s_log_error("Invalid buffer object");
        return 1;
    }

    if (tmp.buffer) {
        ref = kmhal_hidl_parcel_obj_find_by_offset(parcel, off);
        if (!KMHAL_HIDL_PARCEL_OBJ_IS_VALID(ref)) {
            s_log_error("Object at offset %zu not found in parcel", off);
            return 1;
        }
    }

    if (out != NULL) *out = (const void *)tmp.buffer;
    if (out_ref != NULL) *out_ref = ref;
    *offset_p += sizeof(struct binder_buffer_object);

    return 0;
}

int kmhal_hidl_parcel_read_embedded_buffer(const struct kmhal_hidl_parcel *p,
                                           size_t *off_p,
                                           kmhal_hidl_parcel_obj_t parent_ref,
                                           binder_size_t parent_offset,
                                           size_t expected_buf_size,
                                           const void **out_buf,
                                           kmhal_hidl_parcel_obj_t *out_ref)
{
    u_check_params(p != NULL && atomic_load(&p->initialized_));
    u_check_params(off_p != NULL);

    if (validate_parcel_object_ref(p, parent_ref)) {
        s_log_error("Invalid parent object reference");
        return -1;
    }

    const size_t parent_idx = (size_t)parent_ref;
    const binder_size_t parent_off = p->objects[parent_idx].off;
    if (vector_size(p->buffer) < sizeof(struct binder_buffer_object) ||
            parent_off > vector_size(p->buffer)
                - sizeof(struct binder_buffer_object))
    {
        s_log_error("Parent object overflows parcel buffer");
        return -1;
    }

    struct binder_buffer_object parent_obj;
    memcpy(&parent_obj, p->buffer + parent_off,
            sizeof(struct binder_buffer_object));

    if (parent_offset > parent_obj.length ||
            parent_obj.length - parent_offset < sizeof(void *))
    {
        s_log_error("Parent offsets would overflow parent's buffer");
        return 1;
    }

    /* Read the pointer value @ parent_buf[parent_offset] */
    const void *child_buffer_ptr = NULL;
    memcpy(&child_buffer_ptr,
            (const uint8_t *)parent_obj.buffer + parent_offset,
            sizeof(void *)
    );

    if (child_buffer_ptr == NULL && expected_buf_size > 0) {
        s_log_error("Child pointer is NULL while expected size > 0");
        return 1;
    }

    kmhal_hidl_parcel_obj_t child_ref = KMHAL_HIDL_PARCEL_OBJ_INVALID;

    if (child_buffer_ptr != NULL) {
        child_ref = kmhal_hidl_parcel_obj_find_by_offset(p, *off_p);
        if (!KMHAL_HIDL_PARCEL_OBJ_IS_VALID(child_ref)) {
            s_log_error("Couldn't find embedded buffer object");
            return 1;
        }
        const size_t child_idx = (size_t)child_ref;
        const struct parcel_obj *const child = &p->objects[child_idx];

        if (child->off != *off_p) {
            s_log_error("Given and found child object offset mismatch");
            return 1;
        }

        /* If the offset was found in the `offsets` array of the parcel
         * using `kmhal_hidl_parcel_obj_find_by_offset`,
         * we have a guarantee that it's valid */
        struct binder_buffer_object child_obj;
        memcpy(&child_obj, p->buffer + child->off, sizeof(child_obj));

        if ((void *)child_obj.buffer != child_buffer_ptr) {
            s_log_error("Expected and found embedded buffer pointer mismatch");
            return 1;
        }
        /* The rest is validated by `validate_buffer_object` */

        if (validate_buffer_object(p, &child_obj, expected_buf_size,
                    BINDER_BUFFER_FLAG_HAS_PARENT, parent_idx, parent_offset))
        {
            s_log_error("Invalid child buffer object");
            return 1;
        }
    }

    if (out_buf) *out_buf = child_buffer_ptr;
    if (out_ref) *out_ref = child_ref;
    *off_p += sizeof(struct binder_buffer_object);

    return 0;
}

void kmhal_hidl_parcel_destroy(struct kmhal_hidl_parcel **parcel_p)
{
    parcel_destroy__(parcel_p, false);
}

static void parcel_destroy__(struct kmhal_hidl_parcel **parcel_p,
        bool allow_pending_transaction)
{
    if (parcel_p == NULL || *parcel_p == NULL ||
            !atomic_exchange(&(*parcel_p)->initialized_, false))
        return;

    struct kmhal_hidl_parcel *const parcel = *parcel_p;

    const bool txn_pending = atomic_exchange(&parcel->txn_pending, false);
    if (!allow_pending_transaction && txn_pending) {
        switch (parcel->txn_arg.out_reply.status) {
        default:
        case KMHAL_HIDL_BINDER_TR_SG_PENDING:
        case KMHAL_HIDL_BINDER_TR_SG_UNINITIALIZED:
            s_abort(MODULE_NAME, "kmhal_hidl_parcel_destroy",
                    "Attempt to destroy parcel with a pending transaction");
        case KMHAL_HIDL_BINDER_TR_SG_OK:
        case KMHAL_HIDL_BINDER_TR_SG_FAILED:
            s_log_warn("Destroying a parcel without unpacking it first!");
        }
    }

    memset(&parcel->txn_arg, 0, sizeof(parcel->txn_arg));
    vector_destroy(&parcel->txn_object_offsets);

    parcel->sg_buffers_size = 0;
    vector_destroy(&parcel->objects);

    vector_destroy(&parcel->buffer);

    free(parcel);
    *parcel_p = NULL;
}

static inline binder_size_t align4(binder_size_t s)
{
    return (s + UINT64_C(3)) & ~UINT64_C(3);
}

static inline binder_size_t align8(binder_size_t s)
{
    return (s + UINT64_C(7)) & ~UINT64_C(7);
}

static int validate_parcel_object_ref(const struct kmhal_hidl_parcel *parcel,
                                      kmhal_hidl_parcel_obj_t obj_ref)
{
    if (parcel == NULL) {
        s_log_error("Parcel is NULL");
        return -1;
    }

    if (!KMHAL_HIDL_PARCEL_OBJ_IS_VALID(obj_ref)) {
        s_log_error("Invalid object reference");
        return -1;
    }

    const size_t idx = (size_t)obj_ref;
    if (idx >= vector_size(parcel->objects)) {
        s_log_error("Referenced object doesn't exist");
        return -1;
    }

    const struct parcel_obj *const obj = &parcel->objects[idx];
    if (obj->parcel_bp != parcel) {
        s_log_error("Object does not belong to parcel");
        return 1;
    }

    if (obj->self_idx >= vector_size(parcel->objects)) {
        s_log_error("Object's index invalid");
        return 1;
    }

    if (obj != &parcel->objects[obj->self_idx]) {
        s_log_error("Object's self-reference doesn't match parcel's");
        return 1;
    }

    if (obj->off > UINT32_MAX) {
        s_log_error("Object's offset is too big");
        return 1;
    }

    return 0;
}

static int validate_buffer_object(const struct kmhal_hidl_parcel *parcel,
        const struct binder_buffer_object *obj, binder_size_t size, u32 flags,
        binder_size_t parent, binder_size_t parent_offset)
{
    if (parcel == NULL) {
        s_log_error("Parcel is NULL");
        return -1;
    } else if (obj == NULL) {
        s_log_error("Buffer object is NULL");
        return -1;
    }

    if (obj->hdr.type != BINDER_TYPE_PTR) {
        s_log_error("Object is not a BINDER_TYPE_PTR");
        return -1;
    }

    if (obj->length != size) {
        s_log_debug("obj->length: %zu, size: %zu", obj->length, size);
        s_log_error("Object size doesn't match expected value");
        return 1;
    }
    if (obj->flags != flags) {
        s_log_error("Object flags don't match expected value");
        return 1;
    }
    if (flags & BINDER_BUFFER_FLAG_HAS_PARENT) {
        if (obj->parent != parent) {
            s_log_error("Object's parent doesn't match the expected value");
            return 1;
        }
        if (obj->parent_offset != parent_offset) {
            s_log_error("Object's `parent_offset` doesn't match "
                    "the expected value");
            return 1;
        }
    }
    if (!obj->buffer && obj->length > 0) {
        s_log_error("Object's length > 0 while buffer is NULL");
        return 1;
    }

    return 0;
}

static int validate_parent(const struct kmhal_hidl_parcel *parcel,
                           binder_size_t parent_idx, binder_size_t child_idx)
{
    const size_t idx = (size_t)parent_idx;
    if (idx >= vector_size(parcel->objects)) {
        s_log_error("Parent object doesn't exist");
        return -1;
    }

    const kmhal_hidl_parcel_obj_t parent_ref =
        (kmhal_hidl_parcel_obj_t)parent_idx;

    if (validate_parcel_object_ref(parcel, parent_ref)) {
        s_log_error("Parent object invalid");
        return 1;
    }

    const binder_size_t off = parcel->objects[idx].off;
    s_assert(off < UINT32_MAX - sizeof(struct binder_buffer_object),
            "Offset too big");

    if (off > vector_size(parcel->buffer) -
            sizeof(struct binder_buffer_object))
    {
        s_log_error("Parent object out of bounds");
        return 1;
    }

    struct binder_buffer_object obj;
    memcpy(&obj, parcel->buffer + parcel->objects[idx].off,
            sizeof(struct binder_buffer_object));
    if (obj.hdr.type != BINDER_TYPE_PTR) {
        s_log_error("Parent object is not a BINDER_TYPE_PTR");
        return 1;
    }

    if (child_idx == parent_idx) {
        s_log_error("Child object references itself");
        return 1;
    } else if (child_idx < parent_idx) {
        s_log_error("Parent object doesn't precede child object");
        return 1;
    }

    return 0;
}

static int validate_reply(const struct kmhal_hidl_binder_tr_sg_args_out *r)
{
    if (r == NULL) {
        s_log_error("Invalid parameters");
        return 1;
    }

    if (r->data_buf == NULL || r->data_size < sizeof(int32_t)) {
        s_log_error("Invalid data buffer in reply");
        return 1;
    }

    if (r->data_size > UINT32_MAX ||
            (u64)r->offsets_count * sizeof(binder_size_t) > UINT32_MAX)
    {
        s_log_error("Data or offsets size too big");
        return 1;
    }

    if (r->offsets_count > 0 && r->offsets_buf == NULL) {
        s_log_error("Offsets buffer NULL while offsets_count is %zu",
                r->offsets_count);
        return 1;
    }

    i64 bad_idx = -1;
    for (u32 i = 0; i < r->offsets_count; i++) {
        const binder_size_t off = r->offsets_buf[i];
        if (off > UINT32_MAX) {
            s_log_error("Offset too big");
            bad_idx = i;
            break;
        }

        if (off != align4(off)) {
            s_log_error("Unaligned offset");
            bad_idx = i;
            break;
        }

        if (off > r->data_size ||
                sizeof(struct binder_object_header) > r->data_size - off)
        {
            s_log_error("Offset overflows data buffer");
            bad_idx = i;
            break;
        }

        if (i > 0 && r->offsets_buf[i] <= r->offsets_buf[i - 1]) {
            s_log_error("Offsets array not strictly ascending");
            bad_idx = i;
            break;
        }

        struct binder_object_header hdr;
        memcpy(&hdr, r->data_buf + off, sizeof(hdr));

        size_t required_size = 0;

        switch (hdr.type) {
        default:
            s_log_error("Invalid object type %u (0x%x)", hdr.type, hdr.type);
            bad_idx = i;
            goto bad_offset;
        case BINDER_TYPE_BINDER:
        case BINDER_TYPE_WEAK_BINDER:
        case BINDER_TYPE_HANDLE:
        case BINDER_TYPE_WEAK_HANDLE:
            required_size = sizeof(struct flat_binder_object);
            break;
        case BINDER_TYPE_FD:
            required_size = sizeof(struct binder_fd_object);
            break;
        case BINDER_TYPE_FDA:
            required_size = sizeof(struct binder_fd_array_object);
            break;
        case BINDER_TYPE_PTR:
            required_size = sizeof(struct binder_buffer_object);
            break;
        }

        if (off + required_size > r->data_size) {
            bad_idx = i;
            goto bad_offset;
        }

        if (hdr.type == BINDER_TYPE_PTR) {
            struct binder_buffer_object obj;
            memcpy(&obj, r->data_buf + off, sizeof(obj));
            if (obj.flags & BINDER_BUFFER_FLAG_HAS_PARENT &&
                    obj.parent >= r->offsets_count)
            {
                s_log_error("Invalid parent index %llu in buffer object",
                        obj.parent);
                bad_idx = i;
                goto bad_offset;
            }

            if (obj.buffer == 0 && obj.length > 0) {
                s_log_error("Invalid buffer in buffer object");
                bad_idx = i;
                goto bad_offset;
            }
        }
    }
bad_offset:
    if (bad_idx >= 0) {
        s_log_error("Object pointed to by offsets[%"PRIi64"] (%llu) "
                "is invalid or overruns data buffer",
                bad_idx, r->offsets_buf[bad_idx]
        );
        return 1;
    }

    int32_t status = 0;
    memcpy(&status, r->data_buf, sizeof(int32_t));

    if (r->flags & TF_STATUS_CODE) {
        s_log_error("Reply is a status code: %d (%s)",
                status, kmhal_hidl_android_status_toString(status));
        return 1;
    }

    if (status != 0) {
        s_log_error("Non-zero status in reply buffer: %d (%s)",
                status, kmhal_hidl_android_status_toString(status));
        return 1;
    }

    return 0;
}
