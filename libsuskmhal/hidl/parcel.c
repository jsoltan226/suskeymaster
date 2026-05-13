#include "parcel.h"
#include "binderif.h"
#include "hidl-types.h"
#include <core/log.h>
#include <core/int.h>
#include <core/util.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdlib.h>
#include <core/vector.h>
#include <core/bitfield.h>
#include <linux/android/binder.h>
#include <string.h>
#include <unistd.h>

#define MODULE_NAME "hidl-parcel"

struct kmhal_hidl_parcel {
    _Atomic bool initialized_;

    VECTOR(u8) buffer;

    struct bitfield objs_fixup;
    VECTOR(binder_size_t) obj_offsets;
    binder_size_t obj_buffers_size;

    VECTOR(binder_size_t) root_obj_offsets;

    _Atomic bool txn_pending;
    struct kmhal_hidl_binder_tr_sg_args txn_arg;
};

static void parcel_destroy__(struct kmhal_hidl_parcel **parcel_p,
        bool allow_pending_transaction);

static inline binder_size_t align4(binder_size_t s);
static inline binder_size_t align8(binder_size_t s);

static void register_buffer_object(struct kmhal_hidl_parcel *parcel,
        binder_size_t obj_buf_size, u32 serialized_obj_data_off,
        bool obj_buf_in_parcel_buf, bool is_root_obj
);
static void register_simple_object(struct kmhal_hidl_parcel *parcel,
        u32 obj_off);

static u32 get_next_free_obj_idx(struct kmhal_hidl_parcel *parcel);

#if 0
static int write_unaligned(struct kmhal_hidl_parcel *p,
        const void *data, size_t len);
#endif /* 0 */

static int validate_offset(binder_size_t off, i64 idx_hint,
        const struct kmhal_hidl_parcel *parcel);

static int read_object(const VECTOR(u8) buffer,
        binder_size_t offset, struct binder_buffer_object *out);

static int validate_reply(const struct kmhal_hidl_binder_tr_sg_args_out *r);

struct kmhal_hidl_parcel * kmhal_hidl_parcel_new(void)
{
    struct kmhal_hidl_parcel *ret = NULL;

    ret = calloc(1, sizeof(struct kmhal_hidl_parcel));
    if (ret == NULL)
        goto_error("Failed to allocate a new parcel struct");
    atomic_store(&ret->initialized_, true);

    ret->buffer = vector_new(u8);

    bitfield_dyn_init(&ret->objs_fixup, 0);
    ret->obj_offsets = vector_new(binder_size_t);
    ret->obj_buffers_size = 0;
    ret->root_obj_offsets = vector_new(binder_size_t);

    atomic_store(&ret->txn_pending, false);
    /* `ret->txn_arg` already zeroed by `calloc()` */

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
    struct kmhal_hidl_parcel *ret = NULL;

    if (validate_reply(reply))
        goto_error("Invalid or failed reply");

    ret = kmhal_hidl_parcel_new();
    if (ret == NULL)
        goto err;

    vector_resize(&ret->buffer, reply->data_size);
    memcpy(ret->buffer, reply->data_buf, reply->data_size);

    vector_resize(&ret->obj_offsets, reply->offsets_count);
    memcpy(ret->obj_offsets, reply->offsets_buf,
            reply->offsets_count * sizeof(binder_size_t));

    bitfield_dyn_resize(&ret->objs_fixup, reply->offsets_count);

    for (u32 i = 0; i < vector_size(ret->obj_offsets); i++) {
        const binder_size_t off = ret->obj_offsets[i];

        struct binder_object_header hdr;
        memcpy(&hdr, ret->buffer + off, sizeof(hdr));

        switch (hdr.type) {
        case BINDER_TYPE_BINDER:
        case BINDER_TYPE_WEAK_BINDER:
        case BINDER_TYPE_HANDLE:
        case BINDER_TYPE_WEAK_HANDLE:
            break;
        case BINDER_TYPE_FD:
            goto_error("Binder fd type not yet supported");
            break;
        case BINDER_TYPE_FDA:
            goto_error("Binder fd array type not yet supported");
            break;
        case BINDER_TYPE_PTR: {
            struct binder_buffer_object obj;
            memcpy(&obj, ret->buffer + off, sizeof(obj));

            if (!(obj.flags & BINDER_BUFFER_FLAG_HAS_PARENT))
                vector_push_back(&ret->root_obj_offsets, i);

            ret->obj_buffers_size += obj.length;
            break;
        }
        }
    }

    return ret;

err:
    if (ret != NULL)
        kmhal_hidl_parcel_destroy(&ret);

    return NULL;
}

void kmhal_hidl_parcel_write_inline_bytes(struct kmhal_hidl_parcel *parcel,
        const void *data, size_t len)
{
    u_check_params(parcel != NULL && atomic_load(&parcel->initialized_) &&
            (data != NULL || len > 0));

    /* `vector_resize` already memset()s the whole thing to zero,
     * including any of our additional padding bytes */
    const size_t offset = align4(vector_size(parcel->buffer));
    vector_resize(&parcel->buffer, offset + len);
    memcpy(parcel->buffer + offset, data, len);
}

void kmhal_hidl_parcel_write_inline_u32(struct kmhal_hidl_parcel *parcel, u32 u)
{
    u32 u_ = u;
    kmhal_hidl_parcel_write_inline_bytes(parcel, &u_, sizeof(u32));
}

void kmhal_hidl_parcel_write_inline_u64(struct kmhal_hidl_parcel *parcel, u64 u)
{
    u_check_params(parcel != NULL && atomic_load(&parcel->initialized_));

    size_t newpos = align8(vector_size(parcel->buffer));
    size_t newsize = newpos + sizeof(u64);

    vector_resize(&parcel->buffer, newsize);

    const u64 u_ = u;
    memcpy(parcel->buffer + newpos, &u_, sizeof(u64));
}

void kmhal_hidl_parcel_write_inline_cstring(struct kmhal_hidl_parcel *parcel,
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

void kmhal_hidl_parcel_write_handle(
        struct kmhal_hidl_parcel *parcel,
        u32 type, u32 handle, u32 flags, binder_uintptr_t cookie
)
{
    u_check_params(parcel != NULL && atomic_load(&parcel->initialized_) &&
        (
            type == BINDER_TYPE_BINDER || type == BINDER_TYPE_WEAK_BINDER ||
            type == BINDER_TYPE_HANDLE || type == BINDER_TYPE_WEAK_HANDLE
        )
    );

    struct flat_binder_object obj = {
        .hdr.type = type,
        .handle = handle,
        .flags = flags,
        .cookie = cookie
    };

    const binder_size_t off = align4(vector_size(parcel->buffer));
    vector_resize(&parcel->buffer, off + sizeof(obj));
    memcpy(parcel->buffer + off, &obj, sizeof(obj));

    register_simple_object(parcel, off);
}

void kmhal_hidl_parcel_write_hidl_string(
        struct kmhal_hidl_parcel *parcel,
        const struct kmhal_hidl_string *str,
        size_t str_bytes_size
)
{
    u_check_params(parcel != NULL && atomic_load(&parcel->initialized_) &&
            str != NULL);

    const size_t OBJ_SIZE = sizeof(struct binder_buffer_object);

    const size_t hstr_obj_off = align4(vector_size(parcel->buffer));
    const size_t bytes_obj_off = align4(hstr_obj_off + OBJ_SIZE);

    const size_t new_size = bytes_obj_off + sizeof(struct binder_buffer_object);

    struct binder_buffer_object hstr_obj = {
        .hdr.type = BINDER_TYPE_PTR,
        .flags = 0,
        .buffer = (binder_uintptr_t)str,
        .length = sizeof(struct kmhal_hidl_string),
    };
    const binder_size_t hstr_obj_idx = get_next_free_obj_idx(parcel);

    struct binder_buffer_object bytes_obj = {
        .hdr.type = BINDER_TYPE_PTR,
        .flags = BINDER_BUFFER_FLAG_HAS_PARENT,
        .buffer = (binder_uintptr_t)str->buffer,
        .length = str_bytes_size,
        .parent = hstr_obj_idx,
        .parent_offset = offsetof(struct kmhal_hidl_string, buffer)
    };

    vector_resize(&parcel->buffer, new_size);

    memcpy(parcel->buffer + hstr_obj_off, &hstr_obj, sizeof(hstr_obj));
    register_buffer_object(parcel, sizeof(*str), hstr_obj_off, false, true);

    memcpy(parcel->buffer + bytes_obj_off, &bytes_obj, sizeof(bytes_obj));
    register_buffer_object(parcel, str_bytes_size, bytes_obj_off, false, false);
}

void kmhal_hidl_parcel_pack(struct kmhal_hidl_binder_transaction *txn,
                                    struct kmhal_hidl_parcel *parcel,
                                    u32 handle, u32 cmd)
{
    u_check_params(txn != NULL &&
            parcel != NULL && atomic_load(&parcel->initialized_));

    const bool prev_pending = atomic_exchange(&parcel->txn_pending, true);
    s_assert(!prev_pending, "Attempt to queue parcel for transaction twice");

    /* Fill in all the buffer pointers */
    const u32 n_objs = vector_size(parcel->obj_offsets);
    s_assert(n_objs == bitfield_size_bits(parcel->objs_fixup),
            "Invalid state!");
    for (u32 i = 0; i < n_objs; i++) {
        if (!bitfield_getval(&parcel->objs_fixup, i))
            continue;

        const binder_size_t off = parcel->obj_offsets[i];
        if (off + sizeof(struct binder_buffer_object) >
                vector_size(parcel->buffer))
            s_log_fatal("Binder buffer object overruns parcel buffer!");
        else if (off > UINT32_MAX)
            s_log_fatal("Offset %ju too large", off);

        /* It's better to just bear the immeasurable cost of copying 40 bytes
         * rather than to engage in sketchy pointer arithmetic
         * and having to worry about unaligned accesses */
        struct binder_buffer_object obj;
        memcpy(&obj, parcel->buffer + off, sizeof(struct binder_buffer_object));
        const binder_uintptr_t stored_data_offset = obj.buffer;

        obj.buffer = (binder_uintptr_t)parcel->buffer + stored_data_offset;
#if 0
        s_log_debug("[@ %llu] new obj buffer ptr: %p", off, (void *)obj.buffer);
#endif /* 0 */

        memcpy(parcel->buffer + off, &obj, sizeof(struct binder_buffer_object));
    }

#if 0
    s_log_debug("parcel->buffer: %p", parcel->buffer);
    for (uint32_t i = 0; i < vector_size(parcel->buffer); i++) {
        if (i % 16 == 0 && i > 0) putchar('\n');
        printf("%02x ", parcel->buffer[i]);
    }
    putchar('\n');

    s_log_debug("parcel->object_offsets: %p", parcel->object_offsets);
    for (uint32_t i = 0; i < vector_size(parcel->object_offsets); i++) {
        const u64 val = parcel->object_offsets[i];
        printf("0x%llx (%llu)\n",
                (long long unsigned)val, (long long unsigned)val);
    }
#endif /* 0 */

    parcel->txn_arg = (struct kmhal_hidl_binder_tr_sg_args) {
        .in_txn = txn,
        .in_data = {
            .cmd = cmd,
            .flags = TF_ACCEPT_FDS,
            .handle = handle,
            .data_buf = parcel->buffer,
            .data_size = vector_size(parcel->buffer),
            .offsets_buf = parcel->obj_offsets,
            .offsets_count = vector_size(parcel->obj_offsets),
            .sg_buffers_size = parcel->obj_buffers_size
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

int kmhal_hidl_parcel_read_inline_u32(struct kmhal_hidl_parcel *parcel,
        binder_size_t offset, u32 *out)
{
    u_check_params(parcel != NULL && atomic_load(&parcel->initialized_) &&
            parcel->buffer != NULL);
    u_check_params(offset == align4(offset));

    if (offset + sizeof(u32) > vector_size(parcel->buffer)) {
        s_log_error("Requested offset outside of parcel buffer");
        return -1;
    }

    if (out != NULL)
        memcpy(out, parcel->buffer + offset, sizeof(u32));
    return 0;
}

int kmhal_hidl_parcel_read_inline_u64(struct kmhal_hidl_parcel *parcel,
        binder_size_t offset, u64 *out)
{
    u_check_params(parcel != NULL && atomic_load(&parcel->initialized_) &&
            parcel->buffer != NULL);
    u_check_params(offset == align4(offset));

    if (offset + sizeof(u64) > vector_size(parcel->buffer)) {
        s_log_error("Requested offset outside of parcel buffer");
        return -1;
    }

    if (out != NULL)
        memcpy(out, parcel->buffer + offset, sizeof(u64));
    return 0;
}

int kmhal_hidl_parcel_read_handle(
        struct kmhal_hidl_parcel *parcel, binder_size_t off, i64 off_idx_hint,
        u32 *out_type, u32 *out_handle, u32 *out_flags,
        binder_uintptr_t *out_cookie
)
{
    u_check_params(parcel != NULL && atomic_load(&parcel->initialized_) &&
            parcel->buffer != NULL && off_idx_hint < UINT32_MAX);
    if (validate_offset(off, off_idx_hint, parcel)) {
        s_log_error("Invalid flat_binder_object offset");
        return -1;
    }

    u32 type;
    memcpy(&type, (uint8_t *)parcel->buffer + off, sizeof(u32));
    switch (type) {
    case BINDER_TYPE_HANDLE:
    case BINDER_TYPE_WEAK_HANDLE:
    case BINDER_TYPE_BINDER:
    case BINDER_TYPE_WEAK_BINDER:
        break;
    default:
        s_log_error("Invalid flat_binder_object type: %u", type);
        return 1;
    }

    if (off + sizeof(struct flat_binder_object) > vector_size(parcel->buffer)) {
        s_log_error("Requested flat_binder_object is out of bounds");
        return 1;
    }

    struct flat_binder_object obj;
    memcpy(&obj, parcel->buffer + off, sizeof(obj));

    if (out_type != NULL) *out_type = type;
    if (out_handle != NULL) *out_handle = obj.handle;
    if (out_flags != NULL) *out_flags = obj.flags;
    if (out_cookie != NULL) *out_cookie = obj.cookie;
    return 0;
}

int kmhal_hidl_parcel_read_hidl_vec(struct kmhal_hidl_parcel *parcel,
        binder_size_t off, i64 off_idx_hint,
        bool is_child, struct kmhal_hidl_vec *out
)
{
    u_check_params(parcel != NULL && atomic_load(&parcel->initialized_) &&
            parcel->buffer != NULL && off_idx_hint < UINT32_MAX);

    if (validate_offset(off, off_idx_hint, parcel)) {
        s_log_error("Invalid hidl_vec binder_buffer_object offset");
        return -1;
    }

    struct binder_buffer_object obj;
    if (read_object(parcel->buffer, off, &obj)) {
        s_log_error("Failed to read the HIDL vec object");
        return 1;
    }
    if (!!(obj.flags & BINDER_BUFFER_FLAG_HAS_PARENT) != !!is_child) {
        s_log_error("Binder buffer object at offset %llu "
                "expected%sto have a parent", off, is_child ? "" : " not ");
        return 1;
    }
    if (obj.length != sizeof(struct kmhal_hidl_vec)) {
        s_log_error("Invalid size of object buffer "
                "that's supposed to contain an HIDL vec: %llu",
                obj.length);
        return 1;
    } else if (obj.buffer == 0) {
        s_log_error("HIDL vec object buffer is NULL!");
        return 1;
    }

    if (out != NULL)
        memcpy(out, (void *)obj.buffer, sizeof(struct kmhal_hidl_vec));
    return 0;
}

int kmhal_hidl_parcel_read_hidl_string(struct kmhal_hidl_parcel *parcel,
        binder_size_t off, i64 off_idx_hint,
        bool is_child, struct kmhal_hidl_string *out
)
{
    u_check_params(parcel != NULL && atomic_load(&parcel->initialized_) &&
            parcel->buffer != NULL && off_idx_hint < UINT32_MAX);

    if (validate_offset(off, off_idx_hint, parcel)) {
        s_log_error("Invalid HIDL string bytes object offset");
        return -1;
    }

    struct binder_buffer_object bytes_obj;
    if (read_object(parcel->buffer, off, &bytes_obj)) {
        s_log_error("Failed to read the HIDL string bytes object");
        return 1;
    }
    if (!(bytes_obj.flags & BINDER_BUFFER_FLAG_HAS_PARENT)) {
        s_log_error("Binder buffer object at offset %llu "
                "expected to have a parent", off);
        return 1;
    }

    if (bytes_obj.parent >= vector_size(parcel->obj_offsets)) {
        s_log_error("Invalid parent offset index");
        return 1;
    } else if (bytes_obj.parent_offset !=
            offsetof(struct kmhal_hidl_string, buffer))
    {
        s_log_error("Invalid parent_offset value");
        return 1;
    }

    off = parcel->obj_offsets[bytes_obj.parent];
    struct binder_buffer_object hstr_obj;
    if (read_object(parcel->buffer, off, &hstr_obj)) {
        s_log_error("Failed to read the HIDL string object");
        return 1;
    }
    if (!!(hstr_obj.flags & BINDER_BUFFER_FLAG_HAS_PARENT) != !!is_child) {
        s_log_error("Binder buffer object at offset %llu "
                "expected%sto have a parent", off, is_child ? "" : " not ");
        return 1;
    }
    if (hstr_obj.length != sizeof(struct kmhal_hidl_string)) {
        s_log_error("Invalid size of object buffer "
                "that's supposed to contain an HIDL string: %llu",
                hstr_obj.length);
        return 1;
    } else if (hstr_obj.buffer == 0) {
        s_log_error("HIDL string object buffer is NULL!");
        return 1;
    }

    struct kmhal_hidl_string hstr;
    memcpy(&hstr, (void *)hstr_obj.buffer, sizeof(hstr));

    if (bytes_obj.length - 1 != hstr.length ||
            (void *)bytes_obj.buffer != hstr.buffer)
    {
        s_log_error("HIDL string struct and bytes object mismatch");
        return 1;
    }


    if (out != NULL)
        memcpy(out, &hstr, sizeof(hstr));
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

    vector_destroy(&parcel->root_obj_offsets);
    parcel->obj_buffers_size = 0;
    bitfield_dyn_destroy(&parcel->objs_fixup);
    vector_destroy(&parcel->obj_offsets);
    vector_destroy(&parcel->buffer);

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

    free(parcel);
    *parcel_p = NULL;
}

static inline binder_size_t align4(binder_size_t s)
{
    return (s + 3) & ~3;
}

static inline binder_size_t align8(binder_size_t s)
{
    return (s + 7) & ~7;
}

static void register_buffer_object(struct kmhal_hidl_parcel *parcel,
        binder_size_t obj_buf_size, u32 serialized_obj_data_off,
        bool obj_buf_in_parcel_buf, bool is_root_obj
)
{
    vector_push_back(&parcel->obj_offsets, serialized_obj_data_off);
    bitfield_dyn_push_back(&parcel->objs_fixup, obj_buf_in_parcel_buf);
    parcel->obj_buffers_size += align8(obj_buf_size);

    if (is_root_obj)
        vector_push_back(&parcel->root_obj_offsets, serialized_obj_data_off);
}

static void register_simple_object(struct kmhal_hidl_parcel *parcel,
        u32 obj_off)
{
    vector_push_back(&parcel->obj_offsets, obj_off);
}

static u32 get_next_free_obj_idx(struct kmhal_hidl_parcel *parcel)
{
    return vector_size(parcel->obj_offsets);
}

#if 0
static int write_unaligned(struct kmhal_hidl_parcel *p,
        const void *data, size_t len)
{
    if (p == NULL)
        return -1;
    else if (len == 0)
        return 0;
    else if (len > 0 && data == NULL)
        return -1;

    vector_resize(&p->buffer, vector_size(p->buffer) + len);
    memcpy(p->buffer, data, len);
    return 0;
}
#endif /* 0 */

static int validate_offset(binder_size_t off, i64 idx_hint,
        const struct kmhal_hidl_parcel *parcel)
{
    if (off + sizeof(u32) > vector_size(parcel->buffer)) {
        s_log_error("Requested offset outside of parcel buffer");
        return -1;
    } else if (idx_hint >= vector_size(parcel->obj_offsets)) {
        s_log_error("Invalid offset index hint");
        return -1;
    }

    if (parcel->obj_offsets[idx_hint] == off)
        return 0;

    for (u32 i = 0; i < vector_size(parcel->obj_offsets); i++) {
        if (parcel->obj_offsets[i] == off)
            return true;
    }

    s_log_error("Offset %llu not fount in offset list", off);
    return 1;
}

static int read_object(const VECTOR(u8) buffer,
        binder_size_t offset, struct binder_buffer_object *out)
{
    if (buffer == NULL) {
        s_log_error("Invalid parameters");
        return -1;
    }

    if (offset + sizeof(struct binder_buffer_object) > vector_size(buffer)) {
        s_log_error("Requested object is out of bounds");
        return -1;
    }

    memcpy(out, buffer + offset, sizeof(struct binder_buffer_object));
    if (out->hdr.type != BINDER_TYPE_PTR) {
        s_log_error("Read object is not a BINDER_TYPE_PTR buffer object");
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

    i64 bad_idx = -1;
    for (u32 i = 0; i < r->offsets_count; i++) {
        const binder_size_t off = r->offsets_buf[i];

        if (off + sizeof(struct binder_object_header) > r->data_size) {
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
        s_log_error("Object pointed to by offsets[%lli] (%llu) "
                "is invalid or overruns data buffer",
                (long long)bad_idx, r->offsets_buf[bad_idx]
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
