#include "parcel.h"
#include "binderif.h"
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

struct parcel_binder_object {
    u32 serialized_obj_off;
    bool fixup_buffer_addr;
};

struct kmhal_hidl_parcel {
    _Atomic bool initialized_;

    VECTOR(u8) buffer;

    struct bitfield objs_fixup;
    VECTOR(binder_size_t) obj_offsets;
    binder_size_t objs_size;

    _Atomic bool txn_pending;
    struct kmhal_hidl_binder_tr_sg_args txn_arg;
};

static void parcel_destroy__(struct kmhal_hidl_parcel **parcel_p,
        bool allow_pending_transaction);

static inline binder_size_t align4(binder_size_t s);
static inline binder_size_t align8(binder_size_t s);

static void register_object(struct kmhal_hidl_parcel *parcel,
        binder_size_t obj_buf_size, u32 serialized_obj_data_off,
        bool obj_buf_in_parcel_buf
);
static u32 get_next_free_obj_idx(struct kmhal_hidl_parcel *parcel);

#if 0
static int write_unaligned(struct kmhal_hidl_parcel *p,
        const void *data, size_t len);
#endif /* 0 */

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

    atomic_store(&ret->txn_pending, false);
    /* `ret->txn_arg` already zeroed by `calloc()` */

    return ret;

err:
    if (ret != NULL)
        kmhal_hidl_parcel_destroy(&ret);

    return NULL;
}

void kmhal_hidl_parcel_write_bytes_inline(struct kmhal_hidl_parcel *parcel,
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

void kmhal_hidl_parcel_write_u32(struct kmhal_hidl_parcel *parcel, const u32 u)
{
    u32 u_ = u;
    kmhal_hidl_parcel_write_bytes_inline(parcel, &u_, sizeof(u32));
}

void kmhal_hidl_parcel_write_u64(struct kmhal_hidl_parcel *parcel, const u64 u)
{
    u_check_params(parcel != NULL && atomic_load(&parcel->initialized_));

    size_t newpos = align8(vector_size(parcel->buffer));
    size_t newsize = newpos + sizeof(u64);

    vector_resize(&parcel->buffer, newsize);

    const u64 u_ = u;
    memcpy(parcel->buffer + newpos, &u_, sizeof(u64));
}

void kmhal_hidl_parcel_write_cstring_inline(struct kmhal_hidl_parcel *parcel,
        const char *str)
{
    u_check_params(parcel != NULL && atomic_load(&parcel->initialized_) &&
            str != NULL);

    /* Write the string data */
    const binder_size_t str_offset = align4(vector_size(parcel->buffer));
    const size_t str_len = strlen(str),
          str_len_full = align4(str_len + sizeof((char)'\0'));

    vector_resize(&parcel->buffer, str_offset + str_len_full);
    memcpy(parcel->buffer + str_offset, str, str_len);
    parcel->buffer[str_offset + str_len] = '\0';
}

struct serialized_hidl_string {
        const void *buffer;
        u32 size;
        u32 owns_buffer;
};
_Static_assert(offsetof(struct serialized_hidl_string, buffer) == 0,
        "Invalid offset of the buffer pointer in HIDL string");
_Static_assert(offsetof(struct serialized_hidl_string, size) == 8,
        "Invalid offset of the size u32 in HIDL string");
_Static_assert(offsetof(struct serialized_hidl_string, owns_buffer) == 12,
        "Invalid offset of the `owns_buffer` u32 in HIDL string");
_Static_assert(sizeof(struct serialized_hidl_string) == 16,
        "Invalid size of the HIDL string struct");

void kmhal_hidl_parcel_write_hidl_string(
        struct kmhal_hidl_parcel *parcel,
        const char *buffer, u32 size, bool owns_buffer
)
{
    u_check_params(parcel != NULL && atomic_load(&parcel->initialized_) &&
            (size == 0 || buffer != NULL));

    const size_t OBJ_SIZE = sizeof(struct binder_buffer_object);

    const size_t hstr_obj_off = align4(vector_size(parcel->buffer));
    const size_t bytes_obj_off = align4(hstr_obj_off + OBJ_SIZE);
    const size_t hstr_struct_off = align4(bytes_obj_off + OBJ_SIZE);

    const size_t new_size = hstr_struct_off +
        sizeof(struct serialized_hidl_string);

    struct binder_buffer_object hstr_obj = {
        .hdr.type = BINDER_TYPE_PTR,
        .flags = 0,
        .buffer = /* parcel->buffer + */ hstr_struct_off,
        .length = sizeof(struct serialized_hidl_string),
    };
    const binder_size_t hstr_obj_idx = get_next_free_obj_idx(parcel);

    struct binder_buffer_object bytes_obj = {
        .hdr.type = BINDER_TYPE_PTR,
        .flags = BINDER_BUFFER_FLAG_HAS_PARENT,
        .buffer = (binder_uintptr_t)buffer,
        .length = size,
        .parent = hstr_obj_idx,
        .parent_offset = offsetof(struct serialized_hidl_string, buffer)
    };

    struct serialized_hidl_string hstr_struct = {
        .buffer = buffer,
        .size = size - 1,
        .owns_buffer = owns_buffer
    };

    vector_resize(&parcel->buffer, new_size);

    memcpy(parcel->buffer + hstr_obj_off, &hstr_obj, sizeof(hstr_obj));
    register_object(parcel, sizeof(hstr_struct), hstr_obj_off, true);

    memcpy(parcel->buffer + bytes_obj_off, &bytes_obj, sizeof(bytes_obj));
    register_object(parcel, size, bytes_obj_off, false);

    memcpy(parcel->buffer + hstr_struct_off, &hstr_struct, sizeof(hstr_struct));
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
            .sg_buffers_size = parcel->objs_size
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

static void register_object(struct kmhal_hidl_parcel *parcel,
        binder_size_t obj_buf_size, u32 serialized_obj_data_off,
        bool obj_buf_in_parcel_buf
)
{
    vector_push_back(&parcel->obj_offsets, serialized_obj_data_off);
    bitfield_dyn_push_back(&parcel->objs_fixup, obj_buf_in_parcel_buf);
    parcel->objs_size += align8(obj_buf_size);
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
