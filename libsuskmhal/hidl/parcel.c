#include "parcel.h"
#include "binderif.h"
#include <core/log.h>
#include <core/int.h>
#include <core/util.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <core/vector.h>
#include <linux/android/binder.h>
#include <string.h>
#include <unistd.h>

#define MODULE_NAME "hidl-parcel"

struct kmhal_hidl_parcel {
    _Atomic bool initialized_;

    VECTOR(u8) buffer;

    VECTOR(binder_size_t) object_offsets;
    binder_size_t objects_size;

    _Atomic bool txn_pending;
    struct kmhal_hidl_binder_tr_sg_args txn_arg;
};

static void parcel_destroy__(struct kmhal_hidl_parcel **parcel_p,
        bool allow_pending_transaction);

static inline binder_size_t align4(binder_size_t s);
static inline binder_size_t align8(binder_size_t s);

static void register_object(struct kmhal_hidl_parcel *parcel,
        binder_size_t offset, binder_size_t size);

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

    ret->object_offsets = vector_new(binder_size_t);

    atomic_store(&ret->txn_pending, false);
    /* `ret->txn_arg` already zeroed by `calloc()` */

    return ret;

err:
    if (ret != NULL)
        kmhal_hidl_parcel_destroy(&ret);

    return NULL;
}

int kmhal_hidl_parcel_write_bytes(struct kmhal_hidl_parcel *parcel,
        const void *data, size_t len)
{
    if (parcel == NULL || !atomic_load(&parcel->initialized_))
        return -1;
    else if (len == 0)
        return 0;
    else if (len > 0 && data == NULL)
        return -1;

    /* `vector_resize` already memset()s the whole thing to zero,
     * including any of our additional padding bytes */
    const size_t offset = align4(vector_size(parcel->buffer));
    vector_resize(&parcel->buffer, offset + len);
    memcpy(parcel->buffer + offset, data, len);
    return 0;
}

int kmhal_hidl_parcel_write_u32(struct kmhal_hidl_parcel *parcel, const u32 u)
{
    u32 u_ = u;
    return kmhal_hidl_parcel_write_bytes(parcel, &u_, sizeof(u32));
}

int kmhal_hidl_parcel_write_u64(struct kmhal_hidl_parcel *parcel, const u64 u)
{
    if (parcel == NULL || !atomic_load(&parcel->initialized_))
        return -1;

    size_t newpos = align8(vector_size(parcel->buffer));
    size_t newsize = newpos + sizeof(u64);

    vector_resize(&parcel->buffer, newsize);

    const u64 u_ = u;
    memcpy(parcel->buffer + newpos, &u_, sizeof(u64));

    return 0;
}

int kmhal_hidl_parcel_write_string(struct kmhal_hidl_parcel *parcel,
        const char *str)
{
    if (parcel == NULL || !atomic_load(&parcel->initialized_) || str == NULL)
        return -1;

    /* string data || binder_buffer_object
     * everything aligned to 8 bytes */

    /* Write the string data */
    const binder_size_t str_offset = align8(vector_size(parcel->buffer));
    const size_t str_len = strlen(str),
          str_len_full = align8(str_len + 1 /* include '\0' */);

    vector_resize(&parcel->buffer, str_offset + str_len_full);
    memcpy(parcel->buffer + str_offset, str, str_len);
    parcel->buffer[str_offset + str_len] = '\0';

    /* Write the binder_buffer_object */
    struct binder_buffer_object obj = {
        .hdr.type = BINDER_TYPE_PTR,
        .flags = 0,

        /* Fixed up later since `vector_resize` might cause
         * the base pointer to move later */
        .buffer = /* parcel->buffer + */ str_offset,

        .length = str_len_full,

        .parent = 0, .parent_offset = 0
    };
    const size_t obj_offset = align8(vector_size(parcel->buffer));

    vector_resize(&parcel->buffer, obj_offset + sizeof(obj));
    memcpy(parcel->buffer + obj_offset, &obj, sizeof(obj));
    register_object(parcel, obj_offset, str_len_full);

    return 0;
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
    for (u32 i = 0; i < vector_size(parcel->object_offsets); i++) {
        const binder_size_t off = parcel->object_offsets[i];

        if (off + sizeof(struct binder_buffer_object) >
                vector_size(parcel->buffer))
            s_log_fatal("Binder buffer object overruns parcel buffer!");

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
            .offsets_buf = parcel->object_offsets,
            .offsets_count = vector_size(parcel->object_offsets),
            .sg_buffers_size = parcel->objects_size
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

    vector_destroy(&parcel->object_offsets);
    vector_destroy(&parcel->buffer);
    parcel->objects_size = 0;

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
        binder_size_t offset, binder_size_t size)
{
    vector_push_back(&parcel->object_offsets, offset);
    parcel->objects_size += size;
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
