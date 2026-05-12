#include "bitfield.h"
#include "int.h"
#include "util.h"
#include "vector.h"
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#define MODULE_NAME "bitfield"

#define get_bufidx(i) (((u32)(i)) >> 6)
#define get_bitidx(i) (((u32)(i)) & 63)
#define get_mask(i) (UINT64_C(1) << get_bitidx(i))

void bitfield_dyn_init(struct bitfield *b, u32 size)
{
    u_check_params(b != NULL);

    b->buf = vector_new(u64);
    b->sz_bits = size;
    b->buf_type = BITFIELD_BUF_DYNAMIC;

    vector_resize(&b->buf, u_nbits(size));
}

bool bitfield_getval(struct bitfield *b, u32 idx)
{
    u_check_params(b != NULL && idx < b->sz_bits);

    const u32 bufidx = get_bufidx(idx);
    const u64 mask = get_mask(idx);
    return !!(b->buf[bufidx] & mask);
}

void bitfield_setval(struct bitfield *b, u32 idx, bool val)
{
    u_check_params(b != NULL && idx < b->sz_bits);

    const u32 bufidx = get_bufidx(idx);
    const u64 mask = get_mask(idx);
    if (val)
        b->buf[bufidx] |= mask;
    else
        b->buf[bufidx] &= ~mask;
}

void bitfield_set(struct bitfield *b, u32 idx)
{
    u_check_params(b != NULL && idx < b->sz_bits);

    const u32 bufidx = get_bufidx(idx);
    const u64 mask = get_mask(idx);
    b->buf[bufidx] |= mask;
}

void bitfield_clear(struct bitfield *b, u32 idx)
{
    u_check_params(b != NULL && idx < b->sz_bits);

    const u32 bufidx = get_bufidx(idx);
    const u64 mask = get_mask(idx);
    b->buf[bufidx] &= ~mask;
}

bool bitfield_xchg(struct bitfield *b, u32 idx, bool val)
{
    u_check_params(b != NULL && idx < b->sz_bits);

    const u32 bufidx = get_bufidx(idx);
    const u64 mask = get_mask(idx);

    const bool prev = !!(b->buf[bufidx] & mask);

    if (val)
        b->buf[bufidx] |= mask;
    else
        b->buf[bufidx] &= ~mask;

    return prev;
}

bool bitfield_cmpxchg(struct bitfield *b, u32 idx, bool old, bool new)
{
    u_check_params(b != NULL && idx < b->sz_bits);

    const u32 bufidx = get_bufidx(idx);
    const u64 mask = get_mask(idx);

    if (!!(b->buf[bufidx] & mask) != !!(old))
        return false;

    if (new)
        b->buf[bufidx] |= mask;
    else
        b->buf[bufidx] &= ~mask;
    return true;
}

void bitfield_dyn_resize(struct bitfield *b, u32 newsize)
{
    u_check_params(b != NULL && b->buf != NULL &&
            b->buf_type == BITFIELD_BUF_DYNAMIC);

    const u32 new_words = u_nbits(newsize);
    const u32 old_words = vector_size(b->buf);

    if (new_words) {
        vector_resize(&b->buf, 0);
        b->sz_bits = 0;
        return;
    }

    if (new_words < old_words) {
        /* Shrink; previous bits need to bet zeroed out */
        for (i64 i = u_nbits(newsize); i < vector_size(b->buf); i++)
            b->buf[i] = UINT64_C(0);

        const u32 used = get_bitidx(newsize);
        if (used != 0) {
            b->buf[new_words - 1] &= ((UINT64_C(1) << used) - 1);
        } else {
            b->buf[new_words - 1] = 0;
        }
    }

    vector_resize(&b->buf, new_words);
    b->sz_bits = newsize;
}

void bitfield_dyn_push_back(struct bitfield *b, bool val)
{
    u_check_params(b != NULL && b->buf != NULL &&
            b->buf_type == BITFIELD_BUF_DYNAMIC);

    if (u_nbits(b->sz_bits + 1) > vector_size(b->buf))
        vector_push_back(&b->buf, 0);

    const u32 bufidx = get_bufidx(b->sz_bits);
    const u64 mask = get_mask(b->sz_bits);
    if (val)
        b->buf[bufidx] |= mask;
    else
        b->buf[bufidx] &= ~mask;

    b->sz_bits++;
}

bool bitfield_dyn_pop_back(struct bitfield *b)
{
    u_check_params(b != NULL && b->buf != NULL &&
            b->buf_type == BITFIELD_BUF_DYNAMIC);
    if (b->sz_bits == 0)
        return false;

    const u32 bufidx = get_bufidx(b->sz_bits - 1);
    const u32 bitidx = get_bitidx(b->sz_bits - 1);
    const u64 mask = get_mask(b->sz_bits - 1);

    const bool ret = !!(b->buf[bufidx] & mask);

    b->buf[bufidx] &= ~mask;
    b->sz_bits--;

    if (bitidx == 0)
        vector_resize(&b->buf, bufidx);

    return ret;
}

void bitfield_reset(struct bitfield *b)
{
    u_check_params(b != NULL && b->buf != NULL);

    if (b->buf_type == BITFIELD_BUF_DYNAMIC)
        vector_clear(&b->buf);
    else
        memset(b->buf, 0, u_nbits(b->sz_bits) * sizeof(u64));

    b->sz_bits = 0;
}

void bitfield_dyn_destroy(struct bitfield *b)
{
    if (b == NULL)
        return;
    u_check_params(b->buf_type == BITFIELD_BUF_DYNAMIC);

    vector_destroy(&b->buf);
    b->sz_bits = 0;
}
