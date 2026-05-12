#ifndef BITFIELD_H_
#define BITFIELD_H_

#include "static-tests.h"

#include "int.h"
#include <stdbool.h>

enum bitfield_buf_type {
    BITFIELD_BUF_STATIC = 0,
    BITFIELD_BUF_DYNAMIC = 1
};

struct bitfield {
    u64 *buf;
    u32 sz_bits;
    u32 buf_type; /* 0 = static, 1 = dynamic */
};

#define bitfield_size_bits(bf) ((bf).sz_bits)

void bitfield_dyn_init(struct bitfield *b, u32 size_bits);

bool bitfield_getval(struct bitfield *b, u32 idx);
void bitfield_setval(struct bitfield *b, u32 idx, bool val);

void bitfield_set(struct bitfield *b, u32 idx);
void bitfield_clear(struct bitfield *b, u32 idx);

bool bitfield_xchg(struct bitfield *b, u32 idx, bool val);
bool bitfield_cmpxchg(struct bitfield *b, u32 idx, bool old, bool new);

void bitfield_dyn_resize(struct bitfield *b, u32 newsize);
void bitfield_dyn_push_back(struct bitfield *b, bool val);
bool bitfield_dyn_pop_back(struct bitfield *b);

void bitfield_dyn_destroy(struct bitfield *b);

#endif /* BITFIELD_H_ */
