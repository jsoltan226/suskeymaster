#include "certs.h"
#include <core/int.h>
#include <core/vector.h>

/** RSA certificate chain goes here **/

/* From `core/vector.c` */
/*
typedef struct vector_metadata__ {
    u32 n_items;
    u32 item_size;
    u32 capacity;
    u32 dummy_;
} vector_meta_t;

struct uchar_vector__ {
    const vector_meta_t meta;
    const unsigned char data[];
};
*/

/*
static const struct uchar_vector__ rsa_cert_1 = {
    .meta = {
        .n_items = 4,
        .item_size = 1,
        .capacity = 4,
        .dummy_ = 0
    },
    .data = {
        0x78, 0x9A, 0xBC, 0xDE
    }
};
*/

/*
static const struct uchar_vector__ rsa_cert_2 = {
    .meta = {
        .n_items = 0,
        .item_size = 1,
        .capacity = 0,
        .dummy_ = 0
    },
    .data = {
    }
};
*/

/*
static const struct uchar_vector__ rsa_cert_3 = {
    .meta = {
        .n_items = 0,
        .item_size = 1,
        .capacity = 0,
        .dummy_ = 0
    },
    .data = {
    }
};
*/

/*
struct uchar_vector_vector__ {
    const vector_meta_t meta;
    VECTOR(u8 const) data[];
};
static const struct uchar_vector_vector__ rsa_cert_chain__ = {
    .meta = {
        .n_items = 3,
        .item_size = sizeof(VECTOR(u8) const),
        .capacity = 3,
        .dummy_ = 0
    },
    .data = {
        (VECTOR(u8) const)&rsa_cert_1.data,
        (VECTOR(u8) const)&rsa_cert_2.data,
        (VECTOR(u8) const)&rsa_cert_3.data
    }
};

VECTOR(VECTOR(u8 const) const) const cert_chain_rsa =
    (const VECTOR(VECTOR(u8) const)) &rsa_cert_chain__.data;

const char *const cert_chain_rsa_top_issuer_serial =
    "dummy";
*/

const i64 cert_chain_rsa_not_after = 0;
