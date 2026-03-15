#ifndef SUS_CERT_SIGN_KEYBOX_INTERNAL_H_
#define SUS_CERT_SIGN_KEYBOX_INTERNAL_H_

#ifndef SUS_CERT_SIGN_KEYBOX_INTERNAL_GUARD__
#error This is an internal header, not intended for direct use by the application!
#endif /* SUS_CERT_SIGN_KEYBOX_INTERNAL_GUARD__ */

#include <core/int.h>
#include <core/vector.h>

#ifdef __cplusplus
namespace suskeymaster {
extern "C" {
#endif /* __cplusplus */

struct keybox_key {
    VECTOR(VECTOR(u8)) cert_chain;
    VECTOR(u8) keyblob;

    struct keybox_issuer_info {
        VECTOR(u8) title;
        VECTOR(u8) serial;
        u64 not_after;
    } issuer_info;
};
struct keybox {
    bool owns_buffers;
    struct keybox_key ec, rsa;
};

enum keybox_v1_blob_type {
    KEYBOX_V1_BLOB_TYPE_INVALID_,

    KEYBOX_V1_BLOB_TYPE_CERT_EC,
    KEYBOX_V1_BLOB_TYPE_CERT_RSA,
    KEYBOX_V1_BLOB_TYPE_KEY_EC,
    KEYBOX_V1_BLOB_TYPE_KEY_RSA,

    KEYBOX_V1_BLOB_TYPE_ISSUER_TITLE_EC,
    KEYBOX_V1_BLOB_TYPE_ISSUER_TITLE_RSA,
    KEYBOX_V1_BLOB_TYPE_ISSUER_SERIAL_EC,
    KEYBOX_V1_BLOB_TYPE_ISSUER_SERIAL_RSA,
    KEYBOX_V1_BLOB_TYPE_ISSUER_NOTAFTER_EC,
    KEYBOX_V1_BLOB_TYPE_ISSUER_NOTAFTER_RSA,

    KEYBOX_V1_BLOB_TYPE_MAX_
};
struct keybox_v1_blob {
    u32 type; /* enum keybox_v1_blob_type */
    u32 size;
    u8 data[];
};


#define KEYBOX_FILE_MAGIC "_SUSATTESTATION"
struct keybox_file_header {
    struct keybox_file_header_intro {
        u8 magic[sizeof(KEYBOX_FILE_MAGIC)];
        u32 version;
        u32 hdr_data_size;
        u32 file_content_size;
    } __attribute((packed)) intro;

    struct keybox_v1_header_data {
#define KEYBOX_V1_HEADER_MAGIC (u8[]){ 's', 'u', 's', 0x01 }
        u8 magic[4];

        struct keybox_v1_box {
            u32 number_of_certs;
            u64 cert_arr_offset;
            u64 cert_arr_size;

            u64 key_offset;
            u64 key_size;


            u64 issuer_title_offset;
            u64 issuer_title_size;

            u64 issuer_serial_offset;
            u64 issuer_serial_size;

            u64 issuer_notafter_offset;
#define KEYBOX_V1_ISSUER_NOTAFTER_SIZE (sizeof(u64))
#define KEYBOX_V1_ISSUER_NOTAFTER_BLOB_SIZE \
    (KEYBOX_V1_ISSUER_NOTAFTER_SIZE + sizeof(struct keybox_v1_blob))

        } ec, rsa;
    } data;
} __attribute((packed));

#ifdef __cplusplus
} /* extern "C" */
} /* namespace suskeymaster */
#endif /* __cplusplus */

#endif /* SUS_CERT_SIGN_KEYBOX_INTERNAL_H_ */
