#define _GNU_SOURCE
#define SUS_CERT_SIGN_KEYBOX_INTERNAL_GUARD__
#include "keybox-internal.h"
#undef SUS_CERT_SIGN_KEYBOX_INTERNAL_GUARD__
#include "keybox.h"
#include <core/int.h>
#include <core/log.h>
#include <core/util.h>
#include <core/vector.h>
#include <libgenericutil/cert-types.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>

#define MODULE_NAME "keybox"

/* `check_*` functions */

static i32 check_header_intro(VECTOR(u8 const) data);

static i32 check_v1_header_data(const u8 *hdr_start, u64 data_size);

static i32 check_v1_content(const u8 *data_start,
        const struct keybox_v1_header_data *hdr);

static i32 check_v1_blob(const u8 *start, u64 total_size,
        enum keybox_v1_blob_type expected_type);

static i32 check_v1_cert_chain(const u8 *start,
        u64 total_size, u32 n_certs, enum sus_key_variant variant);
static i32 check_v1_key(const u8 *start, u64 size,
        enum sus_key_variant variant);
static i32 check_v1_issuer_title(const u8 *start, u64 size,
        enum sus_key_variant variant);
static i32 check_v1_issuer_serial(const u8 *start, u64 size,
        enum sus_key_variant variant);
static i32 check_v1_issuer_notafter(const u8 *start,
        enum sus_key_variant variant);


/* `copy_*` functions */

static void copy_v1_content(struct keybox *out,
        const u8 *data_start, const struct keybox_v1_header_data *hdr);

static void copy_v1_cert_chain(VECTOR(VECTOR(u8)) *out,
        u32 n_certs, const u8 *start);
static void copy_v1_simple_blob(VECTOR(u8) *out, const u8 *start);
static void copy_v1_notafter(u64 *out, const u8 *start);

/* functions used by `keybox_init` */
static i32 extract_issuer_cert_info(VECTOR(u8 const) cert,
        struct keybox_issuer_info *out);

/* functions used by `keybox_store` */

static inline void add_v1_blob(u64 *off_p, u64 *out_offset, u64 *out_size,
        VECTOR(u8 const) data);
static inline void add_v1_cert_chain(u64 *off_p, u64 *out_offset, u64 *out_size,
        VECTOR(VECTOR(u8 const) const) cert_chain);
static u64 populate_v1_header(struct keybox_v1_header_data *out,
        const struct keybox *kb);

static void write_v1_blob(VECTOR(u8) out, u64 offset, u64 size,
        VECTOR(u8) data, enum keybox_v1_blob_type type);
static void write_v1_cert_chain(VECTOR(u8) out, u64 offset, u64 size,
        VECTOR(VECTOR(u8)) cert_chain, enum sus_key_variant variant);

/* utility functions */

static bool range_intersects(u64 start1, u64 size1, u64 start2, u64 size2);
static bool range_contains(u64 big_start, u64 big_size,
        u64 small_start, u64 small_size);
static bool range_valid(u64 start, u64 size);


struct keybox * keybox_load(VECTOR(u8 const) data)
{
    struct keybox_file_header_intro intro = { 0 };
    struct keybox_v1_header_data hdr = { 0 };

    struct keybox *new = NULL;

    if (data == NULL) {
        s_log_error("Invalid parameters!");
        return NULL;
    }

    if (check_header_intro(data)) {
        s_log_error("Invalid header intro!");
        return NULL;
    }
    /** `intro` trusted **/
    memcpy(&intro, data, sizeof(struct keybox_file_header_intro));

    const u8 *const hdr_start = data + sizeof(intro);
    const u64 content_offset = sizeof(intro) + sizeof(hdr);
    const u64 content_size = intro.file_content_size;

    if (check_v1_header_data(hdr_start, content_size)) {
        s_log_error("Invalid/inconsistent v1 header data!");
        return NULL;
    }
    /** `hdr` trusted **/
    memcpy(&hdr, hdr_start, sizeof(struct keybox_v1_header_data));

    const u8 *content = data + content_offset;
    if (check_v1_content(content, &hdr)) {
        s_log_error("Invalid keybox content!");
        return NULL;
    }
    /** `content` trusted **/

    new = calloc(1, sizeof(struct keybox));
    if (new == NULL) {
        s_log_error("Couldn't allocate a new keybox struct");
        return NULL;
    }
    new->owns_buffers = true;

    copy_v1_content(new, content, &hdr);

    s_log_info("Succesfully loaded keybox data!");
    return new;
}

struct keybox * keybox_init(
        VECTOR(VECTOR(u8)) ec_cert_chain, VECTOR(u8) ec_key,
        VECTOR(VECTOR(u8)) rsa_cert_chain, VECTOR(u8) rsa_key,
        bool should_own)
{
    struct keybox *new = NULL;

    if (vector_size(ec_cert_chain) == 0 ||
            vector_size(rsa_cert_chain) == 0 ||
            vector_size(ec_key) == 0 || vector_size(rsa_key) == 0)
    {
        s_log_error("Invalid parameters: Unexpected NULL pointer/empty vector");
        return NULL;
    }
    for (u32 i = 0; i < vector_size(ec_cert_chain); i++) {
        if (vector_size(ec_cert_chain[i]) == 0){
            s_log_error("Invalid parameters: EC cert %u is zero", i);
            return NULL;
        }
    }
    for (u32 i = 0; i < vector_size(rsa_cert_chain); i++) {
        if (vector_size(rsa_cert_chain[i]) == 0){
            s_log_error("Invalid parameters: RSA cert %u is zero", i);
            return NULL;
        }
    }

    new = calloc(1, sizeof(struct keybox));
    if (new == NULL)
        goto_error("Couldn't allocate a new keybox struct");

    if (extract_issuer_cert_info(ec_cert_chain[0], &new->ec.issuer_info))
        goto_error("Failed to extract the EC issuer cert's info");

    if (extract_issuer_cert_info(ec_cert_chain[0], &new->rsa.issuer_info))
        goto_error("Failed to extract the RSA issuer cert's info");

    new->owns_buffers = should_own;
    if (!should_own) {
        new->ec.cert_chain = vector_new(VECTOR(u8));
        vector_resize(&new->ec.cert_chain, vector_size(ec_cert_chain));
        for (u32 i = 0; i < vector_size(ec_cert_chain); i++) {
            new->ec.cert_chain[i] = vector_clone(ec_cert_chain[i]);
        }

        new->rsa.cert_chain = vector_new(VECTOR(u8));
        vector_resize(&new->rsa.cert_chain, vector_size(rsa_cert_chain));
        for (u32 i = 0; i < vector_size(rsa_cert_chain); i++) {
            new->rsa.cert_chain[i] = vector_clone(rsa_cert_chain[i]);
        }

        new->ec.keyblob = vector_clone(ec_key);
        new->rsa.keyblob = vector_clone(rsa_key);
    } else {
        new->ec.cert_chain = ec_cert_chain;
        new->rsa.cert_chain = rsa_cert_chain;
        new->ec.keyblob = ec_key;
        new->rsa.keyblob = rsa_key;
    }

    return new;

err:
    keybox_destroy(&new);
    return NULL;
}

VECTOR(u8) keybox_store(const struct keybox *kb)
{
    VECTOR(u8) out = vector_new(u8);

    struct keybox_file_header_intro intro = { 0 };
    struct keybox_v1_header_data hdr = { 0 };

    memcpy(intro.magic, KEYBOX_FILE_MAGIC, sizeof(KEYBOX_FILE_MAGIC));
    intro.version = 1;
    intro.hdr_data_size = sizeof(struct keybox_v1_header_data);

    intro.file_content_size = populate_v1_header(&hdr, kb);

    const u64 total_size =
        sizeof(struct keybox_file_header_intro) +
        sizeof(struct keybox_v1_header_data) +
        intro.file_content_size;
    vector_resize(&out, total_size);

    memcpy(out, &intro, sizeof(intro));

    memcpy(out + sizeof(intro), &hdr, sizeof(hdr));
    const u64 B = sizeof(intro) + sizeof(hdr);

    /* for the notAfter blobs */
    VECTOR(u8) tmp = vector_new(u8);
    vector_resize(&tmp, sizeof(u64));

    write_v1_cert_chain(out, B + hdr.ec.cert_arr_offset, hdr.ec.cert_arr_size,
            kb->ec.cert_chain, SUS_KEY_EC);

    write_v1_blob(out, B + hdr.ec.key_offset, hdr.ec.key_size,
            kb->ec.keyblob, KEYBOX_V1_BLOB_TYPE_KEY_EC);

    write_v1_blob(out, B + hdr.ec.issuer_title_offset,
            hdr.ec.issuer_title_size, kb->ec.issuer_info.title,
            KEYBOX_V1_BLOB_TYPE_ISSUER_TITLE_EC);

    write_v1_blob(out, B + hdr.ec.issuer_serial_offset,
            hdr.ec.issuer_serial_size, kb->ec.issuer_info.serial,
            KEYBOX_V1_BLOB_TYPE_ISSUER_SERIAL_EC);

    memcpy(tmp, &kb->ec.issuer_info.not_after, KEYBOX_V1_ISSUER_NOTAFTER_SIZE);
    write_v1_blob(out, B + hdr.ec.issuer_notafter_offset,
            KEYBOX_V1_ISSUER_NOTAFTER_BLOB_SIZE, tmp,
            KEYBOX_V1_BLOB_TYPE_ISSUER_NOTAFTER_EC);


    write_v1_cert_chain(out, B + hdr.rsa.cert_arr_offset, hdr.rsa.cert_arr_size,
            kb->rsa.cert_chain, SUS_KEY_RSA);

    write_v1_blob(out, B + hdr.rsa.key_offset, hdr.rsa.key_size,
            kb->rsa.keyblob, KEYBOX_V1_BLOB_TYPE_KEY_RSA);

    write_v1_blob(out, B + hdr.rsa.issuer_title_offset,
            hdr.rsa.issuer_title_size, kb->rsa.issuer_info.title,
            KEYBOX_V1_BLOB_TYPE_ISSUER_TITLE_RSA);

    write_v1_blob(out, B + hdr.rsa.issuer_serial_offset,
            hdr.rsa.issuer_serial_size, kb->rsa.issuer_info.serial,
            KEYBOX_V1_BLOB_TYPE_ISSUER_SERIAL_RSA);

    memcpy(tmp, &kb->rsa.issuer_info.not_after, KEYBOX_V1_ISSUER_NOTAFTER_SIZE);
    write_v1_blob(out, B + hdr.rsa.issuer_notafter_offset,
            KEYBOX_V1_ISSUER_NOTAFTER_BLOB_SIZE, tmp,
            KEYBOX_V1_BLOB_TYPE_ISSUER_NOTAFTER_RSA);

    vector_destroy(&tmp);

    return out;
}

void keybox_destroy(struct keybox **kb_p)
{
    if (kb_p == NULL || *kb_p == NULL)
        return;

    struct keybox *const kb = *kb_p;

    if (kb->owns_buffers) {
        if (kb->ec.cert_chain != NULL) {
            for (u32 i = 0; i < vector_size(kb->ec.cert_chain); i++)
                vector_destroy(&kb->ec.cert_chain[i]);

            vector_destroy(&kb->ec.cert_chain);
        }

        if (kb->rsa.cert_chain != NULL) {
            for (u32 i = 0; i < vector_size(kb->rsa.cert_chain); i++)
                vector_destroy(&kb->rsa.cert_chain[i]);

            vector_destroy(&kb->rsa.cert_chain);
        }

        vector_destroy(&kb->ec.keyblob);
        vector_destroy(&kb->rsa.keyblob);

        kb->owns_buffers = false;
    } else {
        kb->ec.cert_chain = kb->rsa.cert_chain = NULL;
        kb->ec.keyblob = kb->rsa.keyblob = NULL;
    }

    vector_destroy(&kb->ec.issuer_info.title);
    vector_destroy(&kb->ec.issuer_info.serial);
    kb->ec.issuer_info.not_after = 0;

    vector_destroy(&kb->rsa.issuer_info.title);
    vector_destroy(&kb->rsa.issuer_info.serial);
    kb->rsa.issuer_info.not_after = 0;

    free(kb);
    *kb_p = NULL;
}

const struct keybox * keybox_get_builtin(void)
{
    static struct keybox *builtin_kb = NULL;
#define BUILTIN_KB_LOAD_MAX_TRIES 5
    static u32 builtin_kb_load_failcnt = 0;

    extern VECTOR(u8 const) suskeymaster_builtin_kb;
    if (suskeymaster_builtin_kb == NULL) {
        s_log_error("No built-in keybox in this suskeymaster!");
        return NULL;
    }

    if (builtin_kb == NULL) {
        if (builtin_kb_load_failcnt >= BUILTIN_KB_LOAD_MAX_TRIES) {
            s_log_error("Max number of builtin keybox load attempts exceeded");
            return NULL;
        }

        builtin_kb = keybox_load(suskeymaster_builtin_kb);
        if (builtin_kb == NULL) {
            builtin_kb_load_failcnt++;
            s_log_error("Failed to load the builtin keybox (new failcnt: %u)!",
                    builtin_kb_load_failcnt);
            return NULL;
        }

        s_log_info("Succesfully loaded builtin keybox after %u failed attempts",
                builtin_kb_load_failcnt);
    }

    return builtin_kb;
}

VECTOR(VECTOR(u8 const) const)
keybox_get_cert_chain(const struct keybox *kb, enum sus_key_variant key_type)
{
    if (kb == NULL || !(key_type > SUS_KEY_INVALID_ && key_type < SUS_KEY_MAX_))
    {
        s_log_error("Invalid parameters!");
        return NULL;
    }

    VECTOR(VECTOR(u8)) const ret =
        key_type == SUS_KEY_RSA ? kb->rsa.cert_chain : kb->ec.cert_chain;
    if (ret == NULL) {
        s_log_error("Cert chain is NULL (invalid keybox)!");
        return NULL;
    } else if (vector_size(ret) == 0) {
        s_log_error("Cert chain size is 0!");
        return NULL;
    }

    return (VECTOR(VECTOR(u8 const) const))ret;
}

VECTOR(u8 const) keybox_get_issuer_title(const struct keybox *kb,
        enum sus_key_variant key_type)
{
    if (kb == NULL || !(key_type > SUS_KEY_INVALID_ && key_type < SUS_KEY_MAX_))
    {
        s_log_error("Invalid parameters!");
        return NULL;
    }

    VECTOR(u8) ret = key_type == SUS_KEY_RSA ?
        kb->rsa.issuer_info.title :
        kb->ec.issuer_info.title;
    if (ret == NULL) {
        s_log_error("Cert title is NULL (invalid keybox)!");
        return NULL;
    }

    return (VECTOR(u8 const))ret;
}

VECTOR(u8 const) keybox_get_issuer_serial(const struct keybox *kb,
        enum sus_key_variant key_type)
{
    if (kb == NULL || !(key_type > SUS_KEY_INVALID_ && key_type < SUS_KEY_MAX_))
    {
        s_log_error("Invalid parameters!");
        return NULL;
    }

    VECTOR(u8) ret = key_type == SUS_KEY_RSA ?
        kb->rsa.issuer_info.serial :
        kb->ec.issuer_info.serial;
    if (ret == NULL) {
        s_log_error("Cert serial is NULL (invalid keybox)!");
        return NULL;
    }

    return (VECTOR(u8 const))ret;
}

i32 keybox_get_issuer_not_after(i64 *out, const struct keybox *kb,
        enum sus_key_variant key_type)
{
    if (out == NULL || kb == NULL ||
            !(key_type > SUS_KEY_INVALID_ && key_type < SUS_KEY_MAX_)
    ) {
        s_log_error("Invalid parameters!");
        return 1;
    }

    *out = (key_type == SUS_KEY_RSA) ?
        kb->rsa.issuer_info.not_after :
        kb->ec.issuer_info.not_after;
    return 0;
}

VECTOR(u8 const) keybox_get_keyblob(const struct keybox *kb,
        enum sus_key_variant key_type)
{
    if (kb == NULL || !(key_type > SUS_KEY_INVALID_ && key_type < SUS_KEY_MAX_))
    {
        s_log_error("Invalid parameters!");
        return NULL;
    }

    VECTOR(u8) ret = key_type == SUS_KEY_RSA ?
        kb->rsa.keyblob : kb->ec.keyblob;
    if (ret == NULL) {
        s_log_error("Key is NULL (invalid keybox)!");
        return NULL;
    }

    return (VECTOR(u8 const))ret;
}


/** `check_*` functions **/

#define set_error(...) do {     \
    ok = false;                 \
    s_log_error(__VA_ARGS__);   \
} while (0)

static i32 check_header_intro(VECTOR(u8 const) data)
{
    if (vector_size(data) < sizeof(struct keybox_file_header_intro)) {
        s_log_error("Data too small to contain a keybox file header intro!");
        return 1;
    }

    struct keybox_file_header_intro intro = { 0 };
    memcpy(&intro, data, sizeof(struct keybox_file_header_intro));
    bool ok = true;

    if (memcmp(intro.magic, KEYBOX_FILE_MAGIC, sizeof(KEYBOX_FILE_MAGIC)))
        set_error("Header magic mismatch!");

    if (intro.version != 1)
        set_error("Unsupported header version: %u", intro.version);

    if (intro.hdr_data_size != sizeof(struct keybox_v1_header_data))
        set_error("Invalid header data size %u for header version %u",
                intro.hdr_data_size, intro.version);

    const u64 data_offset =
        sizeof(struct keybox_file_header_intro) +
        sizeof(struct keybox_v1_header_data);
    if (vector_size(data) - data_offset < intro.file_content_size)
        set_error("Data too small to contain the full keybox file!");

    return ok ? 0 : 1;
}

static i32 check_v1_header_data(const u8 *hdr_start, u64 data_size)
{
    bool ok = true;

    struct keybox_v1_header_data hdr = { 0 };
    memcpy(&hdr, hdr_start, sizeof(struct keybox_v1_header_data));

    struct range {
        u64 start;
        u64 size;
        const char *name;
        bool valid;
    };
    struct range ranges[] = {
        /* EC blobs */
        {
            .start = hdr.ec.cert_arr_offset,
            .size = hdr.ec.cert_arr_size,
            .name = "EC cert chain"
        },
        {
            .start = hdr.ec.key_offset,
            .size = hdr.ec.key_size,
            .name = "EC key"
        },
        {
            .start = hdr.ec.issuer_title_offset,
            .size = hdr.ec.issuer_title_size,
            .name = "EC issuer cert title"
        },
        {
            .start = hdr.ec.issuer_serial_offset,
            .size = hdr.ec.issuer_serial_size,
            .name = "EC issuer cert serial"
        },
        {
            .start = hdr.ec.issuer_notafter_offset,
            .size = KEYBOX_V1_ISSUER_NOTAFTER_SIZE,
            .name = "EC issuer cert notAfter"
        },

        /* RSA blobs */
        {
            .start = hdr.rsa.cert_arr_offset,
            .size = hdr.rsa.cert_arr_size,
            .name = "RSA cert chain"
        },
        {
            .start = hdr.rsa.key_offset,
            .size = hdr.rsa.key_size,
            .name = "RSA key"
        },
        {
            .start = hdr.rsa.issuer_title_offset,
            .size = hdr.rsa.issuer_title_size,
            .name = "RSA issuer cert title"
        },
        {
            .start = hdr.rsa.issuer_serial_offset,
            .size = hdr.rsa.issuer_serial_size,
            .name = "RSA issuer cert serial"
        },
        {
            .start = hdr.rsa.issuer_notafter_offset,
            .size = KEYBOX_V1_ISSUER_NOTAFTER_SIZE,
            .name = "RSA issuer cert notAfter"
        },
    };

    for (u32 i = 0; i < u_arr_size(ranges); i++) {
        ranges[i].valid = range_valid(ranges[i].start, ranges[i].size);
        if (!ranges[i].valid)
            set_error("The %s offset & size are invalid!", ranges[i].name);
    }

    for (u32 i = 0; i < u_arr_size(ranges); i++) {
        if (!ranges[i].valid)
            continue;

        for (u32 j = i + 1; j < u_arr_size(ranges); j++) {
            if (!ranges[j].valid)
                continue;

            if (range_intersects(ranges[i].start, ranges[i].size,
                        ranges[j].start, ranges[j].size))
            {
                set_error("The %s and %s intersect",
                        ranges[i].name, ranges[j].name);
            }
        }
    }

    for (u32 i = 0; i < u_arr_size(ranges); i++) {
        if (!ranges[i].valid)
            continue;

        if (!range_contains(0, data_size,
                    ranges[i].start, ranges[i].size))
            set_error("The %s is not contained within the data", ranges[i].name);
    }

    return ok ? 0 : 1;
}

static i32 check_v1_content(const u8 *data_start,
        const struct keybox_v1_header_data *hdr)
{
    const struct {
        const char *name;
        enum sus_key_variant value;
        const struct keybox_v1_box *box;
    } variants[] = {
        { "EC", SUS_KEY_EC, &hdr->ec },
        { "RSA", SUS_KEY_RSA, &hdr->rsa }
    };

    bool ok = true;
    int r = 0;

    for (u32 i = 0; i < u_arr_size(variants); i++) {
        const struct keybox_v1_box *const b = variants[i].box;

        r = check_v1_cert_chain(data_start + b->cert_arr_offset,
                    b->cert_arr_size, b->number_of_certs, variants[i].value);
        if (r) {
            s_log_error("Invalid %s cert chain", variants[i].name);
            if (r < 0) return -1;
            else ok = false;
        }

        r = check_v1_key(data_start + b->key_offset,
                    b->key_size, variants[i].value);
        if (r) {
            s_log_error("Invalid %s key", variants[i].name);
            if (r < 0) return -1;
            else ok = false;
        }

        r = check_v1_issuer_title(data_start + b->issuer_title_offset,
                    b->issuer_title_size, variants[i].value);
        if (r) {
            s_log_error("Invalid %s issuer cert title",
                    variants[i].name);
            if (r < 0) return -1;
            else ok = false;
        }

        r = check_v1_issuer_serial(data_start + b->issuer_serial_offset,
                    b->issuer_serial_size, variants[i].value);
        if (r) {
            s_log_error("Invalid %s issuer cert serial number",
                    variants[i].name);
            if (r < 0) return -1;
            else ok = false;
        }

        r = check_v1_issuer_notafter(data_start + b->issuer_notafter_offset,
                    variants[i].value);
        if (r) {
            set_error("Invalid %s issuer cert notAfter value",
                    variants[i].name);
            if (r < 0) return -1;
            else ok = false;
        }
    }

    return ok ? 0 : 1;
}

static i32 check_v1_blob(const u8 *start, u64 total_size,
        enum keybox_v1_blob_type expected_type)
{
    bool ok = true;

    if (total_size < sizeof(struct keybox_v1_blob)) {
        s_log_error("Blob header truncated!");
        return -1;
    }

    struct keybox_v1_blob blob = { 0 };
    memcpy(&blob, start, sizeof(struct keybox_v1_blob));

    if (blob.type != expected_type)
        set_error("Blob type invalid (%u, expected %u)",
                blob.type, expected_type);

    const u64 expected_data_size = total_size - sizeof(struct keybox_v1_blob);
    if (blob.size != expected_data_size) {
        s_log_error("Blob size invalid (%llu, expected %llu)",
                (unsigned long long)blob.size,
                (unsigned long long)expected_data_size
        );
        return -1;
    }

    return ok ? 0 : 1;
}

static i32 check_v1_cert_chain(const u8 *start,
        u64 total_size, u32 n_certs, enum sus_key_variant variant)
{
    bool ok = true;
    const u8 *curr = (const u8 *)start;
    const u8 *const end = (const u8 *)start + total_size;

    const enum keybox_v1_blob_type expected_type =
        variant == SUS_KEY_EC ?
            KEYBOX_V1_BLOB_TYPE_CERT_EC :
            KEYBOX_V1_BLOB_TYPE_CERT_RSA;

    for (u32 i = 0; i < n_certs; i++) {
        u64 remaining = (u64)(end - curr);
        if (remaining == 0 && i < n_certs)
            set_error("Cert chain shorter than expected");

        /* Check that the header fits */
        if (remaining < sizeof(struct keybox_v1_blob)) {
            s_log_error("Cert no. %u header truncated", i);
            return -1;
        }

        struct keybox_v1_blob blob = { 0 };
        memcpy(&blob, curr, sizeof(struct keybox_v1_blob));

        if (blob.size == 0)
            set_error("Cert no. %u has zero size", i);

        /* Validate the blob type */
        if (blob.type != expected_type)
            set_error("Cert no. %u has invalid type (%u, expected %u)",
                i, blob.type, expected_type);

        /* Validate blob data bounds */
        u64 advance = sizeof(struct keybox_v1_blob) + blob.size;
        if (advance > remaining) {
            s_log_error("Cert no. %u overflows array!", i);
            return -1;
        }

        curr += advance;
    }

    if (curr != end) {
        s_log_error("Extra or missing data in the chain");
        return -1;
    }

    return ok ? 0 : 1;
}

static i32 check_v1_key(const u8 *start, u64 total_size,
        enum sus_key_variant variant)
{
    const enum keybox_v1_blob_type expected_type = variant == SUS_KEY_EC ?
        KEYBOX_V1_BLOB_TYPE_KEY_EC : KEYBOX_V1_BLOB_TYPE_KEY_RSA;

    return check_v1_blob(start, total_size, expected_type);
}

static i32 check_v1_issuer_title(const u8 *start, u64 total_size,
        enum sus_key_variant variant)
{
    const enum keybox_v1_blob_type expected_type = variant == SUS_KEY_EC ?
        KEYBOX_V1_BLOB_TYPE_ISSUER_TITLE_EC :
        KEYBOX_V1_BLOB_TYPE_ISSUER_TITLE_RSA;

    return check_v1_blob(start, total_size, expected_type);
}

static i32 check_v1_issuer_serial(const u8 *start, u64 total_size,
        enum sus_key_variant variant)
{
    const enum keybox_v1_blob_type expected_type = variant == SUS_KEY_EC ?
        KEYBOX_V1_BLOB_TYPE_ISSUER_SERIAL_EC :
        KEYBOX_V1_BLOB_TYPE_ISSUER_SERIAL_RSA;

    return check_v1_blob(start, total_size, expected_type);
}

static i32 check_v1_issuer_notafter(const u8 *start, enum sus_key_variant variant)
{
    const enum keybox_v1_blob_type expected_type = variant == SUS_KEY_EC ?
        KEYBOX_V1_BLOB_TYPE_ISSUER_NOTAFTER_EC :
        KEYBOX_V1_BLOB_TYPE_ISSUER_NOTAFTER_RSA;

    return check_v1_blob(start,
            KEYBOX_V1_ISSUER_NOTAFTER_BLOB_SIZE, expected_type);
}

#undef set_error

/** `copy_*` functions **/

static void copy_v1_content(struct keybox *out,
        const u8 *data_start, const struct keybox_v1_header_data *hdr)
{
    const struct variant {
        struct keybox_key *o;
        const struct keybox_v1_box *i;
    } variants[] = {
        { .o = &out->ec, .i = &hdr->ec },
        { .o = &out->rsa, .i = &hdr->rsa }
    };

    for (u32 i = 0; i < u_arr_size(variants); i++) {
        const struct variant *const v = &variants[i];

        copy_v1_cert_chain(&v->o->cert_chain,
                v->i->number_of_certs, data_start + v->i->cert_arr_offset);

        copy_v1_simple_blob(&v->o->keyblob,
                data_start + v->i->key_offset);

        copy_v1_simple_blob(&v->o->issuer_info.title,
                data_start + v->i->issuer_title_offset);

        copy_v1_simple_blob(&v->o->issuer_info.serial,
                data_start + v->i->issuer_serial_offset);

        copy_v1_notafter(&v->o->issuer_info.not_after,
                data_start + v->i->issuer_notafter_offset);
    }
}

static void copy_v1_cert_chain(VECTOR(VECTOR(u8)) *out,
        u32 n_certs, const u8 *start)
{
    *out = vector_new(VECTOR(u8));
    vector_resize(out, n_certs);

    const u8 *curr = start;
    struct keybox_v1_blob blob = { 0 };

    for (u32 i = 0; i < n_certs; i++) {
        memcpy(&blob, curr, sizeof(struct keybox_v1_blob));
        curr += sizeof(struct keybox_v1_blob);

        (*out)[i] = vector_new(u8);
        vector_resize(&((*out)[i]), blob.size);
        memcpy((*out)[i], curr, blob.size);
        curr += blob.size;
    }
}

static void copy_v1_simple_blob(VECTOR(u8) *out, const u8 *start)
{
    struct keybox_v1_blob blob = { 0 };
    memcpy(&blob, start, sizeof(struct keybox_v1_blob));

    *out = vector_new(u8);
    vector_resize(out, blob.size);
    memcpy(*out, start + sizeof(struct keybox_v1_blob), blob.size);
}

static void copy_v1_notafter(u64 *out, const u8 *start)
{
    struct keybox_v1_blob blob = { 0 };
    memcpy(&blob, start, sizeof(struct keybox_v1_blob));

    memcpy(out, start + sizeof(struct keybox_v1_blob), sizeof(u64));
}

/* functions used by `keybox_init` */

static i32 extract_issuer_cert_info(VECTOR(u8 const) cert,
        struct keybox_issuer_info *out)
{
    VECTOR(u8) ret_title = NULL;
    VECTOR(u8) ret_serial = NULL;
    X509* x509 = NULL;

    const ASN1_TIME *not_after_field = NULL;
    struct tm t = { 0 };
    time_t ret_notafter = 0;

    const X509_NAME *subject = NULL;

    int serial_idx = 0;
    const X509_NAME_ENTRY *serial_entry = NULL;
    const ASN1_STRING *serial_str = NULL;
    u64 serial_str_len = 0;

    int title_idx = 0;
    const X509_NAME_ENTRY *title_entry = NULL;
    const ASN1_STRING *title_str = NULL;
    u64 title_str_len = 0;

    out->serial = out->title = NULL;
    out->not_after = 0;

    const u8 *p = cert;
    bool ok = false;

    x509 = d2i_X509(NULL, &p, vector_size(cert));
    if (x509 == NULL)
        goto_error("Couldn't deserialize the X.509 certificate");

    /* Extract the notafter field */
    not_after_field = X509_get0_notAfter(x509);
    if (not_after_field == NULL)
        goto_error("Couldn't get the notAfter value of the certificate");

    if (ASN1_TIME_to_tm(not_after_field, &t) == 0)
        goto_error("Couldn't parse the ASN1 TIME structure");

    ret_notafter = timegm(&t);
    if (ret_notafter == (time_t)-1)
        goto_error("Couldn't convert the tm struct into time_t: %d (%s)",
                errno, strerror(errno));

    /* extract the title & serial number */
    subject = X509_get_subject_name(x509);
    if (subject == NULL)
        goto_error("Couldn't get the certificate's subject name");

    /* title */
    title_idx = X509_NAME_get_index_by_NID(subject, NID_title, -1);
    if (title_idx < 0)
        goto_error("Couldn't retrieve the title's index "
                "from the subject sequence");

    title_entry = X509_NAME_get_entry(subject, title_idx);
    if (title_entry == NULL)
        goto_error("Couldn't retrieve the title entry "
                "from the subject sequence");

    title_str = X509_NAME_ENTRY_get_data(title_entry);
    if (title_str == NULL)
        goto_error("Couldn't get the title string "
                "from the subject name entry");

    ret_title = vector_new(u8);
    title_str_len = ASN1_STRING_length(title_str);
    vector_resize(&ret_title, title_str_len);
    memcpy(ret_title, ASN1_STRING_get0_data(title_str), title_str_len);

    /* serial */
    serial_idx = X509_NAME_get_index_by_NID(subject, NID_serialNumber, -1);
    if (serial_idx < 0)
        goto_error("Couldn't retrieve the serial number's index "
                "from the subject sequence");

    serial_entry = X509_NAME_get_entry(subject, serial_idx);
    if (serial_entry == NULL)
        goto_error("Couldn't retrieve the serial number entry "
                "from the subject sequence");

    serial_str = X509_NAME_ENTRY_get_data(serial_entry);
    if (serial_str == NULL)
        goto_error("Couldn't get the serial number string "
                "from the subject name entry");


    ret_serial = vector_new(u8);
    serial_str_len = ASN1_STRING_length(serial_str);
    vector_resize(&ret_serial, serial_str_len);
    memcpy(ret_serial, ASN1_STRING_get0_data(serial_str), serial_str_len);

    ok = true;

err:
    serial_str_len = 0;
    serial_str = NULL;
    serial_entry = NULL;
    serial_idx = 0;
    subject = NULL;

    memset(&t, 0, sizeof(struct tm));
    not_after_field = NULL;

    if (x509 != NULL) {
        X509_free(x509);
        x509 = NULL;
    }

    if (!ok) {
        vector_destroy(&ret_serial);
        ret_notafter = 0;
        return 1;
    } else {
        out->title = ret_title;
        out->serial = ret_serial;
        out->not_after = ret_notafter;
        ret_title = ret_serial = NULL;
        ret_notafter = 0;
        return 0;
    }
}

/* functions used by `keybox_store` */

static inline void add_v1_blob(u64 *off_p, u64 *out_offset, u64 *out_size,
        VECTOR(u8 const) data)
{
    *out_offset = *off_p;
    *out_size = sizeof(struct keybox_v1_blob) + vector_size(data);
    *off_p += *out_size;
}

static inline void add_v1_cert_chain(u64 *off_p, u64 *out_offset, u64 *out_size,
        VECTOR(VECTOR(u8 const) const) cert_chain)
{
    *out_offset = *off_p;

    u64 sz = 0;
    for (u32 i = 0; i < vector_size(cert_chain); i++) {
        sz += sizeof(struct keybox_v1_blob);
        sz += vector_size(cert_chain[i]);
    }

    *out_size = sz;
    *off_p += sz;
}

static u64 populate_v1_header(struct keybox_v1_header_data *out,
        const struct keybox *kb)
{
    memcpy(out->magic, KEYBOX_V1_HEADER_MAGIC, sizeof(out->magic));

    u64 o = 0;

    /* We have to do everything indirectly like this to avoid
     * taking the address of a potentially unaligned ((packed)) struct member */
    u64 off, sz;

    out->ec.number_of_certs = vector_size(kb->ec.cert_chain);
    add_v1_cert_chain(&o, &off, &sz, (void *)kb->ec.cert_chain);
    out->ec.cert_arr_offset = off; out->ec.cert_arr_size = sz;
    add_v1_blob(&o, &off, &sz, kb->ec.keyblob);
    out->ec.key_offset = o; out->ec.key_size = sz;
    add_v1_blob(&o, &off, &sz, kb->ec.issuer_info.title);
    out->ec.issuer_title_offset = off; out->ec.issuer_title_size = sz;
    add_v1_blob(&o, &off, &sz, kb->ec.issuer_info.serial);
    out->ec.issuer_serial_offset = off; out->ec.issuer_serial_size = sz;
    out->ec.issuer_notafter_offset = o;
    o += KEYBOX_V1_ISSUER_NOTAFTER_BLOB_SIZE;

    out->rsa.number_of_certs = vector_size(kb->rsa.cert_chain);
    add_v1_cert_chain(&o, &off, &sz, (void *)kb->rsa.cert_chain);
    out->rsa.cert_arr_offset = off; out->rsa.cert_arr_size = sz;
    add_v1_blob(&o, &off, &sz, kb->rsa.keyblob);
    out->rsa.key_offset = o; out->rsa.key_size = sz;
    add_v1_blob(&o, &off, &sz, kb->rsa.issuer_info.title);
    out->rsa.issuer_title_offset = off; out->rsa.issuer_title_size = sz;
    add_v1_blob(&o, &off, &sz, kb->rsa.issuer_info.serial);
    out->rsa.issuer_serial_offset = off; out->rsa.issuer_serial_size = sz;
    out->rsa.issuer_notafter_offset = o;
    o += KEYBOX_V1_ISSUER_NOTAFTER_BLOB_SIZE;
    out->rsa.issuer_notafter_offset = o;
    o += KEYBOX_V1_ISSUER_NOTAFTER_BLOB_SIZE;

    return o;
}

static void write_v1_blob(VECTOR(u8) out, u64 offset, u64 size,
        VECTOR(u8) data, enum keybox_v1_blob_type type)
{
    struct keybox_v1_blob blob = { 0 };

    const u64 total = sizeof(blob) + vector_size(data);
    s_assert(size == total,
            "Impossible outcome - given & computed sizes don't match!");
    s_assert(offset + total <= vector_size(out),
            "Impossible outcome - new blob overflows buffer!");

    blob.size = vector_size(data);
    blob.type = type;

    memcpy(out + offset, &blob, sizeof(blob));
    memcpy(out + offset + sizeof(blob), data, vector_size(data));
}

static void write_v1_cert_chain(VECTOR(u8) out, u64 offset, u64 size,
        VECTOR(VECTOR(u8)) cert_chain, enum sus_key_variant variant)
{
    const enum keybox_v1_blob_type type = variant == SUS_KEY_EC ?
        KEYBOX_V1_BLOB_TYPE_CERT_EC : KEYBOX_V1_BLOB_TYPE_CERT_RSA;

    u64 s = 0;

    for (u32 i = 0; i < vector_size(cert_chain); i++) {
        const u64 blob_size = vector_size(cert_chain[i]) +
            sizeof(struct keybox_v1_blob);

        write_v1_blob(out, offset + s, blob_size, cert_chain[i], type);

        s += blob_size;
    }

    s_assert(s == size, "Wrote an incorrect amount of bytes "
            "(%llu, expected %llu)", s, size);
}

/** utility functions **/

static bool range_intersects(u64 start1, u64 size1, u64 start2, u64 size2)
{
    if (size1 == 0 || size2 == 0)
        return false;

    if (start1 <= start2)
        return start2 - start1 < size1;
    else
        return start1 - start2 < size2;
}

static bool range_contains(u64 big_start, u64 big_size,
                     u64 small_start, u64 small_size)
{
    if (small_size == 0)
        return true;

    if (big_size == 0)
        return false;

    if (small_start < big_start)
        return false;

    u64 offset = small_start - big_start;

    return offset <= big_size && small_size <= big_size - offset;
}

static bool range_valid(u64 start, u64 size)
{
    return size != 0 && start + size >= start;
}
