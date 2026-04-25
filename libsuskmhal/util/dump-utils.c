#include "dump-utils.h"
#include "keymaster-types-c.h"
#include <core/math.h>
#include <openssl/asn1.h>

void KM_dump_param_list(KM_dump_log_proc_t log_proc,
        const char *field_name, const KM_PARAM_LIST *ps,
        uint8_t indent, bool end_without_comma)
{
    ASN1_INTEGER *bool_val_1 = NULL;

    bool_val_1 = ASN1_INTEGER_new();
    if (bool_val_1 == NULL || !ASN1_INTEGER_set(bool_val_1, 1)) {
        log_proc("ERROR: Failed to prepare temporary ASN.1 INTEGER");
        goto out;
    }

    char indent_buf[1024];
    KM_DUMP_sprint_indent(indent_buf, indent);
    const uint8_t i = indent + 1;

    KM_DUMP_FUNCTION_PROLOGUE(
            log_proc, KM_PARAM_LIST, "KEY PARAMETER LIST",
            field_name, "par", ps == NULL,
            indent_buf, end_without_comma, goto out
    );

    /* c++ devs gonna shit their pants when they see this one */


    /** Special handling for Tag::ROOT_OF_TRUST **/

    /* Since Tag::ROOT_OF_TRUST is TagType::BYTES, we must filter out
     * any call to dump_BYTES so that it doesn't include Tag::ROOT_OF_TRUST */

#define dump_BYTES_if_not_ROOT_OF_TRUST(tag, field_name, bound_enum)           \
    (void) _Generic(ps->field_name,                                            \
        KM_ROOT_OF_TRUST_V3 *: ((KM_dump_root_of_trust(log_proc,               \
                    "rootOfTrust", ps->rootOfTrust, i, false)), 0),            \
                                                                               \
        default: ((KM_dump_hex(log_proc, #field_name,                          \
                    (const ASN1_OCTET_STRING *)ps->field_name, i, false)), 0)  \
    )                                                                          \


#define dump_ENUM(tag, field_name, bound_enum) \
        KM_dump_enum_val(log_proc, #field_name, ps->field_name, \
                KM_##bound_enum##_toString, i, false)

#define dump_ENUM_REP(tag, field_name, bound_enum) \
        KM_dump_enum_arr(log_proc, #field_name, ps->field_name, \
                KM_##bound_enum##_toString, i, false)

#define dump_UINT(tag, field_name, bound_enum) \
        KM_dump_u64(log_proc, #field_name, ps->field_name, i, false)

#define dump_UINT_REP(tag, field_name, bound_enum) \
        KM_dump_u64_arr(log_proc, #field_name, ps->field_name, i, false)

#define dump_ULONG(tag, field_name, bound_enum) \
        KM_dump_u64(log_proc, #field_name, ps->field_name, i, false)

#define dump_DATE(tag, field_name, bound_enum) \
        KM_dump_datetime(log_proc, #field_name, ps->field_name, i, false)

#define dump_BOOL(tag, field_name, bound_enum) \
        KM_dump_u64(log_proc, #field_name, bool_val_1, i, false)

#define dump_BIGNUM(tag, field_name, bound_enum) \
        KM_dump_hex(log_proc, #field_name, ps->field_name, i, false)

#define dump_BYTES(tag, field_name, bound_enum) \
        dump_BYTES_if_not_ROOT_OF_TRUST(tag, field_name, bound_enum)

#define dump_ULONG_REP(tag, field_name, bound_enum) \
        KM_dump_u64_arr(log_proc, #field_name, ps->field_name, i, false)


#define KM_DECL_TAG(name, type, tag_val, param_list_field,          \
        bound_enum, asn1_type, asn1_rep) do {                       \
                                                                    \
    if (ps->param_list_field != NULL)                               \
        dump_##type(KM_TAG_##name, param_list_field, bound_enum);   \
                                                                    \
} while (0);

    KM_TAG_LIST__

#undef KM_DECL_TAG

#undef dump_ENUM
#undef dump_ENUM_REP
#undef dump_UINT
#undef dump_UINT_REP
#undef dump_ULONG
#undef dump_DATE
#undef dump_BOOL
#undef dump_BIGNUM
#undef dump_BYTES
#undef dump_ULONG_REP

    KM_DUMP_FUNCTION_EPILOGUE(log_proc, "KEY PARAMETER LIST", field_name,
            indent_buf, end_without_comma);

out:
    if (bool_val_1 != NULL) {
        ASN1_INTEGER_free(bool_val_1);
        bool_val_1 = NULL;
    }
    return;
}

void KM_dump_hex(KM_dump_log_proc_t log_proc, const char *field_name,
        const ASN1_OCTET_STRING *data_, uint8_t indent, bool end_without_comma)
{
    char indent_buf[1024];
    KM_DUMP_sprint_indent(indent_buf, indent);

    int total_sz = 0;
    const bool is_empty = (
            (data_ == NULL) ||
            (total_sz = ASN1_STRING_length(data_)) <= 0
    );

    KM_DUMP_FUNCTION_PROLOGUE(log_proc, u8 *, "HEX", field_name, "data",
            is_empty, indent_buf, end_without_comma, return);

    const unsigned char *data = ASN1_STRING_get0_data(data_);

    u32 n_lines = total_sz / KM_DUMP_HEX_LINE_LEN;
    u32 remainder = total_sz % KM_DUMP_HEX_LINE_LEN;
    if (remainder == 0) {
        n_lines--;
        remainder = KM_DUMP_HEX_LINE_LEN;
    }

    char line_buf[KM_DUMP_HEX_LINE_BUF_SIZE] = { 0 };

    if (n_lines > 0) {
        KM_sprint_hex_line(line_buf, KM_DUMP_HEX_LINE_BUF_SIZE, data,
                KM_DUMP_HEX_LINE_LEN, false);
        line_buf[KM_DUMP_HEX_LINE_BUF_SIZE - 1] = '\0';
        log_proc("%s" KM_DUMP_SINGLE_INDENT "%s", indent_buf, line_buf);
    }

    for (u32 i = 1; i < n_lines; i++) {
        memset(line_buf, 0, KM_DUMP_HEX_LINE_BUF_SIZE);
        KM_sprint_hex_line(line_buf, KM_DUMP_HEX_LINE_BUF_SIZE,
                data + (i * KM_DUMP_HEX_LINE_LEN),
                KM_DUMP_HEX_LINE_LEN, false
        );
        line_buf[KM_DUMP_HEX_LINE_BUF_SIZE - 1] = '\0';
        log_proc("%s" KM_DUMP_SINGLE_INDENT "%s", indent_buf, line_buf);
    }

    memset(line_buf, 0, KM_DUMP_HEX_LINE_BUF_SIZE);
    KM_sprint_hex_line(line_buf, KM_DUMP_HEX_LINE_BUF_SIZE,
            data + (n_lines * KM_DUMP_HEX_LINE_LEN),
            remainder, true
    );
    line_buf[KM_DUMP_HEX_LINE_BUF_SIZE - 1] = '\0';
    log_proc("%s" KM_DUMP_SINGLE_INDENT "%s", indent_buf, line_buf);

    KM_DUMP_FUNCTION_EPILOGUE(log_proc, "HEX", field_name,
            indent_buf, end_without_comma);
}

void KM_sprint_hex_line(char *buf, u32 buf_size,
        const u8 *data, u32 data_size, bool end_without_comma)
{
    for (u32 i = 0; i < u_min(buf_size, data_size); i++) {
        char byte_buf[8] = { 0 };
        int n = 0;
        if (end_without_comma && i == u_min(buf_size, data_size) - 1)
            n = snprintf(byte_buf, 8, "0x%02x", data[i]);
        else
            n = snprintf(byte_buf, 8, "0x%02x, ", data[i]);

        if (n <= 0 || n >= 8)
            continue;

        byte_buf[7] = '\0';
        (void) strncat(buf, byte_buf, u_min((u32)n, buf_size - i - 1));
    }
}

void KM_dump_u64(KM_dump_log_proc_t log_proc,
        const char *field_name, const ASN1_INTEGER *a,
        uint8_t indent, bool end_without_comma)
{
    uint64_t u = 0;
    if (ASN1_INTEGER_get_uint64(&u, a) == 0) {
        log_proc("[%s] ERROR: Couldn't get the value "
                "of an ASN.1 INTEGER (as uint64_t)", field_name);
        return;
    }

    {
        char indent_buf[1024];
        KM_DUMP_sprint_indent(indent_buf, indent);

        log_proc("%s.%s = %llu%s",
                indent_buf, field_name, (unsigned long long)u,
                end_without_comma ? "" : ",");
    }
}

void KM_dump_u64_arr(KM_dump_log_proc_t log_proc,
        const char *field_name, const ASN1_SET_OF_INTEGER *arr,
        uint8_t indent, bool end_without_comma)
{
    char indent_buf[1024];
    int arr_size = 0;

    const bool is_empty = (
            (arr == NULL) ||
            (arr_size = sk_ASN1_INTEGER_num(arr)) <= 0
    );
    KM_DUMP_sprint_indent(indent_buf, indent);

    KM_DUMP_FUNCTION_PROLOGUE(log_proc, "ASN1_SET_OF_INTEGER *", "U64 ARRAY",
            field_name, "arr", is_empty, indent_buf, end_without_comma, return);

    {
        const ASN1_INTEGER *curr = NULL;
        uint64_t u = 0;

        for (int i = 0; i < arr_size; i++) {
            curr = sk_ASN1_INTEGER_value(arr, i);
            if (ASN1_INTEGER_get_uint64(&u, curr) == 0) {
                log_proc("[%s] ERROR: Couldn't get the value "
                        "of an ASN.1 INTEGER (as uint64_t) @ idx %i",
                        field_name, i);
                return;
            }

            log_proc("%s" KM_DUMP_SINGLE_INDENT "%llu%s",
                    indent_buf, (unsigned long long)u,
                    i < arr_size - 1 ? "," : " ");
        }
    }

    KM_DUMP_FUNCTION_EPILOGUE(log_proc, "U64 ARRAY",
            field_name, indent_buf, end_without_comma);
}

void KM_dump_enum_val(KM_dump_log_proc_t log_proc,
        const char *field_name, const ASN1_INTEGER *e,
        KM_enum_toString_proc_t get_str_proc,
        uint8_t indent, bool end_without_comma)
{
    char indent_buf[1024];
    KM_DUMP_sprint_indent(indent_buf, indent);

    const int i = ASN1_INTEGER_get(e);

    log_proc("%s.%s = %d%s // %s", indent_buf, field_name,
            i, (end_without_comma ? "" : ","), get_str_proc(i));
}

void KM_dump_enum_arr(KM_dump_log_proc_t log_proc,
        const char *field_name,
        const ASN1_SET_OF_INTEGER *arr, KM_enum_toString_proc_t get_str_proc,
        uint8_t indent, bool end_without_comma)
{
    int arr_size = 0;
    char indent_buf[1024];

    KM_DUMP_sprint_indent(indent_buf, indent);
    const bool is_empty = (
            (arr == NULL) ||
            (arr_size = sk_ASN1_INTEGER_num(arr)) <= 0
    );

    KM_DUMP_FUNCTION_PROLOGUE(log_proc, "ASN1_SET_OF_INTEGER *",
            "KM ENUM ARRAY", field_name, "arr", is_empty,
            indent_buf, end_without_comma, return);

    for (int i = 0; i < arr_size; i++) {
        int64_t val = 0;
        if (ASN1_INTEGER_get_int64(&val, sk_ASN1_INTEGER_value(arr, i)) == 0) {
            log_proc("[%s] ERROR: Couldn't get the value of an ASN.1 INTEGER "
                    "(as int64_t) @ idx %i", field_name, i);
            return;
        }
        val &= 0x00000000FFFFFFFF;

        log_proc(KM_DUMP_SINGLE_INDENT "%s%lld%s // %s",
                indent_buf, (long long int)val,
                i < arr_size - 1 ? "," : " ", get_str_proc((int)val));
    }

    KM_DUMP_FUNCTION_EPILOGUE(log_proc, "KM ENUM ARRAY",
            field_name, indent_buf, end_without_comma);
}

void KM_dump_datetime(KM_dump_log_proc_t log_proc,
        const char *field_name, const ASN1_INTEGER *d,
        uint8_t indent, bool end_without_comma)
{
    char indent_buf[1024];
    char datetime_buf[256] = { 0 };
    int64_t i = 0;

    KM_DUMP_sprint_indent(indent_buf, indent);

    if (ASN1_INTEGER_get_int64(&i, d) == 0) {
        log_proc("[%s] ERROR: Couldn't get the value of an ASN.1 INTEGER "
                "(as int64_t)", field_name);
        return;
    }

    KM_datetime_to_str(datetime_buf, sizeof(datetime_buf), i);
    log_proc("%s.%s = %lld%s // %s", indent_buf, field_name,
            (long long int)i, (end_without_comma ? "" : ","), datetime_buf);
}

int portable_localtime(const time_t *timep, struct tm *result)
{
#ifdef _WIN32
    return localtime_s(result, timep);
#else
    return localtime_r(timep, result) ? 0 : -1;
#endif
}
void KM_datetime_to_str(char *buf, u32 buf_size, int64_t dt)
{
    struct tm t = { 0 };

    const time_t s = dt / 1000;

    i32 ms = (i32)(dt % 1000);
    if (ms < 1000) ms += 1000;

    if (portable_localtime(&s, &t)) {
        (void) snprintf(buf, buf_size, "N/A");
        return;
    }

    const u64 fmt1_len = strftime(buf, buf_size, "%Y-%m-%d %H:%M:%S", &t);
    if (fmt1_len == 0) {
        (void) snprintf(buf, buf_size, "N/A");
        return;
    }

    i32 r = snprintf(buf + fmt1_len, buf_size - fmt1_len, ".%03d", ms);
    if (r <= 0 || (u32)r >= buf_size - fmt1_len) {
        buf[fmt1_len] = '\0';
        return;
    }

    const u64 fmt2_len = strftime(
            buf + fmt1_len + (u32)r,
            buf_size - fmt1_len - (u32)r,
            " %Z", &t
    );
    if (fmt2_len == 0) {
        buf[fmt1_len + r] = '\0';
        return;
    }
}

void KM_dump_root_of_trust(KM_dump_log_proc_t log_proc,
        const char *field_name, const KM_ROOT_OF_TRUST_V3 *rot,
        uint8_t indent, bool end_without_comma)
{
    char indent_buf[1024];
    KM_DUMP_sprint_indent(indent_buf, indent);

    KM_DUMP_FUNCTION_PROLOGUE(log_proc, KM_ROOT_OF_TRUST, "ROOT OF TRUST",
            field_name, "rot", rot == NULL,
            indent_buf, end_without_comma, return);


    KM_dump_hex(log_proc, "verifiedBootKey", rot->verifiedBootKey,
            indent + 1, false);

    log_proc("%s" KM_DUMP_SINGLE_INDENT ".deviceLocked = %d,",
            indent_buf, rot->deviceLocked ? 1 : 0);

    int64_t val = 0ULL;
    if (!ASN1_ENUMERATED_get_int64(&val, rot->verifiedBootState)) {
        log_proc("ERROR: Failed to get the value of the verifiedBootState "
                "ASN.1 ENUMERATED field");
        return;
    } else {
        val &= 0x00000000FFFFFFFF;
        log_proc("%s" KM_DUMP_SINGLE_INDENT ".verifiedBootState = %lld, // %s",
                indent_buf, (long long int)val,
                KM_VerifiedBootState_toString((int)val)
        );
    }

    KM_dump_hex(log_proc, "verifiedBootHash", rot->verifiedBootHash,
            indent + 1, true);

    KM_DUMP_FUNCTION_EPILOGUE(log_proc, "ROOT OF TRUST", field_name,
            indent_buf, end_without_comma);
}
