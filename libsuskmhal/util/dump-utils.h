#ifndef SUSKEYMASTER_KMHAL_UTIL_DUMP_H_
#define SUSKEYMASTER_KMHAL_UTIL_DUMP_H_

#include "keymaster-types-c.h"
#include <limits.h>

#ifdef __cplusplus
namespace suskeymaster {
namespace kmhal {
namespace util {
extern "C" {
#endif /* __cplusplus */

/** Welcome to macro hell! **/

#define KM_DUMP_INDENT_WIDTH 4
#define KM_DUMP_INDENT_CHAR ' '
#define KM_DUMP_SINGLE_INDENT "    "
#define KM_DUMP_sprint_indent(buf, n) do {                          \
    static_assert(sizeof((buf)) > KM_DUMP_INDENT_WIDTH * UINT8_MAX, \
            "Indentation buffer too small");                        \
    memset((buf), KM_DUMP_INDENT_CHAR, KM_DUMP_INDENT_WIDTH * (n)); \
    (buf)[KM_DUMP_INDENT_WIDTH * (n)] = '\0';                       \
} while (0)

/* A function that prints the printf-style `fmt` & varargs to some log output,
 * with a newline at the end of each line */
typedef void (*KM_dump_log_proc_t)(const char *fmt, ...);

#define KM_DUMP_FUNCTION_PROLOGUE(                                             \
        LOG_PROC, TYPE_NAME, DESCRIPTION,                                      \
        FIELD_NAME_PARAM, DEFAULT_FIELD_NAME, IS_DATA_NULL_COND,               \
        INDENT_BUF, NO_COMMA, OUT_STATEMENT                                    \
) do {                                                                         \
    if ((FIELD_NAME_PARAM) == NULL) {                                          \
        LOG_PROC("%s===== BEGIN " DESCRIPTION " DUMP =====", (INDENT_BUF));    \
                                                                               \
        if ((IS_DATA_NULL_COND)) {                                             \
            LOG_PROC("%s" #TYPE_NAME " par = { /* empty */ };", (INDENT_BUF)); \
            OUT_STATEMENT;                                                     \
        }                                                                      \
                                                                               \
        LOG_PROC("%s" #TYPE_NAME " " DEFAULT_FIELD_NAME " = {", (INDENT_BUF)); \
    } else {                                                                   \
        if ((IS_DATA_NULL_COND)) {                                             \
            LOG_PROC("%s.%s = { /* empty */ }%s",                              \
                    (INDENT_BUF), (FIELD_NAME_PARAM), (NO_COMMA) ? "" : ",");  \
            OUT_STATEMENT;                                                     \
        }                                                                      \
                                                                               \
        LOG_PROC("%s.%s = {", (INDENT_BUF), (FIELD_NAME_PARAM));               \
    }                                                                          \
} while (0)

#define KM_DUMP_FUNCTION_EPILOGUE(                                             \
        LOG_PROC, DESCRIPTION, FIELD_NAME_PARAM, INDENT_BUF, NO_COMMA          \
) do {                                                                         \
    if ((FIELD_NAME_PARAM) == NULL) {                                          \
        LOG_PROC("%s};", (INDENT_BUF));                                        \
        LOG_PROC("%s=====  END " DESCRIPTION " DUMP  =====", (INDENT_BUF));    \
    } else {                                                                   \
        log_proc("%s}%s", (INDENT_BUF), ((NO_COMMA) ? "" : ","));              \
    }                                                                          \
} while (0)

#define KM_DUMP_DECL_FUNCTION(FUNCTION_NAME, TYPE, PARAM_NAME)  \
    void FUNCTION_NAME(KM_dump_log_proc_t log_proc,             \
            const char *field_name, const TYPE *PARAM_NAME,     \
            uint8_t indent, bool end_without_comma)             \


KM_DUMP_DECL_FUNCTION(KM_dump_param_list, KM_PARAM_LIST, ps);

#define KM_DUMP_HEX_LINE_LEN 8
#define KM_DUMP_HEX_LINE_BUF_SIZE (KM_DUMP_HEX_LINE_LEN * 16)
void KM_sprint_hex_line(char *buf, u32 buf_size,
        const u8 *data, u32 data_size, bool end_without_comma);
KM_DUMP_DECL_FUNCTION(KM_dump_hex, ASN1_OCTET_STRING, data);

KM_DUMP_DECL_FUNCTION(KM_dump_u64, ASN1_INTEGER, a);
KM_DUMP_DECL_FUNCTION(KM_dump_u64_arr, ASN1_SET_OF_INTEGER, arr);

void KM_dump_enum_val(KM_dump_log_proc_t log_proc,
        const char *field_name, const ASN1_INTEGER *e,
        KM_enum_toString_proc_t get_str_proc,
        uint8_t indent, bool end_without_comma);
void KM_dump_enum_arr(KM_dump_log_proc_t log_proc,
        const char *field_name,
        const ASN1_SET_OF_INTEGER *arr,
        KM_enum_toString_proc_t get_str_proc,
        uint8_t indent, bool end_without_comma);

void KM_datetime_to_str(char *buf, u32 buf_size, int64_t dt);
KM_DUMP_DECL_FUNCTION(KM_dump_datetime, ASN1_INTEGER, datetime);

KM_DUMP_DECL_FUNCTION(KM_dump_root_of_trust, KM_ROOT_OF_TRUST_V3, rot);

#ifdef __cplusplus
} /* extern "C" */
} /* namespace util */
} /* namespace kmhal */
} /* namespace suskeymaster */
#endif /* __cplusplus */

#endif /* SUSKEYMASTER_KMHAL_UTIL_DUMP_H_ */
