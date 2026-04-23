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

void KM_dump_param_list(KM_dump_log_proc_t log_proc,
        const KM_PARAM_LIST *param_list,
        uint8_t indent, const char *field_name);

void KM_sprint_hex_line(char *buf, u32 buf_size,
        const u8 *data, u32 data_size, bool end_without_comma);
void KM_dump_hex(KM_dump_log_proc_t log_proc,
        const char *field_name,
        const ASN1_OCTET_STRING *data, uint8_t n_indent);

void KM_dump_u64_hex(KM_dump_log_proc_t log_proc,
        const char *field_name, const ASN1_INTEGER *u,
        uint8_t indent);
void KM_dump_u64(KM_dump_log_proc_t log_proc,
        const char *field_name, const ASN1_INTEGER *u,
        uint8_t indent);

void KM_dump_u64_arr(KM_dump_log_proc_t log_proc,
        const char *field_name, const ASN1_SET_OF_INTEGER *arr,
        uint8_t indent, bool hex);

void KM_dump_enum_val(KM_dump_log_proc_t log_proc,
        const char *field_name, const ASN1_INTEGER *e,
        KM_enum_toString_proc_t get_str_proc, uint8_t indent);

void KM_dump_enum_arr(KM_dump_log_proc_t log_proc,
        const char *field_name,
        const ASN1_SET_OF_INTEGER *arr, KM_enum_toString_proc_t get_str_proc,
        uint8_t indent);

void KM_dump_datetime(KM_dump_log_proc_t log_proc,
        const char *field_name, const ASN1_INTEGER *d, uint8_t indent);

void KM_datetime_to_str(char *buf, u32 buf_size, int64_t dt);

#ifdef __cplusplus
} /* extern "C" */
} /* namespace util */
} /* namespace kmhal */
} /* namespace suskeymaster */
#endif /* __cplusplus */

#endif /* SUSKEYMASTER_KMHAL_UTIL_DUMP_H_ */
