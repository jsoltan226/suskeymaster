#ifndef SUSKEYMASTER_KMHAL_SAMSUNG_UTILS_H_
#define SUSKEYMASTER_KMHAL_SAMSUNG_UTILS_H_

#include "dump-utils.h"
#include "keymaster-types-c.h"
#include <stdbool.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct KM_samsung_param {
    ASN1_INTEGER *tag;
    ASN1_INTEGER *i;
    ASN1_OCTET_STRING *b;
} KM_SAMSUNG_PARAM;
DECLARE_ASN1_FUNCTIONS(KM_SAMSUNG_PARAM)
DEFINE_STACK_OF(KM_SAMSUNG_PARAM)
/* DECLARE_DUP_FUNCTION doesn't exist in boringssl */
__attribute__((unused))
static inline KM_SAMSUNG_PARAM * KM_SAMSUNG_PARAM_dup(const KM_SAMSUNG_PARAM *x)
{
    return (KM_SAMSUNG_PARAM *)ASN1_item_dup(
            (const ASN1_ITEM *)ASN1_ITEM_rptr(KM_SAMSUNG_PARAM),
            (void *)x
    );
}

typedef struct KM_samsung_indata {
    ASN1_INTEGER *ver;
    ASN1_INTEGER *km_ver;
    ASN1_INTEGER *cmd;
    ASN1_INTEGER *pid;

    ASN1_INTEGER *int0;
    ASN1_INTEGER *long0;
    ASN1_INTEGER *long1;
    ASN1_OCTET_STRING *bin0;
    ASN1_OCTET_STRING *bin1;
    ASN1_OCTET_STRING *bin2;
    ASN1_OCTET_STRING *key;

    STACK_OF(KM_SAMSUNG_PARAM) *par;
} KM_SAMSUNG_INDATA;
DECLARE_ASN1_FUNCTIONS(KM_SAMSUNG_INDATA)

typedef struct KM_samsung_outdata {
    ASN1_INTEGER *ver;
    ASN1_INTEGER *cmd;
    ASN1_INTEGER *pid;
    ASN1_INTEGER *err;

    ASN1_INTEGER *int0;
    ASN1_INTEGER *long0;
    ASN1_OCTET_STRING *bin0;
    ASN1_OCTET_STRING *bin1;
    STACK_OF(KM_SAMSUNG_PARAM) *par;

    STACK_OF(ASN1_OCTET_STRING) *log;
} KM_SAMSUNG_OUTDATA;
DEFINE_STACK_OF(ASN1_OCTET_STRING)
DECLARE_ASN1_FUNCTIONS(KM_SAMSUNG_OUTDATA)

typedef struct KM_samsung_ekey_blob {
    ASN1_INTEGER *enc_ver;
    ASN1_OCTET_STRING *ekey;
    STACK_OF(KM_SAMSUNG_PARAM) *enc_par;
} KM_SAMSUNG_EKEY_BLOB;
DECLARE_ASN1_FUNCTIONS(KM_SAMSUNG_EKEY_BLOB)

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#ifdef __cplusplus
namespace suskeymaster {
namespace kmhal {
namespace util {
extern "C" {
#endif /* __cplusplus */

bool KM_samsung_is_integer_param(uint32_t tag);

int KM_samsung_make_integer_param(KM_SAMSUNG_PARAM **out_par,
        uint32_t tag, int64_t val);

int KM_samsung_make_octet_string_param(KM_SAMSUNG_PARAM **out_par,
        uint32_t tag, const unsigned char *data, size_t len);

int KM_samsung_push_param_or_free(STACK_OF(KM_SAMSUNG_PARAM) *paramset,
        KM_SAMSUNG_PARAM *par);

void KM_samsung_dump_indata(KM_dump_log_proc_t log_proc,
        const KM_SAMSUNG_INDATA *indata, uint8_t indent,
        const char *field_name);

void KM_samsung_dump_outdata(KM_dump_log_proc_t log_proc,
        const KM_SAMSUNG_OUTDATA *outdata, uint8_t indent,
        const char *field_name);

int KM_samsung_paramset_to_param_list(
        const STACK_OF(KM_SAMSUNG_PARAM) *ekey_params,
        KM_PARAM_LIST **out_param_list
);

#ifdef __cplusplus
} /* extern "C" */
} /* namespace util */
} /* namespace kmhal */
} /* namespace suskeymaster */
#endif /* __cplusplus */

#endif /* SUSKEYMASTER_KMHAL_SAMSUNG_UTILS_H_ */
