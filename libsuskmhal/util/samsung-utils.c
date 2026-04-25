#include "samsung-utils.h"
#include "dump-utils.h"
#include "keymaster-types-c.h"
#include <core/log.h>

#define MODULE_NAME "samsung-utils"

ASN1_SEQUENCE(KM_SAMSUNG_PARAM) = {
    ASN1_SIMPLE(KM_SAMSUNG_PARAM, tag, ASN1_INTEGER),
    ASN1_EXP_OPT(KM_SAMSUNG_PARAM, i, ASN1_INTEGER, 0),
    ASN1_EXP_OPT(KM_SAMSUNG_PARAM, b, ASN1_OCTET_STRING, 1)
} ASN1_SEQUENCE_END(KM_SAMSUNG_PARAM)
IMPLEMENT_ASN1_FUNCTIONS(KM_SAMSUNG_PARAM)

ASN1_SEQUENCE(KM_SAMSUNG_INDATA) = {
    ASN1_SIMPLE(KM_SAMSUNG_INDATA, ver, ASN1_INTEGER),
    ASN1_SIMPLE(KM_SAMSUNG_INDATA, km_ver, ASN1_INTEGER),
    ASN1_SIMPLE(KM_SAMSUNG_INDATA, cmd, ASN1_INTEGER),
    ASN1_SIMPLE(KM_SAMSUNG_INDATA, pid, ASN1_INTEGER),

    ASN1_EXP_OPT(KM_SAMSUNG_INDATA, int0, ASN1_INTEGER, 0),
    ASN1_EXP_OPT(KM_SAMSUNG_INDATA, long0, ASN1_INTEGER, 1),
    ASN1_EXP_OPT(KM_SAMSUNG_INDATA, long1, ASN1_INTEGER, 2),
    ASN1_EXP_OPT(KM_SAMSUNG_INDATA, bin0, ASN1_OCTET_STRING, 3),
    ASN1_EXP_OPT(KM_SAMSUNG_INDATA, bin1, ASN1_OCTET_STRING, 4),
    ASN1_EXP_OPT(KM_SAMSUNG_INDATA, bin2, ASN1_OCTET_STRING, 5),
    ASN1_EXP_OPT(KM_SAMSUNG_INDATA, key, ASN1_OCTET_STRING, 6),

    ASN1_EXP_SET_OF_OPT(KM_SAMSUNG_INDATA, par, KM_SAMSUNG_PARAM, 8)
} ASN1_SEQUENCE_END(KM_SAMSUNG_INDATA)
IMPLEMENT_ASN1_FUNCTIONS(KM_SAMSUNG_INDATA)

ASN1_SEQUENCE(KM_SAMSUNG_OUTDATA) = {
    ASN1_SIMPLE(KM_SAMSUNG_OUTDATA, ver, ASN1_INTEGER),
    ASN1_SIMPLE(KM_SAMSUNG_OUTDATA, cmd, ASN1_INTEGER),
    ASN1_SIMPLE(KM_SAMSUNG_OUTDATA, pid, ASN1_INTEGER),
    ASN1_SIMPLE(KM_SAMSUNG_OUTDATA, err, ASN1_INTEGER),

    ASN1_EXP_OPT(KM_SAMSUNG_OUTDATA, int0, ASN1_INTEGER, 0),
    ASN1_EXP_OPT(KM_SAMSUNG_OUTDATA, long0, ASN1_INTEGER, 1),
    ASN1_EXP_OPT(KM_SAMSUNG_OUTDATA, bin0, ASN1_OCTET_STRING, 2),
    ASN1_EXP_OPT(KM_SAMSUNG_OUTDATA, bin1, ASN1_OCTET_STRING, 3),
    ASN1_EXP_SET_OF_OPT(KM_SAMSUNG_OUTDATA, par, KM_SAMSUNG_PARAM, 4),

    ASN1_IMP_SEQUENCE_OF(KM_SAMSUNG_OUTDATA, log, ASN1_OCTET_STRING, 5)
} ASN1_SEQUENCE_END(KM_SAMSUNG_OUTDATA)
IMPLEMENT_ASN1_FUNCTIONS(KM_SAMSUNG_OUTDATA)

ASN1_SEQUENCE(KM_SAMSUNG_EKEY_BLOB) = {
    ASN1_SIMPLE(KM_SAMSUNG_EKEY_BLOB, enc_ver, ASN1_INTEGER),
    ASN1_SIMPLE(KM_SAMSUNG_EKEY_BLOB, ekey, ASN1_OCTET_STRING),
    ASN1_SET_OF(KM_SAMSUNG_EKEY_BLOB, enc_par, KM_SAMSUNG_PARAM)
} ASN1_SEQUENCE_END(KM_SAMSUNG_EKEY_BLOB)
IMPLEMENT_ASN1_FUNCTIONS(KM_SAMSUNG_EKEY_BLOB)

bool KM_samsung_is_integer_param(uint32_t tag)
{
    const enum KM_TagType tt = (enum KM_TagType)(__KM_TAG_TYPE_MASK(tag));
    return (tt != KM_TAG_TYPE_BYTES && tt != KM_TAG_TYPE_BIGNUM);
}

int KM_samsung_make_integer_param(KM_SAMSUNG_PARAM **out_par,
        uint32_t tag, int64_t val)
{
    *out_par = NULL;

    KM_SAMSUNG_PARAM *p = KM_SAMSUNG_PARAM_new();
    if (p == NULL) {
        s_log_error("Couldn't allocate a new samsung key parameter");
        return 1;
    }

    if (!ASN1_INTEGER_set(p->tag, (long)tag)) {
        s_log_error("Couldn't set the value of an ASN.1 INTEGER");
        KM_SAMSUNG_PARAM_free(p);
        return 1;
    }

    p->i = ASN1_INTEGER_new();
    if (p->i == NULL) {
        s_log_error("Couldn't allocate a new ASN.1 INTEGER");
        KM_SAMSUNG_PARAM_free(p);
        return 1;
    }

    if (!ASN1_INTEGER_set_int64(p->i, (long)val)) {
        s_log_error("Couldn't set the value of an ASN.1 INTEGER");
        KM_SAMSUNG_PARAM_free(p);
        return 1;
    }

    *out_par = p;
    return 0;
}

int KM_samsung_make_octet_string_param(KM_SAMSUNG_PARAM **out_par,
        uint32_t tag, const unsigned char *data, size_t len)
{
    *out_par = NULL;

    KM_SAMSUNG_PARAM *p = KM_SAMSUNG_PARAM_new();
    if (p == NULL) {
        s_log_error("Couldn't allocate a new samsung key parameter");
        return 1;
    }

    if (!ASN1_INTEGER_set(p->tag, (long)tag)) {
        s_log_error("Couldn't set the value of an ASN.1 INTEGER");
        KM_SAMSUNG_PARAM_free(p);
        return 1;
    }

    p->b = ASN1_INTEGER_new();
    if (p->b == NULL) {
        s_log_error("Couldn't allocate a new ASN.1 OCTET_STRING");
        KM_SAMSUNG_PARAM_free(p);
        return 1;
    }

    if (!ASN1_OCTET_STRING_set(p->b, data, len)) {
        s_log_error("Couldn't set the value of an ASN.1 OCTET_STRING");
        KM_SAMSUNG_PARAM_free(p);
        return 1;
    }

    *out_par = p;
    return 0;
}

int KM_samsung_push_param_or_free(STACK_OF(KM_SAMSUNG_PARAM) *paramset,
        KM_SAMSUNG_PARAM *par)
{
    if (sk_KM_SAMSUNG_PARAM_push(paramset, par) <= 0) {
        KM_SAMSUNG_PARAM_free(par);
        s_log_error("Failed to push a key parameter to the set");
        return 1;
    }

    return 0;
}

static const char * to_be_filled_in_by_libsuskeymaster(uint32_t val)
{
    (void) val;
    return "to be filled in by libsuskeymaster";
}
void KM_samsung_dump_indata(KM_dump_log_proc_t log_proc,
        const char *field_name, const KM_SAMSUNG_INDATA *indata,
        uint8_t indent, bool end_without_comma)
{
    char indent_buf[1024];
    const uint8_t i = indent + 1;

    KM_DUMP_sprint_indent(indent_buf, indent);

    KM_DUMP_FUNCTION_PROLOGUE(log_proc, KM_SAMSUNG_INDATA, "KM_INDATA",
            field_name, "indata", indata == NULL,
            indent_buf, end_without_comma, return);

    KM_dump_enum_val(log_proc, "ver", indata->ver,
            to_be_filled_in_by_libsuskeymaster, i, false);
    KM_dump_enum_val(log_proc, "km_ver", indata->km_ver,
            to_be_filled_in_by_libsuskeymaster, i, false);
    KM_dump_u64(log_proc, "cmd", indata->cmd, i, false);
    KM_dump_enum_val(log_proc, "pid", indata->pid,
            to_be_filled_in_by_libsuskeymaster, i, false);

    if (indata->int0) KM_dump_u64(log_proc, "int0", indata->int0, i, false);
    if (indata->long0) KM_dump_u64(log_proc, "long0", indata->long0, i, false);
    if (indata->long1) KM_dump_u64(log_proc, "long0", indata->long1, i, false);
    if (indata->bin0) KM_dump_hex(log_proc, "bin0", indata->bin0, i, false);
    if (indata->bin1) KM_dump_hex(log_proc, "bin1", indata->bin1, i, false);
    if (indata->bin2) KM_dump_hex(log_proc, "bin1", indata->bin2, i, false);
    if (indata->key) KM_dump_hex(log_proc, "key", indata->key, i, false);
    if (indata->par) {
        KM_PARAM_LIST *param_list = NULL;
        if (KM_samsung_paramset_to_param_list(indata->par, &param_list)) {
            s_log_error("Faield to convert samsung KM_PARAM set to a param list");
        } else {
            KM_dump_param_list(log_proc, "par", param_list, i, true);
            KM_PARAM_LIST_free(param_list);
        }
    }

    KM_DUMP_FUNCTION_EPILOGUE(log_proc, "KM_INDATA", field_name,
            indent_buf, end_without_comma);
}

void KM_samsung_dump_outdata(KM_dump_log_proc_t log_proc,
        const char *field_name, const KM_SAMSUNG_OUTDATA *outdata,
        uint8_t indent, bool end_without_comma)
{
    char indent_buf[1024];
    const uint8_t i = indent + 1;

    KM_DUMP_sprint_indent(indent_buf, indent);

    KM_DUMP_FUNCTION_PROLOGUE(log_proc, KM_SAMSUNG_OUTDATA, "KM_OUTDATA",
            field_name, "outdata", outdata == NULL,
            indent_buf, end_without_comma, return);

    KM_dump_u64(log_proc, "ver", outdata->ver, i, false);
    KM_dump_u64(log_proc, "cmd", outdata->cmd, i, false);
    KM_dump_u64(log_proc, "pid", outdata->pid, i, false);
    KM_dump_enum_val(log_proc, "err", outdata->err,
            KM_ErrorCode_toString, i, false);

    if (outdata->int0) KM_dump_u64(log_proc, "int0", outdata->int0, i, false);
    if (outdata->long0) KM_dump_u64(log_proc, "long0",
            outdata->long0, i, false);
    if (outdata->bin0) KM_dump_hex(log_proc, "bin0", outdata->bin0, i, false);
    if (outdata->bin1) KM_dump_hex(log_proc, "bin1", outdata->bin1, i, false);
    if (outdata->par) {
        KM_PARAM_LIST *param_list = NULL;
        if (KM_samsung_paramset_to_param_list(outdata->par, &param_list)) {
            s_log_error("Faield to convert samsung KM_PARAM set to a param list");
        } else {
            KM_dump_param_list(log_proc, "par", param_list, i,
                    outdata->log ? false : true);
            KM_PARAM_LIST_free(param_list);
        }
    }

    if (outdata->log) {
        log_proc("%s" KM_DUMP_SINGLE_INDENT" .log = {", indent_buf);
        int n_strs = sk_ASN1_OCTET_STRING_num(outdata->log);
        if (n_strs < 0) {
            log_proc("ERROR: Failed to get the number of OCTET_STRINGs "
                    "in the stack");
        } else {
            for (int i = 0; i < n_strs; i++) {
                const ASN1_OCTET_STRING *str =
                    sk_ASN1_OCTET_STRING_value(outdata->log, i);
                if (str == NULL) {
                    log_proc("ERROR: Failed to get an OCTET_STRING "
                            "from the stack");
                    return;
                }

                log_proc("%s" KM_DUMP_SINGLE_INDENT KM_DUMP_SINGLE_INDENT
                        "\"%s\"%s",
                        indent_buf,
                        (const char *)ASN1_STRING_get0_data(str),
                        (i < n_strs - 1) ? "," : "");
            }
        }
        log_proc("%s" KM_DUMP_SINGLE_INDENT "}", indent_buf);
    }

    KM_DUMP_FUNCTION_EPILOGUE(log_proc, "KM_OUTDATA", field_name,
            indent_buf, end_without_comma);
}

int KM_samsung_paramset_to_param_list(
        const STACK_OF(KM_SAMSUNG_PARAM) *ekey_params,
        KM_PARAM_LIST **out_param_list
)
{
    KM_PARAM_LIST *ret = NULL;
    int n_params = 0;

    ret = KM_PARAM_LIST_new();
    if (ret == NULL)
        goto_error("Failed to allocate a new param list");

    n_params = sk_KM_SAMSUNG_PARAM_num(ekey_params);
    if (n_params < 0)
        goto_error("Failed to get the number of parameters in the stack");

    for (int i = 0; i < n_params; i++) {
        const KM_SAMSUNG_PARAM *const curr =
            sk_KM_SAMSUNG_PARAM_value(ekey_params, i);
        if (curr == NULL)
            goto_error("Failed to retrieve a parameter from the stack");

        int64_t tag = 0;
        if (!ASN1_INTEGER_get_int64(&tag, curr->tag))
            goto_error("Failed to get the value of the parameter tag INTEGER");
        tag &= 0x00000000FFFFFFFF;

        /* Special handling for root of trust */
        if (tag == KM_TAG_ROOT_OF_TRUST) {
            if (curr->b == NULL || ASN1_STRING_length(curr->b) <= 0) {
                s_log_warn("Expected non-empty OCTET_STRING for ROOT_OF_TRUST; "
                        "not adding");
                continue;
            }

            const unsigned char *data = ASN1_STRING_get0_data(curr->b);
            const unsigned char *p = data;
            const int len = ASN1_STRING_length(curr->b);

            ret->rootOfTrust = d2i_KM_ROOT_OF_TRUST_V3(&ret->rootOfTrust,
                    &p, len);
            if (ret->rootOfTrust == NULL) {
                s_log_warn("Failed to parse the rootOfTrust SEQUENCE; not adding");
                continue;
            }

            if (p != data + len)
                goto_error("Parsed an incorrect number of bytes (delta: %lld)",
                        (long long int)(p - (data + len)));

            continue;
        }

        enum {
            TARGET_BOOL, TARGET_INTEGER, TARGET_INTEGER_SET, TARGET_OCTET_STRING
        } target_type;
        switch ((enum KM_TagType)__KM_TAG_TYPE_MASK(tag)) {
            case KM_TAG_TYPE_BOOL:
                target_type = TARGET_BOOL;
                break;
            case KM_TAG_TYPE_ENUM:
            case KM_TAG_TYPE_UINT:
            case KM_TAG_TYPE_ULONG:
            case KM_TAG_TYPE_DATE:
                target_type = TARGET_INTEGER;
                break;
            case KM_TAG_TYPE_ENUM_REP:
            case KM_TAG_TYPE_UINT_REP:
            case KM_TAG_TYPE_ULONG_REP:
                target_type = TARGET_INTEGER_SET;
                break;
            case KM_TAG_TYPE_BYTES:
            case KM_TAG_TYPE_BIGNUM:
                target_type = TARGET_OCTET_STRING;
                break;
            default:
            case KM_TAG_TYPE_INVALID:
                goto_error("Invalid keymaster tag: 0x%016llx",
                        (long long unsigned)tag);
        }

        union {
            ASN1_NULL **_NULL_;
            ASN1_INTEGER **_INTEGER_;
            ASN1_SET_OF_INTEGER **_SET_OF_INTEGER_;
            ASN1_OCTET_STRING **_OCTET_STRING_;

            KM_ROOT_OF_TRUST_V3 **_ROOT_OF_TRUST_V3_;

            void *v;
        } target;

        switch ((enum KM_Tag)tag) {
#define KM_DECL_TAG(name_, type, tag_val, param_list_field, bound_enum, asn1_type, asn1_rep)    \
            case KM_TAG_##name_: target.asn1_rep##asn1_type##_ = &ret->param_list_field; break;
        KM_TAG_LIST__
#undef KM_DECL_TAG
        default:
            goto_error("Unknown keymaster tag: 0x%08lx", (long unsigned)tag);
        }

        if (target_type == TARGET_OCTET_STRING && curr->b == NULL) {
            goto_error("Unexpected NULL OCTET_STRING value in tag 0x%08lx (%s)",
                    (long unsigned)tag, KM_Tag_toString((uint32_t)tag));
        } else if (target_type != TARGET_OCTET_STRING && curr->i == NULL) {
            goto_error("Unexpected NULL INTEGER value in tag 0x%08lx (%s)",
                    (long unsigned)tag, KM_Tag_toString((uint32_t)tag));
        }

        int64_t bval;
        ASN1_INTEGER *istmp;
        switch (target_type) {
        case TARGET_BOOL:
            if (!ASN1_INTEGER_get_int64(&bval, curr->i))
                goto_error("Failed to get the value of an ASN.1 INTEGER");

            bval &= 0x00000000FFFFFFFF;
            if (bval != 0) {
                if (*target._NULL_ != NULL) {
                    s_log_warn("Value already exists for tag 0x%08lx (%s); "
                            "not adding",
                            (long unsigned)tag, KM_Tag_toString((uint32_t)tag));
                    break;
                }

                *target._NULL_ = ASN1_NULL_new();
                if (*target._NULL_ == NULL)
                    goto_error("Failed allocate a new ASN.1 NULL");
            } else {
                s_log_warn("Not adding boolean value 0 to param list "
                        "(tag 0x%08lx - %s)",
                        (long unsigned)tag, KM_Tag_toString((uint32_t)tag));
            }
            break;

        case TARGET_INTEGER:
            if (*target._INTEGER_ != NULL) {
                s_log_warn("Value for INTEGER tag 0x%08lx (%s) already exists "
                        "with value 0x%08lx, freeing...",
                        (long unsigned) tag, KM_Tag_toString((uint32_t)tag),
                        (long unsigned)ASN1_INTEGER_get(*target._INTEGER_)
                );
                ASN1_INTEGER_free(*target._INTEGER_);
            }

            *target._INTEGER_ = ASN1_INTEGER_dup(curr->i);
            if (*target._INTEGER_ == NULL)
                goto_error("Failed to duplicate an ASN.1 INTEGER");
            break;

        case TARGET_INTEGER_SET:
            istmp = ASN1_INTEGER_dup(curr->i);
            if (istmp == NULL)
                goto_error("Failed to duplicate an ASN.1 INTEGER");

            if (*target._SET_OF_INTEGER_ == NULL) {
                *target._SET_OF_INTEGER_ = sk_ASN1_INTEGER_new_null();
                if (*target._SET_OF_INTEGER_ == NULL)
                    goto_error("Failed to create a new ASN.1 INTEGER set");
            }

            {
                bool found = false;
                const int n_ints = sk_ASN1_INTEGER_num(*target._SET_OF_INTEGER_);
                for (int i = 0; i < n_ints; i++) {
                    const ASN1_INTEGER *curr =
                        sk_ASN1_INTEGER_value(*target._SET_OF_INTEGER_, i);
                    if (!ASN1_INTEGER_cmp(curr, istmp)) {
                        s_log_warn("Repeatable tag 0x%08lx (%s) "
                                "with value 0x%08lx already exists; "
                                "not adding",
                                (long unsigned)tag,
                                KM_Tag_toString((uint32_t)tag),
                                (long unsigned)ASN1_INTEGER_get(curr)
                        );
                        found = true;
                        break;
                    }
                }
                if (found)
                    break;
            }

            if (sk_ASN1_INTEGER_push(*target._SET_OF_INTEGER_, istmp) <= 0)
                goto_error("Failed to push an ASN.1 INTEGER to the set");

            break;

        case TARGET_OCTET_STRING:
            if (*target._OCTET_STRING_ != NULL) {
                s_log_warn("Value for OCTET_STRING tag 0x%08lx (%s) "
                        "already exists; freeing...",
                        (long unsigned) tag, KM_Tag_toString((uint32_t)tag)
                );
                ASN1_OCTET_STRING_free(*target._OCTET_STRING_);
            }

            *target._OCTET_STRING_ = ASN1_OCTET_STRING_dup(curr->b);
            if (*target._OCTET_STRING_ == NULL)
                goto_error("Failed to duplicate an ASN.1 OCTET_STRING");
            break;
        }
    }

    *out_param_list = ret;
    return 0;

err:
    if (ret != NULL) {
        KM_PARAM_LIST_free(ret);
        ret = NULL;
    }

    *out_param_list = NULL;
    return 1;
}
