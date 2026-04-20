#define HIDL_DISABLE_INSTRUMENTATION
#include "cli.hpp"
#include <core/log.h>
#include <core/math.h>
#include <core/util.h>
#include <libsuskmhal/hidl/hidl-hal.hpp>
#include <libsuskmhal/keymaster-types-c.h>
#include <libsuskmhal/util/samsung-sus-indata.hpp>
#include <android/hardware/keymaster/4.0/types.h>
#include <cstdlib>
#include <unordered_map>
#include <string.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/asn1t.h>
#include <openssl/crypto.h>
#include <openssl/safestack.h>

#define MODULE_NAME "samsung-utils"

namespace suskeymaster {
namespace cli {
namespace samsung {

using namespace kmhal;

static int serialize_indata(hidl_vec<uint8_t>& out,
        uint32_t *ver, uint32_t *km_ver, uint32_t cmd, uint32_t *pid,
        uint32_t *int0, uint64_t *long0, uint64_t *long1, const hidl_vec<uint8_t> *bin0,
        const hidl_vec<uint8_t> *bin1, const hidl_vec<uint8_t> *bin2,
        const hidl_vec<uint8_t> *key, const hidl_vec<KeyParameter> *par
);
static int deserialize_and_dump_outdata(hidl_vec<hidl_vec<uint8_t>> const& cert_chain);

static void dump_outdata(const KM_SAMSUNG_OUTDATA *o);

namespace ekey {

static bool is_repeatable(int64_t tag);
static bool is_integer_param(int64_t tag);
static int make_integer_param(KM_SAMSUNG_PARAM **out_par,
        Tag tag, int64_t val);
static int make_octet_string_param(KM_SAMSUNG_PARAM **out_par,
        Tag tag, hidl_vec<uint8_t> const& val);
static int push_param_or_free(STACK_OF(KM_SAMSUNG_PARAM) *paramset,
        KM_SAMSUNG_PARAM *par);

static int km_tag_cmp(KeyParameter const& kp, KM_SAMSUNG_PARAM *p);


static void dump_param_list(const KM_PARAM_LIST_SEQ *ps,
        uint8_t indent, const char *field_name);

#define INDENT_WIDTH 4
#define INDENT_CHAR ' '
#define SINGLE_INDENT "    "
#define sprint_indent(buf, n) do {                          \
    static_assert(sizeof((buf)) > INDENT_WIDTH * UINT8_MAX, \
            "Indentation buffer too small");                \
    memset((buf), INDENT_CHAR, INDENT_WIDTH * (n));         \
    (buf)[INDENT_WIDTH * (n)] = '\0';                       \
} while (0)

static void dump_hex_line(char *buf, u32 buf_size,
        const u8 *data, u32 data_size, bool end_without_comma);

static void dump_hex(const char *field_name,
        const ASN1_OCTET_STRING *data, uint8_t n_indent);

#define DUMP_U64_HEX true
static void dump_u64(const char *field_name, const ASN1_INTEGER *u,
        uint8_t indent, bool hex);
static void dump_u64(const char *field_name, const ASN1_INTEGER *u,
        uint8_t indent)
{
    dump_u64(field_name, u, indent, false);
}

static void dump_u64_arr(const char *field_name, const ASN1_SET_OF_INTEGER *arr,
        uint8_t indent, bool hex);

static void dump_enum_val(const char *field_name, const ASN1_INTEGER *e,
        KM_enum_toString_proc_t get_str_proc, uint8_t indent);

static void dump_enum_arr(const char *field_name,
        const ASN1_SET_OF_INTEGER *arr, KM_enum_toString_proc_t get_str_proc,
        uint8_t indent);

static void dump_datetime(const char *field_name, const ASN1_INTEGER *d,
        uint8_t indent);

static void datetime_to_str(char *buf, u32 buf_size, int64_t dt);

static int deserialize_ekey_blob_and_params(const hidl_vec<uint8_t>& ekey,
        KM_SAMSUNG_EKEY_BLOB *& out, hidl_vec<KM_SAMSUNG_PARAM *> *out_opt_par);
static int serialize_ekey_blob(KM_SAMSUNG_EKEY_BLOB *& ekey,
        hidl_vec<uint8_t>& out_ekey_der);

static int ekey_params_to_param_list(const hidl_vec<KM_SAMSUNG_PARAM *>& ekey_params,
        KM_PARAM_LIST_SEQ **out_param_list);


int list_tags(const hidl_vec<uint8_t> &in_keyblob)
{
    int ret = -1;

    KM_SAMSUNG_EKEY_BLOB *ekey = NULL;
    hidl_vec<KM_SAMSUNG_PARAM *> ekey_params;

    KM_PARAM_LIST_SEQ *param_list = NULL;

    if (deserialize_ekey_blob_and_params(in_keyblob, ekey, &ekey_params))
        goto_error("Failed to deserialize the encrypted key blob!");

    if (ekey_params_to_param_list(ekey_params, &param_list))
        goto_error("Failed to parse the key blob parameters!");

    dump_param_list(param_list, 0, NULL);
    ret = 0;

err:
    if (param_list != NULL) {
        KM_PARAM_LIST_SEQ_free(param_list);
        param_list = NULL;
    }

    for (size_t i = 0; i < ekey_params.size(); i++) {
        KM_SAMSUNG_PARAM_free(ekey_params[i]);
        ekey_params[i] = NULL;
    }
    if (ekey != NULL) {
        KM_SAMSUNG_EKEY_BLOB_free(ekey);
        ekey = NULL;
    }

    return ret;
}

int add_tags(const hidl_vec<uint8_t> &in_keyblob,
        const hidl_vec<KeyParameter> &in_tags_to_add, hidl_vec<uint8_t> &out_keyblob)
{
    int ret = 1;
    KM_SAMSUNG_PARAM * curr = NULL;

    KM_SAMSUNG_EKEY_BLOB *ekey = NULL;
    hidl_vec<KM_SAMSUNG_PARAM *> blob_params;
    std::unordered_map<int64_t, std::vector<KM_SAMSUNG_PARAM *>> blob_params_map;

    if (deserialize_ekey_blob_and_params(in_keyblob, ekey, &blob_params))
        goto_error("Couldn't deserialize the encrypted key blob");

    for (uint32_t i = 0; i < blob_params.size(); i++) {
        KM_SAMSUNG_PARAM *par = blob_params[i];

        int64_t t = 0;
        if (!ASN1_INTEGER_get_int64(&t, par->tag))
            goto_error("Couldn't get the value of an ASN.1 INTEGER");
        t &= 0x00000000FFFFFFFF;

        blob_params_map[t].push_back(par);
    }

    for (const auto& kp : in_tags_to_add) {
        const int64_t t = static_cast<int64_t>(kp.tag);

        const auto& found = blob_params_map.find(t);
        const bool exists = found != blob_params_map.end()
            && found->second.size() > 0;

        if (exists) {
            if (is_repeatable(t)) {
                bool skip_adding = false;
                for (const KM_SAMSUNG_PARAM *curr : found->second) {
                    int64_t val = 0;
                    /* repeatable also means it's not an OCTET_STRING */
                    if (!ASN1_INTEGER_get_int64(&val, curr->i))
                        goto_error("Couldn't get the value of an ASN.1 INTEGER");
                    val &= 0x00000000FFFFFFFF;

                    if (val == static_cast<int64_t>(kp.f.longInteger)) {
                        skip_adding = true;
                        break;
                    }
                }

                if (!skip_adding) {
                    KM_SAMSUNG_PARAM *new_par = NULL;
                    s_log_info("Repeatable tag 0x%08lx (%s): adding value: 0x%016llx",
                            (long unsigned)kp.tag, KM_Tag_toString((uint32_t)kp.tag),
                            (long long unsigned)kp.f.longInteger);

                    if (make_integer_param(&new_par, kp.tag, kp.f.longInteger))
                        goto err;

                    if (push_param_or_free(ekey->enc_par, new_par))
                        goto err;
                } else {
                    s_log_warn("Repeatable tag 0x%08lx (%s) with value 0x%016llx "
                            "already exists; not adding",
                            (long unsigned)kp.tag, KM_Tag_toString((uint32_t)kp.tag),
                            (long long unsigned)kp.f.longInteger);
                }
            } else {
                KM_SAMSUNG_PARAM *p = found->second[0];
                if (is_integer_param(t)) {
                    s_log_info("Tag 0x%08lx (%s): changing integer value: 0x%016llx",
                            (long unsigned)kp.tag, KM_Tag_toString((uint32_t)kp.tag),
                            (long long unsigned)kp.f.longInteger);

                    if (!ASN1_INTEGER_set_int64(p->i, kp.f.longInteger))
                        goto_error("Failed to set the value of an ASN.1 INTEGER");
                } else {
                    s_log_info("Tag 0x%08lx (%s): changing octet string value...",
                            (long unsigned)kp.tag, KM_Tag_toString((uint32_t)kp.tag));

                    if (!ASN1_OCTET_STRING_set(p->b, kp.blob.data(), kp.blob.size()))
                        goto_error("Failed to set the value of an ASN.1 OCTET_STRING");
                }
            }
        } else {
            KM_SAMSUNG_PARAM *new_par = NULL;

            if (is_integer_param(t)) {
                s_log_info("Adding tag 0x%08lx (%s) with integer value: 0x%016llx",
                        (long unsigned)kp.tag, KM_Tag_toString((uint32_t)kp.tag),
                        (long long unsigned)kp.f.longInteger);

                if (make_integer_param(&new_par, kp.tag, kp.f.longInteger))
                    goto err;
            } else {
                s_log_info("Adding tag 0x%08lx (%s) with octet string value...",
                        (long unsigned)kp.tag, KM_Tag_toString((uint32_t)kp.tag));

                if (make_octet_string_param(&new_par, kp.tag, kp.blob))
                    goto err;
            }

            if (push_param_or_free(ekey->enc_par, new_par))
                goto err;
        }
    }

    if (serialize_ekey_blob(ekey, out_keyblob))
        goto_error("Couldn't serialize the new encrypted key blob!");

    s_log_info("Successfully serialized new encrypted key blob");

    ret = 0;

err:
    if (curr != NULL) {
        KM_SAMSUNG_PARAM_free(curr);
        curr = NULL;
    }

    for (KM_SAMSUNG_PARAM *&par : blob_params) {
        KM_SAMSUNG_PARAM_free(par);
        par = NULL;
    }

    if (ekey != NULL) {
        KM_SAMSUNG_EKEY_BLOB_free(ekey);
        ekey = NULL;
    }

    return ret;
}

int del_tags(const hidl_vec<uint8_t> &in_keyblob,
        const hidl_vec<KeyParameter> &in_tags_to_del, hidl_vec<uint8_t> &out_keyblob)
{
    KM_SAMSUNG_EKEY_BLOB *ekey = NULL;
    int ret = 1;

    if (deserialize_ekey_blob_and_params(in_keyblob, ekey, nullptr))
        goto_error("Failed to deserialize the encrypted key blob");

    for (const auto& kp : in_tags_to_del) {
        bool found = false;
        for (int i = sk_KM_SAMSUNG_PARAM_num(ekey->enc_par) - 1; i >= 0; i--) {
            KM_SAMSUNG_PARAM *p =
                sk_KM_SAMSUNG_PARAM_value(ekey->enc_par, i);
            if (p == NULL)
                goto_error("Couldn't get the value of an encryption parameter");

            const int64_t t = static_cast<int64_t>(kp.tag);
            if (!km_tag_cmp(kp, p)) {
                if (is_integer_param(t)) {
                    uint64_t v;
                    if (!ASN1_INTEGER_get_uint64(&v, p->i))
                        goto_error("Couldn't get the value "
                                "of an ASN.1 INTEGER");

                    s_log_info("Deleting tag 0x%08lx (%s) "
                            "(with INTEGER value 0x%llx)...",
                            (long unsigned)t, KM_Tag_toString((uint32_t)t),
                            (long long unsigned)v
                    );
                } else {
                    s_log_info("Deleting tag 0x%08lx (%s) "
                            "(with OCTET_STRING value)...",
                            (long unsigned)t, KM_Tag_toString((uint32_t)t)
                    );
                }

                KM_SAMSUNG_PARAM *const removed =
                    sk_KM_SAMSUNG_PARAM_delete(ekey->enc_par, i);
                if (removed == NULL)
                    goto_error("Failed to delete tag @ idx %i", i);
                KM_SAMSUNG_PARAM_free(removed);

                found = true;
                break;
            }
        }
        if (!found) {
            const int64_t t = static_cast<int64_t>(kp.tag);
            if (is_repeatable(t)) {
                s_log_warn("No repeatable tag 0x%08lx (%s) "
                        "with the value 0x%08lx was found!",
                        (long unsigned)t, KM_Tag_toString((uint32_t)kp.tag),
                       (long unsigned)kp.f.longInteger);
            } else {
                s_log_warn("No tag 0x%08lx (%s) was found!",
                        (long unsigned)t, KM_Tag_toString((uint32_t)t));
            }
        }
    }

    if (serialize_ekey_blob(ekey, out_keyblob))
        goto_error("Failed to serialize the new encrypted key blob");

    s_log_info("Successfully serialized new encrypted key blob");
    ret = EXIT_SUCCESS;

err:
    if (ekey != NULL) {
        KM_SAMSUNG_EKEY_BLOB_free(ekey);
        ekey = NULL;
    }

    return ret;
}

} /* namespace ekey */

int send_indata(HidlSusKeymaster4& hal,
        uint32_t *ver, uint32_t *km_ver, uint32_t cmd, uint32_t *pid,
        uint32_t *int0, uint64_t *long0, uint64_t *long1, const hidl_vec<uint8_t> *bin0,
        const hidl_vec<uint8_t> *bin1, const hidl_vec<uint8_t> *bin2,
        const hidl_vec<uint8_t> *key, const hidl_vec<KeyParameter> *par)
{
    hidl_vec<uint8_t> tmp_keyblob;
    {
        hidl_vec<KeyParameter> partmp(1);
        partmp[0].tag = Tag::ALGORITHM;
        partmp[0].f.algorithm = Algorithm::EC;

        /* the hal_ops::generate_key wrapper will automatically fill in the
         * required default generation parameters */
        if (cli::hal_ops::generate_key(hal, partmp, tmp_keyblob)) {
            s_log_error("Failed to generate the ephemeral attested keyblob");
            return 1;
        }
    }

    hidl_vec<hidl_vec<uint8_t>> cert_chain;
    {
        hidl_vec<uint8_t> indata_der;
        if (serialize_indata(indata_der, ver, km_ver, cmd, pid,
                    int0, long0, long1, bin0, bin1, bin2, key, par))
        {
            s_log_error("Failed to serialize KM_INDATA");
            return 1;
        }

        hidl_vec<KeyParameter> partmp(2);
        partmp[0].tag = Tag::ATTESTATION_CHALLENGE;
        partmp[0].blob = hidl_vec<uint8_t>(
            certmod::g_send_indata_att_challenge,
            certmod::g_send_indata_att_challenge + certmod::g_send_indata_att_challenge_len
        );
        partmp[1].tag = Tag::ATTESTATION_APPLICATION_ID;
        partmp[1].blob = indata_der;

        ErrorCode e = hal.attestKey(tmp_keyblob, partmp, cert_chain);
        if (e != ErrorCode::OK) {
            s_log_error("Failed to attest the ephemeral key: %d (%s)",
                    static_cast<int>(e), toString(e).c_str());
            return 1;
        }
    }

    int r = deserialize_and_dump_outdata(cert_chain);
    if (r < 0) {
        s_log_error("Failed to deserialize & dump the returned KM_OUTDATA");
        return 1;
    } else if (r > 0) {
        s_log_error("KM_INDATA raw request failed");
        return 1;
    }

    s_log_info("KM_INDATA raw request OK");
    return 0;
}

static int serialize_indata(hidl_vec<uint8_t>& out,
        uint32_t *ver, uint32_t *km_ver, uint32_t cmd, uint32_t *pid,
        uint32_t *int0, uint64_t *long0, uint64_t *long1, const hidl_vec<uint8_t> *bin0,
        const hidl_vec<uint8_t> *bin1, const hidl_vec<uint8_t> *bin2,
        const hidl_vec<uint8_t> *key, const hidl_vec<KeyParameter> *par
)
{
    KM_SAMSUNG_INDATA *indata = NULL;
    unsigned char *indata_der = NULL;
    long indata_der_len = 0;

    indata = KM_SAMSUNG_INDATA_new();
    if (indata == NULL)
        goto_error("Couldn't allocate a new INDATA struct");

    /* Mandatory fields (except for `cmd`) are either specified here
     * or left to be filled out by libsuskeymaster */

    if (ver && !ASN1_INTEGER_set(indata->ver, (long)*ver)) {
        goto_error("Failed to set the INDATA blob version INTEGER");
    } else if (!ver) {
        if (indata->ver == NULL && (indata->ver = ASN1_INTEGER_new()) == NULL)
            goto_error("Failed to allocate a new ASN.1 INTEGER");

        if (!ASN1_INTEGER_set(indata->ver, 0))
            goto_error("Failed to set the value of an ASN.1 INTEGER");
    }

    if (km_ver && !ASN1_INTEGER_set(indata->km_ver, (long)*km_ver)) {
        goto_error("Failed to set the INDATA skeymaster version INTEGER");
    } else if (!km_ver && indata->km_ver != NULL) {
        if (indata->km_ver == NULL && (indata->km_ver = ASN1_INTEGER_new()) == NULL)
            goto_error("Failed to allocate a new ASN.1 INTEGER");

        if (!ASN1_INTEGER_set(indata->km_ver, 0))
            goto_error("Failed to set the value of an ASN.1 INTEGER");
    }

    if (!ASN1_INTEGER_set(indata->cmd, (long)cmd))
        goto_error("Failed to set the INDATA command INTEGER");

    if (pid && !ASN1_INTEGER_set(indata->pid, (long)*pid)) {
        goto_error("Failed to set the INDATA HAL process ID field");
    } else if (!pid && indata->pid != NULL) {
        if (indata->pid == NULL && (indata->pid = ASN1_INTEGER_new()) == NULL)
            goto_error("Failed to allocate a new ASN.1 INTEGER");

        if (!ASN1_INTEGER_set(indata->pid, 0))
            goto_error("Failed to set the value of an ASN.1 INTEGER");
    }

    /* Optional fields are all either set here or left as NULL */
    if (indata->int0 != NULL) { ASN1_INTEGER_free(indata->int0); indata->int0 = NULL; }
    if (indata->long0 != NULL) { ASN1_INTEGER_free(indata->long0); indata->long0 = NULL; }
    if (indata->long1 != NULL) { ASN1_INTEGER_free(indata->long1); indata->long1 = NULL; }
    if (indata->bin0 != NULL) { ASN1_OCTET_STRING_free(indata->bin0); indata->bin0 = NULL; }
    if (indata->bin1 != NULL) { ASN1_OCTET_STRING_free(indata->bin1); indata->bin1 = NULL; }
    if (indata->bin2 != NULL) { ASN1_OCTET_STRING_free(indata->bin2); indata->bin2 = NULL; }
    if (indata->key != NULL) { ASN1_OCTET_STRING_free(indata->key); indata->key = NULL; }
    if (indata->par != NULL) {
        sk_KM_SAMSUNG_PARAM_pop_free(indata->par, KM_SAMSUNG_PARAM_free);
        indata->par = NULL;
    }

    if (int0 && ((indata->int0 = ASN1_INTEGER_new()) == NULL ||
                (!ASN1_INTEGER_set(indata->int0, (long)*int0))))
        goto_error("Failed to set the INDATA blob `int0` parameter");

    if (long0 && ((indata->long0 = ASN1_INTEGER_new()) == NULL ||
                (!ASN1_INTEGER_set(indata->long0, (long)*long0))))
        goto_error("Failed to set the INDATA blob `long0` parameter");

    if (long1 && ((indata->long1 = ASN1_INTEGER_new()) == NULL ||
                (!ASN1_INTEGER_set(indata->long1, (long)*long1))))
        goto_error("Failed to set the INDATA blob `long1` parameter");

    if (bin0 && ((indata->bin0 = ASN1_OCTET_STRING_new()) == NULL ||
                (!ASN1_OCTET_STRING_set(indata->bin0, bin0->data(), (int)bin0->size()))))
        goto_error("Failed to set the INDATA blob `bin0` parameter");

    if (bin1 && ((indata->bin1 = ASN1_OCTET_STRING_new()) == NULL ||
                (!ASN1_OCTET_STRING_set(indata->bin1, bin1->data(), (int)bin1->size()))))
        goto_error("Failed to set the INDATA blob `bin1` parameter");

    if (bin2 && ((indata->bin2 = ASN1_OCTET_STRING_new()) == NULL ||
                (!ASN1_OCTET_STRING_set(indata->bin2, bin2->data(), (int)bin2->size()))))
        goto_error("Failed to set the INDATA blob `bin2` parameter");

    if (key && ((indata->key = ASN1_OCTET_STRING_new()) == NULL ||
                (!ASN1_OCTET_STRING_set(indata->key, key->data(), (int)key->size()))))
        goto_error("Failed to set the INDATA blob `key` parameter");

    if (par) {
        indata->par = sk_KM_SAMSUNG_PARAM_new_null();
        if (indata->par == NULL)
            goto_error("Failed to allocate a new samsung KM_PARAM stack");

        for (const auto& kp : *par) {
            KM_SAMSUNG_PARAM *new_par = NULL;
            if (ekey::is_integer_param(static_cast<int64_t>(kp.tag))) {

                if (ekey::make_integer_param(&new_par, kp.tag, (int64_t)kp.f.longInteger))
                    goto_error("Failed to make a new samsung INTEGER KM_PARAM");
            } else {
                if (ekey::make_octet_string_param(&new_par, kp.tag, kp.blob))
                    goto_error("Failed to make a new samsung OCTET_STRING KM_PARAM");
            }

            if (ekey::push_param_or_free(indata->par, new_par))
                goto err;
        }
    }

    indata_der_len = i2d_KM_SAMSUNG_INDATA(indata, &indata_der);
    if (indata_der_len <= 0)
        goto_error("Failed to serialize the samsung KM_INDATA ASN.1 struct");

    out.resize(indata_der_len);
    std::memcpy(out.data(), indata_der, indata_der_len);

    OPENSSL_free(indata_der);
    KM_SAMSUNG_INDATA_free(indata);
    return 0;

err:
    if (indata_der != NULL) {
        OPENSSL_free(indata_der);
        indata_der = NULL;
    }
    if (indata != NULL) {
        KM_SAMSUNG_INDATA_free(indata);
        indata = NULL;
    }
    return -1;
}

static int deserialize_and_dump_outdata(hidl_vec<hidl_vec<uint8_t>> const& cert_chain)
{
    using namespace kmhal::util;

    if (cert_chain.size() != 2) {
        s_log_error("Invalid cert chain size");
        return -1;
    }

    send_indata_err send_err = UNKNOWN_ERROR;
    if (deserialize_send_indata_err(send_err, cert_chain[0])) {
        s_log_error("Failed to deserialize the send_indata_err sequence");
        return -1;
    }
    if (send_err != OK) {
        s_log_error("Failed to send request to the TEE: %d", send_err);
        return -1;
    }

    const unsigned char *p = cert_chain[1].data();
    KM_SAMSUNG_OUTDATA *outdata = d2i_KM_SAMSUNG_OUTDATA(NULL, &p, cert_chain[1].size());
    if (outdata == NULL || p != cert_chain[1].data() + cert_chain[1].size()) {
        if (outdata) KM_SAMSUNG_OUTDATA_free(outdata);
        s_log_error("Failed to deserialize the KM_OUTDATA DER");
        return -1;
    }

    int ret = -1;
    ErrorCode e = ErrorCode::UNKNOWN_ERROR;
    int64_t v;
    if (!ASN1_INTEGER_get_int64(&v, outdata->err))
        goto_error("Couldn't get the value of a ASN.1 INTEGER");
    v &= 0x00000000FFFFFFFF;
    e = static_cast<ErrorCode>(v);

    if (e != ErrorCode::OK) {
        ret = 1;
        s_log_error("Keymaster returned error: %d (%s)",
                static_cast<int>(e), toString(e).c_str());
    } else {
        ret = 0;
    }
    dump_outdata(outdata);

err:
    if (outdata != NULL) {
        KM_SAMSUNG_OUTDATA_free(outdata);
        outdata = NULL;
    }
    if (ret != 0)
        return ret;

    return 0;
}

static void dump_outdata(const KM_SAMSUNG_OUTDATA *o)
{
    const char *old_line = NULL;
    s_configure_log_line(S_LOG_INFO, "%s\n", &old_line);
    s_log_info("===== BEGIN KM_OUTDATA DUMP =====");
    s_log_info("KM_OUTDATA outdata = {");

    ekey::dump_u64("ver", o->ver, 1);
    ekey::dump_u64("cmd", o->cmd, 1);
    ekey::dump_u64("pid", o->pid, 1);
    ekey::dump_enum_val("err", o->err, KM_ErrorCode_toString, 1);

    if (o->int0) ekey::dump_u64("int0", o->int0, 1);
    if (o->long0) ekey::dump_u64("long0", o->long0, 1);
    if (o->bin0) ekey::dump_hex("bin0", o->bin0, 1);
    if (o->bin1) ekey::dump_hex("bin1", o->bin1, 1);
    if (o->par) {
        hidl_vec<KM_SAMSUNG_PARAM *> ekey_params;
        int n_params = sk_KM_SAMSUNG_PARAM_num(o->par);
        if (n_params >= 0)
            ekey_params.resize(n_params);
        for (int i = 0; i < n_params; i++)
            ekey_params[i] = sk_KM_SAMSUNG_PARAM_value(o->par, i);

        KM_PARAM_LIST_SEQ *param_list = NULL;
        if (ekey::ekey_params_to_param_list(ekey_params, &param_list)) {
            s_log_error("Faield to convert samsung KM_PARAM set to a param list");
        } else {
            ekey::dump_param_list(param_list, 1, "par");
            KM_PARAM_LIST_SEQ_free(param_list);
        }
    }

    if (o->log) {
        s_log_info(SINGLE_INDENT ".log = {");
        int n_strs = sk_ASN1_OCTET_STRING_num(o->log);
        if (n_strs < 0) {
            s_log_error("Failed to get the number of OCTET_STRINGs "
                    "in the stack");
        } else {
            for (int i = 0; i < n_strs; i++) {
                const ASN1_OCTET_STRING *str =
                    sk_ASN1_OCTET_STRING_value(o->log, i);
                if (str == NULL) {
                    s_log_error("Failed to get an OCTET_STRING from the stack");
                    break;
                }

                s_log_info(SINGLE_INDENT SINGLE_INDENT "\"%s\"%s",
                        (const char *)ASN1_STRING_get0_data(str),
                        (i < n_strs - 1) ? "," : "");
            }
        }
        s_log_info(SINGLE_INDENT "}");
    }

    s_log_info("};");
    s_log_info("=====  END KM_OUTDATA DUMP  =====");
    s_configure_log_line(S_LOG_INFO, old_line, NULL);
}

namespace ekey {

static bool is_repeatable(int64_t tag)
{
    const TagType tt = static_cast<TagType>(__KM_TAG_TYPE_MASK(tag));
    return (tt == TagType::UINT_REP)
        || (tt == TagType::ENUM_REP)
        || (tt == TagType::ULONG_REP);
}

static bool is_integer_param(int64_t tag)
{
    const TagType tt = static_cast<TagType>(__KM_TAG_TYPE_MASK(tag));
    return (tt != TagType::BYTES && tt != TagType::BIGNUM);
}

static int make_integer_param(KM_SAMSUNG_PARAM **out_par,
        Tag tag, int64_t val)
{
    *out_par = NULL;

    KM_SAMSUNG_PARAM *p = KM_SAMSUNG_PARAM_new();
    if (p == NULL) {
        s_log_error("Couldn't allocate a new samsung key parameter");
        return 1;
    }

    if (!ASN1_INTEGER_set(p->tag, static_cast<int>(tag))) {
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

    if (!ASN1_INTEGER_set(p->i, val)) {
        s_log_error("Couldn't set the value of an ASN.1 INTEGER");
        KM_SAMSUNG_PARAM_free(p);
        return 1;
    }

    *out_par = p;
    return 0;
}

static int make_octet_string_param(KM_SAMSUNG_PARAM **out_par,
        Tag tag, hidl_vec<uint8_t> const& val)
{
    *out_par = NULL;

    KM_SAMSUNG_PARAM *p = KM_SAMSUNG_PARAM_new();
    if (p == NULL) {
        s_log_error("Couldn't allocate a new samsung key parameter");
        return 1;
    }

    if (!ASN1_INTEGER_set(p->tag, static_cast<int>(tag))) {
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

    if (!ASN1_OCTET_STRING_set(p->b, val.data(), val.size())) {
        s_log_error("Couldn't set the value of an ASN.1 OCTET_STRING");
        KM_SAMSUNG_PARAM_free(p);
        return 1;
    }

    *out_par = p;
    return 0;
}

static int push_param_or_free(STACK_OF(KM_SAMSUNG_PARAM) *paramset,
        KM_SAMSUNG_PARAM *par)
{
    if (sk_KM_SAMSUNG_PARAM_push(paramset, par) <= 0) {
        KM_SAMSUNG_PARAM_free(par);
        s_log_error("Failed to push a key parameter to the set");
        return 1;
    }

    return 0;
}

static int km_tag_cmp(KeyParameter const& kp, KM_SAMSUNG_PARAM *p)
{
    if (p == NULL)
        return 1;

    int64_t pt;
    if (!ASN1_INTEGER_get_int64(&pt, p->tag)) {
        s_log_error("%s: Couldn't get the tag value for p", __func__);
        return -1;
    }
    pt &= 0x00000000FFFFFFFF;

    if (kp.tag == static_cast<Tag>(pt)) {
        if (!is_repeatable(pt))
            return 0;

        if (is_integer_param(pt)) {
            if (p->i == NULL)
                return 1;

            return kp.f.longInteger - ASN1_INTEGER_get(p->i);
        } else {
            if (p->b == NULL ||
                    kp.blob.data() == NULL || ASN1_STRING_get0_data(p->b) == NULL)
                return 1;

            const size_t s = std::min(
                    kp.blob.size(),
                    static_cast<size_t>(std::max(0, ASN1_STRING_length(p->b)))
            );
            return memcmp(kp.blob.data(), ASN1_STRING_get0_data(p->b), s);
        }
    }

    return static_cast<int>(kp.tag) - pt;
}

static void dump_param_list(const KM_PARAM_LIST_SEQ *ps,
        uint8_t indent, const char *field_name)
{
    const char *old_line = NULL;
    s_configure_log_line(S_LOG_INFO, "%s\n", &old_line);
    ASN1_INTEGER *bool_val_1 = NULL;

    bool_val_1 = ASN1_INTEGER_new();
    if (bool_val_1 == NULL || !ASN1_INTEGER_set(bool_val_1, 1)) {
        s_log_error("Failed to prepare temporary ASN.1 INTEGER");
        return;
    }

    char indent_buf[1024];
    sprint_indent(indent_buf, indent);

    const uint8_t i = indent + 1;

    if (field_name == NULL) {
        s_log_info("%s===== BEGIN KEY PARAMETER LIST DUMP =====", indent_buf);

        if (ps == NULL) {
            s_log_info("%sKM_PARAM_LIST_SEQ par = { /* empty */ };", indent_buf);
            goto restore_log_and_out;
        }

        s_log_info("KM_PARAM_SET_SEQ par = {");
    } else {
        if (ps == NULL) {
            s_log_info("%s.%s = { /* empty */ };", indent_buf, field_name);
            goto restore_log_and_out;
        }

        s_log_info("%s.%s = {", indent_buf, field_name);
    }

    if (ps->purpose != NULL)
        dump_enum_arr("purpose", ps->purpose, KM_KeyPurpose_toString, i);

    if (ps->algorithm != NULL)
        dump_enum_val("algorithm", ps->algorithm, KM_Algorithm_toString, i);

    if (ps->keySize != NULL)
        dump_u64("keySize", ps->keySize, i, false);

    if (ps->blockMode != NULL)
        dump_enum_arr("blockMode", ps->blockMode, KM_BlockMode_toString, i);

    if (ps->digest != NULL)
        dump_enum_arr("digest", ps->digest, KM_Digest_toString, i);

    if (ps->padding != NULL)
        dump_enum_arr("padding", ps->padding, KM_PaddingMode_toString, i);

    if (ps->callerNonce != NULL)
        dump_u64("callerNonce", bool_val_1, i);

    if (ps->minMacLength != NULL)
        dump_u64("minMacLength", ps->minMacLength, i);

    if (ps->ecCurve != NULL)
        dump_enum_val("ecCurve", ps->ecCurve, KM_EcCurve_toString, i);

    if (ps->rsaPublicExponent != NULL)
        dump_u64("rsaPublicExponent", ps->rsaPublicExponent, i, DUMP_U64_HEX);

    if (ps->includeUniqueId != NULL)
        dump_u64("includeUniqueId", bool_val_1, i);

    if (ps->keyBlobUsageRequirements != NULL)
        dump_enum_val("keyBlobUsageRequirements", ps->keyBlobUsageRequirements,
                KM_KeyBlobUsageRequirements_toString, i);

    if (ps->bootloaderOnly != NULL)
        dump_u64("bootloaderOnly", bool_val_1, i);

    if (ps->rollbackResistance != NULL)
        dump_u64("rollbackResistance", bool_val_1, i);

    if (ps->hardwareType != NULL)
        dump_u64("hardwareType", ps->hardwareType, i, DUMP_U64_HEX);

    if (ps->activeDateTime != NULL)
        dump_datetime("activeDateTime", ps->activeDateTime, i);

    if (ps->originationExpireDateTime != NULL)
        dump_datetime("originationExpireDateTime",
                ps->originationExpireDateTime, i);

    if (ps->usageExpireDateTime != NULL)
        dump_datetime("usageExpireDateTime", ps->usageExpireDateTime, i);

    if (ps->minSecondsBetweenOps != NULL)
        dump_u64("minSecondsBetweenOps", ps->minSecondsBetweenOps, i);

    if (ps->maxUsesPerBoot != NULL)
        dump_u64("maxUsesPerBoot", ps->maxUsesPerBoot, i);

    if (ps->userId != NULL)
        dump_u64("userId", ps->userId, i);

    if (ps->userSecureId != NULL)
        dump_u64_arr("userSecureId", ps->userSecureId, i, false);

    if (ps->noAuthRequired != NULL)
        dump_u64("noAuthRequired", bool_val_1, i);

    if (ps->userAuthType != NULL)
        dump_u64("userAuthType", ps->userAuthType, i, DUMP_U64_HEX);

    if (ps->authTimeout != NULL)
        dump_u64("authTimeout", ps->authTimeout, i);

    if (ps->allowWhileOnBody != NULL)
        dump_u64("allowWhileOnBody", bool_val_1, i);

    if (ps->trustedUserPresenceReq != NULL)
        dump_u64("trustedUserPresenceReq", bool_val_1, i);

    if (ps->trustedConfirmationReq != NULL)
        dump_u64("trustedConfirmationReq", bool_val_1, i);

    if (ps->unlockedDeviceReq != NULL)
        dump_u64("unlockedDeviceReq", bool_val_1, i);

    if (ps->applicationId != NULL)
        dump_hex("applicationId", ps->applicationId, i);

    if (ps->applicationData != NULL)
        dump_hex("applicationData", ps->applicationData, i);

    if (ps->creationDateTime != NULL)
        dump_datetime("creationDateTime", ps->creationDateTime, i);

    if (ps->keyOrigin != NULL)
        dump_enum_val("keyOrigin", ps->keyOrigin, KM_KeyOrigin_toString, i);

    if (ps->rootOfTrust != NULL) {
        s_log_info("%s" SINGLE_INDENT ".rootOfTrust = {", indent_buf);
        dump_hex("verifiedBootKey",
                ps->rootOfTrust->verifiedBootKey, i + 1);
        s_log_info("%s" SINGLE_INDENT SINGLE_INDENT ".deviceLocked = %d,",
                indent_buf, ps->rootOfTrust->deviceLocked);
        dump_enum_val("verifiedBootState", ps->rootOfTrust->verifiedBootState,
                KM_VerifiedBootState_toString, i + 1);
        dump_hex("verifiedBootHash",
                ps->rootOfTrust->verifiedBootHash, i + 1);
        s_log_info("%s" SINGLE_INDENT "},", indent_buf);
    }

    if (ps->osVersion != NULL)
        dump_u64("osVersion", ps->osVersion, i);

    if (ps->osPatchLevel != NULL)
        dump_u64("osPatchLevel", ps->osPatchLevel, i);

    if (ps->uniqueId != NULL)
        dump_hex("uniqueId", ps->uniqueId, i);

    if (ps->attestationChallenge != NULL)
        dump_hex("attestationChallenge", ps->attestationChallenge, i);

    if (ps->attestationApplicationId != NULL)
        dump_hex("attestationApplicationId", ps->attestationApplicationId, i);

    if (ps->attestationIdBrand != NULL)
        dump_hex("attestationIdBrand", ps->attestationIdBrand, i);

    if (ps->attestationIdDevice != NULL)
        dump_hex("attestationIdDevice", ps->attestationIdDevice, i);

    if (ps->attestationIdProduct != NULL)
        dump_hex("attestationIdProduct", ps->attestationIdProduct, i);

    if (ps->attestationIdSerial != NULL)
        dump_hex("attestationIdSerial", ps->attestationIdSerial, i);

    if (ps->attestationIdImei != NULL)
        dump_hex("attestationIdImei", ps->attestationIdImei, i);

    if (ps->attestationIdMeid != NULL)
        dump_hex("attestationIdMeid", ps->attestationIdMeid, i);

    if (ps->attestationIdManufacturer != NULL)
        dump_hex("attestationIdManufacturer", ps->attestationIdManufacturer, i);

    if (ps->attestationIdModel != NULL)
        dump_hex("attestationIdModel", ps->attestationIdModel, i);

    if (ps->vendorPatchLevel != NULL)
        dump_u64("vendorPatchLevel", ps->vendorPatchLevel, i);

    if (ps->bootPatchLevel != NULL)
        dump_u64("bootPatchLevel", ps->bootPatchLevel, i);

    if (ps->associatedData != NULL)
        dump_hex("associatedData", ps->associatedData, i);

    if (ps->nonce != NULL)
        dump_hex("nonce", ps->nonce, i);

    if (ps->macLength != NULL)
        dump_u64("macLength", ps->macLength, i);

    if (ps->resetSinceIdRotation != NULL)
        dump_u64("resetSinceIdRotation", bool_val_1, i);

    if (ps->confirmationToken != NULL)
        dump_hex("confirmationToken", ps->confirmationToken, i);

    if (ps->authToken != NULL)
        dump_hex("authToken", ps->authToken, i);

    if (ps->verificationToken != NULL)
        dump_hex("verificationToken", ps->verificationToken, i);

    if (ps->allUsers != NULL)
        dump_u64("allUsers", bool_val_1, i);

    if (ps->eciesSingleHashMode != NULL)
        dump_u64("eciesSingleHashMode", bool_val_1, i);

    if (ps->kdf != NULL)
        dump_enum_val("kdf", ps->kdf, KM_KeyDerivationFunction_toString, i);

    if (ps->exportable != NULL)
        dump_u64("exportable", bool_val_1, i);

    if (ps->keyAuth != NULL)
        dump_u64("keyAuth", bool_val_1, i);

    if (ps->opAuth != NULL)
        dump_u64("opAuth", bool_val_1, i);

    if (ps->operationHandle != NULL)
        dump_u64("operationHandle", ps->operationHandle, i, DUMP_U64_HEX);

    if (ps->operationFailed != NULL)
        dump_u64("operationFailed", bool_val_1, i);

    if (ps->internalCurrentDateTime != NULL)
        dump_datetime("internalCurrentDateTime", ps->internalCurrentDateTime, i);

    if (ps->ekeyBlobIV != NULL)
        dump_hex("ekeyBlobIV", ps->ekeyBlobIV, i);

    if (ps->ekeyBlobAuthTag != NULL)
        dump_hex("ekeyBlobAuthTag", ps->ekeyBlobAuthTag, i);

    if (ps->ekeyBlobCurrentUsesPerBoot != NULL)
        dump_u64("ekeyBlobCurrentUsesPerBoot", ps->ekeyBlobCurrentUsesPerBoot, i);

    if (ps->ekeyBlobLastOpTimestamp != NULL)
        dump_u64("ekeyBlobLastOpTimestamp", ps->ekeyBlobLastOpTimestamp, i);

    if (ps->ekeyBlobDoUpgrade != NULL)
        dump_u64("ekeyBlobDoUpgrade", ps->ekeyBlobDoUpgrade, i);

    if (ps->ekeyBlobPassword != NULL)
        dump_hex("ekeyBlobPassword", ps->ekeyBlobPassword, i);

    if (ps->ekeyBlobSalt != NULL)
        dump_hex("ekeyBlobSalt", ps->ekeyBlobSalt, i);

    if (ps->ekeyBlobEncVer != NULL)
        dump_u64("ekeyBlobEncVer", ps->ekeyBlobEncVer, i);

    if (ps->ekeyBlobRaw != NULL)
        dump_u64("ekeyBlobRaw", ps->ekeyBlobRaw, i);

    if (ps->ekeyBlobUniqKDM != NULL)
        dump_hex("ekeyBlobUniqKDM", ps->ekeyBlobUniqKDM, i);

    if (ps->ekeyBlobIncUseCount != NULL)
        dump_u64("ekeyBlobIncUseCount", ps->ekeyBlobIncUseCount, i);

    if (ps->samsungRequestingTA != NULL)
        dump_hex("samsungRequestingTA", ps->samsungRequestingTA, i);

    if (ps->samsungRotRequired != NULL)
        dump_u64("samsungRotRequired", bool_val_1, i);

    if (ps->samsungLegacyRot != NULL)
        dump_u64("samsungLegacyRot", bool_val_1, i);

    if (ps->useSecureProcessor != NULL)
        dump_u64("useSecureProcessor", bool_val_1, i);

    if (ps->storageKey != NULL)
        dump_u64("storageKey", bool_val_1, i);

    if (ps->integrityStatus != NULL)
        dump_u64("integrityStatus", ps->integrityStatus, i, DUMP_U64_HEX);

    if (ps->isSamsungKey != NULL)
        dump_u64("isSamsungKey", bool_val_1, i);

    if (ps->samsungAttestationRoot != NULL)
        dump_hex("samsungAttestationRoot", ps->samsungAttestationRoot, i);

    if (ps->samsungAttestIntegrity != NULL)
        dump_u64("samsungAttestIntegrity", bool_val_1, i);

    if (ps->knoxObjectProtectionRequired != NULL)
        dump_u64("knoxObjectProtectionRequired", bool_val_1, i);

    if (ps->knoxCreatorId != NULL)
        dump_hex("knoxCreatorId", ps->knoxCreatorId, i);

    if (ps->knoxAdministratorId != NULL)
        dump_hex("knoxAdministratorId", ps->knoxAdministratorId, i);

    if (ps->knoxAccessorId != NULL)
        dump_hex("knoxAccessorId", ps->knoxAccessorId, i);

    if (ps->samsungAuthPackage != NULL)
        dump_hex("samsungAuthPackage", ps->samsungAuthPackage, i);

    if (ps->samsungCertificateSubject != NULL)
        dump_hex("samsungCertificateSubject", ps->samsungCertificateSubject, i);

    if (ps->samsungKeyUsage != NULL)
        dump_u64("samsungKeyUsage", ps->samsungKeyUsage, i, DUMP_U64_HEX);

    if (ps->samsungExtendedKeyUsage != NULL)
        dump_hex("samsungExtendedKeyUsage", ps->samsungExtendedKeyUsage, i);

    if (ps->samsungSubjectAlternativeName != NULL)
        dump_hex("samsungSubjectAlternativeName",
                ps->samsungSubjectAlternativeName, i);

    if (ps->provGacEc1 != NULL)
        dump_hex("provGacEc1", ps->provGacEc1, i);

    if (ps->provGacEc2 != NULL)
        dump_hex("provGacEc2", ps->provGacEc2, i);

    if (ps->provGacEc3 != NULL)
        dump_hex("provGacEc3", ps->provGacEc3, i);

    if (ps->provGakEc != NULL)
        dump_hex("provGakEc", ps->provGakEc, i);

    if (ps->provGakEcVtoken != NULL)
        dump_hex("provGakEcVtoken", ps->provGakEcVtoken, i);

    if (ps->provGacRsa1 != NULL)
        dump_hex("provGacRsa1", ps->provGacRsa1, i);

    if (ps->provGacRsa2 != NULL)
        dump_hex("provGacRsa2", ps->provGacRsa2, i);

    if (ps->provGacRsa3 != NULL)
        dump_hex("provGacRsa3", ps->provGacRsa3, i);

    if (ps->provGakRsa != NULL)
        dump_hex("provGakRsa", ps->provGakRsa, i);

    if (ps->provGakRsaVtoken != NULL)
        dump_hex("provGakRsaVtoken", ps->provGakRsaVtoken, i);

    if (ps->provSakEc != NULL)
        dump_hex("provSakEc", ps->provSakEc, i);

    if (ps->provSakEcVtoken != NULL)
        dump_hex("provSakEcVtoken", ps->provSakEcVtoken, i);

    if (field_name == NULL) {
        s_log_info("%s};", indent_buf);
        s_log_info("%s=====  END KEY PARAMETER LIST DUMP  =====", indent_buf);
    } else {
        s_log_info("%s},", indent_buf);
    }

restore_log_and_out:
    s_configure_log_line(S_LOG_INFO, old_line, NULL);
}

static void dump_hex_line(char *buf, u32 buf_size,
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

static void dump_hex(const char *field_name,
        const ASN1_OCTET_STRING *data_, uint8_t indent)
{
    char indent_buf[1024];
    sprint_indent(indent_buf, indent);

    int total_sz = 0;
    if (data_ == NULL || (total_sz = ASN1_STRING_length(data_)) <= 0) {
        s_log_info("%s.%s = { /* (empty) */ },", indent_buf, field_name);
        return;
    }
    const unsigned char *data = ASN1_STRING_get0_data(data_);

#define LINE_LEN 8

    u32 n_lines = total_sz / LINE_LEN;
    u32 remainder = total_sz % LINE_LEN;
    if (remainder == 0) {
        n_lines--;
        remainder = LINE_LEN;
    }

#define LINE_BUF_SIZE (LINE_LEN * 16)
    char line_buf[LINE_BUF_SIZE] = { 0 };

    if (n_lines == 0) {
        dump_hex_line(line_buf, LINE_BUF_SIZE, data, remainder, true);
        line_buf[LINE_BUF_SIZE - 1] = '\0';
        s_log_info("%s.%s = { %s },", indent_buf, field_name, line_buf);
        return;
    }

    s_log_info("%s.%s = {", indent_buf, field_name);

    dump_hex_line(line_buf, LINE_BUF_SIZE, data, LINE_LEN, false);
    line_buf[LINE_BUF_SIZE - 1] = '\0';
    s_log_info("%s" SINGLE_INDENT "%s", indent_buf, line_buf);

    for (u32 i = 1; i < n_lines; i++) {
        memset(line_buf, 0, LINE_BUF_SIZE);
        dump_hex_line(line_buf, LINE_BUF_SIZE,
                data + (i * LINE_LEN),
                LINE_LEN, false
        );
        line_buf[LINE_BUF_SIZE - 1] = '\0';
        s_log_info("%s" SINGLE_INDENT "%s", indent_buf, line_buf);
    }

    memset(line_buf, 0, LINE_BUF_SIZE);
    dump_hex_line(line_buf, LINE_BUF_SIZE,
            data + (n_lines * LINE_LEN),
            remainder, true
    );
    line_buf[LINE_BUF_SIZE - 1] = '\0';
    s_log_info("%s" SINGLE_INDENT "%s", indent_buf, line_buf);
    s_log_info("%s},", indent_buf);

#undef LINE_LEN
}

static void dump_u64(const char *field_name, const ASN1_INTEGER *a,
        uint8_t indent, bool hex)
{
    uint64_t u = 0;
    if (ASN1_INTEGER_get_uint64(&u, a) == 0) {
        s_log_error("[%s] Couldn't get the value "
                "of an ASN.1 INTEGER (as uint64_t)", field_name);
        return;
    }

    {
        char indent_buf[1024];
        sprint_indent(indent_buf, indent);

        if (hex)
            s_log_info("%s.%s = 0x%016llx,",
                    indent_buf, field_name, (unsigned long long)u);
        else
            s_log_info("%s.%s = %llu,",
                    indent_buf, field_name, (unsigned long long)u);
    }
}

static void dump_u64_arr(const char *field_name, const ASN1_SET_OF_INTEGER *arr,
        uint8_t indent, bool hex)
{
    char indent_buf[1024];
    char tmp_buf[1024] = { 0 };
    u32 write_index = 0;
    int arr_size = 0;
    const char *const fmt = hex ? "0x%016llx, " : "%llu, ";

    sprint_indent(indent_buf, indent);

    if (arr == NULL || (arr_size = sk_ASN1_INTEGER_num(arr)) <= 0) {
        s_log_info("%s.%s = { /* (empty) */ },", indent_buf, field_name);
        return;
    }


    {
        const ASN1_INTEGER *curr = NULL;
        uint64_t u = 0;
        int r = 0;

        for (int i = 0; i < arr_size - 1; i++) {
            curr = sk_ASN1_INTEGER_value(arr, i);
            if (ASN1_INTEGER_get_uint64(&u, curr) == 0) {
                s_log_error("[%s] Couldn't get the value of an ASN.1 INTEGER "
                        "(as uint64_t) @ idx %i", field_name, i);
                break;
            }

            r = snprintf(tmp_buf + write_index, 256 - write_index - 1,
                    fmt, (unsigned long long)u);
            if (r <= 0 || r >= 256) {
                s_log_error("[%s] Invalid return value of snprintf "
                        "(@ idx %d): %d", field_name, i, r);
                return;
            }

            write_index += r;
        }

        curr = sk_ASN1_INTEGER_value(arr, arr_size - 1);
        if (ASN1_INTEGER_get_uint64(&u, curr) == 0) {
            s_log_error("[%s] Couldn't get the value of an ASN.1 INTEGER "
                    "(as uint64_t) @ idx %i", field_name, arr_size - 1);
            return;
        }
        r = snprintf(tmp_buf + write_index, 256 - write_index - 1,
                fmt, (unsigned long long)u);
        if (r <= 0 || r >= 256) {
            s_log_error("[%s] Invalid return value of snprintf (@ idx %d): %d",
                    field_name, arr_size - 1, r);
            return;
        }
    }

    s_log_info("%s.%s = { %s },", indent_buf, field_name, tmp_buf);
}

static void dump_enum_val(const char *field_name, const ASN1_INTEGER *e,
        KM_enum_toString_proc_t get_str_proc, uint8_t indent)
{
    char indent_buf[1024];
    sprint_indent(indent_buf, indent);

    const int i = ASN1_INTEGER_get(e);

    s_log_info("%s.%s = %lld, // %s", indent_buf, field_name,
            (long long int)i, get_str_proc((int)i));
}

static void dump_enum_arr(const char *field_name,
        const ASN1_SET_OF_INTEGER *arr, KM_enum_toString_proc_t get_str_proc,
        uint8_t indent)
{
    int arr_size = 0;
    char indent_buf[1024];
    sprint_indent(indent_buf, indent);

    if (arr == NULL || (arr_size = sk_ASN1_INTEGER_num(arr)) <= 0) {
        s_log_info("%s.%s = { /* (empty) */ },", indent_buf, field_name);
        return;
    }

    s_log_info("%s.%s = {", indent_buf, field_name);

    for (int i = 0; i < arr_size - 1; i++) {
        int64_t val = 0;
        if (ASN1_INTEGER_get_int64(&val, sk_ASN1_INTEGER_value(arr, i)) == 0) {
            s_log_error("[%s] Couldn't get the value of an ASN.1 INTEGER "
                    "(as int64_t) @ idx %i", field_name, i);
            return;
        }
        val &= 0x00000000FFFFFFFF;

        s_log_info(SINGLE_INDENT "%s.%s = %lld, // %s",
                indent_buf, field_name,
                (long long int)val, get_str_proc((int)val)
        );
    }

    {
        int64_t val = 0;
        if (ASN1_INTEGER_get_int64(&val,
                    sk_ASN1_INTEGER_value(arr, arr_size - 1)) == 0)
        {
            s_log_error("[%s] Couldn't get the value of an ASN.1 INTEGER "
                    "(as int64_t) @ idx %i", field_name, arr_size - 1);
            return;
        }
        val &= 0x00000000FFFFFFFF;
        s_log_info(SINGLE_INDENT "%s.%s = %lld // %s",
                indent_buf, field_name,
                (long long int)val, get_str_proc((int)val)
        );
    }

    s_log_info("%s},", indent_buf);
}

static void dump_datetime(const char *field_name, const ASN1_INTEGER *d,
        uint8_t indent)
{
    char indent_buf[1024];
    char datetime_buf[256] = { 0 };
    int64_t i = 0;

    sprint_indent(indent_buf, indent);

    if (ASN1_INTEGER_get_int64(&i, d) == 0) {
        s_log_error("[%s] Couldn't get the value of an ASN.1 INTEGER "
                "(as int64_t)", field_name);
        return;
    }

    datetime_to_str(datetime_buf, sizeof(datetime_buf), i);
    s_log_info("%s.%s = %lld, // %s", indent_buf, field_name,
            (long long int)i, datetime_buf);
}

static int portable_localtime(const time_t *timep, struct tm *result)
{
#ifdef _WIN32
    return localtime_s(result, timep);
#else
    return localtime_r(timep, result) ? 0 : -1;
#endif
}
static void datetime_to_str(char *buf, u32 buf_size, int64_t dt)
{
    struct tm t = {};

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

static int deserialize_ekey_blob_and_params(const hidl_vec<uint8_t>& ekey,
        KM_SAMSUNG_EKEY_BLOB *& out, hidl_vec<KM_SAMSUNG_PARAM *> *out_par)
{
    const unsigned char *p = ekey.data();
    long len = (long)ekey.size();
    KM_SAMSUNG_EKEY_BLOB *ekey_blob = NULL;

    if (out_par)
        out_par->resize(0);

    ekey_blob = d2i_KM_SAMSUNG_EKEY_BLOB(NULL, &p, len);
    if (ekey_blob == NULL)
        goto_error("Failed to d2i the encrypted key blob");

    {
        int64_t blob_ver = 0;
        if (!ASN1_INTEGER_get_int64(&blob_ver, ekey_blob->enc_ver))
            goto_error("Couldn't get the encrypted key blob version INTEGER");
        s_log_info("Encrypted key blob version: %lli", (long long int)blob_ver);
    }

    if (out_par) {
        int n_params = sk_KM_SAMSUNG_PARAM_num(ekey_blob->enc_par);
        if (n_params < 0)
            goto_error("Couldn't get the number of encryption parameters");

        for (int i = 0; i < n_params; i++) {
            KM_SAMSUNG_PARAM *p =
                sk_KM_SAMSUNG_PARAM_value(ekey_blob->enc_par, i);
            if (p == NULL)
                goto_error("Couldn't get the value of an encryption parameter");

            p = KM_SAMSUNG_PARAM_dup(p);
            if (p == NULL)
                goto_error("Couldn't duplicate an encryption parameter");

            out_par->resize(out_par->size() + 1);
            (*out_par)[out_par->size() - 1] = p;
        }
    }

    out = ekey_blob;

    return 0;

err:
    if (out_par) {
        for (size_t i = 0; i < out_par->size(); i++) {
            KM_SAMSUNG_PARAM_free((*out_par)[i]);
            (*out_par)[i] = NULL;
        }
        out_par->resize(0);
    }

    if (ekey_blob != NULL) {
        KM_SAMSUNG_EKEY_BLOB_free(ekey_blob);
        ekey_blob = NULL;
    }
    out = NULL;

    return 1;
}

static int serialize_ekey_blob(KM_SAMSUNG_EKEY_BLOB *& ekey,
        hidl_vec<uint8_t>& out_ekey_der)
{
    int length = 0;
    unsigned char *der = NULL;

    length = i2d_KM_SAMSUNG_EKEY_BLOB(ekey, NULL);
    if (length <= 0)
        goto_error("Couldn't measure the length of the new ekey blob DER");

    der = (unsigned char *)OPENSSL_malloc(length);
    if (der == NULL)
        goto_error("Failed to allocate the new ekey blob DER");

    {
        unsigned char *p = der;
        if (i2d_KM_SAMSUNG_EKEY_BLOB(ekey, &p) != length ||
                p != der + length)
        {
            OPENSSL_free(der);
            goto_error("Failed to serialize the new ekey blob DER");
        }
    }

    out_ekey_der.resize(length);
    memcpy(out_ekey_der.data(), der, length);
    OPENSSL_free(der);

    return 0;

err:
    out_ekey_der.resize(0);
    if (der != NULL) {
        OPENSSL_free(der);
        der = NULL;
    }

    return 1;
}

static int ekey_params_to_param_list(const hidl_vec<KM_SAMSUNG_PARAM *>& ekey_params,
        KM_PARAM_LIST_SEQ **out_param_list)
{
    KM_PARAM_LIST_SEQ *ret = KM_PARAM_LIST_SEQ_new();
    if (ret == NULL)
        goto_error("Failed to allocate a new param list");

    for (const KM_SAMSUNG_PARAM *curr : ekey_params) {
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

            ret->rootOfTrust = d2i_KM_ROOT_OF_TRUST_SEQ(&ret->rootOfTrust,
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
            ASN1_NULL **b;
            ASN1_INTEGER **i;
            ASN1_SET_OF_INTEGER **iset;
            ASN1_OCTET_STRING **str;

            void *v;
        } target;

        switch ((enum KM_Tag)tag) {
        case KM_TAG_PURPOSE: target.iset = &ret->purpose; break;
        case KM_TAG_ALGORITHM: target.i = &ret->algorithm; break;
        case KM_TAG_KEY_SIZE: target.i = &ret->keySize; break;
        case KM_TAG_BLOCK_MODE: target.iset = &ret->blockMode; break;
        case KM_TAG_DIGEST: target.iset = &ret->digest; break;
        case KM_TAG_PADDING: target.iset = &ret->padding; break;
        case KM_TAG_CALLER_NONCE: target.b = &ret->callerNonce; break;
        case KM_TAG_MIN_MAC_LENGTH: target.i = &ret->minMacLength; break;
        case KM_TAG_EC_CURVE: target.i = &ret->ecCurve; break;
        case KM_TAG_RSA_PUBLIC_EXPONENT: target.i = &ret->rsaPublicExponent; break;
        case KM_TAG_ROLLBACK_RESISTANCE: target.b = &ret->rollbackResistance; break;
        case KM_TAG_ACTIVE_DATETIME: target.i = &ret->activeDateTime; break;
        case KM_TAG_ORIGINATION_EXPIRE_DATETIME: target.i = &ret->originationExpireDateTime; break;
        case KM_TAG_USAGE_EXPIRE_DATETIME: target.i = &ret->usageExpireDateTime; break;
        case KM_TAG_USER_SECURE_ID: target.iset = &ret->userSecureId; break;
        case KM_TAG_NO_AUTH_REQUIRED: target.b = &ret->noAuthRequired; break;
        case KM_TAG_USER_AUTH_TYPE: target.i = &ret->userAuthType; break;
        case KM_TAG_AUTH_TIMEOUT: target.i = &ret->authTimeout; break;
        case KM_TAG_ALLOW_WHILE_ON_BODY: target.b = &ret->allowWhileOnBody; break;
        case KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED: target.b = &ret->trustedUserPresenceReq; break;
        case KM_TAG_TRUSTED_CONFIRMATION_REQUIRED: target.b = &ret->trustedConfirmationReq; break;
        case KM_TAG_UNLOCKED_DEVICE_REQUIRED: target.b = &ret->unlockedDeviceReq; break;
        case KM_TAG_CREATION_DATETIME: target.i = &ret->creationDateTime; break;
        case KM_TAG_ORIGIN: target.i = &ret->keyOrigin; break;
        case KM_TAG_OS_VERSION: target.i = &ret->osVersion; break;
        case KM_TAG_OS_PATCHLEVEL: target.i = &ret->osPatchLevel; break;
        case KM_TAG_ATTESTATION_APPLICATION_ID: target.str = &ret->attestationApplicationId; break;
        case KM_TAG_ATTESTATION_ID_BRAND: target.str = &ret->attestationIdBrand; break;
        case KM_TAG_ATTESTATION_ID_DEVICE: target.str = &ret->attestationIdDevice; break;
        case KM_TAG_ATTESTATION_ID_PRODUCT: target.str = &ret->attestationIdProduct; break;
        case KM_TAG_ATTESTATION_ID_SERIAL: target.str = &ret->attestationIdSerial; break;
        case KM_TAG_ATTESTATION_ID_IMEI: target.str = &ret->attestationIdImei; break;
        case KM_TAG_ATTESTATION_ID_MEID: target.str = &ret->attestationIdMeid; break;
        case KM_TAG_ATTESTATION_ID_MANUFACTURER: target.str = &ret->attestationIdManufacturer; break;
        case KM_TAG_ATTESTATION_ID_MODEL: target.str = &ret->attestationIdModel; break;
        case KM_TAG_VENDOR_PATCHLEVEL: target.i = &ret->vendorPatchLevel; break;
        case KM_TAG_BOOT_PATCHLEVEL: target.i = &ret->bootPatchLevel; break;
        case KM_TAG_INCLUDE_UNIQUE_ID: target.b = &ret->includeUniqueId; break;
        case KM_TAG_BLOB_USAGE_REQUIREMENTS: target.i = &ret->keyBlobUsageRequirements; break;
        case KM_TAG_BOOTLOADER_ONLY: target.b = &ret->bootloaderOnly; break;
        case KM_TAG_HARDWARE_TYPE: target.i = &ret->hardwareType; break;
        case KM_TAG_MIN_SECONDS_BETWEEN_OPS: target.i = &ret->minSecondsBetweenOps; break;
        case KM_TAG_MAX_USES_PER_BOOT: target.i = &ret->maxUsesPerBoot; break;
        case KM_TAG_USER_ID: target.i = &ret->userId; break;
        case KM_TAG_APPLICATION_ID: target.str = &ret->applicationId; break;
        case KM_TAG_APPLICATION_DATA: target.str = &ret->applicationData; break;
        case KM_TAG_UNIQUE_ID: target.str = &ret->uniqueId; break;
        case KM_TAG_ATTESTATION_CHALLENGE: target.str = &ret->attestationChallenge; break;
        case KM_TAG_ASSOCIATED_DATA: target.str = &ret->associatedData; break;
        case KM_TAG_NONCE: target.str = &ret->nonce; break;
        case KM_TAG_MAC_LENGTH: target.i = &ret->macLength; break;
        case KM_TAG_RESET_SINCE_ID_ROTATION: target.b = &ret->resetSinceIdRotation; break;
        case KM_TAG_CONFIRMATION_TOKEN: target.str = &ret->confirmationToken; break;
        case KM_TAG_AUTH_TOKEN: target.str = &ret->authToken; break;
        case KM_TAG_VERIFICATION_TOKEN: target.str = &ret->verificationToken; break;
        case KM_TAG_ALL_USERS: target.b = &ret->allUsers; break;
        case KM_TAG_ECIES_SINGLE_HASH_MODE: target.b = &ret->eciesSingleHashMode; break;
        case KM_TAG_KDF: target.i = &ret->kdf; break;
        case KM_TAG_EXPORTABLE: target.b = &ret->exportable; break;
        case KM_TAG_KEY_AUTH: target.b = &ret->keyAuth; break;
        case KM_TAG_OP_AUTH: target.b = &ret->opAuth; break;
        case KM_TAG_OPERATION_HANDLE: target.i = &ret->operationHandle; break;
        case KM_TAG_OPERATION_FAILED: target.b = &ret->operationFailed; break;
        case KM_TAG_INTERNAL_CURRENT_DATETIME: target.i = &ret->internalCurrentDateTime; break;
        case KM_TAG_EKEY_BLOB_IV: target.str = &ret->ekeyBlobIV; break;
        case KM_TAG_EKEY_BLOB_AUTH_TAG: target.str = &ret->ekeyBlobAuthTag; break;
        case KM_TAG_EKEY_BLOB_CURRENT_USES_PER_BOOT: target.i = &ret->ekeyBlobCurrentUsesPerBoot; break;
        case KM_TAG_EKEY_BLOB_LAST_OP_TIMESTAMP: target.i = &ret->ekeyBlobLastOpTimestamp; break;
        case KM_TAG_EKEY_BLOB_DO_UPGRADE: target.i = &ret->ekeyBlobDoUpgrade; break;
        case KM_TAG_EKEY_BLOB_PASSWORD: target.str = &ret->ekeyBlobPassword; break;
        case KM_TAG_EKEY_BLOB_SALT: target.str = &ret->ekeyBlobSalt; break;
        case KM_TAG_EKEY_BLOB_ENC_VER: target.i = &ret->ekeyBlobEncVer; break;
        case KM_TAG_EKEY_BLOB_RAW: target.i = &ret->ekeyBlobRaw; break;
        case KM_TAG_EKEY_BLOB_UNIQ_KDM: target.str = &ret->ekeyBlobUniqKDM; break;
        case KM_TAG_EKEY_BLOB_INC_USE_COUNT: target.i = &ret->ekeyBlobIncUseCount; break;
        case KM_TAG_SAMSUNG_REQUESTING_TA: target.str = &ret->samsungRequestingTA; break;
        case KM_TAG_SAMSUNG_ROT_REQUIRED: target.b = &ret->samsungRotRequired; break;
        case KM_TAG_SAMSUNG_LEGACY_ROT: target.b = &ret->samsungLegacyRot; break;
        case KM_TAG_USE_SECURE_PROCESSOR: target.b = &ret->useSecureProcessor; break;
        case KM_TAG_STORAGE_KEY: target.b = &ret->storageKey; break;
        case KM_TAG_INTEGRITY_STATUS: target.i = &ret->integrityStatus; break;
        case KM_TAG_IS_SAMSUNG_KEY: target.b = &ret->isSamsungKey; break;
        case KM_TAG_SAMSUNG_ATTESTATION_ROOT: target.str = &ret->samsungAttestationRoot; break;
        case KM_TAG_SAMSUNG_ATTEST_INTEGRITY: target.b = &ret->samsungAttestIntegrity; break;
        case KM_TAG_KNOX_OBJECT_PROTECTION_REQUIRED: target.b = &ret->knoxObjectProtectionRequired; break;
        case KM_TAG_KNOX_CREATOR_ID: target.str = &ret->knoxCreatorId; break;
        case KM_TAG_KNOX_ADMINISTRATOR_ID: target.str = &ret->knoxAdministratorId; break;
        case KM_TAG_KNOX_ACCESSOR_ID: target.str = &ret->knoxAccessorId; break;
        case KM_TAG_SAMSUNG_AUTHENTICATE_PACKAGE: target.str = &ret->samsungAuthPackage; break;
        case KM_TAG_SAMSUNG_CERTIFICATE_SUBJECT: target.str = &ret->samsungCertificateSubject; break;
        case KM_TAG_SAMSUNG_KEY_USAGE: target.i = &ret->samsungKeyUsage; break;
        case KM_TAG_SAMSUNG_EXTENDED_KEY_USAGE: target.str = &ret->samsungExtendedKeyUsage; break;
        case KM_TAG_SAMSUNG_SUBJECT_ALTERNATIVE_NAME: target.str = &ret->samsungSubjectAlternativeName; break;
        case KM_TAG_PROV_GAC_EC1: target.str = &ret->provGacEc1; break;
        case KM_TAG_PROV_GAC_EC2: target.str = &ret->provGacEc2; break;
        case KM_TAG_PROV_GAC_EC3: target.str = &ret->provGacEc3; break;
        case KM_TAG_PROV_GAK_EC: target.str = &ret->provGakEc; break;
        case KM_TAG_PROV_GAK_EC_VTOKEN: target.str = &ret->provGakEcVtoken; break;
        case KM_TAG_PROV_GAC_RSA1: target.str = &ret->provGacRsa1; break;
        case KM_TAG_PROV_GAC_RSA2: target.str = &ret->provGacRsa2; break;
        case KM_TAG_PROV_GAC_RSA3: target.str = &ret->provGacRsa3; break;
        case KM_TAG_PROV_GAK_RSA: target.str = &ret->provGakRsa; break;
        case KM_TAG_PROV_GAK_RSA_VTOKEN: target.str = &ret->provGakRsaVtoken; break;
        case KM_TAG_PROV_SAK_EC: target.str = &ret->provSakEc; break;
        case KM_TAG_PROV_SAK_EC_VTOKEN: target.str = &ret->provSakEcVtoken; break;
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
                if (*target.b != NULL) {
                    s_log_warn("Value already exists for tag 0x%08lx (%s); "
                            "not adding",
                            (long unsigned)tag, KM_Tag_toString((uint32_t)tag));
                    break;
                }

                *target.b = ASN1_NULL_new();
                if (*target.b == NULL)
                    goto_error("Failed allocate a new ASN.1 NULL");
            } else {
                s_log_warn("Not adding boolean value 0 to param list "
                        "(tag 0x%08lx - %s)",
                        (long unsigned)tag, KM_Tag_toString((uint32_t)tag));
            }
            break;

        case TARGET_INTEGER:
            if (*target.i != NULL) {
                s_log_warn("Value for INTEGER tag 0x%08lx (%s) already exists "
                        "with value 0x%08lx, freeing...",
                        (long unsigned) tag, KM_Tag_toString((uint32_t)tag),
                        (long unsigned)ASN1_INTEGER_get(*target.i)
                );
                ASN1_INTEGER_free(*target.i);
            }

            *target.i = ASN1_INTEGER_dup(curr->i);
            if (*target.i == NULL)
                goto_error("Failed to duplicate an ASN.1 INTEGER");
            break;

        case TARGET_INTEGER_SET:
            istmp = ASN1_INTEGER_dup(curr->i);
            if (istmp == NULL)
                goto_error("Failed to duplicate an ASN.1 INTEGER");

            if (*target.iset == NULL) {
                *target.iset = sk_ASN1_INTEGER_new_null();
                if (*target.iset == NULL)
                    goto_error("Failed to create a new ASN.1 INTEGER set");
            }

            {
                bool found = false;
                const int n_ints = sk_ASN1_INTEGER_num(*target.iset);
                for (int i = 0; i < n_ints; i++) {
                    const ASN1_INTEGER *curr =
                        sk_ASN1_INTEGER_value(*target.iset, i);
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

            if (sk_ASN1_INTEGER_push(*target.iset, istmp) <= 0)
                goto_error("Failed to push an ASN.1 INTEGER to the set");

            break;

        case TARGET_OCTET_STRING:
            if (*target.str != NULL) {
                s_log_warn("Value for OCTET_STRING tag 0x%08lx (%s) "
                        "already exists; freeing...",
                        (long unsigned) tag, KM_Tag_toString((uint32_t)tag)
                );
                ASN1_OCTET_STRING_free(*target.str);
            }

            *target.str = ASN1_OCTET_STRING_dup(curr->b);
            if (*target.str == NULL)
                goto_error("Failed to duplicate an ASN.1 OCTET_STRING");
            break;
        }
    }

    *out_param_list = ret;
    return 0;

err:
    if (ret != NULL) {
        KM_PARAM_LIST_SEQ_free(ret);
        ret = NULL;
    }

    *out_param_list = NULL;
    return 1;
}

} /* namespace ekey */

} /* namespace samsung */
} /* namespace cli */
} /* namespace suskeymaster */
