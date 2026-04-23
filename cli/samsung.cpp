#define HIDL_DISABLE_INSTRUMENTATION
#include "cli.hpp"
#include <core/log.h>
#include <core/math.h>
#include <core/util.h>
#include <libsuskmhal/hidl/hidl-hal.hpp>
#include <libsuskmhal/util/dump-utils.h>
#include <libsuskmhal/util/samsung-utils.h>
#include <libsuskmhal/util/keymaster-types-c.h>
#include <libsuskmhal/util/samsung-sus-indata.hpp>
#include <android/hardware/keymaster/4.0/types.h>
#include <cstdarg>
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

static void pr_info(const char *fmt, ...)
{
    va_list vlist;
    va_start(vlist, fmt);
    s_logv(S_LOG_INFO, MODULE_NAME, fmt, vlist);
    va_end(vlist);
}

using namespace kmhal::util;

static int dump_and_serialize_indata(hidl_vec<uint8_t>& out,
        uint32_t *ver, uint32_t *km_ver, uint32_t cmd, uint32_t *pid,
        uint32_t *int0, uint64_t *long0, uint64_t *long1, const hidl_vec<uint8_t> *bin0,
        const hidl_vec<uint8_t> *bin1, const hidl_vec<uint8_t> *bin2,
        const hidl_vec<uint8_t> *key, const hidl_vec<KeyParameter> *par
);
static int deserialize_and_dump_outdata(hidl_vec<hidl_vec<uint8_t>> const& cert_chain);

namespace ekey {

static int km_tag_cmp(KeyParameter const& kp, KM_SAMSUNG_PARAM *p);

static int deserialize_ekey_blob(const hidl_vec<uint8_t>& ekey, KM_SAMSUNG_EKEY_BLOB *& out);
static int serialize_ekey_blob(KM_SAMSUNG_EKEY_BLOB *& ekey, hidl_vec<uint8_t>& out_ekey_der);

int list_tags(const hidl_vec<uint8_t> &in_keyblob)
{
    int ret = -1;

    KM_SAMSUNG_EKEY_BLOB *ekey = NULL;
    KM_PARAM_LIST *param_list = NULL;
    const char *old_line = NULL;

    if (deserialize_ekey_blob(in_keyblob, ekey))
        goto_error("Failed to deserialize the encrypted key blob!");

    if (KM_samsung_paramset_to_param_list(ekey->enc_par, &param_list))
        goto_error("Failed to parse the encrypted key blob parameters!");

    s_configure_log_line(S_LOG_INFO, "%s\n", &old_line);
    KM_dump_param_list(pr_info, param_list, 0, NULL);
    s_configure_log_line(S_LOG_INFO, old_line, NULL);
    ret = 0;

err:
    if (param_list != NULL) {
        KM_PARAM_LIST_free(param_list);
        param_list = NULL;
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

    int n_params = 0;

    KM_SAMSUNG_EKEY_BLOB *ekey = NULL;
    std::unordered_map<int64_t, std::vector<KM_SAMSUNG_PARAM *>> blob_params_map;

    if (deserialize_ekey_blob(in_keyblob, ekey))
        goto_error("Couldn't deserialize the encrypted key blob");

    n_params = sk_KM_SAMSUNG_PARAM_num(ekey->enc_par);
    if (n_params < 0)
        goto_error("Couldn't get the number of parameters in stack");
    for (int i = 0; i < n_params; i++) {
        KM_SAMSUNG_PARAM *const curr =
            sk_KM_SAMSUNG_PARAM_value(ekey->enc_par, i);
        if (curr == NULL)
            goto_error("Couldn't get parameter value from stack");

        int64_t t = 0;
        if (!ASN1_INTEGER_get_int64(&t, curr->tag))
            goto_error("Couldn't get the value of an ASN.1 INTEGER");
        t &= 0x00000000FFFFFFFF;

        blob_params_map[t].push_back(curr);
    }

    for (const auto& kp : in_tags_to_add) {
        const int64_t t = static_cast<int64_t>(kp.tag);

        const auto& found = blob_params_map.find(t);
        const bool exists = found != blob_params_map.end()
            && found->second.size() > 0;

        if (exists) {
            if (KM_Tag_is_repeatable(t)) {
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

                    if (KM_samsung_make_integer_param(&new_par,
                                static_cast<uint32_t>(kp.tag), kp.f.longInteger))
                        goto err;

                    if (KM_samsung_push_param_or_free(ekey->enc_par, new_par))
                        goto err;
                } else {
                    s_log_warn("Repeatable tag 0x%08lx (%s) with value 0x%016llx "
                            "already exists; not adding",
                            (long unsigned)kp.tag, KM_Tag_toString((uint32_t)kp.tag),
                            (long long unsigned)kp.f.longInteger);
                }
            } else {
                KM_SAMSUNG_PARAM *p = found->second[0];
                if (KM_samsung_is_integer_param(t)) {
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

            if (KM_samsung_is_integer_param(t)) {
                s_log_info("Adding tag 0x%08lx (%s) with integer value: 0x%016llx",
                        (long unsigned)kp.tag, KM_Tag_toString((uint32_t)kp.tag),
                        (long long unsigned)kp.f.longInteger);

                if (KM_samsung_make_integer_param(&new_par,
                            static_cast<uint32_t>(kp.tag), kp.f.longInteger))
                    goto err;
            } else {
                s_log_info("Adding tag 0x%08lx (%s) with octet string value...",
                        (long unsigned)kp.tag, KM_Tag_toString((uint32_t)kp.tag));

                if (KM_samsung_make_octet_string_param(&new_par, static_cast<uint32_t>(kp.tag),
                            kp.blob.data(), kp.blob.size()))
                    goto err;
            }

            if (KM_samsung_push_param_or_free(ekey->enc_par, new_par))
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

    if (deserialize_ekey_blob(in_keyblob, ekey))
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
                if (KM_samsung_is_integer_param(t)) {
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
            if (KM_Tag_is_repeatable(t)) {
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
        if (dump_and_serialize_indata(indata_der, ver, km_ver, cmd, pid,
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

        s_log_info("Sending cmd 0x%llx...", (long long unsigned)cmd);

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

static int dump_and_serialize_indata(hidl_vec<uint8_t>& out,
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
     * or left to be filled in by libsuskeymaster (by setting them to `0`) */

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
            if (KM_samsung_is_integer_param(static_cast<int64_t>(kp.tag))) {

                if (KM_samsung_make_integer_param(&new_par,
                            (uint32_t)kp.tag, (int64_t)kp.f.longInteger))
                    goto_error("Failed to make a new samsung INTEGER KM_PARAM");
            } else {
                if (KM_samsung_make_octet_string_param(&new_par, (uint32_t)kp.tag,
                            kp.blob.data(), kp.blob.size()))
                    goto_error("Failed to make a new samsung OCTET_STRING KM_PARAM");
            }

            if (KM_samsung_push_param_or_free(indata->par, new_par))
                goto err;
        }
    }

    {
        const char *old_line = NULL;
        s_configure_log_line(S_LOG_INFO, "%s\n", &old_line);
        KM_samsung_dump_indata(pr_info, indata, 0, NULL);
        s_configure_log_line(S_LOG_INFO, old_line, NULL);
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

    {
        const char *old_line = NULL;
        s_configure_log_line(S_LOG_INFO, "%s\n", &old_line);
        KM_samsung_dump_outdata(pr_info, outdata, 0, NULL);
        s_configure_log_line(S_LOG_INFO, old_line, NULL);
    }

err:
    if (outdata != NULL) {
        KM_SAMSUNG_OUTDATA_free(outdata);
        outdata = NULL;
    }
    if (ret != 0)
        return ret;

    return 0;
}

namespace ekey {

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
        if (!KM_Tag_is_repeatable(pt))
            return 0;

        if (KM_samsung_is_integer_param(pt)) {
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

static int deserialize_ekey_blob(const hidl_vec<uint8_t>& ekey, KM_SAMSUNG_EKEY_BLOB *& out)
{
    const unsigned char *p = ekey.data();
    long len = (long)ekey.size();
    KM_SAMSUNG_EKEY_BLOB *ekey_blob = NULL;

    ekey_blob = d2i_KM_SAMSUNG_EKEY_BLOB(NULL, &p, len);
    if (ekey_blob == NULL)
        goto_error("Failed to d2i the encrypted key blob");

    {
        int64_t blob_ver = 0;
        if (!ASN1_INTEGER_get_int64(&blob_ver, ekey_blob->enc_ver))
            goto_error("Couldn't get the encrypted key blob version INTEGER");
        s_log_info("Encrypted key blob version: %lli", (long long int)blob_ver);
    }

    out = ekey_blob;

    return 0;

err:
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

} /* namespace ekey */

} /* namespace samsung */
} /* namespace cli */
} /* namespace suskeymaster */
