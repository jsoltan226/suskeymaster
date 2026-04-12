#define HIDL_DISABLE_INSTRUMENTATION
#include "samsung-sus-indata.hpp"
#include <core/log.h>
#include <openssl/asn1t.h>
#include <openssl/crypto.h>

#define MODULE_NAME "samsung-sus-indata"

namespace suskeymaster {
namespace kmhal {
namespace util {

ASN1_SEQUENCE(SUSKEYMASTER_SEND_INDATA_ERR) = {
    ASN1_SIMPLE(SUSKEYMASTER_SEND_INDATA_ERR, err, ASN1_ENUMERATED)
} ASN1_SEQUENCE_END(SUSKEYMASTER_SEND_INDATA_ERR)
IMPLEMENT_ASN1_FUNCTIONS(SUSKEYMASTER_SEND_INDATA_ERR)

int serialize_send_indata_err(hidl_vec<uint8_t>& out, send_indata_err e)
{

    SUSKEYMASTER_SEND_INDATA_ERR *asn1 = SUSKEYMASTER_SEND_INDATA_ERR_new();
    int64_t v = static_cast<int64_t>(e);
    if (!ASN1_ENUMERATED_set_int64(asn1->err, v)) {
        s_log_error("Failed to set the value of an ASN.1 ENUMERATED field");
        SUSKEYMASTER_SEND_INDATA_ERR_free(asn1);
        return 1;
    }

    unsigned char *der = NULL;
    long len = i2d_SUSKEYMASTER_SEND_INDATA_ERR(asn1, &der);
    if (len <= 0) {
        s_log_error("Failed to i2d the SEND_INDATA_ERR sequence");
        SUSKEYMASTER_SEND_INDATA_ERR_free(asn1);
        return 1;
    }

    out.resize(len);
    std::memcpy(out.data(), der, len);

    OPENSSL_free(der);
    SUSKEYMASTER_SEND_INDATA_ERR_free(asn1);
    return 0;
}

int deserialize_send_indata_err(send_indata_err& out, hidl_vec<uint8_t> const& der)
{
    const unsigned char *p = der.data();
    SUSKEYMASTER_SEND_INDATA_ERR *asn1 =
        d2i_SUSKEYMASTER_SEND_INDATA_ERR(NULL, &p, der.size());
    if (asn1 == NULL || p != der.data() + der.size()) {
        if (asn1) SUSKEYMASTER_SEND_INDATA_ERR_free(asn1);
        s_log_error(
                "Failed to d2i the SEND_INDATA_ERR sequence");
        return 1;
    }

    int64_t v;
    if (!ASN1_ENUMERATED_get_int64(&v, asn1->err)) {
        s_log_error("Failed to get the value of an ASN.1 ENUMERATED field");
        SUSKEYMASTER_SEND_INDATA_ERR_free(asn1);
        return 1;
    }
    v &= 0x00000000FFFFFFFF;

    out = static_cast<send_indata_err>(v);
    return 0;
}

} /* namespace util */
} /* namespace kmhal */
} /* namespace suskeymaster */
