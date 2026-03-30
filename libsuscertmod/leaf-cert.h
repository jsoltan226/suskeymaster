#ifndef SUS_CERT_MOD_CERT_PARSE_H_
#define SUS_CERT_MOD_CERT_PARSE_H_

#include <core/int.h>
#include <libgenericutil/cert-types.h>
#include <libgenericutil/keymaster-c-types.h>
#include <openssl/asn1.h>

#ifdef __cplusplus
extern "C" {
namespace suskeymaster {
namespace certmod {
using ::suskeymaster::util::sus_key_variant;
#endif /* __cplusplus */

i32 leaf_cert_parse(const VECTOR(u8) cert,
        enum sus_key_variant *out_variant,
        EVP_PKEY **out_subj_pubkey,
        struct KM_KeyDescription_v3 **out_km_desc
);

i32 leaf_cert_gen(VECTOR(u8) *out,
        enum sus_key_variant signing_key_variant,
        EVP_PKEY *subj_pubkey,
        const struct KM_KeyDescription_v3 *km_desc
);

#ifdef __cplusplus
} /* namespace certmod */
} /* namespace suskeymaster */
} /* extern "C" */
#endif /* __cplusplus */

#endif /* SUS_CERT_MOD_CERT_PARSE_H_ */
