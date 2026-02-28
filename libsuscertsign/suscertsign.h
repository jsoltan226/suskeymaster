#ifndef SUS_CERT_SIGN_H_
#define SUS_CERT_SIGN_H_

#include <core/int.h>
#include <core/vector.h>
#include <libgenericutil/cert-types.h>

#ifdef __cplusplus
namespace suskeymaster {
extern "C" {
#endif /* __cplusplus */

int sus_cert_sign(unsigned char *tbs_der, unsigned long tbs_der_len,
        unsigned char **out_sig, unsigned long *out_sig_len,
        enum sus_key_variant variant);

VECTOR(VECTOR(u8 const) const)
sus_cert_sign_retrieve_chain(enum sus_key_variant variant);

int sus_cert_sign_retrieve_chain_data(enum sus_key_variant variant,
    const char **out_top_issuer_serial, i64 *out_not_after);

#ifdef __cplusplus
} /* extern "C" */
} /* namespace suskeymaster */
#endif /* __cplusplus */

#endif /* SUS_CERT_SIGN_H_ */
