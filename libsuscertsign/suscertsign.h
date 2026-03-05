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

#ifdef __cplusplus
} /* extern "C" */
} /* namespace suskeymaster */
#endif /* __cplusplus */

#endif /* SUS_CERT_SIGN_H_ */
