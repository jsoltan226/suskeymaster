#ifndef SUS_CERT_SIGN_H_
#define SUS_CERT_SIGN_H_

#include "certmod.h"
#include <core/int.h>
#include <core/vector.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

i32 sus_cert_sign(VECTOR(u8 const) tbs_der, VECTOR(u8) *out_sig,
        enum sus_key_variant variant);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* SUS_CERT_SIGN_H_ */
