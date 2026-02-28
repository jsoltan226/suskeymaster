#ifndef SUS_CERT_MOD_H_
#define SUS_CERT_MOD_H_

#include <core/int.h>
#include <core/vector.h>

#include <libgenericutil/cert-types.h>

#ifdef __cplusplus
extern "C" {
namespace suskeymaster {
#endif /* __cplusplus */

i32 sus_cert_generate_leaf(const VECTOR(u8) old_leaf,
        enum sus_key_variant *out_variant, VECTOR(u8) *out_new_leaf);

#ifdef __cplusplus
} /* namespace suskeymaster */
} /* extern "C" */
#endif /* __cplusplus */

#endif /* SUS_CERT_MOD_H_ */
