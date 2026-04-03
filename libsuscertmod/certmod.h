#ifndef SUS_CERT_MOD_H_
#define SUS_CERT_MOD_H_

#include <core/int.h>
#include <core/vector.h>

#ifdef __cplusplus
extern "C" {
namespace suskeymaster {
namespace certmod {
#endif /* __cplusplus */

enum sus_key_variant {
    SUS_KEY_INVALID_,
    SUS_KEY_EC,
    SUS_KEY_RSA,
    SUS_KEY_MAX_
};

i32 sus_cert_generate_leaf(const VECTOR(u8) old_leaf,
        enum sus_key_variant *out_variant, VECTOR(u8) *out_new_leaf);

#ifdef __cplusplus
} /* namespace certmod */
} /* namespace suskeymaster */
} /* extern "C" */
#endif /* __cplusplus */

#endif /* SUS_CERT_MOD_H_ */
