#ifndef SUS_CERT_MOD_H_
#define SUS_CERT_MOD_H_

#include "samsung-sus-indata.h"
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

#ifdef SUSKEYMASTER_ENABLE_SAMSUNG_SEND_INDATA
i32 sus_cert_generate_leaf(const VECTOR(u8) old_leaf,
        bool *out_is_sus_send_indata,
        enum sus_key_variant *out_variant, VECTOR(u8) *out_new_leaf);
#else
i32 sus_cert_generate_leaf(const VECTOR(u8) old_leaf,
        enum sus_key_variant *out_variant, VECTOR(u8) *out_new_leaf);
#endif /* SUSKEYMASTER_ENABLE_SAMSUNG_SEND_INDATA */

#ifdef __cplusplus
} /* namespace certmod */
} /* namespace suskeymaster */
} /* extern "C" */
#endif /* __cplusplus */

#endif /* SUS_CERT_MOD_H_ */
