#ifndef SUS_CERT_MOD_H_
#define SUS_CERT_MOD_H_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <core/int.h>
#include <core/vector.h>

enum sus_cert_chain_variant {
    SUS_CERT_CHAIN_INVALID_,
    SUS_CERT_CHAIN_EC,
    SUS_CERT_CHAIN_RSA,
    SUS_CERT_CHAIN_MAX_
};

i32 sus_cert_generate_leaf(const VECTOR(u8) old_leaf,
        enum sus_cert_chain_variant *out_variant, VECTOR(u8) *out_new_leaf);

VECTOR(VECTOR(u8 const) const)
sus_cert_retrieve_chain(enum sus_cert_chain_variant variant);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* SUS_CERT_MOD_H_ */
