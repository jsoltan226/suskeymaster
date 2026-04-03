#ifndef SUS_CERT_MOD_CERT_PARSE_H_
#define SUS_CERT_MOD_CERT_PARSE_H_

#define OPENSSL_API_COMPAT 0x10002000L
#include "certmod.h"
#include <core/int.h>
#include <core/vector.h>
#include <libsuskmhal/keymaster-types-c.h>
#include <openssl/crypto.h>

#ifdef __cplusplus
extern "C" {
namespace suskeymaster {
namespace certmod {
using ::suskeymaster::kmhal::KM_KeyDescription_v3;
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
