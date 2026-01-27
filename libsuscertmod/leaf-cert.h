#ifndef SUS_CERT_MOD_CERT_PARSE_H_
#define SUS_CERT_MOD_CERT_PARSE_H_

#include "certmod.h"
#include "keymaster-types.h"
#include <core/int.h>
#include <openssl/asn1.h>

i32 leaf_cert_parse(const VECTOR(u8) cert,
        enum sus_cert_chain_variant *out_variant,
        EVP_PKEY **out_subj_pubkey,
        struct KM_KeyDescription_v3 **out_km_desc
);

i32 leaf_cert_gen(VECTOR(u8) *out,
        enum sus_cert_chain_variant signing_key_variant,
        EVP_PKEY *subj_pubkey,
        const struct KM_KeyDescription_v3 *km_desc
);

#endif /* SUS_CERT_MOD_CERT_PARSE_H_ */
