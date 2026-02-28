#ifndef CERTS_H_
#define CERTS_H_

#include <core/vector.h>

#ifdef __cplusplus
namespace suskeymaster {
extern "C" {
#endif /* __cplusplus */

extern VECTOR(VECTOR(u8 const) const) const cert_chain_rsa;

extern VECTOR(VECTOR(u8 const) const) const cert_chain_ec;

extern const char *const cert_chain_rsa_top_issuer_serial;
extern const char *const cert_chain_ec_top_issuer_serial;

extern const i64 cert_chain_rsa_not_after;
extern const i64 cert_chain_ec_not_after;

#ifdef __cplusplus
} /* extern "C" */
} /* namespace suskeymaster */
#endif /* __cplusplus */

#endif /* CERTS_H_ */
