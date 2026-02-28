#ifndef SUS_CERT_SIGN_KEYS_H_
#define SUS_CERT_SIGN_KEYS_H_

#ifdef __cplusplus
namespace suskeymaster {
extern "C" {
#endif /* __cplusplus */

extern const unsigned char sus_sign_ec_wrapped_blob_bin[];
extern const unsigned int sus_sign_ec_wrapped_blob_bin_len;

extern const unsigned char sus_sign_rsa_wrapped_blob_bin[];
extern const unsigned int sus_sign_rsa_wrapped_blob_bin_len;

#ifdef __cplusplus
} /* extern "C" */
} /* namespace suskeymaster */
#endif /* __cplusplus */

#endif /* SUS_CERT_SIGN_KEYS_H_ */
