#ifndef SUS_CERT_SIGN_H_
#define SUS_CERT_SIGN_H_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define SUS_CERT_SIGN_EC 1
#define SUS_CERT_SIGN_RSA 0

int sus_cert_sign(unsigned char *tbs_der, unsigned long tbs_der_len,
        unsigned char **out_sig, unsigned long *out_sig_len,
        int ec_or_rsa);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* SUS_CERT_SIGN_H_ */
