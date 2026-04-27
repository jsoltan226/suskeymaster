#ifndef SUS_CERT_MOD_SAMSUNG_SUS_INDATA_H_
#define SUS_CERT_MOD_SAMSUNG_SUS_INDATA_H_

#ifndef SUSKEYMASTER_BUILD_HOST
#define SUSKEYMASTER_ENABLE_SAMSUNG_SEND_INDATA
#endif /* SUSKEYMASTER_BUILD_HOST */

#ifdef __cplusplus
namespace suskeymaster {
namespace certmod {
extern "C" {
#endif /* __cplusplus */

static const __attribute__((unused))
unsigned char g_send_indata_att_challenge[] = {
    's', 'u', 's', '_', 's', 'e', 'n', 'd', '_', 'i', 'n', 'd', 'a', 't', 'a'
};
static const __attribute__((unused))
unsigned int g_send_indata_att_challenge_len = sizeof(g_send_indata_att_challenge);

#ifdef __cplusplus
} /* extern "C" */
} /* namespace certmod */
} /* namespace suskeymaster */
#endif /* __cplusplus */

#endif /* SUS_CERT_MOD_SAMSUNG_SUS_INDATA_H_ */
