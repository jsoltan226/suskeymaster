#ifndef SUS_CERT_MOD_SAMSUNG_SUS_INDATA_H_
#define SUS_CERT_MOD_SAMSUNG_SUS_INDATA_H_

#define SUSKEYMASTER_ENABLE_SAMSUNG_SEND_INDATA

#ifdef SUSKEYMASTER_ENABLE_SAMSUNG_SEND_INDATA

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
#endif /* SUSKEYMASTER_ENABLE_SAMSUNG_SEND_INDATA */

#ifdef __cplusplus
} /* extern "C" */
} /* namespace certmod */
} /* namespace suskeymaster */
#endif /* __cplusplus */

#endif /* SUS_CERT_MOD_SAMSUNG_SUS_INDATA_H_ */
