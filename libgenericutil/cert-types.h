#ifndef SUSKEYMASTER_GENERIC_UTIL_CERT_TYPES_H_
#define SUSKEYMASTER_GENERIC_UTIL_CERT_TYPES_H_

#ifdef __cplusplus
namespace suskeymaster {
namespace util {
extern "C" {
#endif /* __cplusplus */

enum sus_key_variant {
    SUS_KEY_INVALID_,
    SUS_KEY_EC,
    SUS_KEY_RSA,
    SUS_KEY_MAX_
};

#ifdef __cplusplus
} /* extern "C" */
} /* namespace util */
} /* namespace suskeymaster */
#endif /* __cplusplus */

#endif /* SUSKEYMASTER_GENERIC_UTIL_CERT_TYPES_H_ */
