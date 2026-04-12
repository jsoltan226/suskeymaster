#ifndef SUSKEYMASTER_UTIL_SAMSUNG_SUS_INDATA_H_
#define SUSKEYMASTER_UTIL_SAMSUNG_SUS_INDATA_H_

#define HIDL_DISABLE_INSTRUMENTATION
#include <openssl/asn1t.h>
#include <hidl/HidlSupport.h>

namespace suskeymaster {
namespace kmhal {
namespace util {

using ::android::hardware::hidl_vec;

enum send_indata_err {
    OK,
    INVALID_ARGUMENT,
    DLOPEN_KM_HELPER_FAILED,
    FILL_SERIALIZE_INDATA_FAILED,
    TEE_SEND_FAILED,
    TEE_RECV_FAILED,
    UNKNOWN_ERROR
};
typedef struct send_indata_err_st {
    ASN1_ENUMERATED *err;
} SUSKEYMASTER_SEND_INDATA_ERR;
DECLARE_ASN1_FUNCTIONS(SUSKEYMASTER_SEND_INDATA_ERR);

int serialize_send_indata_err(hidl_vec<uint8_t>& out, send_indata_err e);
int deserialize_send_indata_err(send_indata_err& out, hidl_vec<uint8_t> const& der);

} /* namespace util */
} /* namespace kmhal */

} /* namespace suskeymaster */

#endif /* SUSKEYMASTER_UTIL_SAMSUNG_SUS_INDATA_H_ */
