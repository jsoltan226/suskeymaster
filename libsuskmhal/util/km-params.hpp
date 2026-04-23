#ifndef SUSKEYMASTER_GENERIC_UTIL_KM_PARAMS_H_
#define SUSKEYMASTER_GENERIC_UTIL_KM_PARAMS_H_

#define HIDL_DISABLE_INSTRUMENTATION

#include "keymaster-types-c.h"
#include <vector>
#include <cstdint>
#include <hidl/HidlSupport.h>
#include <android/hardware/keymaster/4.0/types.h>

namespace suskeymaster {
namespace kmhal {
namespace util {

using namespace ::android::hardware::keymaster::V4_0;
using namespace ::android::hardware;

int parse_km_tag_params(const char *arg,
        hidl_vec<KeyParameter>& out);

struct km_default {
public:
    km_default(Tag, Algorithm);
    km_default(Tag, std::vector<BlockMode> const&);
    km_default(Tag, std::vector<PaddingMode> const&);
    km_default(Tag, std::vector<Digest> const&);
    km_default(Tag, EcCurve);
    km_default(Tag, KeyOrigin);
    km_default(Tag, KeyBlobUsageRequirements);
    km_default(Tag, std::vector<KeyPurpose> const&);
    km_default(Tag, std::vector<KeyDerivationFunction> const&);
    km_default(Tag, HardwareAuthenticatorType);
    km_default(Tag, SecurityLevel);
    km_default(Tag, bool);
    km_default(Tag, uint32_t);
    km_default(Tag, int);
    km_default(Tag, long);
    km_default(Tag, uint64_t);

    km_default(Tag, std::vector<uint8_t>);

private:
    std::vector<KeyParameter> val = {};
    bool found = false;

    friend void init_default_params(hidl_vec<KeyParameter>&,
        std::vector<struct km_default> const&);
};
void init_default_params(hidl_vec<KeyParameter>& params,
    std::vector<struct km_default> const& defaults);

KM_PARAM_LIST * key_params_2_param_list(hidl_vec<KeyParameter> const& params);

int b64decode(std::string const& in, std::vector<uint8_t> &out);

} /* namespace util */
} /* namespace kmhal */
} /* namespace suskeymaster */

#endif /* SUSKEYMASTER_GENERIC_UTIL_KM_PARAMS_H_ */
