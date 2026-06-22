#ifndef SUSKEYMASTER_GENERIC_UTIL_KM_PARAMS_H_
#define SUSKEYMASTER_GENERIC_UTIL_KM_PARAMS_H_

#define HIDL_DISABLE_INSTRUMENTATION

#include "../keymaster-types-c.h"
#include "../keymaster-types-cpp.hpp"
#include <vector>
#include <cstdint>

namespace suskeymaster {
namespace kmhal {
namespace util {

using namespace generic;
using namespace ::android::hardware;

int parse_km_tag_params(const char *arg,
        std::vector<KeyParameter>& out);

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

    friend void init_default_params(std::vector<KeyParameter>&,
        std::vector<struct km_default> const&);
};
void init_default_params(std::vector<KeyParameter>& params,
    std::vector<struct km_default> const& defaults);

KM_PARAM_LIST * key_params_2_param_list(std::vector<KeyParameter> const& params);

void dump_params_as_param_list(std::vector<KeyParameter> const& params);

int b64decode(std::string const& in, std::vector<uint8_t> &out);

static inline std::vector<u8> get_attestation_challenge(void) {
    static const u8 challenge[] = "suskeymaster";
    static const size_t challenge_len = sizeof(challenge) - 1;

    return std::vector<u8>(challenge, challenge + challenge_len);
}

static inline std::vector<u8> get_attestation_application_id(void) {
    static const u8 att_application_id[] = "suskeymaster TEST ATTESTATION APPLICATION ID";
    static const size_t att_application_id_len = sizeof(att_application_id) - 1;

    return std::vector<u8>(att_application_id, att_application_id + att_application_id_len);
}

} /* namespace util */
} /* namespace kmhal */
} /* namespace suskeymaster */

#endif /* SUSKEYMASTER_GENERIC_UTIL_KM_PARAMS_H_ */
