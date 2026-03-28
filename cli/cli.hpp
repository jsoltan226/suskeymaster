#ifndef CLI_SUSKEYMASTER_HPP_
#define CLI_SUSKEYMASTER_HPP_

#include "hidl-hal.hpp"
#include <libgenericutil/cert-types.h>
#include <libsuscertmod/keymaster-types.h>
#include <unordered_map>
#include <vector>
#include <string>
#include <cstdint>
#include <utils/StrongPointer.h>
#include "../aosp-headers/include-keymaster/android/hardware/keymaster/4.0/types.h"
#include "../aosp-headers/include-keymaster/android/hardware/keymaster/4.0/IKeymasterDevice.h"

namespace suskeymaster {
namespace cli {

int generate_key(
    HidlSusKeymaster4&                                                      hal,
    ::android::hardware::keymaster::V4_0::Algorithm                         alg,
    ::android::hardware::hidl_vec
        <::android::hardware::keymaster::V4_0::KeyParameter> const&         in_gen_params,

    ::android::hardware::hidl_vec<uint8_t>&                                 out_wrapped_blob
);
int attest_key(
    HidlSusKeymaster4&                                                      hal,
    ::android::hardware::hidl_vec<uint8_t> const&                           key,
    ::android::hardware::hidl_vec
        <::android::hardware::keymaster::V4_0::KeyParameter> const&         in_attest_params
);

int import_key(
    HidlSusKeymaster4&                                                      hal,
    ::android::hardware::hidl_vec<uint8_t> const&                           priv_pkcs8,
    ::android::hardware::keymaster::V4_0::Algorithm                         alg,
    ::android::hardware::hidl_vec
        <::android::hardware::keymaster::V4_0::KeyParameter> const&         in_import_params,

    ::android::hardware::hidl_vec<uint8_t>&                                 out_wrapped_blob
);
int export_key(
    HidlSusKeymaster4&                                                      hal,
    ::android::hardware::hidl_vec<uint8_t> const&                           key,

    ::android::hardware::hidl_vec<uint8_t>&                                 out_public_key_x509
);

int sign(
    HidlSusKeymaster4&                                                      hal,
    ::android::hardware::hidl_vec<uint8_t> const&                           message,
    ::android::hardware::hidl_vec<uint8_t> const&                           key,
    ::android::hardware::hidl_vec
        <::android::hardware::keymaster::V4_0::KeyParameter> const&         in_sign_params,

    ::android::hardware::hidl_vec<uint8_t>&                                 out_signature
);

/* Implemented in `sign.cpp` for convenience */
int get_key_characteristics(
    HidlSusKeymaster4&                                                      hal,
    ::android::hardware::hidl_vec<uint8_t> const&                           key,
    ::android::hardware::hidl_vec
        <::android::hardware::keymaster::V4_0::KeyParameter> const&         in_application_id_data
);

namespace keybox {
    int make_kb(
        std::vector<std::string> const& ec_cert_paths,
        std::string const& ec_wrapped_key_path,

        std::vector<std::string> const& rsa_cert_paths,
        std::string const& rsa_wrapped_key_path,

        std::string const& out_file_path
    );
    int dump_kb(
        std::string const& keybox_path,

        std::string const& out_dir_path
    );
} /* namespace keybox */

namespace transact {
    namespace client {
        int generate_and_attest_wrapping_key(
            HidlSusKeymaster4&                                                  hal,

            ::android::hardware::hidl_vec<uint8_t>&                             out_wrapping_blob,
            ::android::hardware::hidl_vec<uint8_t>&                             out_wrapping_pubkey,
            ::android::hardware::hidl_vec<::android::hardware::hidl_vec<uint8_t>> * out_cert_chain,
            ::android::hardware::hidl_vec
                <::android::hardware::keymaster::V4_0::KeyParameter> const&     in_gen_params
        );
    }

    namespace server {
        int verify_attestation(
            ::android::hardware::hidl_vec<::android::hardware::hidl_vec<uint8_t>> const& cert_chain
        );

        int wrap_key(
            ::android::hardware::hidl_vec<uint8_t> const&                       in_private_key,
            enum ::suskeymaster::util::sus_key_variant                          in_key_variant,
            ::android::hardware::hidl_vec<uint8_t> const&                       in_wrapping_key,
            ::android::hardware::hidl_vec
                <::android::hardware::keymaster::V4_0::KeyParameter> const&     in_key_params,

            ::android::hardware::hidl_vec<uint8_t>&                             out_wrapped_data,
            ::android::hardware::hidl_vec<uint8_t>&                             out_masking_key
        );
    }

    namespace client {
        int import_wrapped_key(
            HidlSusKeymaster4&                                                  hal,

            ::android::hardware::hidl_vec<uint8_t> const&                       in_wrapped_data,
            ::android::hardware::hidl_vec<uint8_t> const&                       in_masking_key,
            ::android::hardware::hidl_vec<uint8_t> const&                       in_wrapping_blob,
            ::android::hardware::hidl_vec
                <::android::hardware::keymaster::V4_0::KeyParameter> const& in_unwrapping_params,

            ::android::hardware::hidl_vec<uint8_t>&                             out_key_blob
        );
    };

} /* namespace transact */

int parse_km_tag_params(
        const char *                                                            arg,

        ::android::hardware::hidl_vec<::android::hardware::keymaster::V4_0::KeyParameter>& out
);

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

    friend void init_default_params(
        ::android::hardware::hidl_vec<::android::hardware::keymaster::V4_0::KeyParameter>&,
        std::vector<struct km_default>
    );
};
void init_default_params(
    ::android::hardware::hidl_vec<::android::hardware::keymaster::V4_0::KeyParameter>& params,
    std::vector<struct km_default> defaults
);

void key_params_2_auth_list(
        ::android::hardware::hidl_vec
            <::android::hardware::keymaster::V4_0::KeyParameter> const& params,
        struct certmod::KM_AuthorizationList_v3 *out
);

} /* namespace cli */
} /* namespace suskeymaster */

#endif /* CLI_SUSKEYMASTER_HPP_ */
