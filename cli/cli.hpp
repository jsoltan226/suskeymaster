#ifndef CLI_SUSKEYMASTER_HPP_
#define CLI_SUSKEYMASTER_HPP_

#include <libsuscertmod/certmod.h>
#include <libsuskmhal/hidl/hidl-hal.hpp>
#include <vector>
#include <string>
#include <cstdint>
#include <hidl/HidlSupport.h>
#include <android/hardware/keymaster/4.0/types.h>

namespace suskeymaster {
namespace cli {

using ::suskeymaster::kmhal::hidl::HidlSusKeymaster4;
using namespace ::android::hardware::keymaster::V4_0;
using ::android::hardware::hidl_vec;

namespace hidl_ops {

int generate_key(HidlSusKeymaster4& hal, Algorithm alg,
    hidl_vec<KeyParameter> const& in_gen_params,
    hidl_vec<uint8_t>& out_wrapped_blob);

int attest_key(HidlSusKeymaster4& hal,
    hidl_vec<uint8_t> const& key, hidl_vec<KeyParameter> const& in_attest_params);

int import_key(HidlSusKeymaster4& hal,
    hidl_vec<uint8_t> const& priv_pkcs8, Algorithm alg,
    hidl_vec<KeyParameter> const& in_import_params,
    hidl_vec<uint8_t>& out_wrapped_blob);

int export_key(HidlSusKeymaster4& hal,
    hidl_vec<uint8_t> const& key,
    hidl_vec<uint8_t>& out_public_key_x509);

int sign(HidlSusKeymaster4& hal, hidl_vec<uint8_t> const& message,
    hidl_vec<uint8_t> const& key, hidl_vec<KeyParameter> const& in_sign_params,
    hidl_vec<uint8_t>& out_signature);

/* Implemented in `sign.cpp` for convenience */
int get_key_characteristics(HidlSusKeymaster4& hal,
    hidl_vec<uint8_t> const& key, hidl_vec<KeyParameter> const& in_application_id_data);

} /* namespace hidl_ops */

namespace keybox {
    int make_kb(
        std::vector<std::string> const& ec_cert_paths, std::string const& ec_wrapped_key_path,
        std::vector<std::string> const& rsa_cert_paths, std::string const& rsa_wrapped_key_path,
        std::string const& out_file_path
    );
    int dump_kb(std::string const& keybox_path,
        std::string const& out_dir_path);

} /* namespace keybox */

namespace transact {
    namespace client {
        int generate_and_attest_wrapping_key(HidlSusKeymaster4& hal,
            hidl_vec<uint8_t>& out_wrapping_blob, hidl_vec<uint8_t>& out_wrapping_pubkey,
            hidl_vec<hidl_vec<uint8_t>> * out_opt_cert_chain,
            hidl_vec<KeyParameter> const& in_gen_params
        );
    }

    namespace server {
        int verify_attestation(hidl_vec<hidl_vec<uint8_t>> const& cert_chain);

        int wrap_key(hidl_vec<uint8_t> const& in_private_key,
            enum certmod::sus_key_variant in_key_variant,
            hidl_vec<uint8_t> const& in_wrapping_key, hidl_vec<KeyParameter> const& in_key_params,
            hidl_vec<uint8_t>& out_wrapped_data, hidl_vec<uint8_t>& out_masking_key);
    }

    namespace client {
        int import_wrapped_key(HidlSusKeymaster4& hal, hidl_vec<uint8_t> const& in_wrapped_data,
            hidl_vec<uint8_t> const& in_masking_key, hidl_vec<uint8_t> const& in_wrapping_blob,
            hidl_vec<KeyParameter> const& in_unwrapping_params,
            hidl_vec<uint8_t>& out_key_blob);
    };

} /* namespace transact */

} /* namespace cli */
} /* namespace suskeymaster */

#endif /* CLI_SUSKEYMASTER_HPP_ */
