#ifndef CLI_SUSKEYMASTER_HPP_
#define CLI_SUSKEYMASTER_HPP_

#include <libsuskmhal/hidl/hidl-hal.hpp>
#include <vector>
#include <string>
#include <cstdint>
#include <hidl/HidlSupport.h>
#include <android/hardware/keymaster/4.0/types.h>
#include <openssl/evp.h>

namespace suskeymaster {
namespace cli {

using ::suskeymaster::kmhal::hidl::HidlSusKeymaster4;
using namespace ::android::hardware::keymaster::V4_0;
using ::android::hardware::hidl_vec;

namespace hal_ops {

int get_key_characteristics(HidlSusKeymaster4& hal,
    hidl_vec<uint8_t> const& key, hidl_vec<KeyParameter> const& in_application_id_data);

int generate_key(HidlSusKeymaster4& hal,
    hidl_vec<KeyParameter> const& in_gen_params,
    hidl_vec<uint8_t>& out_wrapped_blob);

int attest_key(HidlSusKeymaster4& hal,
    hidl_vec<uint8_t> const& key, hidl_vec<KeyParameter> const& in_attest_params);

int import_key(HidlSusKeymaster4& hal,
    hidl_vec<uint8_t> const& priv_pkcs8,
    hidl_vec<KeyParameter> const& in_import_params,
    hidl_vec<uint8_t>& out_wrapped_blob);

int export_key(HidlSusKeymaster4& hal,
    hidl_vec<uint8_t> const& key,
    hidl_vec<uint8_t>& out_public_key_x509,
    hidl_vec<KeyParameter> const& in_application_id_data);

int upgrade_key(HidlSusKeymaster4& hal,
    hidl_vec<uint8_t> const& in_keyblob_to_upgrade,
    hidl_vec<KeyParameter> const& in_upgrade_params,
    hidl_vec<uint8_t>& out_upgraded_keyblob);

namespace crypto {
    int encrypt(HidlSusKeymaster4& hal, hidl_vec<uint8_t> const& plaintext,
            hidl_vec<uint8_t> const& key, hidl_vec<KeyParameter> const& encrypt_params,
            hidl_vec<uint8_t>& out_ciphertext);

    int decrypt(HidlSusKeymaster4& hal, hidl_vec<uint8_t> const& ciphertext,
            hidl_vec<uint8_t> const& key, hidl_vec<KeyParameter> const& decrypt_params,
            hidl_vec<uint8_t>& out_plaintext);

    int sign(HidlSusKeymaster4& hal, hidl_vec<uint8_t> const& message,
        hidl_vec<uint8_t> const& key, hidl_vec<KeyParameter> const& in_sign_params,
        hidl_vec<uint8_t>& out_signature);

    int verify(HidlSusKeymaster4& hal,
        hidl_vec<uint8_t> const& message, hidl_vec<uint8_t> const& signature,
        hidl_vec<uint8_t> const& key, hidl_vec<KeyParameter> const& in_verify_params);
} /* namespace crypto */

} /* namespace hal_ops */

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


static inline void extract_application_id_and_data(hidl_vec<KeyParameter> const& params,
        hidl_vec<uint8_t>& out_application_id, hidl_vec<uint8_t>& out_application_data)
{
    for (const auto& kp : params) {
        if (kp.tag == Tag::APPLICATION_ID)
            out_application_id = kp.blob;
        else if (kp.tag == Tag::APPLICATION_DATA)
            out_application_data = kp.blob;
    }
}

static inline Algorithm find_algorithm(hidl_vec<KeyParameter> const& params,
        const std::vector<Algorithm>& allowed_algs)
{
    for (const auto& kp : params) {
        if (kp.tag == Tag::ALGORITHM) {
            for (const auto& a : allowed_algs) {
                if (kp.f.algorithm == a)
                    return kp.f.algorithm;
            }

            std::cerr << "Unsupported algorithm: " << toString(kp.f.algorithm) << std::endl;
            return static_cast<Algorithm>(-1);
        }
    }

    std::cerr << "No ALGORITHM provided in key parameters" << std::endl;
    return static_cast<Algorithm>(-1);
}

static inline std::vector<hidl_vec<uint8_t>>
find_rep_blob_tag(Tag t, hidl_vec<KeyParameter> const& params)
{
    std::vector<hidl_vec<uint8_t>> ret;

    for (const auto& kp : params) {
        if (kp.tag == t)
            ret.push_back(kp.blob);
    }

    return ret;
}

template<typename R>
static inline std::vector<R>
find_rep_tag(Tag t, hidl_vec<KeyParameter> const& params)
{
    std::vector<R> ret;

    for (const auto& kp : params) {
        if (kp.tag == t)
            ret.push_back(static_cast<R>(kp.f.longInteger));
    }

    return ret;
}

static inline const hidl_vec<uint8_t>*
find_blob_tag(Tag t, hidl_vec<KeyParameter> const& params)
{
    for (const auto& kp : params) {
        if (kp.tag == t)
            return &kp.blob;
    }
    return nullptr;
}

template<typename R>
static inline R find_tag(Tag t, hidl_vec<KeyParameter> const& params)
{
    for (const auto& kp : params) {
        if (kp.tag == t)
            return static_cast<R>(kp.f.longInteger);
    }

    return static_cast<R>(-1);
}

static inline Algorithm determine_pkey_algorithm(hidl_vec<uint8_t> const& priv_pkcs8)
{
    EVP_PKEY *pkey = NULL;
    const unsigned char *p = NULL;

    p = priv_pkcs8.data();
    pkey = d2i_PrivateKey(EVP_PKEY_EC, NULL, &p, priv_pkcs8.size());
    if (pkey != NULL) {
        EVP_PKEY_free(pkey);
        return Algorithm::EC;
    }

    p = priv_pkcs8.data();
    pkey = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &p, priv_pkcs8.size());
    if (pkey != NULL) {
        EVP_PKEY_free(pkey);
        return Algorithm::RSA;
    }

    return static_cast<Algorithm>(-1);
}

} /* namespace cli */
} /* namespace suskeymaster */

#endif /* CLI_SUSKEYMASTER_HPP_ */
