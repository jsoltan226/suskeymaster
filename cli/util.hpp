#pragma once
#include <libsuskmhal/keymaster-types-cpp.hpp>
#include <vector>

namespace suskeymaster {
namespace cli {
namespace util {

using namespace kmhal::generic;

/* Key parameter utilities */

void extract_application_id_and_data(std::vector<KeyParameter> const& params,
                                     std::vector<u8>& out_application_id,
                                     std::vector<u8>& out_application_data);

HardwareAuthToken extract_auth_token(std::vector<KeyParameter>& params);

Algorithm find_algorithm(std::vector<KeyParameter> const& params,
                         const std::vector<Algorithm>& allowed_algs);

const std::vector<u8> * find_blob_tag(Tag t, std::vector<KeyParameter> const& params);
std::vector<std::vector<u8>> find_rep_blob_tag(Tag t, std::vector<KeyParameter> const& params);

template<typename R>
static inline std::vector<R>
find_rep_tag(Tag t, std::vector<KeyParameter> const& params)
{
    std::vector<R> ret;

    for (const auto& kp : params) {
        if (kp.tag == t)
            ret.push_back(static_cast<R>(kp.f.longInteger));
    }

    return ret;
}

static inline bool tag_exists(Tag t, const std::vector<KeyParameter>& params)
{
    for (const auto& kp : params) {
        if (kp.tag == t)
            return true;
    }

    return false;
}

template<typename R>
static inline R find_tag(Tag t, std::vector<KeyParameter> const& params)
{
    for (const auto& kp : params) {
        if (kp.tag == t)
            return static_cast<R>(kp.f.longInteger);
    }

    return static_cast<R>(-1);
}

Algorithm determine_pkey_algorithm(std::vector<u8> const& priv_pkcs8);

Algorithm determine_algorithm_from_params_and_pkey(std::vector<KeyParameter> const& params,
                                                   std::vector<u8> const& pkey);

void init_default_params_for_alg_and_purposes(std::vector<KeyParameter>& params,
                                              Algorithm alg,
                                              const std::vector<KeyPurpose>& purposes,
                                              bool is_generate_key, bool is_keymint);

/* Gatekeeper/vold crypto utilities */

std::vector<u8> keystore_blob_to_km_blob(std::vector<u8> const& keystore_blob);

std::vector<uint8_t> to_uppercase_hex_string(std::vector<uint8_t> const& data);

int parse_hex_string(const std::vector<uint8_t>& hex, std::vector<uint8_t>& out);

static constexpr u32 AES_GCM_KEY_SIZE = 32;
static constexpr u32 AES_GCM_IV_SIZE = 12;
static constexpr u32 AES_GCM_TAG_SIZE = 16;

int extract_gcm_data(std::vector<u8> const& blob,
                     std::vector<u8>& out_iv, std::vector<u8>& out_ciphertext_with_tag);

int extract_gcm_data(std::vector<u8> const& blob,
                     std::vector<u8>& out_iv,
                     std::vector<u8>& out_ciphertext,
                     std::vector<u8>& out_tag);

int aes256gcm_software_decrypt(std::vector<u8> const& key, std::vector<u8> const& blob,
                               std::vector<u8>& out_plaintext);

int aes256gcm_software_decrypt(std::vector<u8> const& key, std::vector<u8> const& iv,
                               std::vector<u8> const& ciphertext,
                               std::vector<u8> const& tag,
                               std::vector<u8>& out_plaintext);

int personalized_hash(std::vector<uint8_t> const& in_data, const char *personalization,
                      std::vector<uint8_t>& out_hash);

int sp800_derive_with_context(std::vector<uint8_t> const& in_key,
                              const char *label, size_t label_size,
                              const char *context, size_t context_size,
                              std::vector<uint8_t>& out);

} /* namespace util */
} /* namespace cli */
} /* namespace suskeymaster */
