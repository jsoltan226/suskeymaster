#ifndef CLI_SUSKEYMASTER_HPP_
#define CLI_SUSKEYMASTER_HPP_

#include <core/log.h>
#include <libsuskmhal/hidl/hidl-hal.hpp>
#include <libsuskmhal/util/km-params.hpp>
#include <libsuscertmod/samsung-sus-indata.h>
#include <vector>
#include <string>
#include <cstring>
#include <cstdint>
#include <hidl/HidlSupport.h>
#include <android/hardware/keymaster/generic/types.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/crypto.h>

namespace suskeymaster {
namespace cli {

using ::suskeymaster::kmhal::hidl::HidlSusKeymaster;
using namespace ::android::hardware::keymaster::generic;
using ::android::hardware::hidl_vec;

namespace hal_ops {

int get_key_characteristics(HidlSusKeymaster& hal,
    hidl_vec<uint8_t> const& key, hidl_vec<KeyParameter> const& in_application_id_data);

int generate_key(HidlSusKeymaster& hal,
    hidl_vec<KeyParameter> const& in_gen_params,
    hidl_vec<uint8_t>& out_wrapped_blob);

int attest_key(HidlSusKeymaster& hal,
    hidl_vec<uint8_t> const& key, hidl_vec<KeyParameter> const& in_attest_params);

int import_key(HidlSusKeymaster& hal,
    hidl_vec<uint8_t> const& priv_pkcs8,
    hidl_vec<KeyParameter> const& in_import_params,
    hidl_vec<uint8_t>& out_wrapped_blob);

int export_key(HidlSusKeymaster& hal,
    hidl_vec<uint8_t> const& key,
    hidl_vec<uint8_t>& out_public_key_x509,
    hidl_vec<KeyParameter> const& in_application_id_data);

int upgrade_key(HidlSusKeymaster& hal,
    hidl_vec<uint8_t> const& in_keyblob_to_upgrade,
    hidl_vec<KeyParameter> const& in_upgrade_params,
    hidl_vec<uint8_t>& out_upgraded_keyblob);

namespace crypto {
    int encrypt(HidlSusKeymaster& hal, hidl_vec<uint8_t> const& plaintext,
            hidl_vec<uint8_t> const& key, hidl_vec<KeyParameter> const& encrypt_params,
            hidl_vec<uint8_t>& out_ciphertext, hidl_vec<uint8_t>& out_aes_gcm_iv);

    int decrypt(HidlSusKeymaster& hal, hidl_vec<uint8_t> const& ciphertext,
            hidl_vec<uint8_t> const& key, hidl_vec<KeyParameter> const& decrypt_params,
            hidl_vec<uint8_t>& out_plaintext);

    int sign(HidlSusKeymaster& hal, hidl_vec<uint8_t> const& message,
        hidl_vec<uint8_t> const& key, hidl_vec<KeyParameter> const& in_sign_params,
        hidl_vec<uint8_t>& out_signature);

    int verify(HidlSusKeymaster& hal,
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
        int generate_and_attest_wrapping_key(HidlSusKeymaster& hal,
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
        int import_wrapped_key(HidlSusKeymaster& hal, hidl_vec<uint8_t> const& in_wrapped_data,
            hidl_vec<uint8_t> const& in_masking_key, hidl_vec<uint8_t> const& in_wrapping_blob,
            hidl_vec<KeyParameter> const& in_unwrapping_params,
            hidl_vec<uint8_t>& out_key_blob);
    };

} /* namespace transact */

namespace vold {
    int generate_app_id(hidl_vec<uint8_t> const& in_secdiscardable,
            hidl_vec<uint8_t>& out_app_id);

    int decrypt_vold_key_with_keystore_key(HidlSusKeymaster& hal,
            hidl_vec<uint8_t> const& in_keystore_key, hidl_vec<uint8_t> const& in_secdiscardable,
            hidl_vec<uint8_t> const& in_encrypted_key, hidl_vec<uint8_t>& out_decrypted_key);
};

namespace samsung {
    namespace ekey {
        int list_tags(hidl_vec<uint8_t> const& in_keyblob);

        int add_tags(hidl_vec<uint8_t> const& in_keyblob,
                hidl_vec<KeyParameter> const& in_tags_to_add, hidl_vec<uint8_t>& out_keyblob);

        int del_tags(hidl_vec<uint8_t> const& in_keyblob,
                hidl_vec<KeyParameter> const& in_tags_to_del, hidl_vec<uint8_t>& out_keyblob);
    } /* namespace ekey */

#ifdef SUSKEYMASTER_ENABLE_SAMSUNG_SEND_INDATA
    int send_indata(HidlSusKeymaster& hal,
            uint32_t *ver, uint32_t *km_ver, uint32_t cmd, uint32_t *pid,
            uint32_t *int0, uint64_t *long0, uint64_t *long1, const hidl_vec<uint8_t> *bin0,
            const hidl_vec<uint8_t> *bin1, const hidl_vec<uint8_t> *bin2,
            const hidl_vec<uint8_t> *key, const hidl_vec<KeyParameter> *par);
#endif /* SUSKEYMASTER_ENABLE_SAMSUNG_SEND_INDATA */
} /* namespace samsung */


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

static inline Algorithm determine_algorithm_from_params_and_pkey(
        hidl_vec<KeyParameter> const& params, hidl_vec<uint8_t> const& pkey
)
{
    Algorithm ret = find_tag<Algorithm>(Tag::ALGORITHM, params);
    if (ret == static_cast<Algorithm>(-1)) {
        std::cerr << "WARNING: No ALGORITHM tag specified in parameters; "
            "attempting to guess from key binary..." << std::endl;

        ret = determine_pkey_algorithm(pkey);
        if (ret == static_cast<Algorithm>(-1)) {
            std::cerr << "The key blob is not a valid EC or RSA PKCS#8 private key"
                << std::endl;
            std::cerr << "Can't guess which algorithm is wanted from just raw bytes" << std::endl;
            return ret;
        }
    }

    return ret;
}

static inline void init_default_params_for_alg_and_purposes(hidl_vec<KeyParameter>& params,
        Algorithm alg, const std::vector<KeyPurpose>& purposes, bool gen)
{
    bool sign_verify = false, enc_dec = false, wrap_key = false;
    bool private_ops = false;
    for (KeyPurpose p : purposes) {
        if (p == KeyPurpose::SIGN || p == KeyPurpose::VERIFY)
            sign_verify = true;
        else if (p == KeyPurpose::ENCRYPT || p == KeyPurpose::DECRYPT)
            enc_dec = true;
        else if (p == KeyPurpose::WRAP_KEY)
            wrap_key = true;

        if (p == KeyPurpose::SIGN || p == KeyPurpose::DECRYPT)
            private_ops = true;
    }

    switch (alg) {
    case Algorithm::RSA:
        break;
    case Algorithm::EC:
    case Algorithm::HMAC:
        if (enc_dec) {
            enc_dec = false;
            std::cerr << "WARNING: Encryption and decryption "
                "is not be supported for EC and HMAC keys!" << std::endl;
        }
        if (wrap_key) {
            wrap_key = false;
            std::cerr << "WARNING: EC and HMAC keys cannot be used "
                "as the wrapping key for a secure import!" << std::endl;
        }
        break;
    case Algorithm::TRIPLE_DES:
        if (wrap_key) {
            wrap_key = false;
            std::cerr << "WARNING: Triple-DES key cannot be used "
                "as the wrapping key for a secure import!" << std::endl;
        }

    [[fallthrough]];
    case Algorithm::AES:
        if (sign_verify) {
            sign_verify = false;
            std::cerr << "WARNING: AES and Triple-DES keys cannot "
                "be used for signing and verification!" << std::endl;
        }
    }

    std::vector<kmhal::util::km_default> defaults;
    std::vector<PaddingMode> padding_modes;
    std::vector<BlockMode> block_modes;
    bool has_gcm = false, has_ctr_gcm = false, has_ecb_cbc = false;

    /* Universal defaults for all algorithms */
    defaults = {
        { Tag::ALGORITHM, alg },
        { Tag::NO_AUTH_REQUIRED, true }
    };

    switch (alg) {
    case Algorithm::RSA:
        if (gen) {
            /* Only 2048-bit RSA keys are guaranteed to be supported
             * by both TEE and STRONGBOX devices */
            defaults.emplace_back(Tag::KEY_SIZE, 2048);

            defaults.emplace_back(Tag::RSA_PUBLIC_EXPONENT, 65537);
        }

        /* All RSA private operations require an authorized digest */
        if (private_ops)
            defaults.push_back({ Tag::DIGEST, { Digest::SHA_2_256 } });

        if (sign_verify) padding_modes.push_back(PaddingMode::RSA_PKCS1_1_5_SIGN);
        if (enc_dec) padding_modes.push_back(PaddingMode::RSA_PKCS1_1_5_ENCRYPT);
        if (wrap_key) padding_modes.push_back(PaddingMode::RSA_OAEP);

        defaults.emplace_back(Tag::PADDING, padding_modes);
        break;
    case Algorithm::EC:
        /* Only P-256 EC keys are guaranteed to be supported
         * by both TEE and STRONGBOX devices */
        /* Don't initialize Tag::EC_CURVE if the user has already provided Tag::KEY_SIZE */
        if (gen && find_tag<int64_t>(Tag::KEY_SIZE, params) == -1)
            defaults.emplace_back(Tag::EC_CURVE, EcCurve::P_256);

        if (sign_verify && private_ops)
            defaults.push_back({ Tag::DIGEST, { Digest::SHA_2_256 } });

        break;
    case Algorithm::AES:
        if (gen)
            defaults.emplace_back(Tag::KEY_SIZE, 256);

        if (!enc_dec || !private_ops)
            break;

        block_modes = find_rep_tag<BlockMode>(Tag::BLOCK_MODE, params);
        if (!block_modes.size()) {
            defaults.push_back({ Tag::BLOCK_MODE, { BlockMode::GCM } });
            defaults.push_back({ Tag::PADDING, { PaddingMode::NONE } });
            defaults.push_back({ Tag::MIN_MAC_LENGTH, 128 });
        } else {
            for (BlockMode b : block_modes) {
                if (b == BlockMode::GCM)
                    has_gcm = true;
                if (b == BlockMode::GCM || b == BlockMode::CTR)
                    has_ctr_gcm = true;
                if (b == BlockMode::ECB || b == BlockMode::CBC)
                    has_ecb_cbc = true;
            }

            if (has_gcm) defaults.push_back({ Tag::MIN_MAC_LENGTH, 128 });

            if (has_ctr_gcm) defaults.push_back({ Tag::PADDING, { PaddingMode::NONE } });
            else if (has_ecb_cbc) defaults.push_back({ Tag::PADDING, { PaddingMode::PKCS7 } });
        }

        break;
    case Algorithm::TRIPLE_DES:
        if (gen)
            defaults.push_back({ Tag::KEY_SIZE, 168 });

        if (enc_dec && private_ops) {
            defaults.push_back({ Tag::BLOCK_MODE, { BlockMode::CBC } });
            defaults.push_back({ Tag::PADDING, { PaddingMode::PKCS7 } });
        }
        break;
    case Algorithm::HMAC:
        if (gen) {
            defaults.push_back({ Tag::KEY_SIZE, 256 });
            defaults.push_back({ Tag::MIN_MAC_LENGTH, 256 });
        }

        /* SHA_2_256 is the only digest (for HMAC keys) guaranteed to be supported
         * by both TRUSTED_ENVIRONMENT and STRONGBOX keymasters */
        if (sign_verify && private_ops)
            defaults.push_back({ Tag::DIGEST, { Digest::SHA_2_256 } });
        break;
    }

    kmhal::util::init_default_params(params, defaults);
}

} /* namespace cli */
} /* namespace suskeymaster */

#endif /* CLI_SUSKEYMASTER_HPP_ */
