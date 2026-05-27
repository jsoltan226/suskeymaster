#ifndef CLI_SUSKEYMASTER_HPP_
#define CLI_SUSKEYMASTER_HPP_

#include <core/log.h>
#include <libsuskmhal/hidl/base.h>
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
    hidl_vec<u8> const& key, hidl_vec<KeyParameter> const& in_application_id_data);

int generate_key(HidlSusKeymaster& hal,
    hidl_vec<KeyParameter> const& in_gen_params,
    hidl_vec<u8>& out_wrapped_blob);

int attest_key(HidlSusKeymaster& hal,
    hidl_vec<u8> const& key, hidl_vec<KeyParameter> const& in_attest_params,
    hidl_vec<hidl_vec<u8>>& out_cert_chain);

int import_key(HidlSusKeymaster& hal,
    hidl_vec<u8> const& priv_pkcs8,
    hidl_vec<KeyParameter> const& in_import_params,
    hidl_vec<u8>& out_wrapped_blob);

int export_key(HidlSusKeymaster& hal,
    hidl_vec<u8> const& key,
    hidl_vec<u8>& out_public_key_x509,
    hidl_vec<KeyParameter> const& in_application_id_data);

int upgrade_key(HidlSusKeymaster& hal,
    hidl_vec<u8> const& in_keyblob_to_upgrade,
    hidl_vec<KeyParameter> const& in_upgrade_params,
    hidl_vec<u8>& out_upgraded_keyblob);

namespace crypto {
    int encrypt(HidlSusKeymaster& hal, hidl_vec<u8> const& plaintext,
            hidl_vec<u8> const& key, hidl_vec<KeyParameter> const& encrypt_params,
            hidl_vec<u8>& out_ciphertext, hidl_vec<u8>& out_aes_gcm_iv);

    int decrypt(HidlSusKeymaster& hal, hidl_vec<u8> const& ciphertext,
            hidl_vec<u8> const& key, hidl_vec<KeyParameter> const& decrypt_params,
            hidl_vec<u8>& out_plaintext);

    int sign(HidlSusKeymaster& hal, hidl_vec<u8> const& message,
        hidl_vec<u8> const& key, hidl_vec<KeyParameter> const& in_sign_params,
        hidl_vec<u8>& out_signature);

    int verify(HidlSusKeymaster& hal,
        hidl_vec<u8> const& message, hidl_vec<u8> const& signature,
        hidl_vec<u8> const& key, hidl_vec<KeyParameter> const& in_verify_params);
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
            hidl_vec<u8>& out_wrapping_blob, hidl_vec<u8>& out_wrapping_pubkey,
            hidl_vec<hidl_vec<u8>> * out_opt_cert_chain,
            hidl_vec<KeyParameter> const& in_gen_params
        );
    }

    namespace server {
        int verify_attestation(hidl_vec<hidl_vec<u8>> const& cert_chain);

        int wrap_key(hidl_vec<u8> const& in_private_key,
            hidl_vec<u8> const& in_wrapping_key, hidl_vec<KeyParameter> const& in_key_params,
            hidl_vec<u8>& out_wrapped_data, hidl_vec<u8>& out_masking_key);
    }

    namespace client {
        int import_wrapped_key(HidlSusKeymaster& hal, hidl_vec<u8> const& in_wrapped_data,
            hidl_vec<u8> const& in_masking_key, hidl_vec<u8> const& in_wrapping_blob,
            hidl_vec<KeyParameter> const& in_unwrapping_params,
            hidl_vec<u8>& out_key_blob);
    };

} /* namespace transact */

namespace vold {
    int generate_app_id(hidl_vec<u8> const& in_secdiscardable,
            hidl_vec<u8> const& in_secret,
            hidl_vec<u8>& out_app_id);

    int decrypt_de_key(HidlSusKeymaster& hal,
            hidl_vec<u8> const& in_keystore_key, hidl_vec<u8> const& in_secdiscardable,
            hidl_vec<u8> const& in_encrypted_key, hidl_vec<u8>& out_decrypted_key);

    int decrypt_ce_key(
            hidl_vec<u8> const& in_secret, hidl_vec<u8> const& in_secdiscardable,
            hidl_vec<u8> const& in_encrypted_key, hidl_vec<u8>& out_decrypted_key);

    int fscrypt_legacy_install_key(hidl_vec<u8> const& key);
};

namespace gatekeeper {
    struct gk_hal {
    private:
        struct kmhal_hidl_hal_sp *hal_sp;
        bool owns;
    public:

        /* Implemented in `gatekeeper.cpp` */
        gk_hal();
        gk_hal(HidlSusKeymaster&);
        ~gk_hal();

        gk_hal(const gk_hal& other) {
            this->hal_sp = other.hal_sp;
            this->owns = false;
        }
        gk_hal& operator=(const gk_hal& other) {
            this->hal_sp = other.hal_sp;
            this->owns = false;
            return *this;
        }

        bool is_ok() const { return this->hal_sp != nullptr; }

        struct kmhal_hidl_hal_sp * get_hal_sp() const { return this->hal_sp; }
    };

    int verify(HidlSusKeymaster& kmhal, u32 uid, u64 challenge, hidl_vec<uint8_t> const& cred,
               hidl_vec<uint8_t> const& handle, hidl_vec<uint8_t>& out,
               struct gk_hal *opt_gk_hal = nullptr);

    /* See "frameworks/base/core/java/com/android/internal/widget/LockPatternUtils.java"
     * and "frameworks/base/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java"*/
    struct sp_pwd_data {
        enum class credential_type : u32 {
            NONE = static_cast<u32>(-1),
            PATTERN = 1,
            PASSWORD_OR_PIN = 2,
            PIN = 3,
            PASSWORD = 4
        } type = credential_type::NONE;
        static const char * credential_type_toString(u32 ct) {
            switch (static_cast<credential_type>(ct)) {
                case credential_type::NONE: return "CREDENTIAL_TYPE_NONE";
                case credential_type::PATTERN: return "CREDENTIAL_TYPE_PATTERN";
                case credential_type::PASSWORD_OR_PIN: return "CREDENTIAL_TYPE_PASSWORD_OR_PIN";
                case credential_type::PIN: return "CREDENTIAL_TYPE_PIN";
                case credential_type::PASSWORD: return "CREDENTIAL_TYPE_PASSWORD";
                default: return "(unknown)";
            }
        }

        static constexpr u8 PASSWORD_SCRYPT_LOG_N = 11;
        static constexpr u8 PASSWORD_SCRYPT_LOG_R = 3;
        static constexpr u8 PASSWORD_SCRYPT_LOG_P = 1;
        u8 N = PASSWORD_SCRYPT_LOG_N,
           R = PASSWORD_SCRYPT_LOG_R,
           P = PASSWORD_SCRYPT_LOG_P;

        static constexpr u8 PASSWORD_SALT_LENGTH = 16;
        hidl_vec<u8> salt = hidl_vec<u8>(PASSWORD_SALT_LENGTH);

        hidl_vec<u8> handle;

        static constexpr i32 PIN_LENGTH_UNAVAILABLE = -1;
        static constexpr i32 MIN_AUTO_PIN_REQUIREMENT_LENGTH = 6;
        i32 pin_length = PIN_LENGTH_UNAVAILABLE;
    };

    int read_pwd_data(hidl_vec<u8> const& pwd_data, sp_pwd_data& out, bool log);

    constexpr const u8 DEFAULT_PASSWORD[] = "default-password";
    static constexpr u32 STRETCHED_LSKF_LENGTH = 32;
    int stretch_lskf(hidl_vec<u8> const& credential, sp_pwd_data const& pwd, hidl_vec<u8>& out);

    int unwrap_sp_blob(HidlSusKeymaster& kmhal, u32 uid, hidl_vec<u8> const& km_key_blob,
                       hidl_vec<u8> const& stretched_cred, hidl_vec<u8> const& handle,
                       hidl_vec<u8> const& secdiscardable, hidl_vec<u8> const& sp_blob,
                       hidl_vec<u8>& out, u8& out_blob_version);

    int validate_synthetic_password(HidlSusKeymaster& kmhal, u32 uid,
                                    hidl_vec<u8> const& synthetic_password, u8 sp_blob_ver,
                                    hidl_vec<u8> const& null_pwd_handle);

    int derive_synthetic_password_subkey(hidl_vec<u8> const& synthetic_password, u8 sp_blob_ver,
                                         const char *personalization, size_t personalization_size,
                                         hidl_vec<u8>& out);
}; /* namespace gatekeeper */

namespace samsung {
    namespace ekey {
        int list_tags(hidl_vec<u8> const& in_keyblob);

        int add_tags(hidl_vec<u8> const& in_keyblob,
                     hidl_vec<KeyParameter> const& in_tags_to_add, hidl_vec<u8>& out_keyblob);

        int del_tags(hidl_vec<u8> const& in_keyblob,
                     hidl_vec<KeyParameter> const& in_tags_to_del, hidl_vec<u8>& out_keyblob);
    } /* namespace ekey */

#ifdef SUSKEYMASTER_ENABLE_SAMSUNG_SEND_INDATA
    int send_indata(HidlSusKeymaster& hal,
                    u32 *ver, u32 *km_ver, u32 cmd, u32 *pid,
                    u32 *int0, u64 *long0, u64 *long1, const hidl_vec<u8> *bin0,
                    const hidl_vec<u8> *bin1, const hidl_vec<u8> *bin2,
                    const hidl_vec<u8> *key, const hidl_vec<KeyParameter> *par);
#endif /* SUSKEYMASTER_ENABLE_SAMSUNG_SEND_INDATA */
} /* namespace samsung */

namespace util {

/* Key parameter utilities */

void extract_application_id_and_data(hidl_vec<KeyParameter> const& params,
                                     hidl_vec<u8>& out_application_id,
                                     hidl_vec<u8>& out_application_data);

Algorithm find_algorithm(hidl_vec<KeyParameter> const& params,
                         const std::vector<Algorithm>& allowed_algs);

const hidl_vec<u8> * find_blob_tag(Tag t, hidl_vec<KeyParameter> const& params);
std::vector<hidl_vec<u8>> find_rep_blob_tag(Tag t, hidl_vec<KeyParameter> const& params);

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

template<typename R>
static inline R find_tag(Tag t, hidl_vec<KeyParameter> const& params)
{
    for (const auto& kp : params) {
        if (kp.tag == t)
            return static_cast<R>(kp.f.longInteger);
    }

    return static_cast<R>(-1);
}

Algorithm determine_pkey_algorithm(hidl_vec<u8> const& priv_pkcs8);

Algorithm determine_algorithm_from_params_and_pkey(hidl_vec<KeyParameter> const& params,
                                                   hidl_vec<u8> const& pkey);

void init_default_params_for_alg_and_purposes(hidl_vec<KeyParameter>& params,
                                              Algorithm alg,
                                              const std::vector<KeyPurpose>& purposes,
                                              bool is_generate_key);

/* Gatekeeper/vold crypto utilities */

hidl_vec<u8> keystore_blob_to_km_blob(hidl_vec<u8> const& keystore_blob);

hidl_vec<uint8_t> to_uppercase_hex_string(hidl_vec<uint8_t> const& data);

int parse_hex_string(const hidl_vec<uint8_t>& hex, hidl_vec<uint8_t>& out);

static constexpr u32 AES_GCM_KEY_SIZE = 32;
static constexpr u32 AES_GCM_IV_SIZE = 12;
static constexpr u32 AES_GCM_TAG_SIZE = 16;

int extract_gcm_data(hidl_vec<u8> const& blob,
                     hidl_vec<u8>& out_iv, hidl_vec<u8>& out_ciphertext_with_tag);

int extract_gcm_data(hidl_vec<u8> const& blob,
                     hidl_vec<u8>& out_iv, hidl_vec<u8>& out_ciphertext, hidl_vec<u8>& out_tag);

int aes256gcm_software_decrypt(hidl_vec<u8> const& key, hidl_vec<u8> const& blob,
                               hidl_vec<u8>& out_plaintext);

int aes256gcm_software_decrypt(hidl_vec<u8> const& key, hidl_vec<u8> const& iv,
                               hidl_vec<u8> const& ciphertext, hidl_vec<u8> const& tag,
                               hidl_vec<u8>& out_plaintext);

int personalized_hash(hidl_vec<uint8_t> const& in_data,
                      const char *personalization, size_t personalization_size,
                      hidl_vec<uint8_t>& out_hash);

int sp800_derive_with_context(hidl_vec<uint8_t> const& in_key,
                              const char *label, size_t label_size,
                              const char *context, size_t context_size,
                              hidl_vec<uint8_t>& out);

} /* namespace util */

} /* namespace cli */
} /* namespace suskeymaster */

#endif /* CLI_SUSKEYMASTER_HPP_ */
