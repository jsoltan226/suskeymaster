#ifndef CLI_SUSKEYMASTER_HPP_
#define CLI_SUSKEYMASTER_HPP_

#include <core/log.h>
#include <libsuskmhal/suskmhal.hpp>
#include <libsuskmhal/util/km-params.hpp>
#include <libsuskmhal/keymaster-types-cpp.hpp>
#include <libsuskmhal/transport/aosp-hidl-support.hpp>
#include <libsuscertmod/samsung-sus-indata.h>
#include <vector>
#include <string>

namespace suskeymaster {
namespace cli {

using ::suskeymaster::kmhal::SusKMHal;
using namespace kmhal::generic;

namespace hal_ops {

int get_print_key_characteristics(SusKMHal& hal,
                                  std::vector<u8> const& key,
                                  std::vector<KeyParameter> const& in_application_id_data);

int generate_key(SusKMHal& hal,
                 std::vector<KeyParameter> const& in_gen_params,
                 std::vector<u8>& out_wrapped_blob,
                 std::vector<std::vector<u8>> *out_opt_keymint_cert_chain = nullptr);

int attest_key(SusKMHal& hal,
               std::vector<u8> const& key,
               std::vector<KeyParameter> const& in_attest_params,
               std::vector<std::vector<u8>>& out_cert_chain);

int import_key(SusKMHal& hal,
               std::vector<u8> const& priv_pkcs8,
               std::vector<KeyParameter> const& in_import_params,
               std::vector<u8>& out_wrapped_blob,
               std::vector<std::vector<u8>> *out_opt_keymint_cert_chain = nullptr);

int export_key(SusKMHal& hal,
               std::vector<u8> const& key,
               std::vector<KeyParameter> const& in_application_id_data,
               std::vector<u8>& out_public_key_x509);

int upgrade_key(SusKMHal& hal,
                std::vector<u8> const& in_keyblob_to_upgrade,
                std::vector<KeyParameter> const& in_upgrade_params,
                std::vector<u8>& out_upgraded_keyblob);

namespace crypto {
    int encrypt(SusKMHal& hal, std::vector<u8> const& plaintext,
                std::vector<u8> const& key, std::vector<KeyParameter> const& encrypt_params,
                HardwareAuthToken const& auth_token,
                std::vector<u8>& out_ciphertext, std::vector<u8>& out_nonce);

    int decrypt(SusKMHal& hal, std::vector<u8> const& ciphertext,
                std::vector<u8> const& key, std::vector<KeyParameter> const& decrypt_params,
                HardwareAuthToken const& auth_token,
                std::vector<u8>& out_plaintext);

    int sign(SusKMHal& hal, std::vector<u8> const& message,
             std::vector<u8> const& key, std::vector<KeyParameter> const& in_sign_params,
             HardwareAuthToken const& auth_token,
             std::vector<u8>& out_signature);

    int verify(SusKMHal& hal,
               std::vector<u8> const& message, std::vector<u8> const& signature,
               std::vector<u8> const& key, std::vector<KeyParameter> const& in_verify_params,
               HardwareAuthToken const& auth_token);
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

namespace secureimport {
    namespace target {
        int generate_and_attest_wrapping_key(SusKMHal& hal,
            std::vector<u8>& out_wrapping_blob, std::vector<u8>& out_wrapping_pubkey,
            std::vector<std::vector<u8>> * out_opt_cert_chain,
            std::vector<KeyParameter> const& in_gen_params
        );
    }

    namespace host {
        int verify_attestation(std::vector<std::vector<u8>> const& cert_chain);

        int wrap_key(std::vector<u8> const& in_private_key,
            std::vector<u8> const& in_wrapping_key, std::vector<KeyParameter> const& in_key_params,
            std::vector<u8>& out_wrapped_data, std::vector<u8>& out_masking_key);
    }

    namespace target {
        int import_wrapped_key(SusKMHal& hal, std::vector<u8> const& in_wrapped_data,
            std::vector<u8> const& in_masking_key, std::vector<u8> const& in_wrapping_blob,
            std::vector<KeyParameter> const& in_unwrapping_params,
            std::vector<u8>& out_key_blob,
            std::vector<std::vector<u8>> *out_opt_keymint_cert_chain = nullptr);
    };

} /* namespace secureimport */

namespace vold {
    int generate_app_id(std::vector<u8> const& in_secdiscardable,
            std::vector<u8> const& in_secret,
            std::vector<u8>& out_app_id);

    int decrypt_de_key(SusKMHal& hal,
            std::vector<u8> const& in_keystore_key, std::vector<u8> const& in_secdiscardable,
            std::vector<u8> const& in_encrypted_key, std::vector<u8>& out_decrypted_key);

    int decrypt_ce_key(
            std::vector<u8> const& in_secret, std::vector<u8> const& in_secdiscardable,
            std::vector<u8> const& in_encrypted_key, std::vector<u8>& out_decrypted_key);

    int fscrypt_legacy_install_key(std::vector<u8> const& key);
};

namespace samsung {
    namespace ekey {
        int list_tags(std::vector<u8> const& in_keyblob);

        int add_tags(std::vector<u8> const& in_keyblob,
                     std::vector<KeyParameter> const& in_tags_to_add,
                     std::vector<u8>& out_keyblob);

        int del_tags(std::vector<u8> const& in_keyblob,
                     std::vector<KeyParameter> const& in_tags_to_del,
                     std::vector<u8>& out_keyblob);
    } /* namespace ekey */

#ifdef SUSKEYMASTER_ENABLE_SAMSUNG_SEND_INDATA
    int send_indata(SusKMHal& hal,
                    u32 *ver, u32 *km_ver, u32 cmd, u32 *pid,
                    u32 *int0, u64 *long0, u64 *long1, const std::vector<u8> *bin0,
                    const std::vector<u8> *bin1, const std::vector<u8> *bin2,
                    const std::vector<u8> *key, const std::vector<KeyParameter> *par);
#endif /* SUSKEYMASTER_ENABLE_SAMSUNG_SEND_INDATA */
} /* namespace samsung */


} /* namespace cli */
} /* namespace suskeymaster */

#endif /* CLI_SUSKEYMASTER_HPP_ */
