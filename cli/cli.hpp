#ifndef CLI_SUSKEYMASTER_HPP_
#define CLI_SUSKEYMASTER_HPP_

#include "auth-hal.hpp"
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
                                  const std::vector<u8>& key,
                                  const std::vector<KeyParameter>& in_application_id_data);

int generate_key(SusKMHal& hal,
                 const std::vector<KeyParameter>& in_gen_params,
                 std::vector<u8>& out_wrapped_blob,
                 std::vector<std::vector<u8>> *out_opt_keymint_cert_chain = nullptr);

int attest_key(SusKMHal& hal,
               const std::vector<u8>& key,
               const std::vector<KeyParameter>& in_attest_params,
               std::vector<std::vector<u8>>& out_cert_chain);

int import_key(SusKMHal& hal,
               const std::vector<u8>& priv_pkcs8,
               const std::vector<KeyParameter>& in_import_params,
               std::vector<u8>& out_wrapped_blob,
               std::vector<std::vector<u8>> *out_opt_keymint_cert_chain = nullptr);

int export_key(SusKMHal& hal,
               const std::vector<u8>& key,
               const std::vector<KeyParameter>& in_application_id_data,
               std::vector<u8>& out_public_key_x509);

int upgrade_key(SusKMHal& hal,
                const std::vector<u8>& in_keyblob_to_upgrade,
                const std::vector<KeyParameter>& in_upgrade_params,
                std::vector<u8>& out_upgraded_keyblob);

namespace crypto {
    struct gk_auth_data {
        HardwareAuthToken user_provided = {};

        struct {
            u32 uid = 0;
            std::vector<u8> credential = {};
            std::vector<u8> pwd_file = {};
            auth::GatekeeperHAL *opt_gk_hal = nullptr;
        } generated_on_the_fly;
    };

    int encrypt(SusKMHal& hal, const std::vector<u8>& plaintext, const std::vector<u8>& key,
                const std::vector<KeyParameter>& encrypt_params, const gk_auth_data& auth_data,
                std::vector<u8>& out_ciphertext, std::vector<u8>& out_nonce);

    int decrypt(SusKMHal& hal, const std::vector<u8>& ciphertext,
                const std::vector<u8>& key, const std::vector<KeyParameter>& decrypt_params,
                const gk_auth_data& auth_data, std::vector<u8>& out_plaintext);

    int sign(SusKMHal& hal, const std::vector<u8>& message,
             const std::vector<u8>& key, const std::vector<KeyParameter>& in_sign_params,
             const gk_auth_data& auth_data, std::vector<u8>& out_signature);

    int verify(SusKMHal& hal,
               const std::vector<u8>& message, const std::vector<u8>& signature,
               const std::vector<u8>& key, const std::vector<KeyParameter>& in_verify_params,
               const gk_auth_data& auth_data);
} /* namespace crypto */

} /* namespace hal_ops */

namespace keybox {
    int make_kb(
        const std::vector<std::string>& ec_cert_paths, const std::string& ec_wrapped_key_path,
        const std::vector<std::string>& rsa_cert_paths, const std::string& rsa_wrapped_key_path,
        const std::string& out_file_path
    );
    int dump_kb(std::string const& keybox_path,
        const std::string& out_dir_path);

} /* namespace keybox */

namespace secureimport {
    namespace target {
        int generate_and_attest_wrapping_key(SusKMHal& hal,
            std::vector<u8>& out_wrapping_blob, std::vector<u8>& out_wrapping_pubkey,
            std::vector<std::vector<u8>> * out_opt_cert_chain,
            const std::vector<KeyParameter>& in_gen_params
        );
    }

    namespace host {
        int verify_attestation(std::vector<std::vector<u8>> const& cert_chain);

        int wrap_key(std::vector<u8> const& in_private_key,
            const std::vector<u8>& in_wrapping_key, const std::vector<KeyParameter>& in_key_params,
            std::vector<u8>& out_wrapped_data, std::vector<u8>& out_masking_key);
    }

    namespace target {
        int import_wrapped_key(SusKMHal& hal, const std::vector<u8>& in_wrapped_data,
            const std::vector<u8>& in_masking_key, const std::vector<u8>& in_wrapping_blob,
            const std::vector<KeyParameter>& in_unwrapping_params,
            std::vector<u8>& out_key_blob,
            std::vector<std::vector<u8>> *out_opt_keymint_cert_chain = nullptr);
    };

} /* namespace secureimport */

namespace vold {
    int generate_app_id(std::vector<u8> const& in_secdiscardable,
            const std::vector<u8>& in_secret,
            std::vector<u8>& out_app_id);

    int decrypt_de_key(SusKMHal& hal,
            const std::vector<u8>& in_keystore_key, const std::vector<u8>& in_secdiscardable,
            const std::vector<u8>& in_encrypted_key, std::vector<u8>& out_decrypted_key);

    int decrypt_ce_key(
            const std::vector<u8>& in_secret, const std::vector<u8>& in_secdiscardable,
            const std::vector<u8>& in_encrypted_key, std::vector<u8>& out_decrypted_key);

    int fscrypt_legacy_install_key(std::vector<u8> const& key);
};

namespace samsung {
    namespace ekey {
        int list_tags(std::vector<u8> const& in_keyblob);

        int add_tags(std::vector<u8> const& in_keyblob,
                     const std::vector<KeyParameter>& in_tags_to_add,
                     std::vector<u8>& out_keyblob);

        int del_tags(std::vector<u8> const& in_keyblob,
                     const std::vector<KeyParameter>& in_tags_to_del,
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
