#include "cli.hpp"
#include "util.hpp"
#include <core/int.h>
#include <libsuscertmod/key-desc.h>
#include <libsuscertmod/leaf-cert.h>
#include <libsuskmhal/suskmhal.hpp>
#include <libsuskmhal/keymaster-types-c.h>
#include <libsuskmhal/util/km-params.hpp>
#include <ctime>
#include <cstdio>
#include <vector>
#include <cstdlib>
#include <cstring>
#include <ostream>
#include <iostream>
#include <openssl/evp.h>

namespace suskeymaster {
namespace cli {
namespace hal_ops {

using namespace kmhal::generic;
using kmhal::SusKMHal;

static void pr_info(const char *fmt, ...) {
    va_list vlist;
    va_start(vlist, fmt);
    std::vprintf(fmt, vlist);
    std::putchar('\n');
    va_end(vlist);
}

int get_print_key_characteristics(SusKMHal& hal,
                                  std::vector<u8> const& key,
                                  std::vector<KeyParameter> const& in_application_id_data)
{
    std::vector<u8> app_id;
    std::vector<u8> app_data;
    util::extract_application_id_and_data(in_application_id_data, app_id, app_data);

    KeyCharacteristics kc;
    ErrorCode e = hal.getKeyCharacteristics(key, app_id, app_data, kc);
    if (e != ErrorCode::OK) {
        std::cerr << "Couldn't get the key's characteristics: "
            << static_cast<int>(e) << " (" << toString(e) << ")" << std::endl;
        return 1;
    }

    {
        std::unique_ptr<KM_PARAM_LIST, decltype(&KM_PARAM_LIST_free)>
            sw_par(nullptr, KM_PARAM_LIST_free), hw_par(nullptr, KM_PARAM_LIST_free);

        sw_par.reset(kmhal::util::key_params_2_param_list(kc.softwareEnforced));
        if (sw_par == NULL) {
            std::cerr << "Failed to convert softwareEnforced key param vec to a param list"
                << std::endl;
            return EXIT_FAILURE;
        }

        hw_par.reset(kmhal::util::key_params_2_param_list(kc.hardwareEnforced));
        if (hw_par == NULL) {
            std::cerr << "Failed to convert hardwareEnforced key param vec to a param list"
                << std::endl;
            return EXIT_FAILURE;
        }

        std::cout << "===== BEGIN KEY CHARACTERISTICS DUMP =====" << std::endl;
        std::cout << "KeyCharacteristics kc = {" << std::endl;
        KM_dump_param_list(pr_info, "softwareEnforced", sw_par.get(), 1, false);
        KM_dump_param_list(pr_info, "hardwareEnforced", hw_par.get(), 1, true);
        std::cout << "};" << std::endl;
        std::cout << "=====  END KEY CHARACTERISTICS DUMP  =====" << std::endl;
    }

    return EXIT_SUCCESS;
}

int generate_key(SusKMHal& hal,
                 std::vector<KeyParameter> const& in_gen_params,
                 std::vector<u8>& out_key_blob,
                 std::vector<std::vector<u8>> *out_opt_keymint_cert_chain)
{
    Algorithm alg = util::find_algorithm(in_gen_params,
        { Algorithm::EC, Algorithm::RSA, Algorithm::AES, Algorithm::TRIPLE_DES, Algorithm::HMAC }
    );
    if (alg == static_cast<Algorithm>(-1))
        return EXIT_FAILURE;

    std::vector<KeyParameter> params(in_gen_params);
    util::init_default_params_for_alg_and_purposes(params, alg,
            util::find_rep_tag<KeyPurpose>(Tag::PURPOSE, params),
            true, hal.getVersion() >= 0x100);

    if (util::find_rep_tag<KeyPurpose>(Tag::PURPOSE, params).empty())
        std::cerr << "WARNING: Generating key with no purpose" << std::endl;

    KeyCharacteristics dummy;
    ErrorCode e = hal.generateKey(params, out_key_blob, dummy, out_opt_keymint_cert_chain);
    if (e != ErrorCode::OK) {
        std::cerr << "generateKey operation failed: "
            << static_cast<i32>(e) << " (" << toString(e) << ")" << std::endl;
        return 1;
    }
    std::cout << "Successfully generated " << toString(alg) << " key" << std::endl;

    return 0;
}

int attest_key(SusKMHal& hal,
               std::vector<u8> const& key, std::vector<KeyParameter> const& in_attest_params,
               std::vector<std::vector<u8>>& out_cert_chain)
{
    std::vector<KeyParameter> params = in_attest_params;

    kmhal::util::init_default_params(params, {
        { Tag::ATTESTATION_CHALLENGE, kmhal::util::get_attestation_challenge() },
        { Tag::ATTESTATION_APPLICATION_ID, kmhal::util::get_attestation_application_id() }
    });

    std::vector<std::vector<u8>> cert_chain = {};

    ErrorCode e = hal.attestKey(key, params, cert_chain);
    if (e != ErrorCode::OK) {
        std::cerr << "attestKey operation failed: "
            << static_cast<i32>(e) << " (" << toString(e) << ")" << std::endl;
        return 1;
    }

    std::cout << "Successfully generated KeyMaster key attestation" << std::endl;
    out_cert_chain = cert_chain;

    return secureimport::host::verify_attestation(cert_chain);
}

int import_key(SusKMHal& hal,
               std::vector<u8> const& in_private_key,
               std::vector<KeyParameter> const& in_import_params,
               std::vector<u8>& out_key_blob,
               std::vector<std::vector<u8>> *out_opt_keymint_cert_chain)
{
    Algorithm alg = util::determine_algorithm_from_params_and_pkey(in_import_params,
                                                                   in_private_key);
    if (alg == static_cast<Algorithm>(-1)) {
        std::cerr << "Failed to determine the algorithm of the key to be imported" << std::endl;
        return 1;
    }

    KeyFormat format;
    switch (alg) {
        case Algorithm::EC: case Algorithm::RSA:
            format = KeyFormat::PKCS8;
            break;
        case Algorithm::AES:
        case Algorithm::TRIPLE_DES:
        case Algorithm::HMAC:
            format = KeyFormat::RAW;
            break;
        default:
            std::cerr << "Algorithm " << static_cast<int>(alg) << " (" << toString(alg) << ") "
                "is not supported" << std::endl;
            return -1;
    }

    std::cout << "Private key algorithm is " << toString(alg) <<
        " (inferred format: " << toString(format) << ")" << std::endl;

    std::vector<KeyParameter> params(in_import_params);
    util::init_default_params_for_alg_and_purposes(params, alg,
            util::find_rep_tag<KeyPurpose>(Tag::PURPOSE, params),
            false, hal.getVersion() >= 0x100);

    KeyCharacteristics c;
    ErrorCode e = hal.importKey(params, format, in_private_key, out_key_blob, c,
            out_opt_keymint_cert_chain);
    if (e != ErrorCode::OK) {
        std::cerr << "importKey operation failed: "
            << static_cast<i32>(e) << " (" << toString(e) << ")" << std::endl;
        return 1;
    }

    std::cout << "Successfully imported an " << toString(alg)
        << " private key into KeyMaster" << std::endl;
    return 0;
}

int export_key(SusKMHal& hal,
               std::vector<u8> const& key,
               std::vector<KeyParameter> const& in_application_id_data,
               std::vector<u8>& out_public_key_x509)
{
    std::vector<u8> app_id;
    std::vector<u8> app_data;
    util::extract_application_id_and_data(in_application_id_data, app_id, app_data);

    /* Normally, `exportKey` always expects the format to be KeyFormat::X509,
     * because only asymmetric keys are exportable.
     * However, samsung has an internal tag `EXPORTABLE` which allows for
     * the exporting for symmetric keys, and so we must account for that */
    KeyFormat out_key_format;
    {
        KeyCharacteristics kc;
        ErrorCode e = hal.getKeyCharacteristics(key, app_id, app_data, kc);
        if (e != ErrorCode::OK) {
            std::cerr << "Failed to get the key's characteristics: "
                << static_cast<i32>(e) << " (" << toString(e) << ")" << std::endl;
            return 1;
        }
        Algorithm alg = util::find_algorithm(kc.hardwareEnforced, {
                Algorithm::EC, Algorithm::RSA,
                Algorithm::AES, Algorithm::TRIPLE_DES, Algorithm::HMAC
        });
        if (alg == static_cast<Algorithm>(-1)) {
            std::cerr << "Couldn't find a valid ALGORITHM tag in the key's characteristics"
                << std::endl;
            return 1;
        }

        switch (alg) {
            case Algorithm::EC:
            case Algorithm::RSA:
                out_key_format = KeyFormat::X509;
                break;
            case Algorithm::AES:
            case Algorithm::TRIPLE_DES:
            case Algorithm::HMAC:
                out_key_format = KeyFormat::RAW;
                break;
            default:
                std::cerr << "Algorithm " << static_cast<int>(alg)
                    << " (" << toString(alg) << ") is not supported" << std::endl;
            return -1;
        }
    }

    ErrorCode e = hal.exportKey(out_key_format, key, app_id, app_data, out_public_key_x509);
    if (e != ErrorCode::OK) {
        std::cerr << "exportKey operation failed: "
            << static_cast<i32>(e) << " (" << toString(e) << ")" << std::endl;
        return 1;
    }

    std::cout << "Successfully exported public key from KeyMaster" << std::endl;
    return 0;
}

int upgrade_key(SusKMHal& hal,
                std::vector<u8> const& in_keyblob_to_upgrade,
                std::vector<KeyParameter> const& in_upgrade_params,
                std::vector<u8>& out_upgraded_keyblob)
{
    ErrorCode e = hal.upgradeKey(in_keyblob_to_upgrade, in_upgrade_params, out_upgraded_keyblob);
    if (e != ErrorCode::OK) {
        std::cerr << "upgradeKey operation failed: "
            << static_cast<i32>(e) << " (" << toString(e) << ")" << std::endl;
        return 1;
    }
    std::cout << "Successfully upgraded key blob" << std::endl;
    return 0;
}

} /* namespace hal_ops */
} /* namespace cli */
} /* namespace suskeymaster */
