#define HIDL_DISABLE_INSTRUMENTATION
#include "cli.hpp"
#include <core/vector.h>
#include <libsuscertmod/key-desc.h>
#include <libsuscertmod/leaf-cert.h>
#include <libsuskmhal/hidl/hidl-hal.hpp>
#include <libsuskmhal/util/km-params.hpp>
#include <libsuskmhal/util/keymaster-types-c.h>
#include <hidl/HidlSupport.h>
#include <android/hardware/keymaster/generic/types.h>
#include <ctime>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ostream>
#include <iostream>
#include <openssl/evp.h>

namespace suskeymaster {
namespace cli {
namespace hal_ops {

using namespace ::android::hardware::keymaster::generic;
using ::android::hardware::hidl_vec;
using kmhal::hidl::HidlSusKeymaster;

static void pr_info(const char *fmt, ...) {
    va_list vlist;
    va_start(vlist, fmt);
    std::vprintf(fmt, vlist);
    std::putchar('\n');
    va_end(vlist);
}

int get_key_characteristics(HidlSusKeymaster& hal,
    hidl_vec<uint8_t> const& key, hidl_vec<KeyParameter> const& in_application_id_data)
{
    hidl_vec<uint8_t> app_id;
    hidl_vec<uint8_t> app_data;
    extract_application_id_and_data(in_application_id_data, app_id, app_data);

    KeyCharacteristics kc;
    ErrorCode e = hal.getKeyCharacteristics(key, app_id, app_data, kc);
    if (e != ErrorCode::OK) {
        std::cerr << "Couldn't get the key's characteristics: "
            << static_cast<int>(e) << " (" << toString(e) << ")" << std::endl;
        return 1;
    }

    {
        kmhal::util::KM_PARAM_LIST *sw_par = NULL, *hw_par = NULL;

        sw_par = kmhal::util::key_params_2_param_list(kc.softwareEnforced);
        if (sw_par == NULL) {
            std::cerr << "Failed to convert softwareEnforced key param vec to a param list"
                << std::endl;
            return EXIT_FAILURE;
        }

        hw_par = kmhal::util::key_params_2_param_list(kc.hardwareEnforced);
        if (hw_par == NULL) {
            std::cerr << "Failed to convert hardwareEnforced key param vec to a param list"
                << std::endl;
            return EXIT_FAILURE;
        }

        std::cout << "===== BEGIN KEY CHARACTERISTICS DUMP =====" << std::endl;
        std::cout << "KeyCharacteristics kc = {" << std::endl;
        kmhal::util::KM_dump_param_list(pr_info, "softwareEnforced", sw_par, 1, false);
        kmhal::util::KM_dump_param_list(pr_info, "hardwareEnforced", hw_par, 1, true);
        std::cout << "};" << std::endl;
        std::cout << "=====  END KEY CHARACTERISTICS DUMP  =====" << std::endl;
    }

    return EXIT_SUCCESS;
}

int generate_key(HidlSusKeymaster& hal,
    hidl_vec<KeyParameter> const& in_gen_params,
    hidl_vec<uint8_t>& out_key_blob)
{
    Algorithm alg = find_algorithm(in_gen_params,
        { Algorithm::EC, Algorithm::RSA, Algorithm::AES, Algorithm::TRIPLE_DES, Algorithm::HMAC }
    );
    if (alg == static_cast<Algorithm>(-1))
        return EXIT_FAILURE;

    hidl_vec<KeyParameter> params(in_gen_params);
    init_default_params_for_alg_and_purposes(params, alg,
            find_rep_tag<KeyPurpose>(Tag::PURPOSE, params), true);

    KeyCharacteristics dummy;
    ErrorCode e = hal.generateKey(params, out_key_blob, dummy);
    if (e != ErrorCode::OK) {
        std::cerr << "generateKey operation failed: "
            << static_cast<int32_t>(e) << " (" << toString(e) << ")" << std::endl;
        return 1;
    }
    std::cout << "Successfully generated " << toString(alg) << " key" << std::endl;

    return 0;
}

int attest_key(HidlSusKeymaster& hal,
    hidl_vec<uint8_t> const& key, hidl_vec<KeyParameter> const& in_attest_params)
{
    hidl_vec<KeyParameter> params = in_attest_params;

    static const uint8_t ch[] = "suskeymaster TEST ATTESTATION CHALLENGE";
    static const size_t ch_len = sizeof(ch) - 1;
    static const uint8_t app_id[] = "suskeymaster TEST ATTESTATION APPLICATION ID";
    static const size_t app_id_len = sizeof(app_id) - 1;
    kmhal::util::init_default_params(params, {
        { Tag::ATTESTATION_CHALLENGE, hidl_vec<uint8_t>(ch, ch + ch_len) },
        { Tag::ATTESTATION_APPLICATION_ID, hidl_vec<uint8_t>(app_id, app_id + app_id_len) }
    });

    hidl_vec<hidl_vec<uint8_t>> cert_chain = {};

    ErrorCode e = hal.attestKey(key, params, cert_chain);
    if (e != ErrorCode::OK) {
        std::cerr << "attestKey operation failed: "
            << static_cast<int32_t>(e) << " (" << toString(e) << ")" << std::endl;
        return 1;
    }

    std::cout << "Successfully generated KeyMaster key attestation" << std::endl;

    return transact::server::verify_attestation(cert_chain);
}

int import_key(HidlSusKeymaster& hal,
    hidl_vec<uint8_t> const& in_private_key,
    hidl_vec<KeyParameter> const& in_import_params,
    hidl_vec<uint8_t>& out_key_blob)
{
    Algorithm alg = determine_algorithm_from_params_and_pkey(in_import_params, in_private_key);
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
    }

    std::cout << "Private key algorithm is " << toString(alg) <<
        " (inferred format: " << toString(format) << ")" << std::endl;

    hidl_vec<KeyParameter> params(in_import_params);
    init_default_params_for_alg_and_purposes(params, alg,
            find_rep_tag<KeyPurpose>(Tag::PURPOSE, params), false);

    KeyCharacteristics c;
    ErrorCode e = hal.importKey(params, format, in_private_key, out_key_blob, c);
    if (e != ErrorCode::OK) {
        std::cerr << "importKey operation failed: "
            << static_cast<int32_t>(e) << " (" << toString(e) << ")" << std::endl;
        return 1;
    }

    std::cout << "Successfully imported an " << toString(alg)
        << " private key into KeyMaster" << std::endl;
    return 0;
}

int export_key(HidlSusKeymaster& hal,
    hidl_vec<uint8_t> const& key,
    hidl_vec<uint8_t>& out_public_key_x509,
    hidl_vec<KeyParameter> const& in_application_id_data)
{
    hidl_vec<uint8_t> app_id;
    hidl_vec<uint8_t> app_data;
    extract_application_id_and_data(in_application_id_data, app_id, app_data);

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
                << static_cast<int32_t>(e) << " (" << toString(e) << ")" << std::endl;
            return 1;
        }
        Algorithm alg = find_algorithm(kc.hardwareEnforced, {
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
        }
    }

    ErrorCode e = hal.exportKey(out_key_format, key, app_id, app_data, out_public_key_x509);
    if (e != ErrorCode::OK) {
        std::cerr << "exportKey operation failed: "
            << static_cast<int32_t>(e) << " (" << toString(e) << ")" << std::endl;
        return 1;
    }

    std::cout << "Successfully exported public key from KeyMaster" << std::endl;
    return 0;
}

int upgrade_key(HidlSusKeymaster& hal,
        hidl_vec<uint8_t> const& in_keyblob_to_upgrade,
        hidl_vec<KeyParameter> const& in_upgrade_params,
        hidl_vec<uint8_t>& out_upgraded_keyblob)
{
    ErrorCode e = hal.upgradeKey(in_keyblob_to_upgrade, in_upgrade_params, out_upgraded_keyblob);
    if (e != ErrorCode::OK) {
        std::cerr << "upgradeKey operation failed: "
            << static_cast<int32_t>(e) << " (" << toString(e) << ")" << std::endl;
        return 1;
    }
    std::cout << "Successfully upgraded key blob" << std::endl;
    return 0;
}

} /* namespace hal_ops */
} /* namespace cli */
} /* namespace suskeymaster */
