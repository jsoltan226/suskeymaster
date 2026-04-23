#define HIDL_DISABLE_INSTRUMENTATION
#include "cli.hpp"
#include <core/vector.h>
#include <libsuscertmod/key-desc.h>
#include <libsuscertmod/leaf-cert.h>
#include <libsuskmhal/hidl/hidl-hal.hpp>
#include <libsuskmhal/util/km-params.hpp>
#include <libsuskmhal/util/keymaster-types-c.h>
#include <hidl/HidlSupport.h>
#include <android/hardware/keymaster/4.0/types.h>
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

using namespace ::android::hardware::keymaster::V4_0;
using ::android::hardware::hidl_vec;
using kmhal::hidl::HidlSusKeymaster4;

static void pr_info(const char *fmt, ...) {
    va_list vlist;
    va_start(vlist, fmt);
    std::vprintf(fmt, vlist);
    std::putchar('\n');
    va_end(vlist);
}

int get_key_characteristics(HidlSusKeymaster4& hal,
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
        kmhal::util::KM_dump_param_list(pr_info, sw_par, 1, "softwareEnforced");
        kmhal::util::KM_dump_param_list(pr_info, hw_par, 1, "hardwareEnforced");
        std::cout << "};" << std::endl;
        std::cout << "=====  END KEY CHARACTERISTICS DUMP  =====" << std::endl;
    }

    return EXIT_SUCCESS;
}

int generate_key(HidlSusKeymaster4& hal,
    hidl_vec<KeyParameter> const& in_gen_params,
    hidl_vec<uint8_t>& out_key_blob)
{
    Algorithm alg = find_algorithm(in_gen_params,
        { Algorithm::EC, Algorithm::RSA, Algorithm::AES, Algorithm::TRIPLE_DES, Algorithm::HMAC }
    );
    if (alg == static_cast<Algorithm>(-1))
        return EXIT_FAILURE;

    std::vector<KeyPurpose> purposes = find_rep_tag<KeyPurpose>(Tag::PURPOSE, in_gen_params);
    bool sign_verify = false, enc_dec = false, wrap_key = false;
    for (KeyPurpose p : purposes) {
        if (p == KeyPurpose::SIGN || p == KeyPurpose::VERIFY)
            sign_verify = true;
        else if (p == KeyPurpose::ENCRYPT || p == KeyPurpose::DECRYPT)
            enc_dec = true;
        else if (p == KeyPurpose::WRAP_KEY)
            wrap_key = true;
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

    hidl_vec<KeyParameter> params(in_gen_params);
    std::vector<kmhal::util::km_default> defaults;
    std::vector<PaddingMode> padding_modes;
    std::vector<BlockMode> block_modes;
    bool has_gcm, has_ctr_gcm, has_ecb_cbc;

    switch (alg) {
    case Algorithm::RSA:
        defaults = {
            { Tag::ALGORITHM, Algorithm::RSA },
            /* Only 2048-bit keys are guaranteed to be supported
             * by both TEE and STRONGBOX devices */
            { Tag::KEY_SIZE, 2048 },
            { Tag::RSA_PUBLIC_EXPONENT, 65537 },
            { Tag::NO_AUTH_REQUIRED, true }
        };

        if (sign_verify) padding_modes.push_back(PaddingMode::RSA_PKCS1_1_5_SIGN);
        if (enc_dec) padding_modes.push_back(PaddingMode::RSA_PKCS1_1_5_ENCRYPT);
        if (wrap_key) padding_modes.push_back(PaddingMode::RSA_OAEP);

        defaults.emplace_back(Tag::PADDING, padding_modes);

        kmhal::util::init_default_params(params, defaults);
        break;
    case Algorithm::EC:
        kmhal::util::init_default_params(params, {
            { Tag::ALGORITHM, Algorithm::EC },
            { Tag::EC_CURVE, EcCurve::P_256 },
            { Tag::NO_AUTH_REQUIRED, true }
        });
        break;
    case Algorithm::AES:
        defaults = {
            { Tag::ALGORITHM, Algorithm::AES },
            { Tag::KEY_SIZE, 256 },
            { Tag::NO_AUTH_REQUIRED, true }
        };

        block_modes = find_rep_tag<BlockMode>(Tag::BLOCK_MODE, in_gen_params);
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

        kmhal::util::init_default_params(params, defaults);
        break;
    case Algorithm::TRIPLE_DES:
        kmhal::util::init_default_params(params, {
            { Tag::ALGORITHM, Algorithm::TRIPLE_DES },
            { Tag::KEY_SIZE, 168 },
            { Tag::PADDING, { PaddingMode::PKCS7 } },
            { Tag::NO_AUTH_REQUIRED, true }
        });
        break;
    case Algorithm::HMAC:
        kmhal::util::init_default_params(params, {
            { Tag::ALGORITHM, Algorithm::HMAC },
            { Tag::KEY_SIZE, 256 },
            { Tag::MIN_MAC_LENGTH, 256 },
            { Tag::NO_AUTH_REQUIRED, true }
        });
        break;
    }
    if (alg == Algorithm::EC) {
    } else /* if (alg == Algorithm::RSA) */ {
    }

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

int attest_key(HidlSusKeymaster4& hal,
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

int import_key(HidlSusKeymaster4& hal,
    hidl_vec<uint8_t> const& priv_pkcs8,
    hidl_vec<KeyParameter> const& in_import_params,
    hidl_vec<uint8_t>& out_key_blob)
{
    Algorithm alg = determine_pkey_algorithm(priv_pkcs8);
    if (alg == static_cast<Algorithm>(-1)) {
        std::cerr << "The key blob is not a valid EC or RSA PKCS#8 private key!" << std::endl;
        return 1;
    }
    std::cout << "Private key algorithm is " << toString(alg) << std::endl;

    hidl_vec<KeyParameter> params(in_import_params);
    kmhal::util::init_default_params(params, { { Tag::ALGORITHM, alg } });

    KeyCharacteristics c;
    ErrorCode e = hal.importKey(params, KeyFormat::PKCS8, priv_pkcs8, out_key_blob, c);
    if (e != ErrorCode::OK) {
        std::cerr << "importKey operation failed: "
            << static_cast<int32_t>(e) << " (" << toString(e) << ")" << std::endl;
        return 1;
    }

    std::cout << "Successfully imported an " << toString(alg)
        << " private key into KeyMaster" << std::endl;
    return 0;
}

int export_key(HidlSusKeymaster4& hal,
    hidl_vec<uint8_t> const& key,
    hidl_vec<uint8_t>& out_public_key_x509,
    hidl_vec<KeyParameter> const& in_application_id_data)
{
    hidl_vec<uint8_t> app_id;
    hidl_vec<uint8_t> app_data;
    extract_application_id_and_data(in_application_id_data, app_id, app_data);

    ErrorCode e = hal.exportKey(KeyFormat::X509, key, app_id, app_data, out_public_key_x509);

    if (e != ErrorCode::OK) {
        std::cerr << "exportKey operation failed: "
            << static_cast<int32_t>(e) << " (" << toString(e) << ")" << std::endl;
        return 1;
    }

    std::cout << "Successfully exported public key from KeyMaster" << std::endl;
    return 0;
}

int upgrade_key(HidlSusKeymaster4& hal,
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
