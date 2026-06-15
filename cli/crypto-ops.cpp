#include "cli.hpp"
#include <core/int.h>
#include <libsuskmhal/suskmhal.hpp>
#include <libsuskmhal/keymaster-types-cpp.hpp>
#include <libsuskmhal/util/km-params.hpp>
#include <libsuskmhal/transport/aosp-hidl-support.hpp>
#include <vector>
#include <cstring>

namespace suskeymaster {
namespace cli {
namespace hal_ops {
namespace crypto {

using namespace kmhal::generic;
using kmhal::SusKMHal;

static ErrorCode do_generic_operation_cycle(SusKMHal& hal,
        KeyPurpose op, std::vector<u8> const& keyblob, std::vector<u8> const& input_,
        std::vector<KeyParameter> const& params, HardwareAuthToken const& authToken,
        std::vector<u8> const* finish_signature,
        std::vector<u8>* output, std::vector<u8>* out_gcm_begin_iv);

static void append_vec(std::vector<u8>& dst, const std::vector<u8>& src);

static void init_encrypt_params_from_user_and_characteristics(
        std::vector<KeyParameter>& params, const KeyCharacteristics& kc,
        bool* is_aes_with_iv
);
static void init_sign_params_from_user_and_characteristics(
        std::vector<KeyParameter>& params, const KeyCharacteristics& kc,
        std::vector<KeyParameter>& out_verify_params
);

int encrypt(SusKMHal& hal, std::vector<u8> const& plaintext,
            std::vector<u8> const& key, std::vector<KeyParameter> const& encrypt_params,
            HardwareAuthToken const& auth_token,
            std::vector<u8>& out_ciphertext, std::vector<u8>& out_nonce)
{
    std::vector<KeyParameter> params(encrypt_params);

    std::vector<u8> app_id, app_data;
    util::extract_application_id_and_data(params, app_id, app_data);
    KeyCharacteristics kc;
    ErrorCode e = ErrorCode::UNKNOWN_ERROR;

    out_nonce.resize(0);

    if ((e = hal.getKeyCharacteristics(key, app_id, app_data, kc)) != ErrorCode::OK) {
        std::cerr << "Couldn't get the key's characteristics: "
            << static_cast<int>(e) << " (" << toString(e) << ")" << std::endl;
        return 1;
    }

    bool is_aes_with_iv = false;
    init_encrypt_params_from_user_and_characteristics(params, kc, &is_aes_with_iv);

    if (do_generic_operation_cycle(hal, KeyPurpose::ENCRYPT, key,
                plaintext, params, auth_token, nullptr, &out_ciphertext,
                (is_aes_with_iv ? &out_nonce : nullptr)
        ) != ErrorCode::OK)
    {
        std::cerr << "Encryption operation failed!" << std::endl;
        return 1;
    }

    std::cout << "Encryption operation successful!" << std::endl;
    return 0;
}

int decrypt(SusKMHal& hal, std::vector<u8> const& ciphertext,
            std::vector<u8> const& key, std::vector<KeyParameter> const& decrypt_params,
            HardwareAuthToken const& auth_token,
            std::vector<u8>& out_plaintext)
{
    std::vector<KeyParameter> params(decrypt_params);

    std::vector<u8> app_id, app_data;
    util::extract_application_id_and_data(params, app_id, app_data);
    KeyCharacteristics kc;
    ErrorCode e = ErrorCode::UNKNOWN_ERROR;
    if ((e = hal.getKeyCharacteristics(key, app_id, app_data, kc)) != ErrorCode::OK) {
        std::cerr << "Couldn't get the key's characteristics: "
            << static_cast<int>(e) << " (" << toString(e) << ")" << std::endl;
        return 1;
    }

    init_encrypt_params_from_user_and_characteristics(params, kc, nullptr);

    if (do_generic_operation_cycle(hal, KeyPurpose::DECRYPT, key, ciphertext,
                params, auth_token, nullptr, &out_plaintext, nullptr) != ErrorCode::OK)
    {
        std::cerr << "Decryption operation failed!" << std::endl;
        return 1;
    }

    std::cout << "Decryption operation successful!" << std::endl;
    return 0;
}

int sign(SusKMHal& hal, std::vector<u8> const& message,
         std::vector<u8> const& key, std::vector<KeyParameter> const& in_sign_params,
         HardwareAuthToken const& auth_token,
         std::vector<u8>& out_signature)
{
    std::vector<KeyParameter> params(in_sign_params), verify_params;

    std::vector<u8> app_id, app_data;
    util::extract_application_id_and_data(params, app_id, app_data);
    KeyCharacteristics kc;
    ErrorCode e = ErrorCode::UNKNOWN_ERROR;
    if ((e = hal.getKeyCharacteristics(key, app_id, app_data, kc)) != ErrorCode::OK) {
        std::cerr << "Couldn't get the key's characteristics: "
            << static_cast<int>(e) << " (" << toString(e) << ")" << std::endl;
        return 1;
    }

    init_sign_params_from_user_and_characteristics(params, kc, verify_params);

    if (do_generic_operation_cycle(hal, KeyPurpose::SIGN, key, message,
                params, auth_token, nullptr, &out_signature, nullptr) != ErrorCode::OK)
    {
        std::cerr << "Signing operation failed!" << std::endl;
        return 1;
    }

    std::cout << "Signing operation OK" << std::endl;

    bool found_purpose_verify = false;
    for (const auto& kp : kc.hardwareEnforced) {
        if (kp.tag == Tag::PURPOSE && kp.f.purpose == KeyPurpose::VERIFY) {
            found_purpose_verify = true;
            break;
        }
    }
    if (!found_purpose_verify) {
        std::cerr << "WARNING: The key doesn't have KeyPurpose::VERIFY; "
            "skipping sanity signature verification" << std::endl;
        return 0;
    }

    if (do_generic_operation_cycle(hal, KeyPurpose::VERIFY, key, message,
                verify_params, auth_token, &out_signature, nullptr, nullptr) != ErrorCode::OK)
    {
        std::cerr << "Sanity signature verification failed!" << std::endl;
        return 1;
    }
    std::cout << "Sanity signature verification OK" << std::endl;
    return 0;
}

int verify(SusKMHal& hal,
           std::vector<u8> const& message, std::vector<u8> const& signature,
           std::vector<u8> const& key, std::vector<KeyParameter> const& in_verify_params,
           HardwareAuthToken const& auth_token)
{
    std::vector<u8> app_id, app_data;
    util::extract_application_id_and_data(in_verify_params, app_id, app_data);
    KeyCharacteristics kc;
    ErrorCode e = ErrorCode::UNKNOWN_ERROR;
    if ((e = hal.getKeyCharacteristics(key, app_id, app_data, kc)) != ErrorCode::OK) {
        std::cerr << "Couldn't get the key's characteristics: "
            << static_cast<int>(e) << " (" << toString(e) << ")" << std::endl;
        return 1;
    }

    std::vector<KeyParameter> dummy(in_verify_params);
    std::vector<KeyParameter> verify_params;
    init_sign_params_from_user_and_characteristics(dummy, kc, verify_params);

    if (do_generic_operation_cycle(hal, KeyPurpose::VERIFY, key, message,
                verify_params, auth_token, &signature, nullptr, nullptr) != ErrorCode::OK)
    {
        std::cerr << "Signature verification failed!" << std::endl;
        return 1;
    }

    std::cout << "Signature verification OK" << std::endl;
    return 0;
}

static ErrorCode do_generic_operation_cycle(SusKMHal& hal,
        KeyPurpose op, std::vector<u8> const& keyblob, std::vector<u8> const& input_,
        std::vector<KeyParameter> const& params, HardwareAuthToken const& auth_token,
        std::vector<u8> const* finish_signature,
        std::vector<u8>* output, std::vector<u8>* out_gcm_begin_iv)
{
    OpaqueOpHandle operation_handle{};
    std::vector<KeyParameter> kp_tmp;
    ErrorCode e = ErrorCode::UNKNOWN_ERROR;

    if (output) output->resize(0);

    e = hal.begin(op, keyblob, params, auth_token, kp_tmp, operation_handle);
    if (e != ErrorCode::OK) {
        std::cerr << toString(op) << ": BEGIN operation failed: "
            << static_cast<int>(e) << " (" << toString(e) << ")" << std::endl;
        return e;
    }
    if (out_gcm_begin_iv) {
        for (const auto& kp : kp_tmp) {
            if (kp.tag == Tag::NONCE) {
                std::cout << "Extracting GCM IV from params returned by begin()..." << std::endl;
                out_gcm_begin_iv->resize(kp.blob.size());
                std::memcpy(out_gcm_begin_iv->data(), kp.blob.data(), kp.blob.size());
                break;
            }
        }
    }

    std::vector<u8> input(input_);
    size_t progress = 0;
    u32 consumed = 0;

    while (progress < input.size()) {
        std::vector<u8> chunk(input.begin() + progress, input.end());
        std::vector<u8> tmp_output;

        e = hal.update(operation_handle, {}, chunk, auth_token,
                consumed, kp_tmp, tmp_output);
        if (e != ErrorCode::OK) {
            std::cerr << toString(op) << ": UPDATE operation failed: "
                << static_cast<int>(e) << " (" << toString(e) << ")" << std::endl;
            (void) hal.abort(operation_handle);
            return e;
        } else if (consumed == 0) {
            std::cerr << toString(op) << ": input_consumed is 0!" << std::endl;
            if ((e = hal.abort(operation_handle)) != ErrorCode::OK) {
                std::cerr << toString(op) << ": ABORT failed: "
                    << static_cast<int>(e) << " (" << toString(e) << ")" << std::endl;
            }
            return ErrorCode::UNKNOWN_ERROR;
        }

        progress += consumed;

        if (output)
            append_vec(*output, tmp_output);
    }

    std::vector<u8> last_tmp_output;
    const std::vector<u8> dummy_;

    const std::vector<u8>& finish_sig_ = finish_signature ? *finish_signature : dummy_;
    e = hal.finish(operation_handle, {}, {}, finish_sig_, auth_token, kp_tmp, last_tmp_output);
    if (e != ErrorCode::OK) {
        std::cerr << toString(op) << ": FINISH operation failed: "
            << static_cast<int>(e) << " (" << toString(e) << ")" << std::endl;
        return e;
    }
    if (output)
        append_vec(*output, last_tmp_output);

    return ErrorCode::OK;
}

static void append_vec(std::vector<u8>& dst, const std::vector<u8>& src)
{
    size_t prev_size = dst.size();
    dst.resize(prev_size + src.size());
    std::memcpy(dst.data() + prev_size, src.data(), src.size());
}

static void init_encrypt_params_from_user_and_characteristics(
        std::vector<KeyParameter>& params, const KeyCharacteristics& kc,
        bool* is_aes_with_iv
)
{
    Algorithm alg = util::find_algorithm(kc.hardwareEnforced,
            { Algorithm::RSA, Algorithm::AES, Algorithm::TRIPLE_DES });
    if (alg == static_cast<Algorithm>(-1))
        std::cerr << "WARNING: Encryption might not be supported for this key!" << std::endl;

    bool digest_found = false, padding_found = false,
         block_mode_found = false, mac_length_found = false;
    Digest digest;
    PaddingMode padding;
    BlockMode block_mode;
    u32 mac_length = 0;

    for (const auto& kp : params) {
        if (kp.tag == Tag::DIGEST && !digest_found) {
            digest_found = true;
            digest = kp.f.digest;
        } else if (kp.tag == Tag::PADDING && !padding_found) {
            padding_found = true;
            padding = kp.f.paddingMode;
        } else if (kp.tag == Tag::BLOCK_MODE) {
            block_mode_found = true;
            block_mode = kp.f.blockMode;
        } else if (kp.tag == Tag::MAC_LENGTH) {
            mac_length_found = true;
            mac_length = kp.f.integer;
        }
    }

    for (const auto& kp : kc.hardwareEnforced) {
        if (alg == Algorithm::RSA) {
            if (kp.tag == Tag::PADDING && !padding_found &&
                    (kp.f.paddingMode == PaddingMode::RSA_OAEP ||
                     kp.f.paddingMode == PaddingMode::RSA_PKCS1_1_5_ENCRYPT ||
                     kp.f.paddingMode == PaddingMode::NONE)
            ) {
                padding = kp.f.paddingMode;
                padding_found = true;
            }
        } else if (alg == Algorithm::AES) {
            if (kp.tag == Tag::BLOCK_MODE && !block_mode_found) {
                block_mode = kp.f.blockMode;
                block_mode_found = true;
            }
        } else if (alg == Algorithm::TRIPLE_DES) {
            if (kp.tag == Tag::BLOCK_MODE && !block_mode_found &&
                    (kp.f.blockMode == BlockMode::ECB || kp.f.blockMode == BlockMode::CBC)
            ) {
                block_mode = kp.f.blockMode;
                block_mode_found = true;
            } else if (kp.tag == Tag::PADDING && !padding_found &&
                    kp.f.paddingMode == PaddingMode::PKCS7) {
                padding = kp.f.paddingMode;
                padding_found = true;
            }
        }
    }
    if (alg == Algorithm::AES && block_mode_found) {
        for (const auto& kp : kc.hardwareEnforced) {
            if (block_mode == BlockMode::GCM) {
                if (kp.tag == Tag::MIN_MAC_LENGTH && !mac_length_found) {
                    mac_length = kp.f.integer;
                    mac_length_found = true;
                }
            }

            if (block_mode == BlockMode::GCM || block_mode == BlockMode::CTR) {
                if (kp.tag == Tag::PADDING && !padding_found &&
                        kp.f.paddingMode == PaddingMode::NONE)
                {
                    padding = PaddingMode::NONE;
                    padding_found = true;
                }
            } else if (block_mode == BlockMode::ECB || block_mode == BlockMode::CBC) {
                if (kp.tag == Tag::PADDING && !padding_found &&
                        kp.f.paddingMode == PaddingMode::PKCS7)
                {
                    padding = PaddingMode::PKCS7;
                    padding_found = true;
                }
            }
        }
    } else if (alg == Algorithm::RSA && padding_found &&
            padding == PaddingMode::RSA_OAEP && !digest_found)
    {
        for (const auto& kp : kc.hardwareEnforced) {
            if (kp.tag == Tag::DIGEST && kp.f.digest != Digest::NONE) {
                digest_found = true;
                digest = kp.f.digest;
                break;
            }
        }
    } else if (alg == Algorithm::RSA && padding_found &&
            padding == PaddingMode::NONE && !digest_found)
    {
        for (const auto& kp : kc.hardwareEnforced) {
            if (kp.tag == Tag::DIGEST && kp.f.digest == Digest::NONE) {
                digest_found = true;
                digest = kp.f.digest;
                break;
            }
        }
    }

    std::vector<kmhal::util::km_default> defaults;

    if (alg == Algorithm::RSA) {
        if (padding_found) {
            std::cout << "RSA encryption padding mode: " << toString(padding) << std::endl;
            defaults.emplace_back(Tag::PADDING, std::vector<PaddingMode>{ padding });

            if (padding == PaddingMode::RSA_OAEP) {
                if (digest_found) {
                    std::cout << "RSA-OAEP encryption digest: " << toString(digest) << std::endl;
                    defaults.emplace_back(Tag::DIGEST, std::vector<Digest>{ digest });
                } else {
                    std::cout << "WARNING: RSA-OAEP encrypting without a digest parameter!"
                        << std::endl;
                }
            }
        } else {
            std::cerr << "WARNING: RSA-encrypting without a padding mode parameter!" << std::endl;
        }
    } else if (alg == Algorithm::AES) {
        if (block_mode_found) {
            std::cout << "AES encryption block mode: " << toString(block_mode) << std::endl;
            defaults.emplace_back(Tag::BLOCK_MODE, std::vector<BlockMode>{ block_mode });
        } else {
            std::cout << "AES-encrypting without a block mode parameter!" << std::endl;
        }

        if (block_mode_found && block_mode == BlockMode::GCM) {
            if (mac_length_found) {
                std::cout << "AES-GCM MAC (auth tag) length: "
                    << mac_length << " bits" << std::endl;
                defaults.emplace_back(Tag::MAC_LENGTH, mac_length);
            } else {
                std::cerr << "WARNING: AES-GCM encrypting without a MAC (auth tag) length "
                    "parameter" << std::endl;
            }
        }

        if (padding_found) {
            if (block_mode_found && is_aes_with_iv)
                *is_aes_with_iv = block_mode == BlockMode::GCM || block_mode == BlockMode::CTR;

            if (block_mode_found &&
                    (block_mode == BlockMode::GCM || block_mode == BlockMode::CTR))
            {
                if (padding != PaddingMode::NONE)
                    std::cerr << "WARNING: Padding mode must be NONE for AES-GCM and AES-CTR"
                        << std::endl;
            } else if (block_mode_found &&
                    (block_mode == BlockMode::ECB || block_mode == BlockMode::CBC))
            {
                if (padding != PaddingMode::PKCS7)
                    std::cerr << "WARNING: Padding mode must be PKCS7 for AES-ECB and AES-CBC"
                        << std::endl;
            }

            std::cout << "AES encryption padding mode: " << toString(padding) << std::endl;
            defaults.emplace_back(Tag::PADDING, std::vector<PaddingMode>{ padding });
        } else {
            std::cerr << "WARNING: AES-encrypting without a padding mode parameter!" << std::endl;
        }
    } else if (alg == Algorithm::TRIPLE_DES) {
        if (block_mode_found) {
            if (block_mode == BlockMode::ECB || block_mode == BlockMode::CBC) {
                std::cout << "Triple-DES encryption block mode: " << toString(block_mode)
                    << std::endl;
                defaults.emplace_back(Tag::BLOCK_MODE, std::vector<BlockMode>{ block_mode });
            } else {
                std::cerr << "WARNING: Unsupported block mode for Triple-DES: "
                    << toString(block_mode) << std::endl;
            }
        } else {
            std::cerr << "WARNING: Triple-DES-encrypting without a block mode parameter!"
                << std::endl;
        }

        if (padding_found) {
            if (padding != PaddingMode::PKCS7)
                std::cerr << "WARNING: Unsupported padding mode for Triple-DES: "
                    << toString(padding) << std::endl;

            std::cout << "Triple-DES encryption padding mode: " << toString(padding) << std::endl;
            defaults.emplace_back(Tag::PADDING, std::vector<PaddingMode>{ padding });
        }
    }

    kmhal::util::init_default_params(params, defaults);
}

static void init_sign_params_from_user_and_characteristics(
        std::vector<KeyParameter>& params, const KeyCharacteristics& kc,
        std::vector<KeyParameter>& out_verify_params
)
{
    Algorithm alg = util::find_algorithm(kc.hardwareEnforced,
            { Algorithm::EC, Algorithm::RSA, Algorithm::HMAC });
    if (alg == static_cast<Algorithm>(-1))
        std::cerr << "WARNING: Signing is not supported for this key!" << std::endl;

    Digest digest;
    PaddingMode padding;
    u32 mac_length = 0;
    bool digest_found = false, padding_found = false, mac_length_found = false;
    for (const auto& kp : params) {
        if (kp.tag == Tag::DIGEST && !digest_found) {
            digest_found = true;
            digest = kp.f.digest;
        } else if (kp.tag == Tag::PADDING && !padding_found) {
            padding_found = true;
            padding = kp.f.paddingMode;
        } else if (kp.tag == Tag::MAC_LENGTH) {
            mac_length_found = true;
            mac_length = kp.f.integer;
        }
    }

    std::vector<kmhal::util::km_default> defaults, verify_defaults;

    for (const auto& kp : kc.hardwareEnforced) {
        if ((alg == Algorithm::EC || alg == Algorithm::HMAC)
                && kp.tag == Tag::DIGEST && !digest_found)
        {
            digest = kp.f.digest;
            digest_found = true;
        }
        if (alg == Algorithm::RSA && kp.tag == Tag::PADDING && !padding_found &&
                (kp.f.paddingMode == PaddingMode::RSA_PKCS1_1_5_SIGN ||
                 kp.f.paddingMode == PaddingMode::RSA_PSS ||
                 kp.f.paddingMode == PaddingMode::NONE)
        ) {
            padding = kp.f.paddingMode;
            padding_found = true;
        }
        if (alg == Algorithm::HMAC && kp.tag == Tag::MIN_MAC_LENGTH && !mac_length_found) {
            mac_length = kp.f.integer;
            mac_length_found = true;
        }
    }
    if (alg == Algorithm::RSA && !digest_found) {
        for (const auto& kp : kc.hardwareEnforced) {
            if (kp.tag != Tag::DIGEST)
                continue;

            if (padding_found) {
                switch(padding) {
                case PaddingMode::NONE:
                    /* For PaddingMode::NONE, Digest::NONE should be specified */
                    if (kp.f.digest != Digest::NONE)
                        continue;
                    break;
                case PaddingMode::RSA_PKCS1_1_5_SIGN: break;
                case PaddingMode::RSA_PSS:
                    /* PaddingMode::RSA_PSS and Digest::NONE are incompatible */
                    if (kp.f.digest == Digest::NONE)
                        continue;
                    break;
                default:
                    continue;
                }
            }

            digest_found = true;
            digest = kp.f.digest;
        }
    }

    if (alg == Algorithm::HMAC) {
        if (mac_length_found) {
            std::cout << "MAC length: " << mac_length << " bits" << std::endl;
            defaults.emplace_back(Tag::MAC_LENGTH, mac_length);
        } else {
            std::cerr << "WARNING: Generating an HMAC without a MAC length parameter!"
                << std::endl;
        }
    }

    if (alg == Algorithm::RSA) {
        if (padding_found) {
            if (padding == PaddingMode::RSA_OAEP || padding == PaddingMode::RSA_PKCS1_1_5_ENCRYPT)
                std::cerr << "WARNING: RSA PaddingMode::" << toString(padding)
                    << " does not support signing!" << std::endl;

            std::cout << "RSA Signature padding: " << toString(padding) << std::endl;
            defaults.emplace_back(Tag::PADDING, std::vector<PaddingMode>{ padding });
            verify_defaults.emplace_back(Tag::PADDING, std::vector<PaddingMode> { padding });
        } else {
            std::cerr << "WARNING: RSA signing without a padding mode parameter!" << std::endl;
        }
    }

    if (alg == Algorithm::RSA || alg == Algorithm::EC || alg == Algorithm::HMAC) {
        if (digest_found) {
            if (alg == Algorithm::RSA && padding_found && padding == PaddingMode::RSA_PSS &&
                    digest == Digest::NONE)
            {
                std::cerr << "WARNING: Digest cannot be NONE for RSA-PSS signing!" << std::endl;
            } else {
                std::cout << toString(alg) << " Signature digest: "
                    << toString(digest) << std::endl;
                defaults.emplace_back(Tag::DIGEST, std::vector<Digest>{ digest });
                verify_defaults.emplace_back(Tag::DIGEST, std::vector<Digest> { digest });
            }
        } else {
            std::cerr << "WARNING: "
                << toString(alg) << " signing without a digest parameter!" << std::endl;
        }
    }

    for (const Tag t : { Tag::APPLICATION_ID, Tag::APPLICATION_DATA }) {
        const std::vector<u8> *blob = util::find_blob_tag(t, params);
        if (blob == nullptr)
            continue;

        verify_defaults.emplace_back(t, *blob);
    }

    kmhal::util::init_default_params(params, defaults);
    kmhal::util::init_default_params(out_verify_params, verify_defaults);
}

} /* namespace crypto */
} /* namespace hal_ops */
} /* namespace cli */
} /* namespace suskeymaster */
