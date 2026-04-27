#define HIDL_DISABLE_INSTRUMENTATION
#include "cli.hpp"
#include <libsuskmhal/hidl/hidl-hal.hpp>
#include <libsuskmhal/util/km-params.hpp>
#include <hidl/HidlSupport.h>
#include <android/hardware/keymaster/generic/types.h>
#include <cstring>

namespace suskeymaster {
namespace cli {
namespace hal_ops {
namespace crypto {

using namespace ::android::hardware::keymaster::generic;
using ::android::hardware::hidl_vec;
using kmhal::hidl::HidlSusKeymaster;

static ErrorCode do_generic_operation_cycle(HidlSusKeymaster& hal,
        KeyPurpose op, hidl_vec<uint8_t> const& keyblob,
        hidl_vec<uint8_t> const& input_, hidl_vec<KeyParameter> const& params,
        hidl_vec<uint8_t> const* finish_signature,
        hidl_vec<uint8_t>* output, hidl_vec<uint8_t>* out_gcm_begin_iv);

static void append_vec(hidl_vec<uint8_t>& dst, const hidl_vec<uint8_t>& src);

static void init_encrypt_params_from_user_and_characteristics(
        hidl_vec<KeyParameter>& params, const KeyCharacteristics& kc,
        bool* is_aes_gcm
);
static void init_sign_params_from_user_and_characteristics(
        hidl_vec<KeyParameter>& params, const KeyCharacteristics& kc,
        hidl_vec<KeyParameter>& out_verify_params
);

int encrypt(HidlSusKeymaster& hal, hidl_vec<uint8_t> const& plaintext,
        hidl_vec<uint8_t> const& key, hidl_vec<KeyParameter> const& encrypt_params,
        hidl_vec<uint8_t>& out_ciphertext, hidl_vec<uint8_t>& out_aes_gcm_iv)
{
    hidl_vec<KeyParameter> params(encrypt_params);

    hidl_vec<uint8_t> app_id, app_data;
    extract_application_id_and_data(params, app_id, app_data);
    KeyCharacteristics kc;
    ErrorCode e = ErrorCode::UNKNOWN_ERROR;

    out_aes_gcm_iv.resize(0);

    if ((e = hal.getKeyCharacteristics(key, app_id, app_data, kc)) != ErrorCode::OK) {
        std::cerr << "Couldn't get the key's characteristics: "
            << static_cast<int>(e) << " (" << toString(e) << ")" << std::endl;
        return 1;
    }

    bool is_aes_gcm = false;
    init_encrypt_params_from_user_and_characteristics(params, kc, &is_aes_gcm);

    if (do_generic_operation_cycle(hal, KeyPurpose::ENCRYPT, key,
                plaintext, params, nullptr, &out_ciphertext,
                (is_aes_gcm ? &out_aes_gcm_iv : nullptr)
        ) != ErrorCode::OK)
    {
        std::cerr << "Encryption operation failed!" << std::endl;
        return 1;
    }

    std::cout << "Encryption operation successful!" << std::endl;
    return 0;
}

int decrypt(HidlSusKeymaster& hal, hidl_vec<uint8_t> const& ciphertext,
        hidl_vec<uint8_t> const& key, hidl_vec<KeyParameter> const& decrypt_params,
        hidl_vec<uint8_t>& out_plaintext)
{
    hidl_vec<KeyParameter> params(decrypt_params);

    hidl_vec<uint8_t> app_id, app_data;
    extract_application_id_and_data(params, app_id, app_data);
    KeyCharacteristics kc;
    ErrorCode e = ErrorCode::UNKNOWN_ERROR;
    if ((e = hal.getKeyCharacteristics(key, app_id, app_data, kc)) != ErrorCode::OK) {
        std::cerr << "Couldn't get the key's characteristics: "
            << static_cast<int>(e) << " (" << toString(e) << ")" << std::endl;
        return 1;
    }

    init_encrypt_params_from_user_and_characteristics(params, kc, nullptr);

    if (do_generic_operation_cycle(hal, KeyPurpose::DECRYPT, key,
                ciphertext, params, nullptr, &out_plaintext, nullptr) != ErrorCode::OK)
    {
        std::cerr << "Decryption operation failed!" << std::endl;
        return 1;
    }

    std::cout << "Decryption operation successful!" << std::endl;
    return 0;
}

int sign(HidlSusKeymaster& hal, hidl_vec<uint8_t> const& message,
    hidl_vec<uint8_t> const& key, hidl_vec<KeyParameter> const& in_sign_params,
    hidl_vec<uint8_t>& out_signature)
{
    hidl_vec<KeyParameter> params(in_sign_params), verify_params;

    hidl_vec<uint8_t> app_id, app_data;
    extract_application_id_and_data(params, app_id, app_data);
    KeyCharacteristics kc;
    ErrorCode e = ErrorCode::UNKNOWN_ERROR;
    if ((e = hal.getKeyCharacteristics(key, app_id, app_data, kc)) != ErrorCode::OK) {
        std::cerr << "Couldn't get the key's characteristics: "
            << static_cast<int>(e) << " (" << toString(e) << ")" << std::endl;
        return 1;
    }

    init_sign_params_from_user_and_characteristics(params, kc, verify_params);

    if (do_generic_operation_cycle(hal, KeyPurpose::SIGN, key,
            message, params, nullptr, &out_signature, nullptr) != ErrorCode::OK)
    {
        std::cerr << "Signing operation failed!" << std::endl;
        return 1;
    }

    std::cout << "Signing operation OK" << std::endl;

    if (do_generic_operation_cycle(hal, KeyPurpose::VERIFY, key,
            message, verify_params, &out_signature, nullptr, nullptr) != ErrorCode::OK)
    {
        std::cerr << "Sanity signature verification failed!" << std::endl;
        return 1;
    }
    std::cout << "Sanity signature verification OK" << std::endl;
    return 0;
}

int verify(HidlSusKeymaster& hal,
    hidl_vec<uint8_t> const& message, hidl_vec<uint8_t> const& signature,
    hidl_vec<uint8_t> const& key, hidl_vec<KeyParameter> const& in_verify_params)
{
    if (do_generic_operation_cycle(hal, KeyPurpose::VERIFY, key,
                message, in_verify_params, &signature, nullptr, nullptr) != ErrorCode::OK)
    {
        std::cerr << "Signature verification failed!" << std::endl;
        return 1;
    }

    std::cout << "Signature verification OK" << std::endl;
    return 0;
}

static ErrorCode do_generic_operation_cycle(HidlSusKeymaster& hal,
        KeyPurpose op, hidl_vec<uint8_t> const& keyblob,
        hidl_vec<uint8_t> const& input_, hidl_vec<KeyParameter> const& params,
        hidl_vec<uint8_t> const* finish_signature,
        hidl_vec<uint8_t>* output, hidl_vec<uint8_t>* out_gcm_begin_iv)
{
    uint64_t operation_handle = 0;
    hidl_vec<KeyParameter> kp_tmp;
    ErrorCode e = ErrorCode::UNKNOWN_ERROR;

    if (output) output->resize(0);

    e = hal.begin(op, keyblob, params, {}, kp_tmp, operation_handle);
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

    hidl_vec<uint8_t> input(input_);
    size_t progress = 0;
    uint32_t consumed = 0;

    while (progress < input.size()) {
        hidl_vec<uint8_t> chunk;
        chunk.setToExternal(
                input.data() + progress,
                input.size() - progress,
                false
        );

        hidl_vec<uint8_t> tmp_output;

        e = hal.update(operation_handle, {}, chunk, {}, {},
                consumed, kp_tmp, tmp_output);
        if (e != ErrorCode::OK) {
            std::cerr << toString(op) << ": UPDATE operation failed: "
                << static_cast<int>(e) << " (" << toString(e) << ")" << std::endl;
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

    hidl_vec<uint8_t> last_tmp_output;
    const hidl_vec<uint8_t> dummy_;

    const hidl_vec<uint8_t>& finish_sig_ = finish_signature ? *finish_signature : dummy_;
    e = hal.finish(operation_handle, {}, {}, finish_sig_, {}, {}, kp_tmp, last_tmp_output);
    if (e != ErrorCode::OK) {
        std::cerr << toString(op) << ": FINISH operation failed: "
            << static_cast<int>(e) << " (" << toString(e) << ")" << std::endl;
        return e;
    }
    if (output)
        append_vec(*output, last_tmp_output);

    return ErrorCode::OK;
}

static void append_vec(hidl_vec<uint8_t>& dst, const hidl_vec<uint8_t>& src)
{
    size_t prev_size = dst.size();
    dst.resize(prev_size + src.size());
    std::memcpy(dst.data() + prev_size, src.data(), src.size());
}

static void init_encrypt_params_from_user_and_characteristics(
        hidl_vec<KeyParameter>& params, const KeyCharacteristics& kc,
        bool* is_aes_gcm
)
{
    Algorithm alg = find_algorithm(kc.hardwareEnforced,
            { Algorithm::RSA, Algorithm::AES, Algorithm::TRIPLE_DES });
    if (alg == static_cast<Algorithm>(-1))
        std::cerr << "WARNING: Encryption might not be supported for this key!" << std::endl;

    bool digest_found = false, padding_found = false,
         block_mode_found = false, mac_length_found = false;
    Digest digest;
    PaddingMode padding;
    BlockMode block_mode;
    uint32_t mac_length = 0;

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
            if (block_mode_found && block_mode == BlockMode::GCM && is_aes_gcm)
                *is_aes_gcm = true;

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
        hidl_vec<KeyParameter>& params, const KeyCharacteristics& kc,
        hidl_vec<KeyParameter>& out_verify_params
)
{
    Algorithm alg = find_algorithm(kc.hardwareEnforced,
            { Algorithm::EC, Algorithm::RSA, Algorithm::HMAC });
    if (alg == static_cast<Algorithm>(-1))
        std::cerr << "WARNING: Signing is not supported for this key!" << std::endl;

    Digest digest;
    PaddingMode padding;
    uint32_t mac_length = 0;
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
        if (alg == Algorithm::EC && kp.tag == Tag::DIGEST && !digest_found) {
            digest = kp.f.digest;
            digest_found = true;
        } else if (alg == Algorithm::RSA && kp.tag == Tag::PADDING && !padding_found &&
                (kp.f.paddingMode == PaddingMode::RSA_PKCS1_1_5_SIGN ||
                 kp.f.paddingMode == PaddingMode::RSA_PSS ||
                 kp.f.paddingMode == PaddingMode::NONE)
        ) {
            padding = kp.f.paddingMode;
            padding_found = true;
        } else if (alg == Algorithm::HMAC && kp.tag == Tag::MIN_MAC_LENGTH && !mac_length_found) {
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

    if (alg == Algorithm::RSA || alg == Algorithm::EC) {
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

    kmhal::util::init_default_params(params, defaults);
    kmhal::util::init_default_params(out_verify_params, verify_defaults);
}

} /* namespace crypto */
} /* namespace hal_ops */
} /* namespace cli */
} /* namespace suskeymaster */
