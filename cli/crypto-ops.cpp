#define HIDL_DISABLE_INSTRUMENTATION
#include "cli.hpp"
#include <libsuskmhal/hidl/hidl-hal.hpp>
#include <libsuskmhal/util/km-params.hpp>
#include <hidl/HidlSupport.h>
#include <android/hardware/keymaster/4.0/types.h>
#include <cstring>

namespace suskeymaster {
namespace cli {
namespace hal_ops {
namespace crypto {

using namespace ::android::hardware::keymaster::V4_0;
using ::android::hardware::hidl_vec;
using kmhal::hidl::HidlSusKeymaster4;

static ErrorCode do_generic_operation_cycle(HidlSusKeymaster4& hal,
        KeyPurpose op, hidl_vec<uint8_t> const& keyblob,
        hidl_vec<uint8_t> const& input, hidl_vec<KeyParameter> const& params,
        hidl_vec<uint8_t> const& finish_signature,
        hidl_vec<uint8_t>& output);

static void append_vec(hidl_vec<uint8_t>& dst, const hidl_vec<uint8_t>& src);

static void init_encrypt_params_from_user_and_characteristics(
        hidl_vec<KeyParameter>& params, const KeyCharacteristics& kc
);
static void init_sign_params_from_user_and_characteristics(
        hidl_vec<KeyParameter>& params, const KeyCharacteristics& kc
);

int encrypt(HidlSusKeymaster4& hal, hidl_vec<uint8_t> const& plaintext,
        hidl_vec<uint8_t> const& key, hidl_vec<KeyParameter> const& encrypt_params,
        hidl_vec<uint8_t>& out_ciphertext)
{
    hidl_vec<KeyParameter> params(encrypt_params);

    hidl_vec<uint8_t> app_id, app_data;
    extract_application_id_and_data(params, app_id, app_data);
    KeyCharacteristics kc;
    ErrorCode e = ErrorCode::UNKNOWN_ERROR;
    if ((e = hal.getKeyCharacteristics(key, app_id, app_data, kc)) != ErrorCode::OK) {
        std::cout << "Couldn't get the key's characteristics: "
            << static_cast<int>(e) << " (" << toString(e) << ")" << std::endl;
        return 1;
    }

    init_encrypt_params_from_user_and_characteristics(params, kc);

    if (do_generic_operation_cycle(hal, KeyPurpose::ENCRYPT, key,
                plaintext, params, {}, out_ciphertext) != ErrorCode::OK)
    {
        std::cout << "Encryption operation failed!" << std::endl;
        return 1;
    }

    std::cerr << "Encryption operation successful!" << std::endl;
    return 0;
}

int decrypt(HidlSusKeymaster4& hal, hidl_vec<uint8_t> const& ciphertext,
        hidl_vec<uint8_t> const& key, hidl_vec<KeyParameter> const& decrypt_params,
        hidl_vec<uint8_t>& out_plaintext)
{
    hidl_vec<KeyParameter> params(decrypt_params);

    hidl_vec<uint8_t> app_id, app_data;
    extract_application_id_and_data(params, app_id, app_data);
    KeyCharacteristics kc;
    ErrorCode e = ErrorCode::UNKNOWN_ERROR;
    if ((e = hal.getKeyCharacteristics(key, app_id, app_data, kc)) != ErrorCode::OK) {
        std::cout << "Couldn't get the key's characteristics: "
            << static_cast<int>(e) << " (" << toString(e) << ")" << std::endl;
        return 1;
    }

    init_encrypt_params_from_user_and_characteristics(params, kc);

    if (do_generic_operation_cycle(hal, KeyPurpose::DECRYPT, key,
                ciphertext, params, {}, out_plaintext) != ErrorCode::OK)
    {
        std::cout << "Decryption operation failed!" << std::endl;
        return 1;
    }

    std::cerr << "Decryption operation successful!" << std::endl;
    return 0;
}

int sign(HidlSusKeymaster4& hal, hidl_vec<uint8_t> const& message,
    hidl_vec<uint8_t> const& key, hidl_vec<KeyParameter> const& in_sign_params,
    hidl_vec<uint8_t>& out_signature)
{
    hidl_vec<KeyParameter> params(in_sign_params);

    hidl_vec<uint8_t> app_id, app_data;
    extract_application_id_and_data(params, app_id, app_data);
    KeyCharacteristics kc;
    ErrorCode e = ErrorCode::UNKNOWN_ERROR;
    if ((e = hal.getKeyCharacteristics(key, app_id, app_data, kc)) != ErrorCode::OK) {
        std::cout << "Couldn't get the key's characteristics: "
            << static_cast<int>(e) << " (" << toString(e) << ")" << std::endl;
        return 1;
    }

    init_sign_params_from_user_and_characteristics(params, kc);

    if (do_generic_operation_cycle(hal, KeyPurpose::SIGN, key,
            message, params, {}, out_signature) != ErrorCode::OK)
    {
        std::cerr << "Signing operation failed!" << std::endl;
        return 1;
    }

    std::cout << "Signing operation OK" << std::endl;

    hidl_vec<uint8_t> dummy;
    hidl_vec<KeyParameter> app_id_data(0);
    if (app_id.size() > 0) {
        app_id_data.resize(app_id_data.size() + 1);
        app_id_data[app_id_data.size() - 1].tag = Tag::APPLICATION_ID,
        app_id_data[app_id_data.size() - 1].blob = app_id;
    }
    if (app_data.size() > 0) {
        app_id_data.resize(app_id_data.size() + 1);
        app_id_data[app_id_data.size() - 1].tag = Tag::APPLICATION_DATA,
        app_id_data[app_id_data.size() - 1].blob = app_data;
    }

    if (do_generic_operation_cycle(hal, KeyPurpose::VERIFY, key,
            message, app_id_data, out_signature, dummy) != ErrorCode::OK)
    {
        std::cerr << "Sanity signature verification failed!" << std::endl;
        return 1;
    }
    std::cout << "Sanity signature verification OK" << std::endl;
    return 0;
}

int verify(HidlSusKeymaster4& hal,
    hidl_vec<uint8_t> const& message, hidl_vec<uint8_t> const& signature,
    hidl_vec<uint8_t> const& key, hidl_vec<KeyParameter> const& in_verify_params)
{
    hidl_vec<uint8_t> dummy;
    if (do_generic_operation_cycle(hal, KeyPurpose::VERIFY, key,
                message, in_verify_params, signature, dummy) != ErrorCode::OK)
    {
        std::cerr << "Signature verification failed!" << std::endl;
        return 1;
    }

    std::cout << "Signature verification OK" << std::endl;
    return 0;
}

static ErrorCode do_generic_operation_cycle(HidlSusKeymaster4& hal,
        KeyPurpose op, hidl_vec<uint8_t> const& keyblob,
        hidl_vec<uint8_t> const& input_, hidl_vec<KeyParameter> const& params,
        hidl_vec<uint8_t> const& finish_signature,
        hidl_vec<uint8_t>& output)
{
    uint64_t operation_handle = 0;
    hidl_vec<KeyParameter> kp_tmp;
    ErrorCode e = ErrorCode::UNKNOWN_ERROR;

    output.resize(0);

    e = hal.begin(op, keyblob, params, {}, kp_tmp, operation_handle);
    if (e != ErrorCode::OK) {
        std::cerr << toString(op) << ": BEGIN operation failed: "
            << static_cast<int>(e) << " (" << toString(e) << ")" << std::endl;
        return e;
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

        append_vec(output, tmp_output);
    }

    hidl_vec<uint8_t> last_tmp_output;
    e = hal.finish(operation_handle, {}, {}, finish_signature, {}, {}, kp_tmp, last_tmp_output);
    if (e != ErrorCode::OK) {
        std::cerr << toString(op) << ": FINISH operation failed: "
            << static_cast<int>(e) << " (" << toString(e) << ")" << std::endl;
        return e;
    }
    append_vec(output, last_tmp_output);

    return ErrorCode::OK;
}

static void append_vec(hidl_vec<uint8_t>& dst, const hidl_vec<uint8_t>& src)
{
    size_t prev_size = dst.size();
    dst.resize(prev_size + src.size());
    std::memcpy(dst.data() + prev_size, src.data(), src.size());
}

static void init_encrypt_params_from_user_and_characteristics(
        hidl_vec<KeyParameter>& params, const KeyCharacteristics& kc
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
                     kp.f.paddingMode == PaddingMode::RSA_PKCS1_1_5_ENCRYPT)
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
            } else {
                std::cout << "AES encryption padding mode: " << toString(padding) << std::endl;
                defaults.emplace_back(Tag::PADDING, std::vector<PaddingMode>{ padding });
            }
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
    }

    kmhal::util::init_default_params(params, defaults);
}

static void init_sign_params_from_user_and_characteristics(
        hidl_vec<KeyParameter>& params, const KeyCharacteristics& kc
)
{
    Algorithm alg = find_algorithm(kc.hardwareEnforced,
            { Algorithm::EC, Algorithm::RSA, Algorithm::HMAC });
    if (alg == static_cast<Algorithm>(-1))
        std::cerr << "WARNING: Signing might not be supported for this key!" << std::endl;

    bool digest_found = false, padding_found = false, mac_length_found = false;
    for (const auto& kp : params) {
        if (kp.tag == Tag::DIGEST) digest_found = true;
        else if (kp.tag == Tag::PADDING) padding_found = true;
        else if (kp.tag == Tag::MAC_LENGTH) mac_length_found = true;
    }

    std::vector<kmhal::util::km_default> defaults;

    Digest digest;
    PaddingMode padding;
    uint32_t mac_length = 0;
    for (const auto& kp : kc.hardwareEnforced) {
        if (alg == Algorithm::EC && kp.tag == Tag::DIGEST && !digest_found) {
            digest = kp.f.digest;
            digest_found = true;
        } else if (alg == Algorithm::RSA && kp.tag == Tag::PADDING && !padding_found &&
                (kp.f.paddingMode == PaddingMode::RSA_OAEP ||
                 kp.f.paddingMode == PaddingMode::RSA_PKCS1_1_5_ENCRYPT)
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
            if (kp.tag == Tag::DIGEST && kp.f.digest != Digest::NONE) {
                digest_found = true;
                digest = kp.f.digest;
            }
        }
    }

    if (alg == Algorithm::RSA || alg == Algorithm::EC) {
        if (digest_found) {
            if (alg == Algorithm::RSA && padding_found && padding == PaddingMode::RSA_OAEP &&
                    digest == Digest::NONE)
            {
                std::cerr << "WARNING: Digest cannot be NONE for RSA-OAEP signing!" << std::endl;
            } else {
                std::cout << toString(alg) << " Signature digest: "
                    << toString(digest) << std::endl;
                defaults.emplace_back(Tag::DIGEST, std::vector<Digest>{ digest });
            }
        } else {
            std::cerr << "WARNING: "
                << toString(alg) << " signing without a digest parameter!" << std::endl;
        }
    }

    if (alg == Algorithm::RSA) {
        if (padding_found) {
            std::cout << "RSA Signature padding: " << toString(padding) << std::endl;
            defaults.emplace_back(Tag::PADDING, std::vector<PaddingMode>{ padding });
        } else {
            std::cerr << "WARNING: RSA signing without a padding mode parameter!" << std::endl;
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

    kmhal::util::init_default_params(params, defaults);
}

} /* namespace crypto */
} /* namespace hal_ops */
} /* namespace cli */
} /* namespace suskeymaster */
