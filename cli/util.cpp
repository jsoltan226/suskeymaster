#define OPENSSL_API_COMPAT 0x10002000L
#define HIDL_DISABLE_INSTRUMENTATION
#include "cli.hpp"
#include <hidl/HidlSupport.h>
#include <cstdio>
#include <cstring>
#include <endian.h>
#ifdef SUSKEYMASTER_BUILD_ANDROID
#include <sys/system_properties.h>
#endif /* SUSKEYMASTER_BUILD_ANDROID */
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

namespace suskeymaster {
namespace cli {
namespace util {

static constexpr u8 SUPPORTED_LEGACY_KEYSTORE_BLOB_VER = 0x3;

static hidl_vec<u8> remove_keystore2_prefix_if_exists(const hidl_vec<u8>& blob);
static hidl_vec<u8> extract_keystore1_blob(const hidl_vec<u8>& blob);
static bool is_samsung(void);
static void append_sha256_sum(hidl_vec<u8>& blob);

static int openssl_err_print_cb(const char *msg, size_t size, void *userdata);
static void print_openssl_errors(void);

/* sp800 */
static int update_u32(HMAC_CTX *ctx, size_t v, const char *name);
static int update_str(HMAC_CTX *ctx, const char *str, const size_t size, const char *name);
static int update_byte(HMAC_CTX *ctx, u8 b, const char *name);

void extract_application_id_and_data(hidl_vec<KeyParameter> const& params,
                                     hidl_vec<u8>& out_application_id,
                                     hidl_vec<u8>& out_application_data)
{
    for (const auto& kp : params) {
        if (kp.tag == Tag::APPLICATION_ID)
            out_application_id = kp.blob;
        else if (kp.tag == Tag::APPLICATION_DATA)
            out_application_data = kp.blob;
    }
}

Algorithm find_algorithm(hidl_vec<KeyParameter> const& params,
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

const hidl_vec<u8> * find_blob_tag(Tag t, hidl_vec<KeyParameter> const& params)
{
    for (const auto& kp : params) {
        if (kp.tag == t)
            return &kp.blob;
    }
    return nullptr;
}

std::vector<hidl_vec<u8>> find_rep_blob_tag(Tag t, hidl_vec<KeyParameter> const& params)
{
    std::vector<hidl_vec<u8>> ret;

    for (const auto& kp : params) {
        if (kp.tag == t)
            ret.push_back(kp.blob);
    }

    return ret;
}

Algorithm determine_pkey_algorithm(hidl_vec<u8> const& priv_pkcs8)
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

Algorithm determine_algorithm_from_params_and_pkey(hidl_vec<KeyParameter> const& params,
                                                   hidl_vec<u8> const& pkey)
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

void init_default_params_for_alg_and_purposes(hidl_vec<KeyParameter>& params,
                                              Algorithm alg,
                                              const std::vector<KeyPurpose>& purposes,
                                              bool is_generate_key)
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
        if (is_generate_key) {
            /* Only 2048-bit RSA keys are guaranteed to be supported
             * by both TEE and STRONGBOX devices */
            defaults.emplace_back(Tag::KEY_SIZE, 2048);

            defaults.emplace_back(Tag::RSA_PUBLIC_EXPONENT, UINT64_C(65537));
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
        if (is_generate_key && find_tag<i64>(Tag::KEY_SIZE, params) == -1)
            defaults.emplace_back(Tag::EC_CURVE, EcCurve::P_256);

        if (sign_verify && private_ops)
            defaults.push_back({ Tag::DIGEST, { Digest::SHA_2_256 } });

        break;
    case Algorithm::AES:
        if (is_generate_key)
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
        if (is_generate_key)
            defaults.push_back({ Tag::KEY_SIZE, 168 });

        if (enc_dec && private_ops) {
            defaults.push_back({ Tag::BLOCK_MODE, { BlockMode::CBC } });
            defaults.push_back({ Tag::PADDING, { PaddingMode::PKCS7 } });
        }
        break;
    case Algorithm::HMAC:
        if (is_generate_key) {
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

hidl_vec<u8> keystore_blob_to_km_blob(hidl_vec<u8> const& keystore_blob)
{
    hidl_vec<u8> ret;

    if (keystore_blob.size() < 1)
        return {};
    else if (keystore_blob[0] == SUPPORTED_LEGACY_KEYSTORE_BLOB_VER)
        ret = extract_keystore1_blob(keystore_blob);
    else
        ret = remove_keystore2_prefix_if_exists(keystore_blob);

    if (is_samsung())
        append_sha256_sum(ret);

    return ret;
}

/* See "framewords/base/core/java/com/android/internal/util/HexDump.java" */
hidl_vec<uint8_t> to_uppercase_hex_string(hidl_vec<uint8_t> const& data)
{
    static constexpr const char HEX_DIGITS[16] =
        { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

    hidl_vec<uint8_t> ret;
    ret.resize(data.size() * 2);

    int bufIndex = 0;
    for (u8 b : data) {
        ret[bufIndex++] = HEX_DIGITS[(b >> 4) & 0x0F];
        ret[bufIndex++] = HEX_DIGITS[b & 0x0F];
    }

    return ret;
}

/* See "system/vold/Utils.cpp" */
int parse_hex_string(const hidl_vec<uint8_t>& hex, hidl_vec<uint8_t>& out) {
    if (hex.size() % 2 != 0) {
        std::cerr << "Hex string uneven" << std::endl;
        return -1;
    }

    out.resize(hex.size() / 2);

    uint8_t cur = 0;
    for (size_t i = 0; i < hex.size(); i++) {
        int val = 0;
        switch (hex[i]) {
            // clang-format off
            case ' ': case '-': case ':': continue;
            case 'f': case 'F': val = 15; break;
            case 'e': case 'E': val = 14; break;
            case 'd': case 'D': val = 13; break;
            case 'c': case 'C': val = 12; break;
            case 'b': case 'B': val = 11; break;
            case 'a': case 'A': val = 10; break;
            case '9': val = 9; break;
            case '8': val = 8; break;
            case '7': val = 7; break;
            case '6': val = 6; break;
            case '5': val = 5; break;
            case '4': val = 4; break;
            case '3': val = 3; break;
            case '2': val = 2; break;
            case '1': val = 1; break;
            case '0': val = 0; break;
            default:
                std::cerr << "Invalid character in hex string" << std::endl;
                return -1;
                // clang-format on
        }

        const bool even = i % 2 == 0;
        if (even) {
            cur = val << 4;
        } else {
            cur += val;
            out[i/2 - 1] = cur;
            cur = 0;
        }
    }

    return 0;
}

int extract_gcm_data(hidl_vec<u8> const& blob,
                     hidl_vec<u8>& out_iv, hidl_vec<u8>& out_ciphertext_with_tag)
{
    if (blob.size() < AES_GCM_IV_SIZE + AES_GCM_TAG_SIZE) {
        std::cerr << "AES-GCM encrypted blob too small" << std::endl;
        return 1;
    }

    /* IV || ciphertext || tag;
     * we want separate IV and ciphertext || tag */

    out_iv.resize(AES_GCM_IV_SIZE);
    memcpy(out_iv.data(), blob.data(), AES_GCM_IV_SIZE);

    out_ciphertext_with_tag.resize(blob.size() - AES_GCM_IV_SIZE);
    memcpy(out_ciphertext_with_tag.data(), blob.data() + AES_GCM_IV_SIZE,
            blob.size() - AES_GCM_IV_SIZE);

    return 0;
}

int extract_gcm_data(hidl_vec<u8> const& blob,
                     hidl_vec<u8>& out_iv, hidl_vec<u8>& out_ciphertext, hidl_vec<u8>& out_tag)
{
    if (blob.size() < AES_GCM_IV_SIZE + AES_GCM_TAG_SIZE) {
        std::cerr << "AES-GCM encrypted blob too small" << std::endl;
        return 1;
    }

    /* IV || ciphertext || tag */
    out_iv.resize(AES_GCM_IV_SIZE);
    memcpy(out_iv.data(), blob.data(), AES_GCM_IV_SIZE);

    const size_t ciphertext_size = blob.size() - AES_GCM_IV_SIZE - AES_GCM_TAG_SIZE;
    out_ciphertext.resize(ciphertext_size);
    memcpy(out_ciphertext.data(), blob.data() + AES_GCM_IV_SIZE, ciphertext_size);

    out_tag.resize(AES_GCM_TAG_SIZE);
    memcpy(out_tag.data(), blob.data() + AES_GCM_IV_SIZE + ciphertext_size, AES_GCM_TAG_SIZE);

    return 0;
}

int aes256gcm_software_decrypt(hidl_vec<u8> const& key, hidl_vec<u8> const& blob,
                               hidl_vec<u8>& out_plaintext)
{
    hidl_vec<u8> iv, ciphertext, tag;
    if (extract_gcm_data(blob, iv, ciphertext, tag)) {
        std::cerr << "Failed to extract AES-GCM data from encrypted blob" << std::endl;
        return 1;
    }

    return aes256gcm_software_decrypt(key, iv, ciphertext, tag, out_plaintext);
}

int aes256gcm_software_decrypt(hidl_vec<u8> const& key, hidl_vec<u8> const& iv,
                               hidl_vec<u8> const& ciphertext, hidl_vec<u8> const& tag_,
                               hidl_vec<u8>& out_plaintext)
{
    hidl_vec<u8> tag(tag_);
    if (key.size() != AES_GCM_KEY_SIZE) {
        std::cerr << "Invalid AES-256 key" << std::endl;
        return -1;
    } else if (iv.size() != AES_GCM_IV_SIZE) {
        std::cerr << "Invalid AES-256-GCM IV" << std::endl;
        return -1;
    } else if (tag.size() != AES_GCM_TAG_SIZE) {
        std::cerr << "Invalid AES-256-GCM auth tag" << std::endl;
        return -1;
    }

    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0, total = 0;
    bool ok = false;

    /* Init the context */
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        std::cerr << "Couldn't create a new EVP cipher context" << std::endl;
        goto err;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        std::cerr << "Failed to initialize the decryption context" << std::endl;
        goto err;
    }
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), iv.data()) != 1) {
        std::cerr << "Failed to set the decryption context parameters" << std::endl;
        goto err;
    }

    std::cout << "ciphertext size is " << ciphertext.size() << " bytes" << std::endl;

    /* Provide the plaintext data */
    out_plaintext.resize(ciphertext.size());
    if (EVP_DecryptUpdate(ctx, out_plaintext.data(), &len,
                ciphertext.data(), ciphertext.size()) != 1)
    {
        std::cerr << "Update operation failed for ciphertext" << std::endl;
        goto err;
    }
    total += len;

    /* Provide the GCM tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_SIZE, tag.data()) != 1) {
        std::cerr << "Couldn't provide the AES-GCM tag" << std::endl;
        goto err;
    }

    /* Do the encryption */
    if (EVP_DecryptFinal_ex(ctx, out_plaintext.data() + total, &len) != 1) {
        std::cerr << "Final operation failed" << std::endl;
        goto err;
    }
    total += len;

    if (total != ciphertext.size()) {
        std::cerr << "Incorrect number of bytes written to plaintext output buffer (" <<
            total << ", expected " << ciphertext.size() << ")!" << std::endl;
        std::abort();
    }


    ok = true;

err:
    if (ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx);
        ctx = NULL;
    }

    if (!ok)
        print_openssl_errors();

    return ok ? 0 : 1;
}

int personalized_hash(hidl_vec<uint8_t> const& in_data, const char *personalization,
                      hidl_vec<uint8_t>& out_hash)
{
    /* AOSP constants */
    static constexpr size_t SHA512_BLOCK_SIZE = 128;

    SHA512_CTX ctx;

    if (!SHA512_Init(&ctx)) {
        std::cerr << "SHA512_Init failed" << std::endl;
        return 1;
    }

    uint8_t prefix[SHA512_BLOCK_SIZE];
    std::memset(prefix, 0, sizeof(prefix));

    const int personalization_size = strlen(personalization);
    if (personalization_size > sizeof(prefix) || personalization_size < 0) {
        std::cerr << "Personalization string invalid or too long" << std::endl;
        return 1;
    }

    std::memcpy(prefix, personalization, personalization_size);

    if (!SHA512_Update(&ctx, prefix, sizeof(prefix))) {
        std::cerr << "SHA512_Update (prefix) failed" << std::endl;
        return 1;
    }

    if (!SHA512_Update(&ctx, in_data.data(), in_data.size())) {
        std::cerr << "SHA512_Update (input) failed" << std::endl;
        return 1;
    }

    out_hash.resize(SHA512_DIGEST_LENGTH);

    if (!SHA512_Final(out_hash.data(), &ctx)) {
        std::cerr << "SHA512_Final failed" << std::endl;
        return 1;
    }

    return 0;
}

int sp800_derive_with_context(hidl_vec<uint8_t> const& in_key,
                              const char *label, size_t label_size,
                              const char *context, size_t context_size,
                              hidl_vec<uint8_t>& out)
{
    int ret = 1;
    HMAC_CTX *ctx = nullptr;
    unsigned int out_len = 0;

    constexpr int HMAC_SHA256_LEN = 32;
    constexpr int HMAC_SHA256_LEN_BITS = 256;

    ctx = HMAC_CTX_new();
    if (ctx == nullptr) {
        std::cerr << "Failed to allocate a new HMAC context" << std::endl;
        goto err;
    }

    out.resize(EVP_MAX_MD_SIZE);
    if (HMAC_Init_ex(ctx, in_key.data(), in_key.size(), EVP_sha256(), nullptr) != 1) {
        std::cerr << "Failed to initialize HMAC-SHA256" << std::endl;
        goto err;
    }

    if (update_u32(ctx, 1, "SP800 hardwired counter value") ||
        update_str(ctx, label, label_size, "label string") ||
        update_byte(ctx, 0, "zero separator") ||
        update_str(ctx, context, context_size, "context string") ||
        update_u32(ctx, context_size * 8, "context string size (in bits)") ||
        update_u32(ctx, HMAC_SHA256_LEN_BITS, "SP800 hardwired output length (in bits)")
    ) goto err;

    if (HMAC_Final(ctx, out.data(), &out_len) != 1) {
        std::cerr << "HMAC_Final failed" << std::endl;
        goto err;
    } else if (out_len != HMAC_SHA256_LEN) {
        std::cerr << "Unexpected out_len value: " << out_len << std::endl;
        goto err;
    }
    out.resize(HMAC_SHA256_LEN);

    ret = 0;

err:
    if (ctx != NULL) {
        HMAC_CTX_free(ctx);
        ctx = NULL;
    }

    if (ret != 0)
        print_openssl_errors();
    return ret;
}

static hidl_vec<u8> remove_keystore2_prefix_if_exists(const hidl_vec<u8>& blob) {
    constexpr size_t PREFIX_SIZE = 8;
    constexpr u8 PREFIX_MAGIC[7] = { 'p', 'K', 'M', 'b', 'l', 'o', 'b' };

    /* Check if the blob is properly prefixed, and if not,
     * treat it as though it was just a normal un-prefixed blob
     * (according to AOSP, earlier versions of keystore didn't prefix the blobs at all) */
    if (blob.size() < PREFIX_SIZE ||
        std::memcmp(blob.data(), PREFIX_MAGIC, sizeof(PREFIX_MAGIC)) ||
        blob[PREFIX_SIZE - 1] != 0 /* isSoftKeyMint byte */
    ) {
        return hidl_vec<u8>(blob);
    }

    return hidl_vec<u8>(blob.begin() + PREFIX_SIZE, blob.end());
}

/* See "system/security/keystore2/src/legacy_blob.rs" */

static hidl_vec<u8> extract_keystore1_blob(const hidl_vec<u8>& blob)
{
    struct legacy_blob_header {
        u8 version;
        u8 blob_type;
        u8 flags;
        u8 info;
        u8 iv[16] /* 12 bytes + 4 bytes of padding */;
        u8 tag[16];
        u32 blob_size;
    } __attribute__((packed));
    if (blob.size() < sizeof(legacy_blob_header)) {
        std::cerr << "Keystore v1 blob too small" << std::endl;
        return {};
    }

    legacy_blob_header hdr;
    memcpy(&hdr, blob.data(), sizeof(hdr));

    if (hdr.version != SUPPORTED_LEGACY_KEYSTORE_BLOB_VER) {
        std::cerr << "Unexpected/unsupported keystore v1 blob version: "
            << static_cast<int>(hdr.version) << std::endl;
        return {};
    }

    enum class blob_types : u8 {
        GENERIC = 1,
        SUPER_KEY = 2,
        _RESERVED = 3,
        KM_BLOB = 4,
        KEY_CHARACTERISTICS = 5,
        KEY_CHARACTERISTICS_CACHE = 6,
        SUPER_KEY_AES256 = 7
    };
    if (hdr.blob_type != static_cast<u8>(blob_types::KM_BLOB)) {
        std::cerr << "Unexpected blob type: " << static_cast<int>(hdr.blob_type) << std::endl;
        return {};
    }

    enum class blob_flags : u8 {
        ENCRYPTED = 1 << 0,
        FALLBACK = 1 << 1,
        SUPER_ENCRYPTED = 1 << 2,
        CRITICAL_TO_DEVICE_ENCRYPTION = 1 << 3,
        STRONGBOX = 1 << 4
    };
    if (!(hdr.flags & static_cast<u8>(blob_flags::CRITICAL_TO_DEVICE_ENCRYPTION))) {
        std::cerr << "WARNING: Blob doesn't have the CRITICAL_TO_DEVICE_ENCRYPTION flag"
            << std::endl;
    } else if (hdr.flags & static_cast<u8>(blob_flags::STRONGBOX)) {
        std::cerr << "WARNING: Blob has the STRONGBOX flag" << std::endl;
    } else if (hdr.flags & static_cast<u8>(blob_flags::SUPER_ENCRYPTED)) {
        std::cerr << "Blob is SUPER_ENCRYPTED, which shouldn't happen" << std::endl;
        return {};
    }

    if (hdr.info != 0) {
        std::cerr << "WARNING: `info` field is not `0`" << std::endl;
        return {};
    }

    u8 empty_iv[sizeof(hdr.iv)] = { 0 };
    if (memcmp(hdr.iv, empty_iv, sizeof(hdr.iv)))
        std::cerr << "WARNING: AES-GCM IV is not zeroed out" << std::endl;

    u8 empty_tag[sizeof(hdr.tag)] = { 0 };
    if (memcmp(hdr.tag, empty_tag, sizeof(hdr.tag)))
        std::cerr << "WARNING: AES-GCM tag is not zeroed out" << std::endl;

    hdr.blob_size = be32toh(hdr.blob_size);
    if (hdr.blob_size > 1000000) {
        std::cerr << "Bogus blob size" << std::endl;
        return {};
    } else if (blob.size() != hdr.blob_size + sizeof(hdr)) {
        std::cerr << "Invalid blob size; trailing or truncated data" << std::endl;
        return {};
    }

    return hidl_vec<u8>(blob.begin() + sizeof(hdr), blob.end());
}

static bool is_samsung(void)
{
#ifndef SUSKEYMASTER_BUILD_ANDROID
    return false;
#else
    const struct prop_info *pi = __system_property_find("ro.build.fingerprint");
    if (pi == nullptr)
        return false;

    bool ret = false;
    __system_property_read_callback(pi,
            [](void *cookie, const char *, const char *value, uint32_t) {
                if (!strncmp(value, "samsung", sizeof("samsung") - 1)) {
                    *(bool *)cookie = true;
                }
            },
            &ret
    );

    /*
    if (ret)
        std::cout << "samsung detected" << std::endl;
        */
    return ret;
#endif /* SUSKEYMASTER_BUILD_HOST */
}

static void append_sha256_sum(hidl_vec<u8>& blob)
{
    u8 digest[SHA256_DIGEST_LENGTH] = { 0 };
    (void) SHA256(blob.data(), blob.size(), digest);

    blob.resize(blob.size() + SHA256_DIGEST_LENGTH);
    std::memcpy(blob.data() + (blob.size() - SHA256_DIGEST_LENGTH),
            digest, SHA256_DIGEST_LENGTH);
}

static int openssl_err_print_cb(const char *msg, size_t size, void *userdata)
{
    (void) size;
    (void) userdata;
    std::cerr << msg;
    return 1;
}

static void print_openssl_errors(void)
{
    std::cerr << "BEGIN OPENSSL ERRORS" << std::endl;
    ERR_print_errors_cb(openssl_err_print_cb, NULL);
    std::cerr << "END OPENSSL ERRORS" << std::endl;
}

static int update_u32(HMAC_CTX *ctx, size_t v, const char *name)
{
    if (v > UINT32_MAX) {
        std::cerr << "update32 failed for " << name << ": value too big" << std::endl;
        return -1;
    }

    u32 be = htobe32(static_cast<u32>(v));
    if (HMAC_Update(ctx, reinterpret_cast<const u8 *>(&be), sizeof(u32)) != 1) {
        std::cerr << "HMAC_Update failed for " << name << std::endl;
        return 1;
    }

    return 0;
}

static int update_str(HMAC_CTX *ctx, const char *str, const size_t size, const char *name)
{
    if (HMAC_Update(ctx, reinterpret_cast<const u8 *>(str), size) != 1) {
        std::cerr << "HMAC_Update failed for " << name << std::endl;
        return 1;
    }

    return 0;
}

static int update_byte(HMAC_CTX *ctx, u8 b, const char *name)
{
    if (HMAC_Update(ctx, reinterpret_cast<const u8 *>(&b), sizeof(u8)) != 1) {
        std::cerr << "HMAC_Update failed for " << name << std::endl;
        return 1;
    }

    return 0;
}

} /* namespace util */
} /* namespace cli */
} /* namespace suskeymaster */
