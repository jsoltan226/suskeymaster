#define OPENSSL_API_COMPAT 0x10002000L
#define HIDL_DISABLE_INSTRUMENTATION
#include "cli.hpp"
#include <libsuskmhal/hidl/hidl-hal.hpp>
#include <android/hardware/keymaster/generic/types.h>
#include <cstring>
#include <openssl/sha.h>

namespace suskeymaster {
namespace cli {
namespace vold {

using namespace ::android::hardware::keymaster::generic;
using ::android::hardware::hidl_vec;
using kmhal::hidl::HidlSusKeymaster;

static hidl_vec<uint8_t> remove_keystore2_prefix_if_exists(const hidl_vec<uint8_t>& blob);
static void append_sha256_sum(hidl_vec<uint8_t>& blob);

static void get_iv_and_ciphertext_from_encrypted_blob(const hidl_vec<uint8_t> encrypted_key,
        hidl_vec<uint8_t>& out_iv, hidl_vec<uint8_t>& out_ciphertext);


int generate_app_id(hidl_vec<uint8_t> const& in_secdiscardable,
        hidl_vec<uint8_t>& out_app_id)
{
    /* AOSP constants */
    static constexpr size_t SHA512_BLOCK_SIZE = 128;
    static const char* HASH_PREFIX = "Android secdiscardable SHA512";

    SHA512_CTX ctx;

    if (!SHA512_Init(&ctx)) {
        std::cerr << "SHA512_Init failed" << std::endl;
        return 1;
    }

    uint8_t prefix[SHA512_BLOCK_SIZE];
    std::memset(prefix, 0, sizeof(prefix));

    size_t prefix_len = std::strlen(HASH_PREFIX);
    if (prefix_len > sizeof(prefix)) {
        std::cerr << "Prefix too long" << std::endl;
        return 1;
    }

    std::memcpy(prefix, HASH_PREFIX, prefix_len);

    if (!SHA512_Update(&ctx, prefix, sizeof(prefix))) {
        std::cerr << "SHA512_Update (prefix) failed" << std::endl;
        return 1;
    }

    if (!SHA512_Update(&ctx, in_secdiscardable.data(), in_secdiscardable.size())) {
        std::cerr << "SHA512_Update (input) failed" << std::endl;
        return 1;
    }

    out_app_id.resize(SHA512_DIGEST_LENGTH);

    if (!SHA512_Final(out_app_id.data(), &ctx)) {
        std::cerr << "SHA512_Final failed" << std::endl;
        return 1;
    }

    return 0;
}

int decrypt_vold_key_with_keystore_key(HidlSusKeymaster& hal,
        hidl_vec<uint8_t> const& in_keystore_key, hidl_vec<uint8_t> const& in_secdiscardable,
        hidl_vec<uint8_t> const& in_encrypted_key, hidl_vec<uint8_t>& out_decrypted_key)
{

    hidl_vec<uint8_t> keystore_key_blob = remove_keystore2_prefix_if_exists(in_keystore_key);
    append_sha256_sum(keystore_key_blob);

    hidl_vec<uint8_t> app_id;
    if (generate_app_id(in_secdiscardable, app_id)) {
        std::cerr << "Failed to generate Tag::APPLICATION_ID from secdiscardable" << std::endl;
        return 1;
    }

    hidl_vec<uint8_t> enc_key_iv, enc_key_ciphertext;
    get_iv_and_ciphertext_from_encrypted_blob(in_encrypted_key, enc_key_iv, enc_key_ciphertext);

    hidl_vec<KeyParameter> params(2);
    params[0].tag = Tag::APPLICATION_ID;
    params[0].blob = app_id;
    params[1].tag = Tag::NONCE;
    params[1].blob = enc_key_iv;

    if (hal_ops::crypto::decrypt(hal, enc_key_ciphertext, keystore_key_blob, params,
                out_decrypted_key))
    {
        std::cerr << "Failed to decrypt vold encrypted key" << std::endl;
        return 1;
    }

    std::cout << "Successfully decrypted vold key with keystore key" << std::endl;
    return 0;
}

static hidl_vec<uint8_t> remove_keystore2_prefix_if_exists(const hidl_vec<uint8_t>& blob) {
    constexpr size_t PREFIX_SIZE = 8;
    constexpr uint8_t PREFIX_MAGIC[7] = { 'p', 'K', 'M', 'b', 'l', 'o', 'b' };

    /* Check if the blob is properly prefixed, and if not,
     * treat it as though it was just a normal un-prefixed blob
     * (according to AOSP, earlier versions of keystore didn't prefix the blobs at all) */
    if (blob.size() < PREFIX_SIZE ||
        std::memcmp(blob.data(), PREFIX_MAGIC, sizeof(PREFIX_MAGIC)) ||
        blob[PREFIX_SIZE - 1] != 0 /* isSoftKeyMint byte */
    ) {
        return hidl_vec<uint8_t>(blob);
    }

    return hidl_vec<uint8_t>(blob.begin() + PREFIX_SIZE, blob.end());
}

static void append_sha256_sum(hidl_vec<uint8_t>& blob)
{
    uint8_t digest[SHA256_DIGEST_LENGTH] = { 0 };
    (void) SHA256(blob.data(), blob.size(), digest);

    blob.resize(blob.size() + SHA256_DIGEST_LENGTH);
    std::memcpy(blob.data() + (blob.size() - SHA256_DIGEST_LENGTH),
            digest, SHA256_DIGEST_LENGTH);
}

static void get_iv_and_ciphertext_from_encrypted_blob(const hidl_vec<uint8_t> blob,
        hidl_vec<uint8_t>& out_iv, hidl_vec<uint8_t>& out_ciphertext)
{
    static constexpr size_t GCM_NONCE_BYTES = 12;
    out_iv = hidl_vec<uint8_t>(blob.begin(), blob.begin() + GCM_NONCE_BYTES);
    out_ciphertext = hidl_vec<uint8_t>(blob.begin() + GCM_NONCE_BYTES, blob.end());
}

} /* namespace vold */
} /* namespace cli */
} /* namespace suskeymaster */
