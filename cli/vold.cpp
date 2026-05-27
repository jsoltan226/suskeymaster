#define OPENSSL_API_COMPAT 0x10002000L
#define HIDL_DISABLE_INSTRUMENTATION
#include "cli.hpp"
#include <libsuskmhal/hidl/hidl-hal.hpp>
#include <android/hardware/keymaster/generic/types.h>
#include <endian.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <openssl/sha.h>
#ifdef SUSKEYMASTER_BUILD_ANDROID
#include <sys/system_properties.h>
#endif /* SUSKEYMASTER_BUILD_ANDROID */

namespace suskeymaster {
namespace cli {
namespace vold {

using namespace ::android::hardware::keymaster::generic;
using ::android::hardware::hidl_vec;
using kmhal::hidl::HidlSusKeymaster;

static hidl_vec<u8> remove_keystore2_prefix_if_exists(const hidl_vec<u8>& blob);
static void append_sha256_sum(hidl_vec<u8>& blob);

static bool is_samsung(void);


int generate_app_id(hidl_vec<u8> const& in_secdiscardable,
        hidl_vec<u8> const& in_secret,
        hidl_vec<u8>& out_app_id)
{
    /* AOSP constants */
    static constexpr const char HASH_PREFIX_SECDISCARDABLE[] = "Android secdiscardable SHA512";

    if (in_secdiscardable.size() > 0) {
        if (util::personalized_hash(in_secdiscardable,
                    HASH_PREFIX_SECDISCARDABLE, sizeof(HASH_PREFIX_SECDISCARDABLE),
                    out_app_id))
        {
            std::cerr << "Failed to hash secdiscardable" << std::endl;
            return 1;
        }
    } else {
        out_app_id.resize(0);
    }

    /* App ID = secdiscardable_hash || auth_secret */
    const size_t prev_size = out_app_id.size();
    out_app_id.resize(prev_size + in_secret.size());
    memcpy(out_app_id.data() + prev_size, in_secret.data(), in_secret.size());

    std::cout << toString(out_app_id) << std::endl;

    return 0;
}

int decrypt_de_key(HidlSusKeymaster& hal,
        hidl_vec<u8> const& in_keystore_key, hidl_vec<u8> const& in_secdiscardable,
        hidl_vec<u8> const& in_encrypted_key, hidl_vec<u8>& out_decrypted_key)
{

    hidl_vec<u8> km_blob = keystore_blob_to_km_blob(in_keystore_key);

    hidl_vec<u8> secret{}; /* empty secret for keystore decryption */
    hidl_vec<u8> app_id;
    if (generate_app_id(in_secdiscardable, secret, app_id)) {
        std::cerr << "Failed to generate Tag::APPLICATION_ID from secdiscardable" << std::endl;
        return 1;
    }
    std::puts("===== BEGIN APPLICATION ID HEX DUMP =====");
    for (u8 b : app_id) {
        std::printf("%02x", (unsigned)b);
    }
    std::putchar('\n');
    std::puts("=====  END APPLICATION ID HEX DUMP  =====");

    hidl_vec<u8> enc_key_iv, enc_key_ciphertext_with_tag;
    if (util::extract_gcm_data(in_encrypted_key, enc_key_iv, enc_key_ciphertext_with_tag)) {
        std::cerr << "Failed to extract the AES-GCM data from the encrypted key" << std::endl;
        return 1;
    }

    hidl_vec<KeyParameter> params(3);
    params[0].tag = Tag::APPLICATION_ID;
    params[0].blob = app_id;
    params[1].tag = Tag::NONCE;
    params[1].blob = enc_key_iv;
    params[2].tag = Tag::MAC_LENGTH;
    params[2].f.integer = util::AES_GCM_TAG_SIZE * 8;

    if (hal_ops::crypto::decrypt(hal, enc_key_ciphertext_with_tag,
                                 km_blob, params, out_decrypted_key))
    {
        std::cerr << "Failed to decrypt vold encrypted key" << std::endl;
        return 1;
    }

    std::cout << "Successfully decrypted vold key with keystore key" << std::endl;
    return 0;
}

int decrypt_ce_key(HidlSusKeymaster& hal,
        hidl_vec<u8> const& in_secret, hidl_vec<u8> const& in_secdiscardable,
        hidl_vec<u8> const& in_encrypted_key, hidl_vec<u8>& out_decrypted_key)
{
    hidl_vec<u8> vold_auth;
    if (util::parse_hex_string(in_secret, vold_auth)) {
        std::cerr << "Invalid vold secret hex string" << std::endl;
        return -1;
    } else if (vold_auth.size() == 0) {
        std::cerr << "Empty vold authentication data; invalid vold secret" << std::endl;
        return -1;
    }

    hidl_vec<u8> app_id;
    if (generate_app_id(in_secdiscardable, vold_auth, app_id)) {
        std::cerr << "Failed to generate app ID from vold auth secret" << std::endl;
        return 1;
    }

    hidl_vec<u8> key;
    static constexpr const char HASH_PREFIX_KEYGEN[] =
        "Android key wrapping key generation SHA512";
    if (util::personalized_hash(app_id, HASH_PREFIX_KEYGEN, sizeof(HASH_PREFIX_KEYGEN), key)) {
        std::cerr << "Failed to derive CE key encryption key from generated app ID" << std::endl;
        return 1;
    }

    /* decrypt without keystore */
    if (util::aes256gcm_software_decrypt(key, in_encrypted_key, out_decrypted_key)) {
        std::cerr << "Failed to decrypt CE key" << std::endl;
        return 1;
    }

    std::cout << "Successfully decrypted CE key!" << std::endl;
    return 0;
}

hidl_vec<u8> keystore_blob_to_km_blob(hidl_vec<u8> const& keystore_blob)
{
    hidl_vec<u8> ret = remove_keystore2_prefix_if_exists(keystore_blob);

    if (is_samsung())
        append_sha256_sum(ret);

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

static void append_sha256_sum(hidl_vec<u8>& blob)
{
    u8 digest[SHA256_DIGEST_LENGTH] = { 0 };
    (void) SHA256(blob.data(), blob.size(), digest);

    blob.resize(blob.size() + SHA256_DIGEST_LENGTH);
    std::memcpy(blob.data() + (blob.size() - SHA256_DIGEST_LENGTH),
            digest, SHA256_DIGEST_LENGTH);
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

} /* namespace vold */
} /* namespace cli */
} /* namespace suskeymaster */
