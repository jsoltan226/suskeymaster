#define OPENSSL_API_COMPAT 0x10002000L
#include "cli.hpp"
#include <libsuskmhal/suskmhal.hpp>
#include <libsuskmhal/keymaster-types-cpp.hpp>
#include <cstdio>
#include <vector>
#include <cstring>
#include <cstdlib>
#ifndef SUSKEYMASTER_BUILD_WINDOWS
#include <iomanip>
#include <sstream>
#include <unistd.h>
#include <linux/unistd.h>
#include <linux/fscrypt.h>
#endif /* SUSKEYMASTER_BUILD_WINDOWS */
#include <openssl/sha.h>

namespace suskeymaster {
namespace cli {
namespace vold {

using namespace kmhal::generic;
using kmhal::SusKMHal;

/* from keyutils.h */

/* key serial number */
typedef int32_t key_serial_t;

/* special process keyring shortcut IDs */
#define KEY_SPEC_THREAD_KEYRING        -1    /* - key ID for thread-specific keyring */
#define KEY_SPEC_PROCESS_KEYRING    -2    /* - key ID for process-specific keyring */
#define KEY_SPEC_SESSION_KEYRING    -3    /* - key ID for session-specific keyring */
#define KEY_SPEC_USER_KEYRING        -4    /* - key ID for UID-specific keyring */
#define KEY_SPEC_USER_SESSION_KEYRING    -5    /* - key ID for UID-session keyring */
#define KEY_SPEC_GROUP_KEYRING        -6    /* - key ID for GID-specific keyring */
#define KEY_SPEC_REQKEY_AUTH_KEY    -7    /* - key ID for assumed request_key auth key */

/* keyctl commands */
#define KEYCTL_SEARCH            10    /* search for a key in a keyring */

#ifndef SUSKEYMASTER_BUILD_WINDOWS
static int derive_key_ref(std::vector<u8> const& key, std::vector<u8>& out);

static std::string get_key_name(const char *prefix, std::vector<u8> const& ref);

static long keyctl_search(key_serial_t ringid,
                          const char *type, const char *description,
                          key_serial_t destringid);

static key_serial_t add_key(const char *type, const char *description,
                            const void *payload, size_t plen,
                            key_serial_t ringid);
#endif /* SUSKEYMASTER_BUILD_WINDOWS */

int generate_app_id(std::vector<u8> const& in_secdiscardable,
        std::vector<u8> const& in_secret,
        std::vector<u8>& out_app_id)
{
    /* AOSP constants */
    static constexpr const char HASH_PREFIX_SECDISCARDABLE[] = "Android secdiscardable SHA512";

    if (in_secdiscardable.size() > 0) {
        if (util::personalized_hash(in_secdiscardable, HASH_PREFIX_SECDISCARDABLE, out_app_id)) {
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

    return 0;
}

int decrypt_de_key(SusKMHal& hal,
        std::vector<u8> const& in_keystore_key, std::vector<u8> const& in_secdiscardable,
        std::vector<u8> const& in_encrypted_key, std::vector<u8>& out_decrypted_key)
{

    std::vector<u8> km_blob = util::keystore_blob_to_km_blob(in_keystore_key);

    std::vector<u8> secret{}; /* empty secret for keystore decryption */
    std::vector<u8> app_id;
    if (generate_app_id(in_secdiscardable, secret, app_id)) {
        std::cerr << "Failed to generate Tag::APPLICATION_ID from secdiscardable" << std::endl;
        return 1;
    }
    /*
    std::puts("===== BEGIN APPLICATION ID HEX DUMP =====");
    for (u8 b : app_id) {
        std::printf("%02x", (unsigned)b);
    }
    std::putchar('\n');
    std::puts("=====  END APPLICATION ID HEX DUMP  =====");
    */

    std::vector<u8> enc_key_iv, enc_key_ciphertext_with_tag;
    if (util::extract_gcm_data(in_encrypted_key, enc_key_iv, enc_key_ciphertext_with_tag)) {
        std::cerr << "Failed to extract the AES-GCM data from the encrypted key" << std::endl;
        return 1;
    }

    std::vector<KeyParameter> params(5);
    params[0].tag = Tag::BLOCK_MODE;
    params[0].f.blockMode = BlockMode::GCM;
    params[1].tag = Tag::PADDING;
    params[1].f.paddingMode = PaddingMode::NONE;
    params[2].tag = Tag::NONCE;
    params[2].blob = enc_key_iv;
    params[3].tag = Tag::MAC_LENGTH;
    params[3].f.integer = util::AES_GCM_TAG_SIZE * 8;
    params[4].tag = Tag::APPLICATION_ID;
    params[4].blob = app_id;

    if (hal_ops::crypto::decrypt(hal, enc_key_ciphertext_with_tag,
                                 km_blob, params, {}, out_decrypted_key))
    {
        std::cerr << "Failed to decrypt vold encrypted key" << std::endl;
        return 1;
    }

    std::cout << "Successfully decrypted vold key with keystore key" << std::endl;
    return 0;
}

int decrypt_ce_key(
        std::vector<u8> const& in_secret, std::vector<u8> const& in_secdiscardable,
        std::vector<u8> const& in_encrypted_key, std::vector<u8>& out_decrypted_key)
{
    std::vector<u8> app_id;
    if (generate_app_id(in_secdiscardable, in_secret, app_id)) {
        std::cerr << "Failed to generate app ID from vold auth secret" << std::endl;
        return 1;
    }

    std::vector<u8> key;
    static constexpr const char HASH_PREFIX_KEYGEN[] =
        "Android key wrapping key generation SHA512";
    if (util::personalized_hash(app_id, HASH_PREFIX_KEYGEN, key)) {
        std::cerr << "Failed to derive CE key encryption key from generated app ID" << std::endl;
        return 1;
    }
    key.resize(util::AES_GCM_KEY_SIZE);

    /* decrypt without keystore */
    if (util::aes256gcm_software_decrypt(key, in_encrypted_key, out_decrypted_key)) {
        std::cerr << "Failed to decrypt CE key" << std::endl;
        return 1;
    }

    std::cout << "Successfully decrypted CE key!" << std::endl;
    return 0;
}

int fscrypt_legacy_install_key(std::vector<u8> const& key)
{
#ifndef SUSKEYMASTER_BUILD_WINDOWS
    if (key.size() != FSCRYPT_MAX_KEY_SIZE) {
        std::cerr << "Invalid fscrypt key" << std::endl;
        return EXIT_FAILURE;
    }

    struct fscrypt_key fs_key;
    static_assert(FSCRYPT_MAX_KEY_SIZE == sizeof(fs_key.raw),
            "Mismatch of max key sizes");
    fs_key.mode = 0; /* unused by kernel */
    fs_key.size = FSCRYPT_MAX_KEY_SIZE,
    memcpy(fs_key.raw, key.data(), FSCRYPT_MAX_KEY_SIZE);

    std::vector<u8> key_ref;
    if (derive_key_ref(key, key_ref)) {
        std::cerr << "Failed to derive the key reference" << std::endl;
        return EXIT_FAILURE;
    }

    key_serial_t fscrypt_device_keyring =
        keyctl_search(KEY_SPEC_SESSION_KEYRING, "keyring", "fscrypt", 0);
    if (fscrypt_device_keyring == -1) {
        std::cerr << "Couldn't find device fscrypt keyring: "
            << errno << " (" << strerror(errno) << ")" << std::endl;
        return EXIT_FAILURE;
    }

    for (const char *prefix : { "ext4", "f2fs", "fscrypt" }) {
        const std::string name = get_key_name(prefix, key_ref);

        key_serial_t s = add_key("logon", name.c_str(),
                &fs_key, sizeof(fs_key), fscrypt_device_keyring);
        if (s == -1) {
            std::cerr << "Failed to add key \"" << name << "\" to device keyring" << std::endl;
            return EXIT_FAILURE;
        }

        std::cout << "Successfully added key " << static_cast<i32>(s)
            << " (" << name << ") to fscrypt keyring" << std::endl;
    }

    return EXIT_SUCCESS;
#else
    (void) key;
    std::cerr << __func__ << " is not implemented on windows" << std::endl;
    return EXIT_FAILURE;
#endif /* SUSKEYMASTER_BUILD_WINDOWS */
}

#ifndef SUSKEYMASTER_BUILD_WINDOWS
static int derive_key_ref(std::vector<u8> const& key, std::vector<u8>& out)
{
    static_assert(FSCRYPT_KEY_DESCRIPTOR_SIZE <= SHA512_DIGEST_LENGTH,
                  "Hash too short for descriptor");

    SHA512_CTX ctx;
    if (!SHA512_Init(&ctx)) {
        std::cerr << "SHA512_Init failed" << std::endl;
        return 1;
    }
    if (!SHA512_Update(&ctx, key.data(), key.size())) {
        std::cerr << "SHA512_Update failed" << std::endl;
        return 1;
    }
    unsigned char key_ref1[SHA512_DIGEST_LENGTH];
    if (!SHA512_Final(key_ref1, &ctx)) {
        std::cerr << "SHA512_Final failed" << std::endl;
        return 1;
    }

    if (!SHA512_Init(&ctx)) {
        std::cerr << "SHA512_Init failed" << std::endl;
        return 1;
    }
    if (!SHA512_Update(&ctx, key_ref1, sizeof(key_ref1))) {
        std::cerr << "SHA512_Update failed" << std::endl;
        return 1;
    }
    unsigned char key_ref2[SHA512_DIGEST_LENGTH];
    if (!SHA512_Final(key_ref2, &ctx)) {
        std::cerr << "SHA512_Final failed" << std::endl;
        return 1;
    }

    out.resize(FSCRYPT_KEY_DESCRIPTOR_SIZE);
    memcpy(out.data(), key_ref2, FSCRYPT_KEY_DESCRIPTOR_SIZE);
    return 0;
}

static std::string get_key_name(const char *prefix, std::vector<u8> const& ref)
{
    std::ostringstream o;
    for (u8 b : ref) {
        o << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    return std::string(prefix) + ":" + o.str();
}

static long keyctl_search(key_serial_t ringid,
                          const char *type, const char *description,
                          key_serial_t destringid)
{
    return syscall(__NR_keyctl, KEYCTL_SEARCH,
            ringid, type, description, destringid);
}

static key_serial_t add_key(const char *type, const char *description,
                            const void *payload, size_t plen,
                            key_serial_t ringid)
{
    return syscall(__NR_add_key,
               type, description, payload, plen, ringid);
}
#endif /* SUSKEYMASTER_BUILD_WINDOWS */

} /* namespace vold */
} /* namespace cli */
} /* namespace suskeymaster */
