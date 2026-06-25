#include "spblob.hpp"
#include "cli.hpp"
#include "util.hpp"
#include "auth-hal.hpp"
#include "pwd-blob.hpp"
#include <core/int.h>
#include <libsuskmhal/keymaster-types-cpp.hpp>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <iostream>

namespace suskeymaster {
namespace cli {
namespace auth {

using kmhal::SusKMHal;
using kmhal::generic::HardwareAuthToken;

static int read_validate_header(const std::vector<u8>& blob, u8& out_version);

static int init_pwd_data_for_gatekeeper(const std::vector<u8>& pwd_data,
                                        const std::vector<u8>& credential,
                                        std::vector<u8>& out_stretched_lskf,
                                        std::vector<u8>& out_gk_handle);

static int prepare_protector_secret(const std::vector<u8>& secdiscardable,
                                    const std::vector<u8>& stretched_lskf,
                                    std::vector<u8>& out);

static int do_user_gatekeeper_auth(GatekeeperHAL& gk_hal,
                                   u32 uid, u64 challenge, const std::vector<u8>& gk_handle,
                                   const std::vector<u8>& stretched_lskf,
                                   HardwareAuthToken& out);

static int do_double_decryption(SusKMHal& kmhal, u8 blob_ver,
                                const std::vector<u8>& ciphertext,
                                const std::vector<u8>& protector_secret,
                                const std::vector<u8>& km_key_blob,
                                const HardwareAuthToken& auth_token,
                                std::vector<u8>& out);


static int decrypt_software(std::vector<u8> const& secret, std::vector<u8> const& enc_blob,
                            std::vector<u8>& out);

static int decrypt_keymaster(SusKMHal& hal, HardwareAuthToken const& auth_token,
                             std::vector<u8> const& keyblob, std::vector<u8> const& enc_blob,
                             std::vector<u8>& out);

spblob::spblob(const std::vector<u8>& secret, u8 version) :
    mSecret(secret),
    mVersion(version),
    mOk(true)
{
    if (version != SYNTHETIC_PASSWORD_VERSION_V1 &&
        version != SYNTHETIC_PASSWORD_VERSION_V2 &&
        version != SYNTHETIC_PASSWORD_VERSION_V3)
    {
        std::cerr << "WARNING: Unsupported SP blob version: " << static_cast<int>(version);
    }
}

spblob::~spblob()
{
    memset(mSecret.data(), 0, mSecret.size());
    mSecret.clear();
    mVersion = static_cast<u8>(-1);
}

int spblob::derive_subkey(const char *personalization, std::vector<u8>& out) const
{
    if (mVersion == SYNTHETIC_PASSWORD_VERSION_V3) {
        static constexpr const char PERSONALIZATION_CONTEXT[] =
            "android-synthetic-password-personalization-context";

        if (util::sp800_derive_with_context(mSecret,
                    personalization, strlen(personalization),
                    PERSONALIZATION_CONTEXT, sizeof(PERSONALIZATION_CONTEXT) - 1,
                    out))
        {
            std::cerr << "Failed to derive key from synthetic password using SP800" << std::endl;
            return EXIT_FAILURE;
        }
    } else if (mVersion == SYNTHETIC_PASSWORD_VERSION_V2 ||
               mVersion == SYNTHETIC_PASSWORD_VERSION_V1)
    {
        if (util::personalized_hash(mSecret, personalization, out)) {
            std::cerr << "Failed to derive key from synthetic password using personalized hash"
                << std::endl;
            return EXIT_FAILURE;
        }
    } else {
        std::cerr << "Invalid or unsupported SP blob version: " << static_cast<int>(mVersion)
            << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int spblob::user_gatekeeper_auth(GatekeeperHAL& gk_hal,
                                 u32 uid, u64 challenge, const std::vector<u8>& pwd_file,
                                 const std::vector<u8>& credential,
                                 kmhal::generic::HardwareAuthToken& out)
{
    if (!gk_hal.is_ok()) {
        std::cerr << "Gatekeeper HAL not properly initialized" << std::endl;
        return EXIT_FAILURE;
    }

    std::vector<u8> stretched_lskf;
    std::vector<u8> gk_handle;
    if (init_pwd_data_for_gatekeeper(pwd_file, credential, stretched_lskf, gk_handle)) {
        std::cerr << "Failed to initialize data from the pwd file" << std::endl;
        return EXIT_FAILURE;
    }

    return do_user_gatekeeper_auth(gk_hal, uid, challenge, gk_handle, stretched_lskf, out);
}

int spblob::sp_gatekeeper_auth(GatekeeperHAL& gk_hal,
                               u32 uid, u64 challenge, const std::vector<u8>& gk_handle,
                               kmhal::generic::HardwareAuthToken& out) const
{
    if (!this->is_ok()) {
        std::cerr << "SP blob is not OK!" << std::endl;
        return EXIT_FAILURE;
    }
    if (!gk_hal.is_ok()) {
        std::cerr << "Gatekeeper HAL not initialized properly!" << std::endl;
        return EXIT_FAILURE;
    }

    std::vector<u8> gk_password;
    static constexpr const char PERSONALIZATION_SP_GK_AUTH[] = "sp-gk-authentication";
    if (this->derive_subkey(PERSONALIZATION_SP_GK_AUTH, gk_password)) {
        std::cerr << "Failed to derive gatekeeper password from SP" << std::endl;
        return EXIT_FAILURE;
    }

    auto res = gk_hal.verify(uid, challenge, gk_handle, gk_password);

    std::cout << "Gatekeeper verification status: "
        << static_cast<i32>(res.code) << " (" << toString(res.code) << ")" << std::endl;
    if (static_cast<i32>(res.code) < 0) {
        if (res.code == GatekeeperStatusCode::ERROR_RETRY_TIMEOUT)
            std::cout << "Gatekeeper retry timeout: " << res.timeout << "ms" << std::endl;
        return EXIT_FAILURE;
    } else if (res.code == GatekeeperStatusCode::STATUS_REENROLL) {
        std::cerr << "WARNING: Gatekeeper verification succeeded, "
            "but the handle should be re-enrolled due to a version change." << std::endl;
    }

    out = res.authToken;
    return EXIT_SUCCESS;
}

spblob::spblob(kmhal::SusKMHal& kmhal, GatekeeperHAL& gk_hal,
               u32 uid, const std::vector<u8>& credential, const std::vector<u8>& pwd_file,
               const std::vector<u8>& secdiscardable, const std::vector<u8>& km_key_blob,
               const std::vector<u8>& sp_blob) :
    mSecret({}),
    mVersion(static_cast<u8>(-1)),
    mOk(false)
{
    if (!kmhal.isHALOk() || !gk_hal.is_ok()) {
        std::cerr << "GK or KM HAL is not properly initialized" << std::endl;
        return;
    } else if (read_validate_header(sp_blob, mVersion)) {
        std::cerr << "Invalid encrypted SP blob" << std::endl;
        return;
    }

    /**
     * What this function does:
     *  - Initialize some data from a combination of user credentials and the pwd file;
     *  - Get GK auth token & derive secret by using data from the above step;
     *  - Use the auth token and secret to actually decrypt the SP blob.
     */


    /** Initialize data from pwd file and user credentials **/

    std::vector<u8> stretched_lskf;
    std::vector<u8> gk_handle;
    /* The pwd file contains:
     *  1) Scrypt parameters - used to stretch the credential
     *  2) Gatekeeper handle, if using Gatekeeper (which is the case here).
     *
     * So this function does:
     *  1) password stretching with the parameters from the blob,
     *  2) deserialization and validation of the stored Gatekeeper handle. */
    if (init_pwd_data_for_gatekeeper(pwd_file, credential, stretched_lskf, gk_handle)) {
        std::cerr << "Failed to initialize data from the pwd file" << std::endl;
        return;
    }


    /** Prepare GK auth token and protector secret **/

    /**
     * There are 2 steps to unwrap the SP blob -
     *  1) Decrypt the blob in Keymaster/KeyMint using an auth token from Gatekeeper;
     *  2) Decrypt the resulting plaintext again, this time in software,
     *      using a key derived from the user's stretched credentials.
     *
     * Note: for v1 blobs, they fucked up the ordering of the above steps
     * and it's reversed. lol
     */

    /* For KM decryption */
    HardwareAuthToken auth_token;
    std::cout << std::endl << "Authenticating with Gatekeeper using user credentials..."
        << std::endl;
    if (do_user_gatekeeper_auth(gk_hal, uid, UINT64_C(0), gk_handle, stretched_lskf,
                                auth_token))
    {
        std::cerr << "Gatekeeper user authentication failed" << std::endl;
        return;
    }

    /* For software decryption */
    std::vector<u8> protector_secret;
    if (prepare_protector_secret(secdiscardable, stretched_lskf, protector_secret)) {
        std::cerr << "Failed to derive protector secret" << std::endl;
        return;
    }

    /** Do the 2-step decryption **/
    const std::vector<u8> ciphertext(sp_blob.begin() + 2 /* SP blob header info is 2 bytes */,
                                     sp_blob.end());
    if (do_double_decryption(kmhal, mVersion, ciphertext,
                             protector_secret, km_key_blob, auth_token,
                             mSecret))
    {
        std::cerr << "Failed to decrypt the SP" << std::endl;
        return;
    }

    mOk = true;
    std::cout << "Successfully unwrapped Synthetic Password blob w/ Gatekeeper" << std::endl;
}

spblob::spblob(kmhal::SusKMHal& kmhal,
        const std::vector<u8>& secdiscardable, const std::vector<u8>& km_key_blob,
        const std::vector<u8>& sp_blob) :
    mSecret({}),
    mVersion(static_cast<u8>(-1)),
    mOk(false)
{
    if (!kmhal.isHALOk()) {
        std::cerr << "GK or KM HAL is not properly initialized" << std::endl;
        return;
    } else if (read_validate_header(sp_blob, mVersion)) {
        std::cerr << "Invalid encrypted SP blob" << std::endl;
        return;
    }

    /* When no lock screen is set, there's no .pwd file and no Gatekeeper handle,
     * so instead of stretching anything, the string "default-password"
     * is padded to the scrypt output length (32) and passed in
     * as the "already streched" credential. */
    std::vector<u8> default_password(std::begin(pwd_blob::DEFAULT_PASSWORD),
                                     std::end(pwd_blob::DEFAULT_PASSWORD) - 1);
    default_password.resize(cli::auth::pwd_blob::STRETCHED_LSKF_LENGTH);

    std::vector<u8> protector_secret;
    if (prepare_protector_secret(secdiscardable, default_password, protector_secret)) {
        std::cerr << "Failed to derive protector secret" << std::endl;
        return;
    }

    const std::vector<u8> ciphertext(sp_blob.begin() + 2 /* SP blob header info is 2 bytes */,
                                     sp_blob.end());
    if (do_double_decryption(kmhal, mVersion, ciphertext, protector_secret, km_key_blob, {},
                             mSecret))
    {
        std::cerr << "Failed to decrypt the SP" << std::endl;
        return;
    }

    mOk = true;
    std::cout << "Successfully unwrapped Synthetic Password w/o authentication" << std::endl;
}

static int read_validate_header(const std::vector<u8>& blob, u8& out_version)
{
    u8 protector_type = static_cast<u8>(-1);

    if (blob.size() <
            sizeof(out_version) +
            sizeof(protector_type) +
            util::AES_GCM_IV_SIZE +
            util::AES_GCM_TAG_SIZE)
    {
        std::cerr << "Encrypted SP blob too small" << std::endl;
        return EXIT_FAILURE;
    }

    out_version = blob[0];
    if (out_version != spblob::SYNTHETIC_PASSWORD_VERSION_V1 &&
        out_version != spblob::SYNTHETIC_PASSWORD_VERSION_V2 &&
        out_version != spblob::SYNTHETIC_PASSWORD_VERSION_V3)
    {
        std::cerr << "Invalid or unsupported SP blob version" << std::endl;
        return EXIT_FAILURE;
    }

    protector_type = blob[1];
    if (protector_type != spblob::PROTECTOR_TYPE_LSKF_BASED) {
        std::cerr << "Invalid or unsupported SP protector type: "
            << static_cast<int>(protector_type) <<
            " (expected 0 - PROTECTOR_TYPE_LSKF_BASED)" << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

static int init_pwd_data_for_gatekeeper(const std::vector<u8>& pwd_data,
                                        const std::vector<u8>& credential,
                                        std::vector<u8>& out_stretched_lskf,
                                        std::vector<u8>& out_gk_handle)
{
    using kmhal::generic::password_handle_t;

    pwd_blob pwd(pwd_data);
    if (!pwd.ok()) {
        std::cerr << "Invalid pwd file data" << std::endl;
        return EXIT_FAILURE;
    }
    if (pwd.stretch_lskf(credential, out_stretched_lskf)) {
        std::cerr << "Failed to stretch credential using pwd data" << std::endl;
        return EXIT_FAILURE;
    }

    if (pwd.handle.size() != sizeof(password_handle_t))
    {
        std::cerr << "Invalid or missing Gatekeeper handle in pwd blob" << std::endl;
        return EXIT_FAILURE;
    } else if (pwd.handle[0] > password_handle_t::HANDLE_VERSION) {
        std::cerr << "WARNING: Unsupported password handle version: "
            << static_cast<int>(pwd.handle[0]) << std::endl;
    }
    out_gk_handle = pwd.handle;

    return EXIT_SUCCESS;
}

static int prepare_protector_secret(const std::vector<u8>& secdiscardable,
                                    const std::vector<u8>& stretched_lskf,
                                    std::vector<u8>& out)
{
    std::vector<u8> secdiscardable_hash;
    static constexpr const char PERSONALIZATION_SECDISCARDABLE[] = "secdiscardable-transform";
    if (util::personalized_hash(secdiscardable, PERSONALIZATION_SECDISCARDABLE,
                                secdiscardable_hash))
    {
        std::cerr << "Failed to hash secdiscardable" << std::endl;
        return EXIT_FAILURE;
    }

    /* Protector secret = Secdiscardable hash || LSKF data */
    out.resize(stretched_lskf.size() + secdiscardable_hash.size());
    memcpy(out.data(),
           stretched_lskf.data(), stretched_lskf.size());
    memcpy(out.data() + stretched_lskf.size(),
           secdiscardable_hash.data(), secdiscardable_hash.size());
    return EXIT_SUCCESS;
}

static int do_user_gatekeeper_auth(GatekeeperHAL& gk_hal,
                                   u32 uid, u64 challenge, const std::vector<u8>& gk_handle,
                                   const std::vector<u8>& stretched_lskf,
                                   HardwareAuthToken& out)
{
    std::vector<u8> gk_password;
    static constexpr const char PERSONALIZATION_USER_GK_AUTH[] = "user-gk-authentication";
    if (util::personalized_hash(stretched_lskf, PERSONALIZATION_USER_GK_AUTH, gk_password)) {
        std::cerr << "Failed to derive the Gatekeeper password" << std::endl;
        return EXIT_FAILURE;
    }

    /* Gatekeeper is always used to derive Keymaster/KeyMint auth tokens
     * using the user's synthetic password, even in the presence of Weaver.
     *
     * But in this case, since Weaver is not available, it is also Gatekeeper's job
     * to handle verification of the actual user credential to unwrap the SP in the first place.
     *
     * This is called "user-gk-authentication", as opposed to the later SP-bound authentication
     * "sp-gk-authentication" (which is what `spblob::validate_with_gatekeeper` does).
     *
     * So, since the uid is already enrolled in Gatekeeper for the later "sp-gk-authentication",
     * a different one has to be enrolled for this "user-gk-authentication",
     * and AOSP simply just uses `uid + 100000` (and calls that "fakeUserId").
     *
     * TLDR:
     *  `uid + 100000`: "user-gk-authentication" - Authentication with user credentials,
     *          only to unwrap the Synthetic Password;
     *
     *  `uid`: "sp-gk-authentication" - Authentication with the Synthetic Password,
     *          to derive KM auth tokens for use by applications.
     */
    const u32 fake_user_id = uid + 100000;
    auto res = gk_hal.verify(fake_user_id, challenge, gk_handle, gk_password);

    std::cout << "Gatekeeper verification status: "
        << static_cast<i32>(res.code) << " (" << toString(res.code) << ")" << std::endl;
    if (static_cast<i32>(res.code) < 0) {
        if (res.code == GatekeeperStatusCode::ERROR_RETRY_TIMEOUT)
            std::cout << "Gatekeeper retry timeout: " << res.timeout << "ms" << std::endl;
        return EXIT_FAILURE;
    } else if (res.code == GatekeeperStatusCode::STATUS_REENROLL) {
        std::cerr << "WARNING: Gatekeeper verification succeeded, "
            "but the handle should be re-enrolled due to a version change." << std::endl;
    }

    out = res.authToken;
    return EXIT_SUCCESS;
}

static int do_double_decryption(SusKMHal& kmhal, u8 blob_ver,
                                const std::vector<u8>& ciphertext,
                                const std::vector<u8>& protector_secret,
                                const std::vector<u8>& km_key_blob,
                                const HardwareAuthToken& auth_token,
                                std::vector<u8>& out)
{
    std::vector<u8> intermediate;
    if (blob_ver == spblob::SYNTHETIC_PASSWORD_VERSION_V1) {
        /* reversed order for v1 */
        std::cout << std::endl << "Performing first decryption (in software)..." << std::endl;
        if (decrypt_software(protector_secret, ciphertext, intermediate)) {
            std::cerr << "First stage of unwrapping (software decryption) failed" << std::endl;
            return EXIT_FAILURE;
        }
        std::cout << std::endl << "Performing second decryption (in TEE)..." << std::endl;
        if (decrypt_keymaster(kmhal, auth_token, km_key_blob, intermediate, out)) {
            std::cerr << "Second stage of unwrapping (KM decryption) failed" << std::endl;
            return EXIT_FAILURE;
        }
        std::cout << std::endl;
    } else {
        std::cout << std::endl << "Performing first decryption (in TEE)..." << std::endl;
        if (decrypt_keymaster(kmhal, auth_token, km_key_blob, ciphertext, intermediate)) {
            std::cerr << "First stage of unwrapping (KM decryption) failed" << std::endl;
            return EXIT_FAILURE;
        }
        std::cout << std::endl << "Performing second decryption (in software)..." << std::endl;
        if (decrypt_software(protector_secret, intermediate, out)) {
            std::cerr << "Second stage of unwrapping (software decryption) failed" << std::endl;
            return EXIT_FAILURE;
        }
        std::cout << std::endl;
    }

    return EXIT_SUCCESS;
}

static int decrypt_software(std::vector<u8> const& secret, std::vector<u8> const& enc_blob,
                            std::vector<u8>& out)
{
    std::vector<u8> derived_key;
    static constexpr const char PROTECTOR_SECRET_PERSONALIZATION[] = "application-id";
    if (util::personalized_hash(secret, PROTECTOR_SECRET_PERSONALIZATION, derived_key)) {
        std::cerr << "Failed to hash the protector secret" << std::endl;
        return 1;
    }
    derived_key.resize(util::AES_GCM_KEY_SIZE);

    return util::aes256gcm_software_decrypt(derived_key, enc_blob, out);
}

static int decrypt_keymaster(SusKMHal& hal, HardwareAuthToken const& auth_token,
                             std::vector<u8> const& keyblob, std::vector<u8> const& enc_blob,
                             std::vector<u8>& out)
{
    std::vector<u8> iv, ciphertext_with_tag;
    if (util::extract_gcm_data(enc_blob, iv, ciphertext_with_tag))
        return 1;

    using namespace kmhal::generic;

    std::vector<KeyParameter> params(4);
    params[0].tag = Tag::BLOCK_MODE;    params[0].f.blockMode   = BlockMode::GCM;
    params[1].tag = Tag::PADDING;       params[1].f.paddingMode = PaddingMode::NONE;
    params[2].tag = Tag::NONCE;         params[2].blob          = iv;
    params[3].tag = Tag::MAC_LENGTH;    params[3].f.integer     = 8 * util::AES_GCM_TAG_SIZE;

    return hal_ops::crypto::decrypt(hal, ciphertext_with_tag,
            keyblob, params, { auth_token, {} }, out);
}

} /* namespace auth */
} /* namespace cli */
} /* namespace suskeymaster */
