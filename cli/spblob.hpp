#pragma once

#include "auth-hal.hpp"
#include <core/int.h>
#include <vector>
#include <libsuskmhal/suskmhal.hpp>

namespace suskeymaster {
namespace cli {
namespace auth {

/**
 * A Synthetic Password (SP) is the actual secret that is used
 * to get auth tokens from Keymaster/KeyMint
 * and to derive the CE storage key encryption key for vold.
 * In other words, this is the actual user's secret password.
 *
 * An SP blob stores that valuable secret in wrapped form, encrypted twice -
 * first with a key derived from the user's credentials and password blob,
 * and then with a secret from a protector (Gatekeeper or Weaver).
 *
 * This means that only after a secure protector validates the given credentials & data
 * can the synthetic password be unwrapped.
 *
 * Another thing is that this additional "indirection" means that a user's synthetic password
 * never changes, and therefore the CE storage doesn't have to be re-encrypted
 * when the user decides to change their credentials - the only thing that does change then
 * is the ciphertext of the SP blob.
 *
 * The layout of an encrypted SP is simple:
 *  - u8 version; // currently 1, 2 or 3
 *  - u8 protector_type; // we only care about `PROTECTOR_TYPE_LSKF_BASED`
 *  - u8 ciphertext_content[];
 */
struct spblob {
    static constexpr u8 SYNTHETIC_PASSWORD_VERSION_V1 = 1;
    static constexpr u8 SYNTHETIC_PASSWORD_VERSION_V2 = 2;
    static constexpr u8 SYNTHETIC_PASSWORD_VERSION_V3 = 3;

    static constexpr u8 PROTECTOR_TYPE_LSKF_BASED = 0;
    static constexpr u8 PROTECTOR_TYPE_STRONG_TOKEN_BASED = 1;
    static constexpr u8 PROTECTOR_TYPE_WEAK_TOKEN_BASED = 2;

    /**
     * Initializes an spblob struct with a provided secret and encrypted blob version.
     * Always succeeds.
     *
     * @param secret The secret to initialize the blob with.
     *
     * @param version Encrypted spblob version.
     */
    explicit spblob(const std::vector<u8>& secret, u8 version);

    /**
     * Deserialize and unwrap an encrypted SP blob using Gatekeeper.
     * Always check whether the operation was successful, with `is_ok`.
     *
     * @param kmhal Keymaster/KeyMint HAL wrapper handle.
     *
     * @param gk_hal Gatekeeper HAL wrapper handle.
     *
     * @param uid Android user ID of the user who owns this Synthetic Password.
     *
     * @param credential User's credential (Lock Screen Knowledge Factor).
     *
     * @param pwd_file The `pwd_blob` of the user, which has data required for unwrapping.
     *
     * @param secdiscardable The `secdis` file stored alongside the spblob.
     *
     * @param km_key_blob Keymaster/KeyMint key blob needed to unwrap the SP.
     *
     * @param sp_blob The encrypted SP blob to unwrap.
     */
    explicit spblob(kmhal::SusKMHal& kmhal, GatekeeperHAL& gk_hal,
                    u32 uid, const std::vector<u8>& credential, const std::vector<u8>& pwd_file,
                    const std::vector<u8>& secdiscardable, const std::vector<u8>& km_key_blob,
                    const std::vector<u8>& sp_blob);

    /**
     * Deserialize and unwrap an encrypted SP blob of a user without a lockscreen set,
     * using the "default-password" without any Gatekeeper/Weaver authentication.
     * Always check whether the operation was successful, with `is_ok`.
     *
     * @param kmhal Keymaster/KeyMint HAL wrapper handle.
     *
     * @param secdiscardable The `secdis` file stored alongside the spblob.
     *
     * @param km_key_blob Keymaster/KeyMint key blob needed to unwrap the SP.
     *
     * @param sp_blob The encrypted SP blob to unwrap.
     */
    explicit spblob(kmhal::SusKMHal& kmhal,
                    const std::vector<u8>& secdiscardable, const std::vector<u8>& km_key_blob,
                    const std::vector<u8>& sp_blob);

    bool is_ok() const { return mOk; };

    /** Zeroizes the stored `mSecret`. */
    ~spblob();

    spblob(const spblob& other) = default;
    spblob& operator=(const spblob& other) = default;

    spblob(spblob&& other) = default;
    spblob& operator=(spblob&& other) = default;

    /**
     * Derives a subkey from the Synthetic Password secret,
     * for use by e.g. `vold` to derive the CE storage key encryption key.
     *
     * @param personalization KDF context string, used to personalize the derived key.
     *
     * @param out Output reference which on success will contain the derived key.
     *
     * @return 0 on success, non-zero on failure.
     */
    int derive_subkey(const char *personalization, std::vector<u8>& out) const;

    /**
     * Authenticates with Gatekeeper using user credentials.
     * Exposed here as a generic utility for use in `main.cpp` ("gatekeeper verify").
     *
     * @param gk_hal Gatekeeper HAL wrapper handle.
     *
     * @param uid The ID of the Android user to authenticate.
     *
     * @param challenge Challenge value for the authentication.
     *
     * @param pwd_file The `pwd_blob` of the user ("*.pwd").
     *
     * @param credential The credentials to verify.
     *
     * @return 0 on success, non-zero on failure.
     */
    static int user_gatekeeper_auth(GatekeeperHAL& gk_hal,
                                    u32 uid, u64 challenge, const std::vector<u8>& pwd_file,
                                    const std::vector<u8>& credential,
                                    kmhal::generic::HardwareAuthToken& out);

    /**
     * Authenticates with Gatekeeper using this Synthetic Password.
     *
     * @param gk_hal Gatekeeper HAL wrapper handle.
     *
     * @param uid The ID of the Android user who owns the SP.
     *
     * @param challenge Challenge value for the authentication.
     *
     * @param gk_handle The contents of the 0000000000000000.handle file
     *  found alongside the encrypted spblob.
     *
     * @param out Output reference which on success will contain a Gatekeeper auth token
     *  for the given user.
     *
     * @return 0 on success, non-zero on failure.
     */
    int sp_gatekeeper_auth(GatekeeperHAL& gk_hal,
                           u32 uid, u64 challenge, const std::vector<u8>& gk_handle,
                           kmhal::generic::HardwareAuthToken& out) const;

    const std::vector<u8>& get_secret(void) const { return mSecret; };

private:
    std::vector<u8> mSecret = {};
    u8 mVersion = static_cast<u8>(-1);

    bool mOk = false;
};

} /* namespace auth */
} /* namespace cli */
} /* namespace suskeymaster */
