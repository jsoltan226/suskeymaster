#pragma once

#include <core/int.h>
#include <libsuskmhal/keymaster-types-cpp.hpp>
#include <vector>

namespace suskeymaster {
namespace cli {
namespace auth {

/* See "frameworks/base/core/java/com/android/internal/widget/LockPatternUtils.java"
 * and "frameworks/base/services/
 *      core/java/com/android/server/locksettings/SyntheticPasswordManager.java"
 * in AOSP */

/**
 * An object representing the "*.pwd" files found in /data/system_de/<uid>/spblob/,
 * which stores data used by `LockSettingsService` to, in combination with provided credentials,
 * derive the Gatekeeper or Weaver secret for the Synthetic Password Blob unwrapping.
 *
 * LockSettingsService takes the credential and, using the parameters from this blob,
 * stretches it with `scrypt`, and then that stretched value is used as the "password"
 * passed into Gatekeeper/Weaver to authenticate.
 *
 * This mitigates the issues of typical lock screen passwords/pins/etc -
 * easy brute-forceability due to their inherent low-entropy nature.
 *
 * Additionally, if using Gatekeeper,
 * the blob also stores the Gatekeeper handle to the given user's enrolled credentials.
 */
struct pwd_blob {
    using HardwareAuthToken = kmhal::generic::HardwareAuthToken;
    using password_handle_t = kmhal::generic::password_handle_t;

    /** Supported types of Lock Screen Knowledge Factors */
    enum class credential_type : i32 {
        NONE = -1,
        PATTERN = 1,
        PASSWORD_OR_PIN = 2, /* Legacy */
        PIN = 3,
        PASSWORD = 4
    } type = credential_type::NONE;

    /** LockSettingsService's default scrypt parameters */
    static constexpr u8 PASSWORD_SCRYPT_LOG_N_OLD = 11;
    static constexpr u8 PASSWORD_SCRYPT_LOG_N = 9;
    static constexpr u8 PASSWORD_SCRYPT_LOG_R = 3;
    static constexpr u8 PASSWORD_SCRYPT_LOG_P = 1;

    /** Scrypt salt length */
    static constexpr u8 PASSWORD_SALT_LENGTH = 16;

    /** PIN Autoconfirm stuff */
    static constexpr i32 PIN_LENGTH_UNAVAILABLE = -1;
    static constexpr i32 MIN_AUTO_PIN_REQUIREMENT_LENGTH = 6;

    /**
     * Default password, used to encrypt the SP blob
     * when the user doesn't yet have a screen lock set (e.g. after a factory reset)
     */
    static constexpr const u8 DEFAULT_PASSWORD[] = "default-password";

    /** Size of the scrypt output */
    static constexpr u32 STRETCHED_LSKF_LENGTH = 32;

    /**
     * Construct a password blob with the default scrypt parameter values
     * and a randomly generated salt. The Gatekeeper handle is left empty.
     */
    pwd_blob();

    /**
     * Construct a password blob with a Gatekeeper handle,
     * setting the scrypt parameters to default values
     * and generating a random salt of the default length.
     */
    explicit pwd_blob(const password_handle_t& gk_handle);

    /**
     * Construct a password blob by deserializing the provided data.
     * Check with `ok` whether the deserialization succeeded.
     *
     * @param Serialized password blob data.
     *
     * @param log Whether to dump the pwd blob to stdout.
     */
    explicit pwd_blob(const std::vector<u8>& in, bool log = false);
    bool ok(void) const { return mDeserializationOk; }

    ~pwd_blob() = default;

    /** Serialize password blob */
    void serialize(std::vector<u8>& out) const;

    /** Stretch given credential using parameters in this blob */
    int stretch_lskf(const std::vector<u8>& lskf, std::vector<u8>& out,
                     bool warn_if_default_password = true) const;

public:
    /** Scrypt N, R, P */
    u8 N = PASSWORD_SCRYPT_LOG_N, R = PASSWORD_SCRYPT_LOG_R, P = PASSWORD_SCRYPT_LOG_P;

    /** Scrypt salt */
    std::vector<u8> salt = std::vector<u8>(PASSWORD_SALT_LENGTH);

    /** Gatekeeper handle (serialized `password_handle_t`) */
    std::vector<u8> handle = {};

    /**
     * PIN length for autoconfirm; set to `PIN_LENGTH_UNAVAILABLE`
     * if PIN autoconfirm is not enabled
     * */
    i32 pin_length = PIN_LENGTH_UNAVAILABLE;

private:
    bool mDeserializationOk = false;
};

const char * toString(pwd_blob::credential_type ct);

} /* namespace auth */
} /* namespace cli */
} /* namespace suskeymaster */
