#pragma once

#include <core/int.h>
#include <libsuskmhal/suskmhal.hpp>
#include <vector>

namespace suskeymaster {
namespace cli {
namespace auth {

/**
 * A common wrapper for initializing and destroying AIDL and HIDL HAL instances,
 * meant for use here by the auth HAL wrappers (IGatekeeper and IWeaver).
 *
 * It tries to initialize an AIDL instance and, if that fails, falls back to HIDL.
 */
struct auth_hal {
protected:
    /**
     * Initializes a new HAL instance,
     * optionally pulling an existing binder device from `opt_kmhal`,
     *
     * first trying `<aidl_fqname>/<instname>` over AIDL,
     * and if that fails, `<hidl_fqname>/<instname>` over HIDL.
     *
     * Always check whether the initialization succeeded, with `is_ok`.
     *
     * @param aidl_fqname Fully qualified name of the AIDL HAL, e.g.
     *  "android.hardware.gatekeeper.IGatekeeper"
     *
     * @param hidl_fqname Fully qualified name of the HIDL HAL, e.g.
     *  "android.hardware.gatekeeper@1.0::IGatekeeper"
     *
     * @param instname Instance name of the HAL, assumed to be the same for both AIDL and HIDL,
     *  e.g. "default".
     *
     * @param opt_kmhal Optionally, a pointer to a Keymaster/KeyMint HAL from which to pull
     *  an existing binder device. If not provided, a new one will be initialized on the fly.
     *
     * Note: If provided, it's up to the user to ensure that the binder device in `opt_kmhal`
     * remains valid for the lifetime of this object.
     */
    explicit auth_hal(const char *aidl_fqname, const char *hidl_fqname, const char *instname,
                      kmhal::SusKMHal *opt_kmhal = nullptr);

public:
    /**
     * Destroys `hal_sp` if `owns == true`.
     */
    ~auth_hal();

    auth_hal(const auth_hal& other) {
        this->hal_sp = other.hal_sp;
        this->owns = false;
    }
    auth_hal& operator=(const auth_hal& other) {
        this->hal_sp = other.hal_sp;
        this->owns = false;
        return *this;
    }

    bool is_ok() const { return this->hal_sp != nullptr; }

    struct kmhal_sp * get_hal_sp() const { return this->hal_sp; }

private:
    struct kmhal_sp *hal_sp;
    bool owns;
};

/* See hardware/interfaces/gatekeeper/1.0/types.hal
 * and hardware/interfaces/gatekeeper/1.0/IGatekeeper.hal */

/**
 * Gatekeeper response codes; success >= 0; error < 0
 */
enum class GatekeeperStatusCode : i32 {
    /**
     * Success, but upper layers should re-enroll
     * the verified password due to a version change
     */
    STATUS_REENROLL         = INT32_C(1),

    /** Operation is successful */
    STATUS_OK               = INT32_C(0),

    /** Operation failed */
    ERROR_GENERAL_FAILURE   = INT32_C(-1),

    /** Operation should be retried after timeout */
    ERROR_RETRY_TIMEOUT     = INT32_C(-2),

    /** Operation is not implemented */
    ERROR_NOT_IMPLEMENTED   = INT32_C(-3)
};

/**
 * Gatekeeper response to enroll requests has this structure as mandatory part
 */
struct GatekeeperEnrollResponse {
    /**
     * Request completion status.
     */
    GatekeeperStatusCode code;

    /** Retry timeout in ms, if code == ERROR_RETRY_TIMEOUT otherwise unused (0) */
    u32 timeout;

    /** Secure user id. Unused in HIDL Gatekeeper. */
    u64 secureUserId;

    /** Optional crypto blob. Opaque to Android system. */
    std::vector<u8> data;
};

/**
 * Gatekeeper response to verify requests has this structure as mandatory part
 */
struct GatekeeperVerifyResponse {
    /**
     * Request completion status.
     */
    GatekeeperStatusCode code;

    /** Retry timeout in ms, if code == ERROR_RETRY_TIMEOUT otherwise unused (0) */
    u32 timeout;

    /**
     * On successful verification of the password,
     * IGatekeeper implementations must return hardware auth token
     * in the response.
     */
    kmhal::generic::HardwareAuthToken authToken;
};

/** Wrapper for the IGatekeeper HAL interface */
struct GatekeeperHAL : public auth_hal {
    /**
     * Attempts to initialize a Gatekeeper HAL instance.
     * AIDL is tried first, then HIDL.
     * Check with `is_ok` whether initialization succeeeded.
     *
     * @param opt_kmhal Optionally, a pointer to a Keymaster/KeyMint HAL from which to pull
     *  an existing binder device. If not provided, a new one will be initialized on the fly.
     *
     * Note: If provided, it's up to the user to ensure that the binder device in `opt_kmhal`
     * remains valid for the lifetime of this object.
     */
    explicit GatekeeperHAL(kmhal::SusKMHal *opt_kmhal = nullptr);

    /**
     * Enrolls desiredPassword, which may be derived from a user selected pin
     * or password, with the private key used only for enrolling authentication
     * factor data.
     *
     * If there was already a password enrolled, current password handle must be
     * passed in currentPasswordHandle, and current password must be passed in
     * currentPassword. Valid currentPassword must verify() against
     * currentPasswordHandle.
     *
     * @param uid The Android user identifier
     *
     * @param currentPasswordHandle The currently enrolled password handle the user
     *    wants to replace. May be empty only if there's no currently enrolled
     *    password. Otherwise must be non-empty.
     *
     * @param currentPassword The user's current password in plain text.
     *    it MUST verify against current_password_handle if the latter is not-empty
     *
     * @param desiredPassword The new password the user wishes to enroll in
     *    plaintext.
     *
     * @return response
     *    On success, data buffer must contain the new password handle referencing
     *    the password provided in desiredPassword.
     *    This buffer can be used on subsequent calls to enroll or
     *    verify. On error, this buffer must be empty.
     *    response.code must always contain operation completion status.
     *    This method may return ERROR_GENERAL_FAILURE or ERROR_RETRY_TIMEOUT on
     *    failure. It must return STATUS_OK on success.
     *    If ERROR_RETRY_TIMEOUT is returned, response.timeout must be non-zero.
     */
    GatekeeperEnrollResponse enroll(u32 uid, const std::vector<u8>& currentPasswordHandle,
                                    const std::vector<u8>& currentPassword,
                                    const std::vector<u8>& desiredPassword);

    /**
     * Verifies that providedPassword matches enrolledPasswordHandle.
     *
     * Implementations of this module may retain the result of this call
     * to attest to the recency of authentication.
     *
     * On success, returns verification token in response.data, which shall be
     * usable to attest password verification to other trusted services.
     *
     * @param uid The Android user identifier
     *
     * @param challenge An optional challenge to authenticate against, or 0.
     *    Used when a separate authenticator requests password verification,
     *    or for transactional password authentication.
     *
     * @param enrolledPasswordHandle The currently enrolled password handle that
     *    user wishes to verify against. Must be non-empty.
     *
     * @param providedPassword The plaintext password to be verified against the
     *    enrolledPasswordHandle
     *
     * @return response
     *    On success, a non-empty data buffer containing the
     *    authentication token resulting from this verification is returned.
     *    On error, data buffer must be empty.
     *    response.code must always contain operation completion status.
     *    This method may return ERROR_GENERAL_FAILURE or ERROR_RETRY_TIMEOUT on
     *    failure. It must return STATUS_OK on success.
     *    If password re-enrollment is necessary, it must return STATUS_REENROLL.
     *    If ERROR_RETRY_TIMEOUT is returned, response.timeout must be non-zero.
     */
    GatekeeperVerifyResponse verify(u32 uid, u64 challenge,
                                    const std::vector<u8>& enrolledPasswordHandle,
                                    const std::vector<u8>& providedPassword);

    /**
     * Deletes the enrolledPasswordHandle associated with the uid.
     * Once deleted the user cannot be verified anymore.
     * This is an optional method.
     *
     * @return:
     *  STATUS_OK if user is deleted successfully.
     *  ERROR_GENERAL_FAILURE on failure.
     *  ERROR_NOT_IMPLEMENTED if not implemented.
     *
     * @param uid The Android user identifier
     */
    GatekeeperStatusCode deleteUser(u32 uid);

    /**
     * Deletes all the enrolled_password_handles for all uid's.
     * Once called, no users must be enrolled on the device.
     * This is an optional method.
     *
     * @return:
     *  STATUS_OK if all the users are deleted successfully.
     *  ERROR_GENERAL_FAILURE on failure.
     *  ERROR_NOT_IMPLEMENTED if not implemented.
     */
    GatekeeperStatusCode deleteAllUsers(void);
};
const char * toString(GatekeeperStatusCode s);


/* See hardware/interfaces/weaver/1.0/types.hal
 * and hardware/interfaces/weaver/1.0/IWeaver.hal */

enum class WeaverStatus : u32 {
    OK                  = UINT32_C(0),
    FAILED              = UINT32_C(1),
    READ_INCORRECT_KEY  = UINT32_C(2),
    READ_THROTTLE       = UINT32_C(3)
};

struct WeaverConfig {
    /** The number of slots available. */
    u32 slots;

    /** The number of bytes used for a key. */
    u32 keySize;

    /** The number of bytes used for a value. */
    u32 valueSize;
};

struct WeaverReadResponse {
    /** The time to wait, in milliseconds, before making the next request. */
    u64 timeout;

    /** The value read from the slot or empty if the value was not read. */
    std::vector<u8> value;
};

/** Wrapper for the IWeaver HAL interface */
struct WeaverHAL : public auth_hal {
    /**
     * Attempts to initialize a Gatekeeper HAL instance.
     * AIDL is tried first, then HIDL.
     * Check with `is_ok` whether initialization succeeeded.
     *
     * @param opt_kmhal Optionally, a pointer to a Keymaster/KeyMint HAL from which to pull
     *  an existing binder device. If not provided, a new one will be initialized on the fly.
     *
     * Note: If provided, it's up to the user to ensure that the binder device in `opt_kmhal`
     * remains valid for the lifetime of this object.
     */
    explicit WeaverHAL(kmhal::SusKMHal *opt_kmhal = nullptr);

    /**
     * Retrieves the config information for this implementation of Weaver.
     * The config is static i.e. every invocation returns the same information.
     *
     * @param out_config Output reference for the data for this implementation of Weaver
     *  if status is OK, otherwise undefined.
     *
     * @return status is OK if the config was successfuly obtained.
     */
    WeaverStatus getConfig(WeaverConfig& out_config);

    /**
     * Overwrites the identified slot with the provided key and value.
     *
     * The new values are written regardless of the current state of the slot in
     * order to remain idempotent.
     *
     * @param slotId of the slot to write to.
     *
     * @param key to write to the slot.
     *
     * @param value to write to slot.
     *
     * @return status is OK if the write was successfully completed.
     */
    WeaverStatus write(u32 slotId, const std::vector<u8>& key, const std::vector<u8>& value);

    /**
     * Attempts to retrieve the value stored in the identified slot.
     *
     * The value is only returned if the provided key matches the key stored in
     * the slot. The value is never returned if the wrong key is provided.
     *
     * Throttling must be used to limit the frequency of failed read attempts.
     * The value is only returned when throttling is not active, even if the
     * correct key is provided. If called when throttling is active, the time
     * until the next attempt can be made is returned.
     *
     * @param slotId of the slot to read from.
     *
     * @param key that is stored in the slot.
     *
     * @return out_readResponse Output reference for the value read and the timeout to wait
     *         before making the next request. If the status is OK, value is set
     *         to the value in the slot and timeout is 0. Otherwise, value is
     *         empty and timeout is set accordingly.
     *
     * @return status is OK if the value was successfully read, INCORRECT_KEY if
     *         the key does not match the key in the slot, THROTTLE if
     *         throttling is active or FAILED if the read was unsuccessful for
     *         another reason.
     */
    WeaverStatus read(u32 slotId, const std::vector<u8>& key,
                      WeaverReadResponse& out_readResponse);
};
const char * toString(WeaverStatus s);

}; /* namespace auth */
}; /* namespace cli */
}; /* namespace suskeymaster */
