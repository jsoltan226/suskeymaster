#ifndef KEYMASTER_TYPES_H_
#define KEYMASTER_TYPES_H_

#include <stdint.h>
#include <stdbool.h>
#include <core/vector.h>
#include <string.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/crypto.h>
#include <openssl/safestack.h>

#ifdef __cplusplus
extern "C" {
namespace suskeymaster {
namespace kmhal {
namespace util {
#endif /* __cplusplus */

/**
 * Time in milliseconds since some arbitrary point in time.  Time must be monotonically increasing,
 * and a secure environment's notion of "current time" must not repeat until the Android device
 * reboots, or until at least 50 million years have elapsed (note that this requirement is satisfied
 * by setting the clock to zero during each boot, and then counting time accurately).
 */
typedef uint64_t KM_Timestamp;

/**
 * A place to define any needed constants.
 */
enum KM_Constants {
    KM_AUTH_TOKEN_MAC_LENGTH = 32u,
};

#define __KM_TAG_TYPE_MASK(tag) ((tag) & 0xF0000000)
#define __KM_TAG_MASK(tag) ((tag) & 0x0FFFFFFF)

enum KM_TagType {
    /**
     * Invalid type, used to designate a tag as uninitialized.
     */
    KM_TAG_TYPE_INVALID = 0u /* 0 << 28 */,
    /**
     * Enumeration value.
     */
    KM_TAG_TYPE_ENUM = 268435456u /* 1 << 28 */,
    /**
     * Repeatable enumeration value.
     */
    KM_TAG_TYPE_ENUM_REP = 536870912u /* 2 << 28 */,
    /**
     * 32-bit unsigned integer.
     */
    KM_TAG_TYPE_UINT = 805306368u /* 3 << 28 */,
    /**
     * Repeatable 32-bit unsigned integer.
     */
    KM_TAG_TYPE_UINT_REP = 1073741824u /* 4 << 28 */,
    /**
     * 64-bit unsigned integer.
     */
    KM_TAG_TYPE_ULONG = 1342177280u /* 5 << 28 */,
    /**
     * 64-bit unsigned integer representing a date and time, in milliseconds since 1 Jan 1970.
     */
    KM_TAG_TYPE_DATE = 1610612736u /* 6 << 28 */,
    /**
     * Boolean.  If a tag with this type is present, the value is "true".  If absent, "false".
     */
    KM_TAG_TYPE_BOOL = 1879048192u /* 7 << 28 */,
    /**
     * Byte string containing an arbitrary-length integer, big-endian ordering.
     */
    KM_TAG_TYPE_BIGNUM = 2147483648u /* 8 << 28 */,
    /**
     * Byte string
     */
    KM_TAG_TYPE_BYTES = 2415919104u /* 9 << 28 */,
    /**
     * Repeatable 64-bit unsigned integer
     */
    KM_TAG_TYPE_ULONG_REP = 2684354560u /* 10 << 28 */,
};

enum KM_Tag {
    KM_TAG_INVALID = 0u /* TagType:INVALID | 0 */,
    /**
     * Tag::PURPOSE specifies the set of purposes for which the key may be used.  Possible values
     * are defined in the KeyPurpose enumeration.
     *
     * This tag is repeatable; keys may be generated with multiple values, although an operation has
     * a single purpose.  When begin() is called to start an operation, the purpose of the operation
     * is specified.  If the purpose specified for the operation is not authorized by the key (the
     * key didn't have a corresponding Tag::PURPOSE provided during generation/import), the
     * operation must fail with ErrorCode::INCOMPATIBLE_PURPOSE.
     *
     * Must be hardware-enforced.
     */
    KM_TAG_PURPOSE = 536870913u /* TagType:ENUM_REP | 1 */,
    /**
     * Tag::ALGORITHM specifies the cryptographic algorithm with which the key is used.  This tag
     * must be provided to generateKey and importKey, and must be specified in the wrapped key
     * provided to importWrappedKey.
     *
     * Must be hardware-enforced.
     */
    KM_TAG_ALGORITHM = 268435458u /* TagType:ENUM | 2 */,
    /**
     * Tag::KEY_SIZE pecifies the size, in bits, of the key, measuring in the normal way for the
     * key's algorithm.  For example, for RSA keys, Tag::KEY_SIZE specifies the size of the public
     * modulus.  For AES keys it specifies the length of the secret key material.  For 3DES keys it
     * specifies the length of the key material, not counting parity bits (though parity bits must
     * be provided for import, etc.).  Since only three-key 3DES keys are supported, 3DES
     * Tag::KEY_SIZE must be 168.
     *
     * Must be hardware-enforced.
     */
    KM_TAG_KEY_SIZE = 805306371u /* TagType:UINT | 3 */,
    /**
     * Tag::BLOCK_MODE specifies the block cipher mode(s) with which the key may be used.  This tag
     * is only relevant to AES and 3DES keys.  Possible values are defined by the BlockMode enum.
     *
     * This tag is repeatable for key generation/import.  For AES and 3DES operations the caller
     * must specify a Tag::BLOCK_MODE in the additionalParams argument of begin().  If the mode is
     * missing or the specified mode is not in the modes specified for the key during
     * generation/import, the operation must fail with ErrorCode::INCOMPATIBLE_BLOCK_MODE.
     *
     * Must be hardware-enforced.
     */
    KM_TAG_BLOCK_MODE = 536870916u /* TagType:ENUM_REP | 4 */,
    /*
     * BlockMode.
     *
     *
     * Tag::DIGEST specifies the digest algorithms that may be used with the key to perform signing
     * and verification operations.  This tag is relevant to RSA, ECDSA and HMAC keys.  Possible
     * values are defined by the Digest enum.
     *
     * This tag is repeatable for key generation/import.  For signing and verification operations,
     * the caller must specify a digest in the additionalParams argument of begin().  If the digest
     * is missing or the specified digest is not in the digests associated with the key, the
     * operation must fail with ErrorCode::INCOMPATIBLE_DIGEST.
     *
     * Must be hardware-enforced.
     */
    KM_TAG_DIGEST = 536870917u /* TagType:ENUM_REP | 5 */,
    /**
     * Tag::PADDING specifies the padding modes that may be used with the key.  This tag is relevant
     * to RSA, AES and 3DES keys.  Possible values are defined by the PaddingMode enum.
     *
     * PaddingMode::RSA_OAEP and PaddingMode::RSA_PKCS1_1_5_ENCRYPT are used only for RSA
     * encryption/decryption keys and specify RSA OAEP padding and RSA PKCS#1 v1.5 randomized
     * padding, respectively.  PaddingMode::RSA_PSS and PaddingMode::RSA_PKCS1_1_5_SIGN are used
     * only for RSA signing/verification keys and specify RSA PSS padding and RSA PKCS#1 v1.5
     * deterministic padding, respectively.
     *
     * PaddingMode::NONE may be used with either RSA, AES or 3DES keys.  For AES or 3DES keys, if
     * PaddingMode::NONE is used with block mode ECB or CBC and the data to be encrypted or
     * decrypted is not a multiple of the AES block size in length, the call to finish() must fail
     * with ErrorCode::INVALID_INPUT_LENGTH.
     *
     * PaddingMode::PKCS7 may only be used with AES and 3DES keys, and only with ECB and CBC modes.
     *
     * In any case, if the caller specifies a padding mode that is not usable with the key's
     * algorithm, the generation or import method must return ErrorCode::INCOMPATIBLE_PADDING_MODE.
     *
     * This tag is repeatable.  A padding mode must be specified in the call to begin().  If the
     * specified mode is not authorized for the key, the operation must fail with
     * ErrorCode::INCOMPATIBLE_BLOCK_MODE.
     *
     * Must be hardware-enforced.
     */
    KM_TAG_PADDING = 536870918u /* TagType:ENUM_REP | 6 */,
    /**
     * Tag::CALLER_NONCE specifies that the caller can provide a nonce for nonce-requiring
     * operations.  This tag is boolean, so the possible values are true (if the tag is present) and
     * false (if the tag is not present).
     *
     * This tag is used only for AES and 3DES keys, and is only relevant for CBC, CTR and GCM block
     * modes.  If the tag is not present in a key's authorization list, implementations must reject
     * any operation that provides Tag::NONCE to begin() with ErrorCode::CALLER_NONCE_PROHIBITED.
     *
     * Must be hardware-enforced.
     */
    KM_TAG_CALLER_NONCE = 1879048199u /* TagType:BOOL | 7 */,
    /**
     * Tag::MIN_MAC_LENGTH specifies the minimum length of MAC that can be requested or verified
     * with this key for HMAC keys and AES keys that support GCM mode.
     *
     * This value is the minimum MAC length, in bits.  It must be a multiple of 8 bits.  For HMAC
     * keys, the value must be least 64 and no more than 512.  For GCM keys, the value must be at
     * least 96 and no more than 128.  If the provided value violates these requirements,
     * generateKey() or importKey() must return ErrorCode::UNSUPPORTED_KEY_SIZE.
     *
     * Must be hardware-enforced.
     */
    KM_TAG_MIN_MAC_LENGTH = 805306376u /* TagType:UINT | 8 */,
    /**
     * Tag::EC_CURVE specifies the elliptic curve.  EC key generation requests may have
     * Tag:EC_CURVE, Tag::KEY_SIZE, or both.  If both are provided and the size and curve do not
     * match, IKeymasterDevice must return ErrorCode::INVALID_ARGUMENT.
     *
     * Must be hardware-enforced.
     */
    KM_TAG_EC_CURVE = 268435466u /* TagType:ENUM | 10 */,
    /**
     * Tag::RSA_PUBLIC_EXPONENT specifies the value of the public exponent for an RSA key pair.
     * This tag is relevant only to RSA keys, and is required for all RSA keys.
     *
     * The value is a 64-bit unsigned integer that satisfies the requirements of an RSA public
     * exponent.  This value must be a prime number.  IKeymasterDevice implementations must support
     * the value 2^16+1 and may support other reasonable values.  If no exponent is specified or if
     * the specified exponent is not supported, key generation must fail with
     * ErrorCode::INVALID_ARGUMENT.
     *
     * Must be hardware-enforced.
     */
    KM_TAG_RSA_PUBLIC_EXPONENT = 1342177480u /* TagType:ULONG | 200 */,
    /**
     * Tag::INCLUDE_UNIQUE_ID is specified during key generation to indicate that an attestation
     * certificate for the generated key should contain an application-scoped and time-bounded
     * device-unique ID.  See Tag::UNIQUE_ID.
     *
     * Must be hardware-enforced.
     */
    KM_TAG_INCLUDE_UNIQUE_ID = 1879048394u /* TagType:BOOL | 202 */,
    /**
     * Tag::BLOB_USAGE_REQUIREMENTS specifies the necessary system environment conditions for the
     * generated key to be used.  Possible values are defined by the KeyBlobUsageRequirements enum.
     *
     * This tag is specified by the caller during key generation or import to require that the key
     * is usable in the specified condition.  If the caller specifies Tag::BLOB_USAGE_REQUIREMENTS
     * with value KeyBlobUsageRequirements::STANDALONE the IKeymasterDevice must return a key blob
     * that can be used without file system support.  This is critical for devices with encrypted
     * disks, where the file system may not be available until after a Keymaster key is used to
     * decrypt the disk.
     *
     * Must be hardware-enforced.
     */
    KM_TAG_BLOB_USAGE_REQUIREMENTS = 268435757u /* TagType:ENUM | 301 */,
    /**
     * Tag::BOOTLOADER_ONLY specifies only the bootloader can use the key.
     *
     * Any attempt to use a key with Tag::BOOTLOADER_ONLY from the Android system must fail with
     * ErrorCode::INVALID_KEY_BLOB.
     *
     * Must be hardware-enforced.
     */
    KM_TAG_BOOTLOADER_ONLY = 1879048494u /* TagType:BOOL | 302 */,
    /**
     * Tag::ROLLBACK_RESISTANCE specifies that the key has rollback resistance, meaning that when
     * deleted with deleteKey() or deleteAllKeys(), the key is guaranteed to be permanently deleted
     * and unusable.  It's possible that keys without this tag could be deleted and then restored
     * from backup.
     *
     * This tag is specified by the caller during key generation or import to require.  If the
     * IKeymasterDevice cannot guarantee rollback resistance for the specified key, it must return
     * ErrorCode::ROLLBACK_RESISTANCE_UNAVAILABLE.  IKeymasterDevice implementations are not
     * required to support rollback resistance.
     *
     * Must be hardwared-enforced.
     */
    KM_TAG_ROLLBACK_RESISTANCE = 1879048495u /* TagType:BOOL | 303 */,
    KM_TAG_HARDWARE_TYPE = 268435760u /* TagType:ENUM | 304 */,
    /**
     * Tag::ACTIVE_DATETIME specifies the date and time at which the key becomes active, in
     * milliseconds since Jan 1, 1970.  If a key with this tag is used prior to the specified date
     * and time, IKeymasterDevice::begin() must return ErrorCode::KEY_NOT_YET_VALID;
     *
     * Need not be hardware-enforced.
     */
    KM_TAG_ACTIVE_DATETIME = 1610613136u /* TagType:DATE | 400 */,
    /*
     * Start of validity.
     *
     *
     * Tag::ORIGINATION_EXPIRE_DATETIME specifies the date and time at which the key expires for
     * signing and encryption purposes.  After this time, any attempt to use a key with
     * KeyPurpose::SIGN or KeyPurpose::ENCRYPT provided to begin() must fail with
     * ErrorCode::KEY_EXPIRED.
     *
     * The value is a 64-bit integer representing milliseconds since January 1, 1970.
     *
     * Need not be hardware-enforced.
     */
    KM_TAG_ORIGINATION_EXPIRE_DATETIME = 1610613137u /* TagType:DATE | 401 */,
    /**
     * Tag::USAGE_EXPIRE_DATETIME specifies the date and time at which the key expires for
     * verification and decryption purposes.  After this time, any attempt to use a key with
     * KeyPurpose::VERIFY or KeyPurpose::DECRYPT provided to begin() must fail with
     * ErrorCode::KEY_EXPIRED.
     *
     * The value is a 64-bit integer representing milliseconds since January 1, 1970.
     *
     * Need not be hardware-enforced.
     */
    KM_TAG_USAGE_EXPIRE_DATETIME = 1610613138u /* TagType:DATE | 402 */,
    /**
     * Tag::MIN_SECONDS_BETWEEN_OPS specifies the minimum amount of time that elapses between
     * allowed operations using a key.  This can be used to rate-limit uses of keys in contexts
     * where unlimited use may enable brute force attacks.
     *
     * The value is a 32-bit integer representing seconds between allowed operations.
     *
     * When a key with this tag is used in an operation, the IKeymasterDevice must start a timer
     * during the finish() or abort() call.  Any call to begin() that is received before the timer
     * indicates that the interval specified by Tag::MIN_SECONDS_BETWEEN_OPS has elapsed must fail
     * with ErrorCode::KEY_RATE_LIMIT_EXCEEDED.  This implies that the IKeymasterDevice must keep a
     * table of use counters for keys with this tag.  Because memory is often limited, this table
     * may have a fixed maximum size and Keymaster may fail operations that attempt to use keys with
     * this tag when the table is full.  The table must acommodate at least 8 in-use keys and
     * aggressively reuse table slots when key minimum-usage intervals expire.  If an operation
     * fails because the table is full, Keymaster returns ErrorCode::TOO_MANY_OPERATIONS.
     *
     * Must be hardware-enforced.
     */
    KM_TAG_MIN_SECONDS_BETWEEN_OPS = 805306771u /* TagType:UINT | 403 */,
    /**
     * Tag::MAX_USES_PER_BOOT specifies the maximum number of times that a key may be used between
     * system reboots.  This is another mechanism to rate-limit key use.
     *
     * The value is a 32-bit integer representing uses per boot.
     *
     * When a key with this tag is used in an operation, a key-associated counter must be
     * incremented during the begin() call.  After the key counter has exceeded this value, all
     * subsequent attempts to use the key must fail with ErrorCode::MAX_OPS_EXCEEDED, until the
     * device is restarted.  This implies that the IKeymasterDevice must keep a table of use
     * counters for keys with this tag.  Because Keymaster memory is often limited, this table can
     * have a fixed maximum size and Keymaster can fail operations that attempt to use keys with
     * this tag when the table is full.  The table needs to acommodate at least 8 keys.  If an
     * operation fails because the table is full, IKeymasterDevice must
     * ErrorCode::TOO_MANY_OPERATIONS.
     *
     * Must be hardware-enforced.
     */
    KM_TAG_MAX_USES_PER_BOOT = 805306772u /* TagType:UINT | 404 */,
    /**
     * Tag::USER_ID specifies the ID of the Android user that is permitted to use the key.
     *
     * Must not be hardware-enforced.
     */
    KM_TAG_USER_ID = 805306869u /* TagType:UINT | 501 */,
    /**
     * Tag::USER_SECURE_ID specifies that a key may only be used under a particular secure user
     * authentication state.  This tag is mutually exclusive with Tag::NO_AUTH_REQUIRED.
     *
     * The value is a 64-bit integer specifying the authentication policy state value which must be
     * present in the userId or authenticatorId field of a HardwareAuthToken provided to begin(),
     * update(), or finish().  If a key with Tag::USER_SECURE_ID is used without a HardwareAuthToken
     * with the matching userId or authenticatorId, the IKeymasterDevice must return
     * ErrorCode::KEY_USER_NOT_AUTHENTICATED.
     *
     * Tag::USER_SECURE_ID interacts with Tag::AUTH_TIMEOUT in a very important way.  If
     * Tag::AUTH_TIMEOUT is present in the key's characteristics then the key is a "timeout-based"
     * key, and may only be used if the difference between the current time when begin() is called
     * and the timestamp in the HardwareAuthToken is less than the value in Tag::AUTH_TIMEOUT * 1000
     * (the multiplier is because Tag::AUTH_TIMEOUT is in seconds, but the HardwareAuthToken
     * timestamp is in milliseconds).  Otherwise the IKeymasterDevice must returrn
     * ErrorCode::KEY_USER_NOT_AUTHENTICATED.
     *
     * If Tag::AUTH_TIMEOUT is not present, then the key is an "auth-per-operation" key.  In this
     * case, begin() must not require a HardwareAuthToken with appropriate contents.  Instead,
     * update() and finish() must receive a HardwareAuthToken with Tag::USER_SECURE_ID value in
     * userId or authenticatorId fields, and the current operation's operation handle in the
     * challenge field.  Otherwise the IKeymasterDevice must returrn
     * ErrorCode::KEY_USER_NOT_AUTHENTICATED.
     *
     * This tag is repeatable.  If repeated, and any one of the values matches the HardwareAuthToken
     * as described above, the key is authorized for use.  Otherwise the operation must fail with
     * ErrorCode::KEY_USER_NOT_AUTHENTICATED.
     *
     * Must be hardware-enforced.
     */
    KM_TAG_USER_SECURE_ID = 2684355062u /* TagType:ULONG_REP | 502 */,
    /*
     * Secure ID of authorized user or authenticator(s).
     * Disallowed if NO_AUTH_REQUIRED is present.
     *
     *
     * Tag::NO_AUTH_REQUIRED specifies that no authentication is required to use this key.  This tag
     * is mutually exclusive with Tag::USER_SECURE_ID.
     *
     * Must be hardware-enforced.
     */
    KM_TAG_NO_AUTH_REQUIRED = 1879048695u /* TagType:BOOL | 503 */,
    /*
     * If key is usable without authentication.
     *
     *
     * Tag::USER_AUTH_TYPE specifies the types of user authenticators that may be used to authorize
     * this key.
     *
     * The value is one or more values from HardwareAuthenticatorType, ORed together.
     *
     * When IKeymasterDevice is requested to perform an operation with a key with this tag, it must
     * receive a HardwareAuthToken and one or more bits must be set in both the HardwareAuthToken's
     * authenticatorType field and the Tag::USER_AUTH_TYPE value.  That is, it must be true that
     *
     *    (token.authenticatorType & tag_user_auth_type) != 0
     *
     * where token.authenticatorType is the authenticatorType field of the HardwareAuthToken and
     * tag_user_auth_type is the value of Tag:USER_AUTH_TYPE.
     *
     * Must be hardware-enforced.
     */
    KM_TAG_USER_AUTH_TYPE = 268435960u /* TagType:ENUM | 504 */,
    /**
     * Tag::AUTH_TIMEOUT specifies the time in seconds for which the key is authorized for use,
     * after user authentication.  If
     * Tag::USER_SECURE_ID is present and this tag is not, then the key requies authentication for
     * every usage (see begin() for the details of the authentication-per-operation flow).
     *
     * The value is a 32-bit integer specifying the time in seconds after a successful
     * authentication of the user specified by Tag::USER_SECURE_ID with the authentication method
     * specified by Tag::USER_AUTH_TYPE that the key can be used.
     *
     * Must be hardware-enforced.
     */
    KM_TAG_AUTH_TIMEOUT = 805306873u /* TagType:UINT | 505 */,
    /**
     * Tag::ALLOW_WHILE_ON_BODY specifies that the key may be used after authentication timeout if
     * device is still on-body (requires on-body sensor).
     *
     * Cannot be hardware-enforced.
     */
    KM_TAG_ALLOW_WHILE_ON_BODY = 1879048698u /* TagType:BOOL | 506 */,
    /**
     * TRUSTED_USER_PRESENCE_REQUIRED is an optional feature that specifies that this key must be
     * unusable except when the user has provided proof of physical presence.  Proof of physical
     * presence must be a signal that cannot be triggered by an attacker who doesn't have one of:
     *
     *    a) Physical control of the device or
     *
     *    b) Control of the secure environment that holds the key.
     *
     * For instance, proof of user identity may be considered proof of presence if it meets the
     * requirements.  However, proof of identity established in one security domain (e.g. TEE) does
     * not constitute proof of presence in another security domain (e.g. StrongBox), and no
     * mechanism analogous to the authentication token is defined for communicating proof of
     * presence across security domains.
     *
     * Some examples:
     *
     *     A hardware button hardwired to a pin on a StrongBox device in such a way that nothing
     *     other than a button press can trigger the signal constitutes proof of physical presence
     *     for StrongBox keys.
     *
     *     Fingerprint authentication provides proof of presence (and identity) for TEE keys if the
     *     TEE has exclusive control of the fingerprint scanner and performs fingerprint matching.
     *
     *     Password authentication does not provide proof of presence to either TEE or StrongBox,
     *     even if TEE or StrongBox does the password matching, because password input is handled by
     *     the non-secure world, which means an attacker who has compromised Android can spoof
     *     password authentication.
     *
     * Note that no mechanism is defined for delivering proof of presence to an IKeymasterDevice,
     * except perhaps as implied by an auth token.  This means that Keymaster must be able to check
     * proof of presence some other way.  Further, the proof of presence must be performed between
     * begin() and the first call to update() or finish().  If the first update() or the finish()
     * call is made without proof of presence, the keymaster method must return
     * ErrorCode::PROOF_OF_PRESENCE_REQUIRED and abort the operation.  The caller must delay the
     * update() or finish() call until proof of presence has been provided, which means the caller
     * must also have some mechanism for verifying that the proof has been provided.
     *
     * Only one operation requiring TUP may be in flight at a time.  If begin() has already been
     * called on one key with TRUSTED_USER_PRESENCE_REQUIRED, and another begin() comes in for that
     * key or another with TRUSTED_USER_PRESENCE_REQUIRED, Keymaster must return
     * ErrorCode::CONCURRENT_PROOF_OF_PRESENCE_REQUESTED.
     *
     * Must be hardware-enforced.
     */
    KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED = 1879048699u /* TagType:BOOL | 507 */,
    /**
     * Tag::TRUSTED_CONFIRMATION_REQUIRED is only applicable to keys with KeyPurpose SIGN, and
     *  specifies that this key must not be usable unless the user provides confirmation of the data
     *  to be signed.  Confirmation is proven to keymaster via an approval token.  See
     *  CONFIRMATION_TOKEN, as well as the ConfirmatinUI HAL.
     *
     * If an attempt to use a key with this tag does not have a cryptographically valid
     * CONFIRMATION_TOKEN provided to finish() or if the data provided to update()/finish() does not
     * match the data described in the token, keymaster must return NO_USER_CONFIRMATION.
     *
     * Must be hardware-enforced.
     */
    KM_TAG_TRUSTED_CONFIRMATION_REQUIRED = 1879048700u /* TagType:BOOL | 508 */,
    /**
     * Tag::UNLOCKED_DEVICE_REQUIRED specifies that the key may only be used when the device is
     * unlocked.
     *
     * Must be software-enforced.
     */
    KM_TAG_UNLOCKED_DEVICE_REQUIRED = 1879048701u /* TagType:BOOL | 509 */,
    /**
     * Tag::APPLICATION_ID.  When provided to generateKey or importKey, this tag specifies data
     * that is necessary during all uses of the key.  In particular, calls to exportKey() and
     * getKeyCharacteristics() must provide the same value to the clientId parameter, and calls to
     * begin must provide this tag and the same associated data as part of the inParams set.  If
     * the correct data is not provided, the method must return ErrorCode::INVALID_KEY_BLOB.
     *
     * The content of this tag must be bound to the key cryptographically, meaning it must not be
     * possible for an adversary who has access to all of the secure world secrets but does not have
     * access to the tag content to decrypt the key without brute-forcing the tag content, which
     * applications can prevent by specifying sufficiently high-entropy content.
     *
     * Must never appear in KeyCharacteristics.
     */
    KM_TAG_APPLICATION_ID = 2415919705u /* TagType:BYTES | 601 */,
    /*
     * Semantically unenforceable tags, either because they have no specific meaning or because
     * they're informational only.
     *
     *
     * Tag::APPLICATION_DATA.  When provided to generateKey or importKey, this tag specifies data
     * that is necessary during all uses of the key.  In particular, calls to exportKey() and
     * getKeyCharacteristics() must provide the same value to the appData parameter, and calls to
     * begin must provide this tag and the same associated data as part of the inParams set.  If
     * the correct data is not provided, the method must return ErrorCode::INVALID_KEY_BLOB.
     *
     * The content of this tag msut be bound to the key cryptographically, meaning it must not be
     * possible for an adversary who has access to all of the secure world secrets but does not have
     * access to the tag content to decrypt the key without brute-forcing the tag content, which
     * applications can prevent by specifying sufficiently high-entropy content.
     *
     * Must never appear in KeyCharacteristics.
     */
    KM_TAG_APPLICATION_DATA = 2415919804u /* TagType:BYTES | 700 */,
    /**
     * Tag::CREATION_DATETIME specifies the date and time the key was created, in milliseconds since
     * January 1, 1970.  This tag is optional and informational only.
     *
     * Tag::CREATED is informational only, and not enforced by anything.  Must be in the
     * software-enforced list, if provided.
     */
    KM_TAG_CREATION_DATETIME = 1610613437u /* TagType:DATE | 701 */,
    /**
     * Tag::ORIGIN specifies where the key was created, if known.  This tag must not be specified
     * during key generation or import, and must be added to the key characteristics by the
     * IKeymasterDevice.  The possible values are defined in the KeyOrigin enum.
     *
     * Must be hardware-enforced.
     */
    KM_TAG_ORIGIN = 268436158u /* TagType:ENUM | 702 */,
    /**
     * Tag::ROOT_OF_TRUST specifies the root of trust, the key used by verified boot to validate the
     * operating system booted (if any).  This tag is never provided to or returned from Keymaster
     * in the key characteristics.  It exists only to define the tag for use in the attestation
     * record.
     *
     * Must never appear in KeyCharacteristics.
     */
    KM_TAG_ROOT_OF_TRUST = 2415919808u /* TagType:BYTES | 704 */,
    /**
     * Tag::OS_VERSION specifies the system OS version with which the key may be used.  This tag is
     * never sent to the IKeymasterDevice, but is added to the hardware-enforced authorization list
     * by the TA.  Any attempt to use a key with a Tag::OS_VERSION value different from the
     * currently-running OS version must cause begin(), getKeyCharacteristics() or exportKey() to
     * return ErrorCode::KEY_REQUIRES_UPGRADE.  See upgradeKey() for details.
     *
     * The value of the tag is an integer of the form MMmmss, where MM is the major version number,
     * mm is the minor version number, and ss is the sub-minor version number.  For example, for a
     * key generated on Android version 4.0.3, the value would be 040003.
     *
     * The IKeymasterDevice HAL must read the current OS version from the system property
     * ro.build.version.release and deliver it to the secure environment when the HAL is first
     * loaded (mechanism is implementation-defined).  The secure environment must not accept another
     * version until after the next boot.  If the content of ro.build.version.release has additional
     * version information after the sub-minor version number, it must not be included in
     * Tag::OS_VERSION.  If the content is non-numeric, the secure environment must use 0 as the
     * system version.
     *
     * Must be hardware-enforced.
     */
    KM_TAG_OS_VERSION = 805307073u /* TagType:UINT | 705 */,
    /**
     * Tag::OS_PATCHLEVEL specifies the system security patch level with which the key may be used.
     * This tag is never sent to the keymaster TA, but is added to the hardware-enforced
     * authorization list by the TA.  Any attempt to use a key with a Tag::OS_PATCHLEVEL value
     * different from the currently-running system patchlevel must cause begin(),
     * getKeyCharacteristics() or exportKey() to return ErrorCode::KEY_REQUIRES_UPGRADE.  See
     * upgradeKey() for details.
     *
     * The value of the tag is an integer of the form YYYYMM, where YYYY is the four-digit year of
     * the last update and MM is the two-digit month of the last update.  For example, for a key
     * generated on an Android device last updated in December 2015, the value would be 201512.
     *
     * The IKeymasterDevice HAL must read the current system patchlevel from the system property
     * ro.build.version.security_patch and deliver it to the secure environment when the HAL is
     * first loaded (mechanism is implementation-defined).  The secure environment must not accept
     * another patchlevel until after the next boot.
     *
     * Must be hardware-enforced.
     */
    KM_TAG_OS_PATCHLEVEL = 805307074u /* TagType:UINT | 706 */,
    /**
     * Tag::UNIQUE_ID specifies a unique, time-based identifier.  This tag is never provided to or
     * returned from Keymaster in the key characteristics.  It exists only to define the tag for use
     * in the attestation record.
     *
     * When a key with Tag::INCLUDE_UNIQUE_ID is attested, the unique ID is added to the attestation
     * record.  The value is a 128-bit hash that is unique per device and per calling application,
     * and changes monthly and on most password resets.  It is computed with:
     *
     *    HMAC_SHA256(T || C || R, HBK)
     *
     * Where:
     *
     *    T is the "temporal counter value", computed by dividing the value of
     *      Tag::CREATION_DATETIME by 2592000000, dropping any remainder.  T changes every 30 days
     *      (2592000000 = 30 * 24 * 60 * 60 * 1000).
     *
     *    C is the value of Tag::ATTESTATION_APPLICATION_ID that is provided to attestKey().
     *
     *    R is 1 if Tag::RESET_SINCE_ID_ROTATION was provided to attestKey or 0 if the tag was not
     *      provided.
     *
     *    HBK is a unique hardware-bound secret known to the secure environment and never revealed
     *    by it.  The secret must contain at least 128 bits of entropy and be unique to the
     *    individual device (probabilistic uniqueness is acceptable).
     *
     *    HMAC_SHA256 is the HMAC function, with SHA-2-256 as the hash.
     *
     * The output of the HMAC function must be truncated to 128 bits.
     *
     * Must be hardware-enforced.
     */
    KM_TAG_UNIQUE_ID = 2415919811u /* TagType:BYTES | 707 */,
    /**
     * Tag::ATTESTATION_CHALLENGE is used to deliver a "challenge" value to the attestKey() method,
     * which must place the value in the KeyDescription SEQUENCE of the attestation extension.  See
     * attestKey().
     *
     * Must never appear in KeyCharacteristics.
     */
    KM_TAG_ATTESTATION_CHALLENGE = 2415919812u /* TagType:BYTES | 708 */,
    /*
     * Used to provide challenge in attestation
     *
     *
     * Tag::ATTESTATION_APPLICATION_ID identifies the set of applications which may use a key, used
     * only with attestKey().
     *
     * The content of Tag::ATTESTATION_APPLICATION_ID is a DER-encoded ASN.1 structure, with the
     * following schema:
     *
     * AttestationApplicationId ::= SEQUENCE {
     *     packageInfoRecords SET OF PackageInfoRecord,
     *     signatureDigests   SET OF OCTET_STRING,
     * }
     *
     * PackageInfoRecord ::= SEQUENCE {
     *     packageName        OCTET_STRING,
     *     version            INTEGER,
     * }
     *
     * See system/security/keystore/keystore_attestation_id.cpp for details of construction.
     * IKeymasterDevice implementers do not need to create or parse the ASN.1 structure, but only
     * copy the tag value into the attestation record.  The DER-encoded string must not exceed 1 KiB
     * in length.
     *
     * Cannot be hardware-enforced.
     */
    KM_TAG_ATTESTATION_APPLICATION_ID = 2415919813u /* TagType:BYTES | 709 */,
    /**
     * Tag::ATTESTATION_ID_BRAND provides the device's brand name, as returned by Build.BRAND in
     * Android, to attestKey().  This field must be set only when requesting attestation of the
     * device's identifiers.
     *
     * If the device does not support ID attestation (or destroyAttestationIds() was previously
     * called and the device can no longer attest its IDs), any key attestation request that
     * includes this tag must fail with ErrorCode::CANNOT_ATTEST_IDS.
     *
     * Must never appear in KeyCharacteristics.
     */
    KM_TAG_ATTESTATION_ID_BRAND = 2415919814u /* TagType:BYTES | 710 */,
    /**
     * Tag::ATTESTATION_ID_DEVICE provides the device's device name, as returned by Build.DEVICE in
     * Android, to attestKey().  This field must be set only when requesting attestation of the
     * device's identifiers.
     *
     * If the device does not support ID attestation (or destroyAttestationIds() was previously
     * called and the device can no longer attest its IDs), any key attestation request that
     * includes this tag must fail with ErrorCode::CANNOT_ATTEST_IDS.
     *
     * Must never appear in KeyCharacteristics.
     */
    KM_TAG_ATTESTATION_ID_DEVICE = 2415919815u /* TagType:BYTES | 711 */,
    /**
     * Tag::ATTESTATION_ID_PRODUCT provides the device's product name, as returned by Build.PRODUCT
     * in Android, to attestKey().  This field must be set only when requesting attestation of the
     * device's identifiers.
     *
     * If the device does not support ID attestation (or destroyAttestationIds() was previously
     * called and the device can no longer attest its IDs), any key attestation request that
     * includes this tag must fail with ErrorCode::CANNOT_ATTEST_IDS.
     *
     * Must never appear in KeyCharacteristics.
     */
    KM_TAG_ATTESTATION_ID_PRODUCT = 2415919816u /* TagType:BYTES | 712 */,
    /**
     * Tag::ATTESTATION_ID_SERIAL the device's serial number.  This field must be set only when
     * requesting attestation of the device's identifiers.
     *
     * If the device does not support ID attestation (or destroyAttestationIds() was previously
     * called and the device can no longer attest its IDs), any key attestation request that
     * includes this tag must fail with ErrorCode::CANNOT_ATTEST_IDS.
     *
     * Must never appear in KeyCharacteristics.
     */
    KM_TAG_ATTESTATION_ID_SERIAL = 2415919817u /* TagType:BYTES | 713 */,
    /**
     * Tag::ATTESTATION_ID_IMEI provides the IMEIs for all radios on the device to attestKey().
     * This field must be set only when requesting attestation of the device's identifiers.
     *
     * If the device does not support ID attestation (or destroyAttestationIds() was previously
     * called and the device can no longer attest its IDs), any key attestation request that
     * includes this tag must fail with ErrorCode::CANNOT_ATTEST_IDS.
     *
     * Must never appear in KeyCharacteristics.
     */
    KM_TAG_ATTESTATION_ID_IMEI = 2415919818u /* TagType:BYTES | 714 */,
    /*
     * Used to provide the device's IMEI to be included
     * in attestation
     *
     *
     * Tag::ATTESTATION_ID_MEID provides the MEIDs for all radios on the device to attestKey().
     * This field must be set only when requesting attestation of the device's identifiers.
     *
     * If the device does not support ID attestation (or destroyAttestationIds() was previously
     * called and the device can no longer attest its IDs), any key attestation request that
     * includes this tag must fail with ErrorCode::CANNOT_ATTEST_IDS.
     *
     * Must never appear in KeyCharacteristics.
     */
    KM_TAG_ATTESTATION_ID_MEID = 2415919819u /* TagType:BYTES | 715 */,
    /*
     * Used to provide the device's MEID to be included
     * in attestation
     *
     *
     * Tag::ATTESTATION_ID_MANUFACTURER provides the device's manufacturer name, as returned by
     * Build.MANUFACTURER in Android, to attstKey().  This field must be set only when requesting
     * attestation of the device's identifiers.
     *
     * If the device does not support ID attestation (or destroyAttestationIds() was previously
     * called and the device can no longer attest its IDs), any key attestation request that
     * includes this tag must fail with ErrorCode::CANNOT_ATTEST_IDS.
     *
     * Must never appear in KeyCharacteristics.
     */
    KM_TAG_ATTESTATION_ID_MANUFACTURER = 2415919820u /* TagType:BYTES | 716 */,
    /**
     * Tag::ATTESTATION_ID_MODEL provides the device's model name, as returned by Build.MODEL in
     * Android, to attestKey().  This field must be set only when requesting attestation of the
     * device's identifiers.
     *
     * If the device does not support ID attestation (or destroyAttestationIds() was previously
     * called and the device can no longer attest its IDs), any key attestation request that
     * includes this tag must fail with ErrorCode::CANNOT_ATTEST_IDS.
     *
     * Must never appear in KeyCharacteristics.
     */
    KM_TAG_ATTESTATION_ID_MODEL = 2415919821u /* TagType:BYTES | 717 */,
    /**
     * Tag::VENDOR_PATCHLEVEL specifies the vendor image security patch level with which the key may
     * be used.  This tag is never sent to the keymaster TA, but is added to the hardware-enforced
     * authorization list by the TA.  Any attempt to use a key with a Tag::VENDOR_PATCHLEVEL value
     * different from the currently-running system patchlevel must cause begin(),
     * getKeyCharacteristics() or exportKey() to return ErrorCode::KEY_REQUIRES_UPGRADE.  See
     * upgradeKey() for details.
     *
     * The value of the tag is an integer of the form YYYYMMDD, where YYYY is the four-digit year of
     * the last update, MM is the two-digit month and DD is the two-digit day of the last
     * update.  For example, for a key generated on an Android device last updated on June 5, 2018,
     * the value would be 20180605.
     *
     * The IKeymasterDevice HAL must read the current vendor patchlevel from the system property
     * ro.vendor.build.security_patch and deliver it to the secure environment when the HAL is first
     * loaded (mechanism is implementation-defined).  The secure environment must not accept another
     * patchlevel until after the next boot.
     *
     * Must be hardware-enforced.
     */
    KM_TAG_VENDOR_PATCHLEVEL = 805307086u /* TagType:UINT | 718 */,
    /**
     * Tag::BOOT_PATCHLEVEL specifies the boot image (kernel) security patch level with which the
     * key may be used.  This tag is never sent to the keymaster TA, but is added to the
     * hardware-enforced authorization list by the TA.  Any attempt to use a key with a
     * Tag::BOOT_PATCHLEVEL value different from the currently-running system patchlevel must
     * cause begin(), getKeyCharacteristics() or exportKey() to return
     * ErrorCode::KEY_REQUIRES_UPGRADE.  See upgradeKey() for details.
     *
     * The value of the tag is an integer of the form YYYYMMDD, where YYYY is the four-digit year of
     * the last update, MM is the two-digit month and DD is the two-digit day of the last
     * update.  For example, for a key generated on an Android device last updated on June 5, 2018,
     * the value would be 20180605.  If the day is not known, 00 may be substituted.
     *
     * During each boot, the bootloader must provide the patch level of the boot image to the secure
     * envirionment (mechanism is implementation-defined).
     *
     * Must be hardware-enforced.
     */
    KM_TAG_BOOT_PATCHLEVEL = 805307087u /* TagType:UINT | 719 */,
    /**
     * Tag::ASSOCIATED_DATA Provides "associated data" for AES-GCM encryption or decryption.  This
     * tag is provided to update and specifies data that is not encrypted/decrypted, but is used in
     * computing the GCM tag.
     *
     * Must never appear KeyCharacteristics.
     */
    KM_TAG_ASSOCIATED_DATA = 2415920104u /* TagType:BYTES | 1000 */,
    /**
     * Tag::NONCE is used to provide or return a nonce or Initialization Vector (IV) for AES-GCM,
     * AES-CBC, AES-CTR, or 3DES-CBC encryption or decryption.  This tag is provided to begin during
     * encryption and decryption operations.  It is only provided to begin if the key has
     * Tag::CALLER_NONCE.  If not provided, an appropriate nonce or IV must be randomly generated by
     * Keymaster and returned from begin.
     *
     * The value is a blob, an arbitrary-length array of bytes.  Allowed lengths depend on the mode:
     * GCM nonces are 12 bytes in length; AES-CBC and AES-CTR IVs are 16 bytes in length, 3DES-CBC
     * IVs are 8 bytes in length.
     *
     * Must never appear in KeyCharacteristics.
     */
    KM_TAG_NONCE = 2415920105u /* TagType:BYTES | 1001 */,
    /**
     * Tag::MAC_LENGTH provides the requested length of a MAC or GCM authentication tag, in bits.
     *
     * The value is the MAC length in bits.  It must be a multiple of 8 and at least as large as the
     * value of Tag::MIN_MAC_LENGTH associated with the key.  Otherwise, begin() must return
     * ErrorCode::INVALID_MAC_LENGTH.
     *
     * Must never appear in KeyCharacteristics.
     */
    KM_TAG_MAC_LENGTH = 805307371u /* TagType:UINT | 1003 */,
    /**
     * Tag::RESET_SINCE_ID_ROTATION specifies whether the device has been factory reset since the
     * last unique ID rotation.  Used for key attestation.
     *
     * Must never appear in KeyCharacteristics.
     */
    KM_TAG_RESET_SINCE_ID_ROTATION = 1879049196u /* TagType:BOOL | 1004 */,
    /**
     * Tag::CONFIRMATION_TOKEN is used to deliver a cryptographic token proving that the user
     * confirmed a signing request.  The content is a full-length HMAC-SHA256 value.  See the
     * ConfirmationUI HAL for details of token computation.
     *
     * Must never appear in KeyCharacteristics.
     */
    KM_TAG_CONFIRMATION_TOKEN = 2415920109u /* TagType:BYTES | 1005 */,

    /*** SAMSUNG-SPECIFIC KEYMASTER TAGS ***/

    /** Tags missing from the core spec? **/

    /* Stores a user authentication token for operations that require it */
    KM_TAG_AUTH_TOKEN = KM_TAG_TYPE_BYTES | 1002u,

    /* Used in the `computeSharedHmac` operation (stores the HMAC verification token SEQUENCE) */
    KM_TAG_VERIFICATION_TOKEN = KM_TAG_TYPE_BYTES | 5200u,

    /* Internal tag idicating that all users can use a given key.
     * Treated similarly to Tag::NO_AUTH_REQUIRED. */
    KM_TAG_ALL_USERS = KM_TAG_TYPE_BOOL | 500u,

    KM_TAG_ECIES_SINGLE_HASH_MODE = KM_TAG_TYPE_BOOL | 201u,

    /* Stores a Key Derivation Function type (see `enum KeyDerivationFunction`). */
    KM_TAG_KDF = KM_TAG_TYPE_ENUM_REP | 9u,

    /* Tag indicating that the key is exportable. Valid only for symmetric keys. */
    KM_TAG_EXPORTABLE = KM_TAG_TYPE_BOOL | 602u,

    /** KM Operation tags **/

    /* An internal parameter tag indicating that the key requires authentication.
     * Set if any of the following tags are present in the key description:
     *  SamsungTag::AUTH_TOKEN, Tag::AUTH_TIMEOUT, Tag::USER_AUTH_TYPE, Tag::USER_SECURE_ID */
    KM_TAG_KEY_AUTH = KM_TAG_TYPE_BOOL | 5013u,

    /* An internal parameter tag indicating that the operation requires authentication.
     * Set if any of the following tags are present in the key description:
     *  Tag::AUTH_TIMEOUT, Tag::USER_SECURE_ID */
    KM_TAG_OP_AUTH = KM_TAG_TYPE_BOOL | 5012u,

    /* An internal tag that represents the operation handle returned by `begin()`
     * and used in `update()` and `finish()`. */
    KM_TAG_OPERATION_HANDLE = KM_TAG_TYPE_ULONG | 5011u,

    /* An internal tag indicating that an operation (`begin()`, `update()`, `finish()`)
     * has failed and should be cleaned up. */
    KM_TAG_OPERATION_FAILED = KM_TAG_TYPE_BOOL | 5030u,

    /* Used to validate datetime requirements in `begin()`,
     * tracks the `softwareEnforced` Tag::CREATION_DATETIME **/
    KM_TAG_INTERNAL_CURRENT_DATETIME = KM_TAG_TYPE_DATE | 800u,

    /* Added to the keyblob params alongside the standard *_PATCHLEVEL tags */
    KM_TAG_INTERNAL_OS_VERSION = KM_TAG_TYPE_UINT | 805,
    KM_TAG_INTERNAL_OS_PATCHLEVEL = KM_TAG_TYPE_UINT | 806,
    KM_TAG_INTERNAL_VENDOR_PATCHLEVEL = KM_TAG_TYPE_UINT | 818,

    /** Encrypted key blob serialization/deserialization related tags **/

    /* Initialization vector used for AES-256-GCM decryption,
     * typically stored in the outer keyblob in plain text */
    KM_TAG_EKEY_BLOB_IV = KM_TAG_TYPE_BYTES | 5000u,

    /* AES-256-GCM authentication tag, stored in the outer keyblob in plain text */
    KM_TAG_EKEY_BLOB_AUTH_TAG = KM_TAG_TYPE_BYTES | 5001u,

    /* Usage count tag used to enforce Tag:MAX_USES_PER_BOOT */
    KM_TAG_EKEY_BLOB_CURRENT_USES_PER_BOOT = KM_TAG_TYPE_UINT | 5003u,

    /* Time of last operation, used to enforce tags such as
     * Tag:MIN_SECONDS_BETWEEN_OPS and Tag:AUTH_TIMEOUT */
    KM_TAG_EKEY_BLOB_LAST_OP_TIMESTAMP = KM_TAG_TYPE_ULONG | 5004u,

    /* A flag indicating that the encrypted key blob should be upgraded to a new version */
    KM_TAG_EKEY_BLOB_DO_UPGRADE = KM_TAG_TYPE_UINT | 5005u,

    /* Used for HMAC keys.
     * Both of these are HMAC'd to derive a key encryption key,
     * which is what's actually used to wrap/unwrap the encrypted key blob.
     * The resulting pkek is added as the key blob's APPLICATION_ID. */
    KM_TAG_EKEY_BLOB_PASSWORD = KM_TAG_TYPE_BYTES | 5006u,
    KM_TAG_EKEY_BLOB_SALT = KM_TAG_TYPE_BYTES | 5007u,

    /* Encrypted key blob version, stored in the EKEY blob in plain text.
     * Typically `40` for keymaster 4.0 blobs. */
    KM_TAG_EKEY_BLOB_ENC_VER = KM_TAG_TYPE_UINT | 5008u,

    /* A tag indicating that the inner encrypted key blob
     * is not wrapped in an ASN.1 container.
     * Originally meant for HMAC keys,
     * however it can be applied to normal keys as well.
     * The presence of this tag during key generation/import disables the use
     * of `KM_TAG_EKEY_BLOB_UNIQ_KDM` for the blob entirely. */
    KM_TAG_EKEY_BLOB_RAW = KM_TAG_TYPE_UINT | 5009u,

    /* A per-encryption unique random value,
     * added to the encryption salt & AES-256-GCM authentication tag.
     * Typically stored in the outer encrypted key blob in plain text */
    KM_TAG_EKEY_BLOB_UNIQ_KDM = KM_TAG_TYPE_BYTES | 5010u,

    /* A flag indicating that the usage count
     * (Tag:EKEY_BLOB_CURRENT_USES_PER_BOOT, Tag:MAX_USES_PER_BOOT)
     * should be incremented */
    KM_TAG_EKEY_BLOB_INC_USE_COUNT = KM_TAG_TYPE_UINT | 5202u,

    /* Used to securely communitate the results between Trusted Applications
     * inside the TEE - the output can only be `tz_unwrap()`ped by a given TA.
     * In other words, binds the keymaster operation to a given TA identifier. */
    KM_TAG_SAMSUNG_REQUESTING_TA = KM_TAG_TYPE_BYTES | 2300u,

    /* Tag indicating that the root of trust value (Tag::ROOT_OF_TRUST)
     * should be added to the key parameters before a `begin` operation. */
    KM_TAG_SAMSUNG_ROT_REQUIRED = KM_TAG_TYPE_BOOL | 2301u,

    /* Tag indicating that a "legacy" root of trust value should be used
     * with the key (for unwrapping and attestations).
     * Used for old encrypted key blobs in a kind of "compatibility mode".
     * Only available in orange state. */
    KM_TAG_SAMSUNG_LEGACY_ROT = KM_TAG_TYPE_BOOL | 2304u,

    /* Tag indicating that a given key is stored in a StrongBox. */
    KM_TAG_USE_SECURE_PROCESSOR = KM_TAG_TYPE_BOOL | 3000u,

    /* Tag indicating that a given key is used for storage encryption (e.g. FBE).
     * Results in special functions being used to manage that key. */
    KM_TAG_STORAGE_KEY = KM_TAG_TYPE_BOOL | 722u,

    /* An internal tag that contains a bitmask of:
     * "oem flag" (0x01) - the result of an oem-specific check
     *      (e.g. "SW fuse" blown on QC devices); set if not ok
     * "trust boot" (0x02) - knox trust boot status; set if not ok
     * "warranty" (0x04) - knox warranty status; set if void
     * "eng build type" (0x10) - whether the current system is an engineering binary
     *
     * also some flags conditionally enabled at compile time,
     * used to work around some issues with bootloader API failures
     * causing the salt value to break (?):
     *
     * "default trust boot" (0x20) - knox trust boot status for "default" RoT; set if not OK
     * "default knox warranty" (0x40) - knox warranty status for "default" RoT; set if void
     *
     * This value is added to the salt used for all key blob unwrapping operations,
     * so any change in its value render all key blobs unusable. */
    KM_TAG_INTEGRITY_STATUS = KM_TAG_TYPE_UINT | 5031u,

    /** Flags controlling Samsung Attestation Key (SAK) attestation **/

    /* Set this tag to enable SAK */
    KM_TAG_IS_SAMSUNG_KEY = KM_TAG_TYPE_BOOL | 5029u,

    /* Also set this to the string "samsung" to enable ID attestation with SAK
     * (ID attestation is disabled for non-SAK attestations) */
    KM_TAG_SAMSUNG_ATTESTATION_ROOT = KM_TAG_TYPE_BYTES | 2102u,

    /* Set this tag to enable SAK on warranty void ("compromised") devices.
     * Makes the "INTEGRITY" SEQUENCE be added to the hardwareEnforced auth list. */
    KM_TAG_SAMSUNG_ATTEST_INTEGRITY = KM_TAG_TYPE_BOOL | 2302u,

    /* Used to enforce that the key can only be used on a device
     * with a samsung-official system ("trust boot status").
     * Also used to gate the `EXPORTABLE` tag, for some reason. */
    KM_TAG_KNOX_OBJECT_PROTECTION_REQUIRED = KM_TAG_TYPE_BOOL | 2000u,

    /** Parameters for SAK attestation,
     * with a similar role to Tag::ATTESTATION_CHALLENGE & Tag::ATTESTATION_ID_* */
    KM_TAG_KNOX_CREATOR_ID = KM_TAG_TYPE_BYTES | 2001u,
    KM_TAG_KNOX_ADMINISTRATOR_ID = KM_TAG_TYPE_BYTES | 2002u,
    KM_TAG_KNOX_ACCESSOR_ID = KM_TAG_TYPE_BYTES | 2003u,
    KM_TAG_SAMSUNG_AUTHENTICATE_PACKAGE = KM_TAG_TYPE_BYTES | 2303u,

    /* Used to supply an alternative value for the attestation leaf cert's subject
     * other than the default "CN=Android Keystore Key".
     * Multiple subject name entries may be supplied in the following format:
     *  entry1=value1,entry2=value2, ...
     * although note that the entries have to be valid X.509 NAMEs, such as CN, SN, OU, etc.
     *
     * Can be set both in the key and attestation parameters,
     * where the one in the attestation params overrides the one in the key.
     * Appears to also work for normal (non-SAK) attestations.
     */
    KM_TAG_SAMSUNG_CERTIFICATE_SUBJECT = KM_TAG_TYPE_BYTES | 2103u,

    /* Used to set an alternative value for the X509v3 keyUsage
     * critical extension in the attestation leaf cert.
     * The value supplied is a mask of the keyUsage values, e.g.
     *  0x90 for digitalSignature|dataEncipherment (0x80|0x10) */
    KM_TAG_SAMSUNG_KEY_USAGE = KM_TAG_TYPE_UINT | 2104u,

    /* Used to set an alternative value for the X509v3 extendedKeyUsage
     * non-critical extension in the attestation leaf cert.
     * Multiple keyUsage values may be supplied, either as a name or an OID,
     * separated by a comma, like so:
     *  `serverAuth,codeSigning, ...` OR `1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.3, ...`
     *
     * Exclusive to SAK attestations. */
    KM_TAG_SAMSUNG_EXTENDED_KEY_USAGE = KM_TAG_TYPE_BYTES | 2105u,

    /* Used to set an alternative value for the X509v3 subjectAltName
     * non-critical extension in the attestation leaf cert.
     * Multiple subject name entries may be supplied in the following format:
     *  entry1=value1,entry2=value2, ...
     * although note that the entries can only be the following X.509 alt names:
     *  "rfc822Name", "dNSName", "uniformResourceIdentifier", "iPAddress"
     *
     * Exclusive to SAK attestations. */
    KM_TAG_SAMSUNG_SUBJECT_ALTERNATIVE_NAME = KM_TAG_TYPE_BYTES | 2106u,

    /** Keybox provisioning tags **/

    /* Used to label the first intermediate cert in the EC cert chain ("issuer" of the key) */
    KM_TAG_PROV_GAC_EC1 = KM_TAG_TYPE_BYTES | 5123u,

    /* Used to label the second intermediate cert in the EC cert chain (the "OEM" cert) */
    KM_TAG_PROV_GAC_EC2 = KM_TAG_TYPE_BYTES | 5124u,

    /* Used to label the root of the EC cert chain */
    KM_TAG_PROV_GAC_EC3 = KM_TAG_TYPE_BYTES | 5125u,

    /* Used to label the EC attestation private key */
    KM_TAG_PROV_GAK_EC = KM_TAG_TYPE_BYTES | 5118u,

    /* Used to label a validation token of the EC attestation private key */
    KM_TAG_PROV_GAK_EC_VTOKEN = KM_TAG_TYPE_BYTES | 5115u,

    /* Used to label the first intermediate cert in the RSA cert chain ("issuer" of the key) */
    KM_TAG_PROV_GAC_RSA1 = KM_TAG_TYPE_BYTES | 5120u,

    /* Used to label the second intermediate cert in the RSA cert chain (the "OEM" cert) */
    KM_TAG_PROV_GAC_RSA2 = KM_TAG_TYPE_BYTES | 5121u,

    /* Used to label the root of the RSA cert chain */
    KM_TAG_PROV_GAC_RSA3 = KM_TAG_TYPE_BYTES | 5122u,

    /* Used to label the RSA attestation private key */
    KM_TAG_PROV_GAK_RSA = KM_TAG_TYPE_BYTES | 5117u,

    /* Used to label a validation token of the RSA attestation private key */
    KM_TAG_PROV_GAK_RSA_VTOKEN = KM_TAG_TYPE_BYTES | 5114u,

    /* Used to label the SAK private key */
    KM_TAG_PROV_SAK_EC = KM_TAG_TYPE_BYTES | 5119u,

    /* Used to label a validation token of the SAK EC private key */
    KM_TAG_PROV_SAK_EC_VTOKEN = KM_TAG_TYPE_BYTES | 5116u,

    /** StrongBox tags' values are yet to be reverse-engineered. **/

    /* Used to label the first intermediate cert in the StrongBox EC cert chain
     * ("issuer" of the key) */
    //KM_TAG_PROV_SGAC_EC1 = 0,

    /* Used to label the second intermediate cert in the StrongBox EC cert chain
     * (the "OEM" cert) */
    //KM_TAG_PROV_SGAC_EC2 = 0,

    /* Used to label the root of the StrongBox EC cert chain */
    //KM_TAG_PROV_SGAC_EC3 = 0,

    /* Used to label the first intermediate cert in the StrongBox RSA cert chain
     * ("issuer" of the key) */
    //KM_TAG_PROV_SGAC_RSA1 = 0,

    /* Used to label the second intermediate cert in the StrongBox RSA cert chain
     * (the "OEM" cert) */
    //KM_TAG_PROV_SGAC_RSA2 = 0,

    /* Used to label the root of the StrongBox RSA cert chain */
    //KM_TAG_PROV_SGAC_RSA3 = 0,
};

/**
 * Algorithms provided by IKeymasterDevice implementations.
 */
enum KM_Algorithm {
    /**
     * Asymmetric algorithms.
     */
    KM_ALG_RSA = 1u,
    KM_ALG_EC = 3u,
    /**
     * Block cipher algorithms
     */
    KM_ALG_AES = 32u,
    KM_ALG_TRIPLE_DES = 33u,
    /**
     * MAC algorithms
     */
    KM_ALG_HMAC = 128u,
};

/**
 * Symmetric block cipher modes provided by keymaster implementations.
 */
enum KM_BlockMode {
    /*
     * Unauthenticated modes, usable only for encryption/decryption and not generally recommended
     * except for compatibility with existing other protocols.
     */
    KM_BLOCK_MODE_ECB = 1u,
    KM_BLOCK_MODE_CBC = 2u,
    KM_BLOCK_MODE_CTR = 3u,
    /*
     * Authenticated modes, usable for encryption/decryption and signing/verification.  Recommended
     * over unauthenticated modes for all purposes.
     */
    KM_BLOCK_MODE_GCM = 32u,
};

/**
 * Padding modes that may be applied to plaintext for encryption operations.  This list includes
 * padding modes for both symmetric and asymmetric algorithms.  Note that implementations should not
 * provide all possible combinations of algorithm and padding, only the
 * cryptographically-appropriate pairs.
 */
enum KM_PaddingMode {
    KM_PADDING_NONE = 1u,
    /*
     * deprecated
     */
    KM_PADDING_RSA_OAEP = 2u,
    KM_PADDING_RSA_PSS = 3u,
    KM_PADDING_RSA_PKCS1_1_5_ENCRYPT = 4u,
    KM_PADDING_RSA_PKCS1_1_5_SIGN = 5u,
    KM_PADDING_PKCS7 = 64u,
};

/**
 * Digests provided by keymaster implementations.
 */
enum KM_Digest {
    KM_DIGEST_NONE = 0u,
    KM_DIGEST_MD5 = 1u,
    KM_DIGEST_SHA1 = 2u,
    KM_DIGEST_SHA_2_224 = 3u,
    KM_DIGEST_SHA_2_256 = 4u,
    KM_DIGEST_SHA_2_384 = 5u,
    KM_DIGEST_SHA_2_512 = 6u,
};

/**
 * Supported EC curves, used in ECDSA
 */
enum KM_EcCurve {
    KM_EC_CURVE_P_224 = 0u,
    KM_EC_CURVE_P_256 = 1u,
    KM_EC_CURVE_P_384 = 2u,
    KM_EC_CURVE_P_521 = 3u,
};

/**
 * The origin of a key (or pair), i.e. where it was generated.  Note that ORIGIN can be found in
 * either the hardware-enforced or software-enforced list for a key, indicating whether the key is
 * hardware or software-based.  Specifically, a key with GENERATED in the hardware-enforced list
 * must be guaranteed never to have existed outide the secure hardware.
 */
enum KM_KeyOrigin {
    /**
     * Generated in keymaster.  Should not exist outside the TEE.
     */
    KM_ORIGIN_GENERATED = 0u,
    /**
     * Derived inside keymaster.  Likely exists off-device.
     */
    KM_ORIGIN_DERIVED = 1u,
    /**
     * Imported into keymaster.  Existed as cleartext in Android.
     */
    KM_ORIGIN_IMPORTED = 2u,
    /**
     * Keymaster did not record origin.  This value can only be seen on keys in a keymaster0
     * implementation.  The keymaster0 adapter uses this value to document the fact that it is
     * unkown whether the key was generated inside or imported into keymaster.
     */
    KM_ORIGIN_UNKNOWN = 3u,
    /**
     * Securely imported into Keymaster.  Was created elsewhere, and passed securely through Android
     * to secure hardware.
     */
    KM_ORIGIN_SECURELY_IMPORTED = 4u,
};

/**
 * Usability requirements of key blobs.  This defines what system functionality must be available
 * for the key to function.  For example, key "blobs" which are actually handles referencing
 * encrypted key material stored in the file system cannot be used until the file system is
 * available, and should have BLOB_REQUIRES_FILE_SYSTEM.
 */
enum KM_KeyBlobUsageRequirements {
    KM_USAGE_STANDALONE = 0u,
    KM_USAGE_REQUIRES_FILE_SYSTEM = 1u,
};

/**
 * Possible purposes of a key (or pair).
 */
enum KM_KeyPurpose {
    KM_PURPOSE_ENCRYPT = 0u,
    /*
     * Usable with RSA, EC and AES keys.
     */
    KM_PURPOSE_DECRYPT = 1u,
    /*
     * Usable with RSA, EC and AES keys.
     */
    KM_PURPOSE_SIGN = 2u,
    /*
     * Usable with RSA, EC and HMAC keys.
     */
    KM_PURPOSE_VERIFY = 3u,
    /*
     * Usable with RSA, EC and HMAC keys.
     *
     *
     * 4 is reserved
     */
    KM_PURPOSE_WRAP_KEY = 5u,
};


/**
 * Keymaster error codes.
 */
enum KM_ErrorCode {
    KM_OK = 0,
    KM_ERR_ROOT_OF_TRUST_ALREADY_SET = -1 /* -1 */,
    KM_ERR_UNSUPPORTED_PURPOSE = -2 /* -2 */,
    KM_ERR_INCOMPATIBLE_PURPOSE = -3 /* -3 */,
    KM_ERR_UNSUPPORTED_ALGORITHM = -4 /* -4 */,
    KM_ERR_INCOMPATIBLE_ALGORITHM = -5 /* -5 */,
    KM_ERR_UNSUPPORTED_KEY_SIZE = -6 /* -6 */,
    KM_ERR_UNSUPPORTED_BLOCK_MODE = -7 /* -7 */,
    KM_ERR_INCOMPATIBLE_BLOCK_MODE = -8 /* -8 */,
    KM_ERR_UNSUPPORTED_MAC_LENGTH = -9 /* -9 */,
    KM_ERR_UNSUPPORTED_PADDING_MODE = -10 /* -10 */,
    KM_ERR_INCOMPATIBLE_PADDING_MODE = -11 /* -11 */,
    KM_ERR_UNSUPPORTED_DIGEST = -12 /* -12 */,
    KM_ERR_INCOMPATIBLE_DIGEST = -13 /* -13 */,
    KM_ERR_INVALID_EXPIRATION_TIME = -14 /* -14 */,
    KM_ERR_INVALID_USER_ID = -15 /* -15 */,
    KM_ERR_INVALID_AUTHORIZATION_TIMEOUT = -16 /* -16 */,
    KM_ERR_UNSUPPORTED_KEY_FORMAT = -17 /* -17 */,
    KM_ERR_INCOMPATIBLE_KEY_FORMAT = -18 /* -18 */,
    KM_ERR_UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM = -19 /* -19 */,
    /**
     * For PKCS8 & PKCS12
     */
    KM_ERR_UNSUPPORTED_KEY_VERIFICATION_ALGORITHM = -20 /* -20 */,
    /**
     * For PKCS8 & PKCS12
     */
    KM_ERR_INVALID_INPUT_LENGTH = -21 /* -21 */,
    KM_ERR_KEY_EXPORT_OPTIONS_INVALID = -22 /* -22 */,
    KM_ERR_DELEGATION_NOT_ALLOWED = -23 /* -23 */,
    KM_ERR_KEY_NOT_YET_VALID = -24 /* -24 */,
    KM_ERR_KEY_EXPIRED = -25 /* -25 */,
    KM_ERR_KEY_USER_NOT_AUTHENTICATED = -26 /* -26 */,
    KM_ERR_OUTPUT_PARAMETER_NULL = -27 /* -27 */,
    KM_ERR_INVALID_OPERATION_HANDLE = -28 /* -28 */,
    KM_ERR_INSUFFICIENT_BUFFER_SPACE = -29 /* -29 */,
    KM_ERR_VERIFICATION_FAILED = -30 /* -30 */,
    KM_ERR_TOO_MANY_OPERATIONS = -31 /* -31 */,
    KM_ERR_UNEXPECTED_NULL_POINTER = -32 /* -32 */,
    KM_ERR_INVALID_KEY_BLOB = -33 /* -33 */,
    KM_ERR_IMPORTED_KEY_NOT_ENCRYPTED = -34 /* -34 */,
    KM_ERR_IMPORTED_KEY_DECRYPTION_FAILED = -35 /* -35 */,
    KM_ERR_IMPORTED_KEY_NOT_SIGNED = -36 /* -36 */,
    KM_ERR_IMPORTED_KEY_VERIFICATION_FAILED = -37 /* -37 */,
    KM_ERR_INVALID_ARGUMENT = -38 /* -38 */,
    KM_ERR_UNSUPPORTED_TAG = -39 /* -39 */,
    KM_ERR_INVALID_TAG = -40 /* -40 */,
    KM_ERR_MEMORY_ALLOCATION_FAILED = -41 /* -41 */,
    KM_ERR_IMPORT_PARAMETER_MISMATCH = -44 /* -44 */,
    KM_ERR_SECURE_HW_ACCESS_DENIED = -45 /* -45 */,
    KM_ERR_OPERATION_CANCELLED = -46 /* -46 */,
    KM_ERR_CONCURRENT_ACCESS_CONFLICT = -47 /* -47 */,
    KM_ERR_SECURE_HW_BUSY = -48 /* -48 */,
    KM_ERR_SECURE_HW_COMMUNICATION_FAILED = -49 /* -49 */,
    KM_ERR_UNSUPPORTED_EC_FIELD = -50 /* -50 */,
    KM_ERR_MISSING_NONCE = -51 /* -51 */,
    KM_ERR_INVALID_NONCE = -52 /* -52 */,
    KM_ERR_MISSING_MAC_LENGTH = -53 /* -53 */,
    KM_ERR_KEY_RATE_LIMIT_EXCEEDED = -54 /* -54 */,
    KM_ERR_CALLER_NONCE_PROHIBITED = -55 /* -55 */,
    KM_ERR_KEY_MAX_OPS_EXCEEDED = -56 /* -56 */,
    KM_ERR_INVALID_MAC_LENGTH = -57 /* -57 */,
    KM_ERR_MISSING_MIN_MAC_LENGTH = -58 /* -58 */,
    KM_ERR_UNSUPPORTED_MIN_MAC_LENGTH = -59 /* -59 */,
    KM_ERR_UNSUPPORTED_KDF = -60 /* -60 */,
    KM_ERR_UNSUPPORTED_EC_CURVE = -61 /* -61 */,
    KM_ERR_KEY_REQUIRES_UPGRADE = -62 /* -62 */,
    KM_ERR_ATTESTATION_CHALLENGE_MISSING = -63 /* -63 */,
    KM_ERR_KEYMASTER_NOT_CONFIGURED = -64 /* -64 */,
    KM_ERR_ATTESTATION_APPLICATION_ID_MISSING = -65 /* -65 */,
    KM_ERR_CANNOT_ATTEST_IDS = -66 /* -66 */,
    KM_ERR_ROLLBACK_RESISTANCE_UNAVAILABLE = -67 /* -67 */,
    KM_ERR_HARDWARE_TYPE_UNAVAILABLE = -68 /* -68 */,
    KM_ERR_PROOF_OF_PRESENCE_REQUIRED = -69 /* -69 */,
    KM_ERR_CONCURRENT_PROOF_OF_PRESENCE_REQUESTED = -70 /* -70 */,
    KM_ERR_NO_USER_CONFIRMATION = -71 /* -71 */,
    KM_ERR_DEVICE_LOCKED = -72 /* -72 */,
    KM_ERR_UNIMPLEMENTED = -100 /* -100 */,
    KM_ERR_VERSION_MISMATCH = -101 /* -101 */,
    KM_ERR_UNKNOWN_ERROR = -1000 /* -1000 */,
};

/**
 * Key derivation functions, mostly used in ECIES.
 */
enum KM_KeyDerivationFunction {
    /**
     * Do not apply a key derivation function; use the raw agreed key
     */
    KM_DERIVATION_NONE = 0u,
    /**
     * HKDF defined in RFC 5869 with SHA256
     */
    KM_DERIVATION_RFC5869_SHA256 = 1u,
    /**
     * KDF1 defined in ISO 18033-2 with SHA1
     */
    KM_DERIVATION_ISO18033_2_KDF1_SHA1 = 2u,
    /**
     * KDF1 defined in ISO 18033-2 with SHA256
     */
    KM_DERIVATION_ISO18033_2_KDF1_SHA256 = 3u,
    /**
     * KDF2 defined in ISO 18033-2 with SHA1
     */
    KM_DERIVATION_ISO18033_2_KDF2_SHA1 = 4u,
    /**
     * KDF2 defined in ISO 18033-2 with SHA256
     */
    KM_DERIVATION_ISO18033_2_KDF2_SHA256 = 5u,
};

/**
 * Hardware authentication type, used by HardwareAuthTokens to specify the mechanism used to
 * authentiate the user, and in KeyCharacteristics to specify the allowable mechanisms for
 * authenticating to activate a key.
 */
enum KM_HardwareAuthenticatorType {
    KM_AUTHENTICATOR_NONE = 0u,
    KM_AUTHENTICATOR_PASSWORD = 1u /* 1 << 0 */,
    KM_AUTHENTICATOR_FINGERPRINT = 2u /* 1 << 1 */,
    KM_AUTHENTICATOR_ANY = 4294967295u /* 0xFFFFFFFF */,
};

/**
 * Device security levels.
 */
enum KM_SecurityLevel {
    KM_SECURITY_LEVEL_SOFTWARE = 0u,
    KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT = 1u,
    /**
     * STRONGBOX specifies that the secure hardware satisfies the requirements specified in CDD
     * 9.11.2.
     */
    KM_SECURITY_LEVEL_STRONGBOX = 2u,
};

/**
 * Formats for key import and export.
 */
enum KM_KeyFormat {
    /**
     * X.509 certificate format, for public key export.
     */
    KM_FORMAT_X509 = 0u,
    /**
     * PCKS#8 format, asymmetric key pair import.
     */
    KM_FORMAT_PKCS8 = 1u,
    /**
     * Raw bytes, for symmetric key import.
     */
    KM_FORMAT_RAW = 3u,
};

union KM_IntegerParams {
    /*
     * Enum types
     */
    enum KM_Algorithm algorithm;
    enum KM_BlockMode blockMode;
    enum KM_PaddingMode paddingMode;
    enum KM_Digest digest;
    enum KM_EcCurve ecCurve;
    enum KM_KeyOrigin origin;
    enum KM_KeyBlobUsageRequirements keyBlobUsageRequirements;
    enum KM_KeyPurpose purpose;
    enum KM_KeyDerivationFunction keyDerivationFunction;
    enum KM_HardwareAuthenticatorType hardwareAuthenticatorType;
    enum KM_SecurityLevel hardwareType;

    /*
     * Other types
     */
    bool boolValue;
    uint32_t integer;
    uint64_t longInteger;
    uint64_t dateTime;
};

struct KM_KeyParameter {

    /**
     * Discriminates the union/blob field used.  The blob cannot be placed in the union, but only
     * one of "f" and "blob" may ever be used at a time.
     */
    enum KM_Tag tag;
    union KM_IntegerParams f;
    VECTOR(u8) blob; /* hidl_vec<uint8_t> */
};
static inline void km_destroy_key_parameter(struct KM_KeyParameter *kp)
{
    if (kp == NULL)
        return;

    kp->tag = KM_TAG_INVALID;
    memset(&kp->f, 0, sizeof(union KM_IntegerParams));
    vector_destroy(&kp->blob);
}
static inline void km_destroy_key_parameters(VECTOR(struct KM_KeyParameter) *kps_p)
{
    if (kps_p == NULL || *kps_p == NULL)
        return;

    VECTOR(struct KM_KeyParameter) const kps = *kps_p;

    for (u32 i = 0; i < vector_size(kps); i++)
        km_destroy_key_parameter(&kps[i]);

    vector_destroy(kps_p);
}

/**
 * The OID for Android attestation records.  For the curious, it breaks down as follows:
 *
 * 1 = ISO
 * 3 = org
 * 6 = DoD (Huh? OIDs are weird.)
 * 1 = IANA
 * 4 = Private
 * 1 = Enterprises
 * 11129 = Google
 * 2 = Google security
 * 1 = certificate extension
 * 17 = Android attestation extension.
 */
__attribute__ ((unused))
static const char KM_kAttestionRecordOid[] = "1.3.6.1.4.1.11129.2.1.17";

/* The C enum representation of the `VerifiedBootState` ASN.1 ENUMERATED type.
 * Present in the `RootOfTrust` struct. */
enum KM_VerifiedBootState {
    KM_VERIFIED_BOOT_VERIFIED = 0,
    KM_VERIFIED_BOOT_SELF_SIGNED = 1,
    KM_VERIFIED_BOOT_UNVERIFIED = 2,
    KM_VERIFIED_BOOT_FAILED = 3,
};

/**
 * KeyCharacteristics defines the attributes of a key, including cryptographic parameters, and usage
 * restrictions.  It consits of two vectors of KeyParameters, one for "softwareEnforced" attributes
 * and one for "hardwareEnforced" attributes.
 *
 * KeyCharacteristics objects are returned by generateKey, importKey, importWrappedKey and
 * getKeyCharacteristics.  The IKeymasterDevice secure environment is responsible for allocating the
 * parameters, all of which are Tags with associated values, to the correct vector.  The
 * hardwareEnforced vector must contain only those attributes which are enforced by secure hardware.
 * All others should be in the softwareEnforced vector.  See the definitions of individual Tag enums
 * for specification of which must be hardware-enforced, which may be software-enforced and which
 * must never appear in KeyCharacteristics.
 */
struct KM_KeyCharacteristics {
    VECTOR(struct KM_KeyParameter) softwareEnforced;
    VECTOR(struct KM_KeyParameter) hardwareEnforced;
};
static inline void km_destroy_key_characteristics(struct KM_KeyCharacteristics *kc)
{
    if (kc == NULL)
        return;

    if (kc->softwareEnforced != NULL) {
        for (u32 i = 0; i < vector_size(kc->softwareEnforced); i++)
            km_destroy_key_parameter(&kc->softwareEnforced[i]);

        vector_destroy(&kc->softwareEnforced);
    }

    if (kc->hardwareEnforced != NULL) {
        for (u32 i = 0; i < vector_size(kc->hardwareEnforced); i++)
            km_destroy_key_parameter(&kc->hardwareEnforced[i]);

        vector_destroy(&kc->hardwareEnforced);
    }
}

/**
 * HardwareAuthToken is used to prove successful user authentication, to unlock the use of a key.
 *
 * HardwareAuthTokens are produced by other secure environment applications, notably GateKeeper and
 * Fingerprint, in response to successful user authentication events.  These tokens are passed to
 * begin(), update(), and finish() to prove that authentication occurred.  See those methods for
 * more details.  It is up to the caller to determine which of the generated auth tokens is
 * appropriate for a given key operation.
 */
struct KM_HardwareAuthToken {
    /**
     * challenge is a value that's used to enable authentication tokens to authorize specific
     * events.  The primary use case for challenge is to authorize an IKeymasterDevice cryptographic
     * operation, for keys that require authentication per operation. See begin() for details.
     */
    uint64_t challenge;
    /**
     *  userId is the a "secure" user ID.  It is not related to any Android user ID or UID, but is
     *  created in the Gatekeeper application in the secure environment.
     */
    uint64_t userId;
    /**
     *  authenticatorId is the a "secure" user ID.  It is not related to any Android user ID or UID,
     *  but is created in an authentication application in the secure environment, such as the
     *  Fingerprint application.
     */
    uint64_t authenticatorId;
    /**
     * authenticatorType describes the type of authentication that took place, e.g. password or
     * fingerprint.
     */
    enum KM_HardwareAuthenticatorType authenticatorType;
    /**
     * timestamp indicates when the user authentication took place, in milliseconds since some
     * starting point (generally the most recent device boot) which all of the applications within
     * one secure environment must agree upon.  This timestamp is used to determine whether or not
     * the authentication occurred recently enough to unlock a key (see Tag::AUTH_TIMEOUT).
     */
    uint64_t timestamp;
    /**
     * MACs are computed with a backward-compatible method, used by Keymaster 3.0, Gatekeeper 1.0
     * and Fingerprint 1.0, as well as pre-treble HALs.
     *
     * The MAC is Constants::AUTH_TOKEN_MAC_LENGTH bytes in length and is computed as follows:
     *
     *     HMAC_SHA256(
     *         H, 0 || challenge || user_id || authenticator_id || authenticator_type || timestamp)
     *
     * where ``||'' represents concatenation, the leading zero is a single byte, and all integers
     * are represented as unsigned values, the full width of the type.  The challenge, userId and
     * authenticatorId values are in machine order, but authenticatorType and timestamp are in
     * network order (big-endian).  This odd construction is compatible with the hw_auth_token_t
     * structure,
     *
     * Note that mac is a vec rather than an array, not because it's actually variable-length but
     * because it could be empty.  As documented in the IKeymasterDevice::begin,
     * IKeymasterDevice::update and IKeymasterDevice::finish doc comments, an empty mac indicates
     * that this auth token is empty.
     */
    uint8_t mac[KM_AUTH_TOKEN_MAC_LENGTH];
};
static inline void km_destroy_hardware_auth_token(struct KM_HardwareAuthToken *auth_token)
{
    if (auth_token == NULL)
        return;

    auth_token->challenge = 0;
    auth_token->userId = 0;
    auth_token->authenticatorId = 0;
    auth_token->authenticatorType = KM_AUTHENTICATOR_NONE;
    auth_token->timestamp = 0;
    memset(auth_token->mac, 0, KM_AUTH_TOKEN_MAC_LENGTH);
}

typedef uint64_t KM_OperationHandle_t;

/**
 * HmacSharingParameters holds the data used in the process of establishing a shared HMAC key
 * between multiple Keymaster instances.  Sharing parameters are returned in this struct by
 * getHmacSharingParameters() and send to computeSharedHmac().  See the named methods in IKeymaster
 * for details of usage.
 */
struct KM_HmacSharingParameters {
    /**
     * Either empty or contains a persistent value that is associated with the pre-shared HMAC
     * agreement key (see documentation of computeSharedHmac in @4.0::IKeymaster).  It is either
     * empty or 32 bytes in length.
     */
    VECTOR(u8) seed;
    /**
     * A 32-byte value which is guaranteed to be different each time
     * getHmacSharingParameters() is called.  Probabilistic uniqueness (i.e. random) is acceptable,
     * though a stronger uniqueness guarantee (e.g. counter) is recommended where possible.
     */
    u8 nonce[32];
};
static inline void km_destroy_hmac_sharing_parameters(struct KM_HmacSharingParameters *params)
{
    if (params == NULL)
        return;

    vector_destroy(&params->seed);
    memset(params->nonce, 0, sizeof(params->nonce));
}

/**
 * VerificationToken enables one Keymaster instance to validate authorizations for another.  See
 * verifyAuthorizations() in IKeymaster for details.
 */
struct KM_VerificationToken {
    /**
     * The operation handle, used to ensure freshness.
     */
    uint64_t challenge;
    /**
     * The current time of the secure environment that generates the VerificationToken.  This can be
     * checked against auth tokens generated by the same secure environment, which avoids needing to
     * synchronize clocks.
     */
    uint64_t timestamp;
    /**
     * A list of the parameters verified.  Empty if the only parameters verified are time-related.
     * In that case the timestamp is the payload.
     */
    VECTOR(struct KM_KeyParameter) parametersVerified;
    /**
     * SecurityLevel of the secure environment that generated the token.
     */
    enum KM_SecurityLevel securityLevel;
    /**
     * 32-byte HMAC-SHA256 of the above values, computed as:
     *
     *    HMAC(H,
     *         "Auth Verification" || challenge || timestamp || securityLevel || parametersVerified)
     *
     * where:
     *
     *   ``HMAC'' is the shared HMAC key (see computeSharedHmac() in IKeymaster).
     *
     *   ``||'' represents concatenation
     *
     * The representation of challenge and timestamp is as 64-bit unsigned integers in big-endian
     * order.  securityLevel is represented as a 32-bit unsigned integer in big-endian order.
     *
     * If parametersVerified is non-empty, the representation of parametersVerified is an ASN.1 DER
     * encoded representation of the values.  The ASN.1 schema used is the AuthorizationList schema
     * from the Keystore attestation documentation.  If parametersVerified is empty, it is simply
     * omitted from the HMAC computation.
     */
    u8 mac[KM_AUTH_TOKEN_MAC_LENGTH];
};
static inline void km_destroy_verification_token(struct KM_VerificationToken *vt)
{
    if (vt == NULL)
        return;

    vt->challenge = 0;
    vt->timestamp = 0;
    vector_destroy(&vt->parametersVerified);
    vt->securityLevel = KM_SECURITY_LEVEL_SOFTWARE;
    memset(vt->mac, 0, KM_AUTH_TOKEN_MAC_LENGTH);
}

typedef struct KM_RootOfTrust_V3 {
    ASN1_OCTET_STRING *verifiedBootKey;
    ASN1_BOOLEAN deviceLocked;
    ASN1_ENUMERATED *verifiedBootState;
    ASN1_OCTET_STRING *verifiedBootHash;
} KM_ROOT_OF_TRUST_V3;
DECLARE_ASN1_FUNCTIONS(KM_ROOT_OF_TRUST_V3);

#define ASN1_SET_OF_INTEGER STACK_OF(ASN1_INTEGER)

typedef struct KM_param_list {
    ASN1_SET_OF_INTEGER *           purpose;
    ASN1_INTEGER *                  algorithm;
    ASN1_INTEGER *                  keySize;
    ASN1_SET_OF_INTEGER *           blockMode;
    ASN1_SET_OF_INTEGER *           digest;
    ASN1_SET_OF_INTEGER *           padding;
    ASN1_NULL *                     callerNonce;
    ASN1_INTEGER *                  minMacLength;
    ASN1_INTEGER *                  ecCurve;
    ASN1_INTEGER *                  rsaPublicExponent;
    ASN1_NULL *                     rollbackResistance;
    ASN1_INTEGER *                  activeDateTime;
    ASN1_INTEGER *                  originationExpireDateTime;
    ASN1_INTEGER *                  usageExpireDateTime;
    ASN1_SET_OF_INTEGER *           userSecureId;
    ASN1_NULL *                     noAuthRequired;
    ASN1_INTEGER *                  userAuthType;
    ASN1_INTEGER *                  authTimeout;
    ASN1_NULL *                     allowWhileOnBody;
    ASN1_NULL *                     trustedUserPresenceReq;
    ASN1_NULL *                     trustedConfirmationReq;
    ASN1_NULL *                     unlockedDeviceReq;
    ASN1_INTEGER *                  creationDateTime;
    ASN1_INTEGER *                  keyOrigin;
    KM_ROOT_OF_TRUST_V3 *           rootOfTrust;
    ASN1_INTEGER *                  osVersion;
    ASN1_INTEGER *                  osPatchLevel;
    ASN1_OCTET_STRING *             attestationApplicationId;
    ASN1_OCTET_STRING *             attestationIdBrand;
    ASN1_OCTET_STRING *             attestationIdDevice;
    ASN1_OCTET_STRING *             attestationIdProduct;
    ASN1_OCTET_STRING *             attestationIdSerial;
    ASN1_OCTET_STRING *             attestationIdImei;
    ASN1_OCTET_STRING *             attestationIdMeid;
    ASN1_OCTET_STRING *             attestationIdManufacturer;
    ASN1_OCTET_STRING *             attestationIdModel;
    ASN1_INTEGER *                  vendorPatchLevel;
    ASN1_INTEGER *                  bootPatchLevel;
    ASN1_NULL *                     includeUniqueId;
    ASN1_INTEGER *                  keyBlobUsageRequirements;
    ASN1_NULL *                     bootloaderOnly;
    ASN1_INTEGER *                  hardwareType;
    ASN1_INTEGER *                  minSecondsBetweenOps;
    ASN1_INTEGER *                  maxUsesPerBoot;
    ASN1_INTEGER *                  userId;
    ASN1_OCTET_STRING *             applicationId;
    ASN1_OCTET_STRING *             applicationData;
    ASN1_OCTET_STRING *             uniqueId;
    ASN1_OCTET_STRING *             attestationChallenge;
    ASN1_OCTET_STRING *             associatedData;
    ASN1_OCTET_STRING *             nonce;
    ASN1_INTEGER *                  macLength;
    ASN1_NULL *                     resetSinceIdRotation;
    ASN1_OCTET_STRING *             confirmationToken;
    ASN1_OCTET_STRING *             authToken;
    ASN1_OCTET_STRING *             verificationToken;
    ASN1_NULL *                     allUsers;
    ASN1_NULL *                     eciesSingleHashMode;
    ASN1_INTEGER *                  kdf;
    ASN1_NULL *                     exportable;
    ASN1_NULL *                     keyAuth;
    ASN1_NULL *                     opAuth;
    ASN1_INTEGER *                  operationHandle;
    ASN1_NULL *                     operationFailed;
    ASN1_INTEGER *                  internalCurrentDateTime;
    ASN1_OCTET_STRING *             ekeyBlobIV;
    ASN1_OCTET_STRING *             ekeyBlobAuthTag;
    ASN1_INTEGER *                  ekeyBlobCurrentUsesPerBoot;
    ASN1_INTEGER *                  ekeyBlobLastOpTimestamp;
    ASN1_INTEGER *                  ekeyBlobDoUpgrade;
    ASN1_OCTET_STRING *             ekeyBlobPassword;
    ASN1_OCTET_STRING *             ekeyBlobSalt;
    ASN1_INTEGER *                  ekeyBlobEncVer;
    ASN1_INTEGER *                  ekeyBlobRaw;
    ASN1_OCTET_STRING *             ekeyBlobUniqKDM;
    ASN1_INTEGER *                  ekeyBlobIncUseCount;
    ASN1_OCTET_STRING *             samsungRequestingTA;
    ASN1_NULL *                     samsungRotRequired;
    ASN1_NULL *                     samsungLegacyRot;
    ASN1_NULL *                     useSecureProcessor;
    ASN1_NULL *                     storageKey;
    ASN1_INTEGER *                  integrityStatus;
    ASN1_NULL *                     isSamsungKey;
    ASN1_OCTET_STRING *             samsungAttestationRoot;
    ASN1_NULL *                     samsungAttestIntegrity;
    ASN1_NULL *                     knoxObjectProtectionRequired;
    ASN1_OCTET_STRING *             knoxCreatorId;
    ASN1_OCTET_STRING *             knoxAdministratorId;
    ASN1_OCTET_STRING *             knoxAccessorId;
    ASN1_OCTET_STRING *             samsungAuthPackage;
    ASN1_OCTET_STRING *             samsungCertificateSubject;
    ASN1_INTEGER *                  samsungKeyUsage;
    ASN1_OCTET_STRING *             samsungExtendedKeyUsage;
    ASN1_OCTET_STRING *             samsungSubjectAlternativeName;
    ASN1_OCTET_STRING *             provGacEc1;
    ASN1_OCTET_STRING *             provGacEc2;
    ASN1_OCTET_STRING *             provGacEc3;
    ASN1_OCTET_STRING *             provGakEc;
    ASN1_OCTET_STRING *             provGakEcVtoken;
    ASN1_OCTET_STRING *             provGacRsa1;
    ASN1_OCTET_STRING *             provGacRsa2;
    ASN1_OCTET_STRING *             provGacRsa3;
    ASN1_OCTET_STRING *             provGakRsa;
    ASN1_OCTET_STRING *             provGakRsaVtoken;
    ASN1_OCTET_STRING *             provSakEc;
    ASN1_OCTET_STRING *             provSakEcVtoken;
} KM_PARAM_LIST;
DECLARE_ASN1_FUNCTIONS(KM_PARAM_LIST)

typedef int64_t KM_DateTime_t;

/* The C struct representation of the `KeyDescription` ASN.1 sequence
 * that stores the result of an Android Key Attestation request.
 *
 * This struct, and all of its sub-structs and enums
 * (`AuthorizationList`, `RootOfTrust`, `SecurityLevel` and `VerifiedBootState`)
 * reflect version 3 of the Android Attestation Extension.
 *
 * For more information and detailed documentation, see
 *  https://source.android.com/docs/security/features/keystore/attestation#attestation-v3
 */
typedef struct KM_KeyDescription_v3 {
    ASN1_INTEGER *attestationVersion;
    ASN1_ENUMERATED *attestationSecurityLevel;
    ASN1_INTEGER *keymasterVersion;
    ASN1_ENUMERATED *keymasterSecurityLevel;
    ASN1_OCTET_STRING *attestationChallenge;
    ASN1_OCTET_STRING *uniqueId;

    /* `KM_PARAM_LIST` is used instead of `KM_AUTH_LIST`
     * for more flexibility (some tags don't appear in `KM_AUTH_LIST`) */

    KM_PARAM_LIST *softwareEnforced;
    KM_PARAM_LIST *hardwareEnforced;
} KM_KEY_DESC_V3;
DECLARE_ASN1_FUNCTIONS(KM_KEY_DESC_V3);

typedef const char * (*KM_enum_toString_proc_t)(int);

bool KM_Tag_is_repeatable(uint32_t tag);

const char * KM_TagType_toString(uint32_t tt);
const char * KM_Tag_toString(uint32_t t);

const char * KM_ErrorCode_toString(int o);
const char * KM_SecurityLevel_toString(int sl);
const char * KM_VerifiedBootState_toString(int vb);
const char * KM_KeyPurpose_toString(int kp);
const char * KM_Algorithm_toString(int alg);
const char * KM_BlockMode_toString(int bm);
const char * KM_Digest_toString(int dig);
const char * KM_PaddingMode_toString(int pm);
const char * KM_EcCurve_toString(int ec);
const char * KM_KeyOrigin_toString(int ko);
const char * KM_KeyBlobUsageRequirements_toString(int kbur);
const char * KM_KeyDerivationFunction_toString(int kdf);

#ifdef __cplusplus
} /* namespace util */
} /* namespace kmhal */
} /* namespace suskeymaster */
} /* extern "C" */
#endif /* __cplusplus */

#endif /* KEYMASTER_TYPES_H_ */
