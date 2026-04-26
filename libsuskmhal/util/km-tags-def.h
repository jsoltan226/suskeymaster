#ifndef KM_TAG_LIST__

#define KM_TAG_LIST__ /* (name, type, tag_val, param_list_field, bound_enum, asn1_type, asn1_rep) */    \
    /**                                                                                                 \
     * Tag::PURPOSE specifies the set of purposes for which the key may be used.  Possible values       \
     * are defined in the KeyPurpose enumeration.                                                       \
     *                                                                                                  \
     * This tag is repeatable; keys may be generated with multiple values, although an operation has    \
     * a single purpose.  When begin() is called to start an operation, the purpose of the operation    \
     * is specified.  If the purpose specified for the operation is not authorized by the key (the      \
     * key didn't have a corresponding Tag::PURPOSE provided during generation/import), the             \
     * operation must fail with ErrorCode::INCOMPATIBLE_PURPOSE.                                        \
     *                                                                                                  \
     * Must be hardware-enforced.                                                                       \
     */                                                                                                 \
    KM_DECL_TAG(PURPOSE, ENUM_REP, 1, purpose, KeyPurpose, INTEGER, _SET_OF_)                           \
                                                                                                        \
    /**                                                                                                 \
     * Tag::ALGORITHM specifies the cryptographic algorithm with which the key is used.  This tag       \
     * must be provided to generateKey and importKey, and must be specified in the wrapped key          \
     * provided to importWrappedKey.                                                                    \
     *                                                                                                  \
     * Must be hardware-enforced.                                                                       \
     */                                                                                                 \
    KM_DECL_TAG(ALGORITHM, ENUM, 2, algorithm, Algorithm, INTEGER, _)                                   \
                                                                                                        \
    /**                                                                                                 \
     * Tag::KEY_SIZE specifies the size, in bits, of the key, measuring in the normal way for the       \
     * key's algorithm.  For example, for RSA keys, Tag::KEY_SIZE specifies the size of the public      \
     * modulus.  For AES keys it specifies the length of the secret key material.  For 3DES keys it     \
     * specifies the length of the key material, not counting parity bits (though parity bits must      \
     * be provided for import, etc.).  Since only three-key 3DES keys are supported, 3DES               \
     * Tag::KEY_SIZE must be 168.                                                                       \
     *                                                                                                  \
     * Must be hardware-enforced.                                                                       \
     */                                                                                                 \
    KM_DECL_TAG(KEY_SIZE, UINT, 3, keySize, NULL, INTEGER, _)                                           \
                                                                                                        \
    /**                                                                                                 \
     * Tag::BLOCK_MODE specifies the block cipher mode(s) with which the key may be used.  This tag     \
     * is only relevant to AES and 3DES keys.  Possible values are defined by the BlockMode enum.       \
     *                                                                                                  \
     * This tag is repeatable for key generation/import.  For AES and 3DES operations the caller        \
     * must specify a Tag::BLOCK_MODE in the additionalParams argument of begin().  If the mode is      \
     * missing or the specified mode is not in the modes specified for the key during                   \
     * generation/import, the operation must fail with ErrorCode::INCOMPATIBLE_BLOCK_MODE.              \
     *                                                                                                  \
     * Must be hardware-enforced.                                                                       \
     */                                                                                                 \
    KM_DECL_TAG(BLOCK_MODE, ENUM_REP, 4, blockMode, BlockMode, INTEGER, _SET_OF_)                       \
                                                                                                        \
    /**                                                                                                 \
     * Tag::DIGEST specifies the digest algorithms that may be used with the key to perform signing     \
     * and verification operations.  This tag is relevant to RSA, ECDSA and HMAC keys.  Possible        \
     * values are defined by the Digest enum.                                                           \
     *                                                                                                  \
     * This tag is repeatable for key generation/import.  For signing and verification operations,      \
     * the caller must specify a digest in the additionalParams argument of begin().  If the digest     \
     * is missing or the specified digest is not in the digests associated with the key, the            \
     * operation must fail with ErrorCode::INCOMPATIBLE_DIGEST.                                         \
     *                                                                                                  \
     * Must be hardware-enforced.                                                                       \
     */                                                                                                 \
    KM_DECL_TAG(DIGEST, ENUM_REP, 5, digest, Digest, INTEGER, _SET_OF_)                                 \
                                                                                                        \
    /**                                                                                                 \
     * Tag::PADDING specifies the padding modes that may be used with the key.  This tag is relevant    \
     * to RSA, AES and 3DES keys.  Possible values are defined by the PaddingMode enum.                 \
     *                                                                                                  \
     * PaddingMode::RSA_OAEP and PaddingMode::RSA_PKCS1_1_5_ENCRYPT are used only for RSA               \
     * encryption/decryption keys and specify RSA OAEP padding and RSA PKCS#1 v1.5 randomized           \
     * padding, respectively.  PaddingMode::RSA_PSS and PaddingMode::RSA_PKCS1_1_5_SIGN are used        \
     * only for RSA signing/verification keys and specify RSA PSS padding and RSA PKCS#1 v1.5           \
     * deterministic padding, respectively.                                                             \
     *                                                                                                  \
     * PaddingMode::NONE may be used with either RSA, AES or 3DES keys.  For AES or 3DES keys, if       \
     * PaddingMode::NONE is used with block mode ECB or CBC and the data to be encrypted or             \
     * decrypted is not a multiple of the AES block size in length, the call to finish() must fail      \
     * with ErrorCode::INVALID_INPUT_LENGTH.                                                            \
     *                                                                                                  \
     * PaddingMode::PKCS7 may only be used with AES and 3DES keys, and only with ECB and CBC modes.     \
     *                                                                                                  \
     * In any case, if the caller specifies a padding mode that is not usable with the key's            \
     * algorithm, the generation or import method must return ErrorCode::INCOMPATIBLE_PADDING_MODE.     \
     *                                                                                                  \
     * This tag is repeatable.  A padding mode must be specified in the call to begin().  If the        \
     * specified mode is not authorized for the key, the operation must fail with                       \
     * ErrorCode::INCOMPATIBLE_BLOCK_MODE.                                                              \
     *                                                                                                  \
     * Must be hardware-enforced.                                                                       \
     */                                                                                                 \
    KM_DECL_TAG(PADDING, ENUM_REP, 6, padding, PaddingMode, INTEGER, _SET_OF_)                          \
                                                                                                        \
    /**                                                                                                 \
     * Tag::CALLER_NONCE specifies that the caller can provide a nonce for nonce-requiring              \
     * operations.  This tag is boolean, so the possible values are true (if the tag is present) and    \
     * false (if the tag is not present).                                                               \
     *                                                                                                  \
     * This tag is used only for AES and 3DES keys, and is only relevant for CBC, CTR and GCM block     \
     * modes.  If the tag is not present in a key's authorization list, implementations must reject     \
     * any operation that provides Tag::NONCE to begin() with ErrorCode::CALLER_NONCE_PROHIBITED.       \
     *                                                                                                  \
     * Must be hardware-enforced.                                                                       \
     */                                                                                                 \
    KM_DECL_TAG(CALLER_NONCE, BOOL, 7, callerNonce, NULL, NULL, _)                                      \
                                                                                                        \
    /**                                                                                                 \
     * Tag::MIN_MAC_LENGTH specifies the minimum length of MAC that can be requested or verified        \
     * with this key for HMAC keys and AES keys that support GCM mode.                                  \
     *                                                                                                  \
     * This value is the minimum MAC length, in bits.  It must be a multiple of 8 bits.  For HMAC       \
     * keys, the value must be least 64 and no more than 512.  For GCM keys, the value must be at       \
     * least 96 and no more than 128.  If the provided value violates these requirements,               \
     * generateKey() or importKey() must return ErrorCode::UNSUPPORTED_KEY_SIZE.                        \
     *                                                                                                  \
     * Must be hardware-enforced.                                                                       \
     */                                                                                                 \
    KM_DECL_TAG(MIN_MAC_LENGTH, UINT, 8, minMacLength, NULL, INTEGER, _)                                \
                                                                                                        \
    /* Tag 9 reserved */                                                                                \
    KM_DECL_TAG(KDF, ENUM_REP, 9, kdf, KeyDerivationFunction, INTEGER, _SET_OF_)                        \
                                                                                                        \
    /**                                                                                                 \
     * Tag::EC_CURVE specifies the elliptic curve.  EC key generation requests may have                 \
     * Tag:EC_CURVE, Tag::KEY_SIZE, or both.  If both are provided and the size and curve do not        \
     * match, IKeymasterDevice must return ErrorCode::INVALID_ARGUMENT.                                 \
     *                                                                                                  \
     * Must be hardware-enforced.                                                                       \
     */                                                                                                 \
    KM_DECL_TAG(EC_CURVE, ENUM, 10, ecCurve, EcCurve, INTEGER, _)                                       \
                                                                                                        \
    /**                                                                                                 \
     * Tag::RSA_PUBLIC_EXPONENT specifies the value of the public exponent for an RSA key pair.         \
     * This tag is relevant only to RSA keys, and is required for all RSA keys.                         \
     *                                                                                                  \
     * The value is a 64-bit unsigned integer that satisfies the requirements of an RSA public          \
     * exponent.  This value must be a prime number.  IKeymasterDevice implementations must support     \
     * the value 2^16+1 and may support other reasonable values.  If no exponent is specified or if     \
     * the specified exponent is not supported, key generation must fail with                           \
     * ErrorCode::INVALID_ARGUMENT.                                                                     \
     *                                                                                                  \
     * Must be hardware-enforced.                                                                       \
     */                                                                                                 \
    KM_DECL_TAG(RSA_PUBLIC_EXPONENT, ULONG, 200, rsaPublicExponent, NULL, INTEGER, _)                   \
                                                                                                        \
    /* Tag 201 reserved */                                                                              \
    KM_DECL_TAG(ECIES_SINGLE_HASH_MODE, BOOL, 201, eciesSingleHashMode, NULL, NULL, _)                  \
                                                                                                        \
    /**                                                                                                 \
     * Tag::INCLUDE_UNIQUE_ID is specified during key generation to indicate that an attestation        \
     * certificate for the generated key should contain an application-scoped and time-bounded          \
     * device-unique ID.  See Tag::UNIQUE_ID.                                                           \
     *                                                                                                  \
     * Must be hardware-enforced.                                                                       \
     */                                                                                                 \
    KM_DECL_TAG(INCLUDE_UNIQUE_ID, BOOL, 202, includeUniqueId, NULL, NULL, _)                           \
                                                                                                        \
    /**                                                                                                 \
     * Tag::BLOB_USAGE_REQUIREMENTS specifies the necessary system environment conditions for the       \
     * generated key to be used.  Possible values are defined by the KeyBlobUsageRequirements enum.     \
     *                                                                                                  \
     * This tag is specified by the caller during key generation or import to require that the key      \
     * is usable in the specified condition.  If the caller specifies Tag::BLOB_USAGE_REQUIREMENTS      \
     * with value KeyBlobUsageRequirements::STANDALONE the IKeymasterDevice must return a key blob      \
     * that can be used without file system support.  This is critical for devices with encrypted       \
     * disks, where the file system may not be available until after a Keymaster key is used to         \
     * decrypt the disk.                                                                                \
     *                                                                                                  \
     * Must be hardware-enforced.                                                                       \
     */                                                                                                 \
    KM_DECL_TAG(BLOB_USAGE_REQUIREMENTS, ENUM, 301, keyBlobUsageRequirements, KeyBlobUsageRequirements, \
            INTEGER, _)                                                                                 \
                                                                                                        \
    /**                                                                                                 \
     * Tag::BOOTLOADER_ONLY specifies only the bootloader can use the key.                              \
     *                                                                                                  \
     * Any attempt to use a key with Tag::BOOTLOADER_ONLY from the Android system must fail with        \
     * ErrorCode::INVALID_KEY_BLOB.                                                                     \
     *                                                                                                  \
     * Must be hardware-enforced.                                                                       \
     */                                                                                                 \
    KM_DECL_TAG(BOOTLOADER_ONLY, BOOL, 302, bootloaderOnly, NULL, NULL, _)                              \
                                                                                                        \
    /**                                                                                                 \
     * Tag::ROLLBACK_RESISTANCE specifies that the key has rollback resistance, meaning that when       \
     * deleted with deleteKey() or deleteAllKeys(), the key is guaranteed to be permanently deleted     \
     * and unusable.  It's possible that keys without this tag could be deleted and then restored       \
     * from backup.                                                                                     \
     *                                                                                                  \
     * This tag is specified by the caller during key generation or import to require.  If the          \
     * IKeymasterDevice cannot guarantee rollback resistance for the specified key, it must return      \
     * ErrorCode::ROLLBACK_RESISTANCE_UNAVAILABLE.  IKeymasterDevice implementations are not            \
     * required to support rollback resistance.                                                         \
     *                                                                                                  \
     * Must be hardware-enforced.                                                                       \
     */                                                                                                 \
    KM_DECL_TAG(ROLLBACK_RESISTANCE, BOOL, 303, rollbackResistance, NULL, NULL, _)                      \
                                                                                                        \
    /* Reserved for future use. */                                                                      \
    KM_DECL_TAG(HARDWARE_TYPE, ENUM, 304, hardwareType, SecurityLevel, INTEGER, _)                      \
                                                                                                        \
    /**                                                                                                 \
     * Tag::ACTIVE_DATETIME specifies the date and time at which the key becomes active, in             \
     * milliseconds since Jan 1, 1970.  If a key with this tag is used prior to the specified date      \
     * and time, IKeymasterDevice::begin() must return ErrorCode::KEY_NOT_YET_VALID.                    \
     *                                                                                                  \
     * Need not be hardware-enforced.                                                                   \
     */                                                                                                 \
    KM_DECL_TAG(ACTIVE_DATETIME, DATE, 400, activeDateTime, NULL, INTEGER, _)                           \
                                                                                                        \
    /**                                                                                                 \
     * Tag::ORIGINATION_EXPIRE_DATETIME specifies the date and time at which the key expires for        \
     * signing and encryption purposes.  After this time, any attempt to use a key with                 \
     * KeyPurpose::SIGN or KeyPurpose::ENCRYPT provided to begin() must fail with                       \
     * ErrorCode::KEY_EXPIRED.                                                                          \
     *                                                                                                  \
     * The value is a 64-bit integer representing milliseconds since January 1, 1970.                   \
     *                                                                                                  \
     * Need not be hardware-enforced.                                                                   \
     */                                                                                                 \
    KM_DECL_TAG(ORIGINATION_EXPIRE_DATETIME, DATE, 401, originationExpireDateTime, NULL, INTEGER, _)    \
                                                                                                        \
    /**                                                                                                 \
     * Tag::USAGE_EXPIRE_DATETIME specifies the date and time at which the key expires for              \
     * verification and decryption purposes.  After this time, any attempt to use a key with            \
     * KeyPurpose::VERIFY or KeyPurpose::DECRYPT provided to begin() must fail with                     \
     * ErrorCode::KEY_EXPIRED.                                                                          \
     *                                                                                                  \
     * The value is a 64-bit integer representing milliseconds since January 1, 1970.                   \
     *                                                                                                  \
     * Need not be hardware-enforced.                                                                   \
     */                                                                                                 \
    KM_DECL_TAG(USAGE_EXPIRE_DATETIME, DATE, 402, usageExpireDateTime, NULL, INTEGER, _)                \
                                                                                                        \
    /**                                                                                                 \
     * Tag::MIN_SECONDS_BETWEEN_OPS specifies the minimum amount of time that elapses between           \
     * allowed operations using a key.  This can be used to rate-limit uses of keys in contexts         \
     * where unlimited use may enable brute force attacks.                                              \
     *                                                                                                  \
     * The value is a 32-bit integer representing seconds between allowed operations.                   \
     *                                                                                                  \
     * When a key with this tag is used in an operation, the IKeymasterDevice must start a timer        \
     * during the finish() or abort() call.  Any call to begin() that is received before the timer      \
     * indicates that the interval specified by Tag::MIN_SECONDS_BETWEEN_OPS has elapsed must fail      \
     * with ErrorCode::KEY_RATE_LIMIT_EXCEEDED.  This implies that the IKeymasterDevice must keep a     \
     * table of use counters for keys with this tag.  Because memory is often limited, this table       \
     * may have a fixed maximum size and Keymaster may fail operations that attempt to use keys with    \
     * this tag when the table is full.  The table must accommodate at least 8 in-use keys and          \
     * aggressively reuse table slots when key minimum-usage intervals expire.  If an operation         \
     * fails because the table is full, Keymaster returns ErrorCode::TOO_MANY_OPERATIONS.               \
     *                                                                                                  \
     * Must be hardware-enforced.                                                                       \
     */                                                                                                 \
    KM_DECL_TAG(MIN_SECONDS_BETWEEN_OPS, UINT, 403, minSecondsBetweenOps, NULL, INTEGER, _)             \
                                                                                                        \
    /**                                                                                                 \
     * Tag::MAX_USES_PER_BOOT specifies the maximum number of times that a key may be used between      \
     * system reboots.  This is another mechanism to rate-limit key use.                                \
     *                                                                                                  \
     * The value is a 32-bit integer representing uses per boot.                                        \
     *                                                                                                  \
     * When a key with this tag is used in an operation, a key-associated counter must be               \
     * incremented during the begin() call.  After the key counter has exceeded this value, all         \
     * subsequent attempts to use the key must fail with ErrorCode::MAX_OPS_EXCEEDED, until the         \
     * device is restarted.  This implies that the IKeymasterDevice must keep a table of use            \
     * counters for keys with this tag.  Because Keymaster memory is often limited, this table can      \
     * have a fixed maximum size and Keymaster can fail operations that attempt to use keys with        \
     * this tag when the table is full.  The table needs to accommodate at least 8 keys.  If an         \
     * operation fails because the table is full, IKeymasterDevice must return                          \
     * ErrorCode::TOO_MANY_OPERATIONS.                                                                  \
     *                                                                                                  \
     * Must be hardware-enforced.                                                                       \
     */                                                                                                 \
    KM_DECL_TAG(MAX_USES_PER_BOOT, UINT, 404, maxUsesPerBoot, NULL, INTEGER, _)                         \
                                                                                                        \
    /* Internal Samsung tag: all users may use the key. */                                              \
    KM_DECL_TAG(ALL_USERS, BOOL, 500, allUsers, NULL, NULL, _)                                          \
                                                                                                        \
    /**                                                                                                 \
     * Tag::USER_ID specifies the ID of the Android user that is permitted to use the key.              \
     *                                                                                                  \
     * Must not be hardware-enforced.                                                                   \
     */                                                                                                 \
    KM_DECL_TAG(USER_ID, UINT, 501, userId, NULL, INTEGER, _)                                           \
                                                                                                        \
    /**                                                                                                 \
     * Tag::USER_SECURE_ID specifies that a key may only be used under a particular secure user         \
     * authentication state.  This tag is mutually exclusive with Tag::NO_AUTH_REQUIRED.                \
     *                                                                                                  \
     * The value is a 64-bit integer specifying the authentication policy state value which must be     \
     * present in the userId or authenticatorId field of a HardwareAuthToken provided to begin(),       \
     * update(), or finish().  If a key with Tag::USER_SECURE_ID is used without a HardwareAuthToken    \
     * with the matching userId or authenticatorId, the IKeymasterDevice must return                    \
     * ErrorCode::KEY_USER_NOT_AUTHENTICATED.                                                           \
     *                                                                                                  \
     * Tag::USER_SECURE_ID interacts with Tag::AUTH_TIMEOUT in a very important way.  If                \
     * Tag::AUTH_TIMEOUT is present in the key's characteristics then the key is a "timeout-based"      \
     * key, and may only be used if the difference between the current time when begin() is called      \
     * and the timestamp in the HardwareAuthToken is less than the value in Tag::AUTH_TIMEOUT * 1000    \
     * (the multiplier is because Tag::AUTH_TIMEOUT is in seconds, but the HardwareAuthToken            \
     * timestamp is in milliseconds).  Otherwise the IKeymasterDevice must return                       \
     * ErrorCode::KEY_USER_NOT_AUTHENTICATED.                                                           \
     *                                                                                                  \
     * If Tag::AUTH_TIMEOUT is not present, then the key is an "auth-per-operation" key.  In this       \
     * case, begin() must not require a HardwareAuthToken with appropriate contents.  Instead,          \
     * update() and finish() must receive a HardwareAuthToken with Tag::USER_SECURE_ID value in         \
     * userId or authenticatorId fields, and the current operation's operation handle in the            \
     * challenge field.  Otherwise the IKeymasterDevice must return                                     \
     * ErrorCode::KEY_USER_NOT_AUTHENTICATED.                                                           \
     *                                                                                                  \
     * This tag is repeatable.  If repeated, and any one of the values matches the HardwareAuthToken    \
     * as described above, the key is authorized for use.  Otherwise the operation must fail with       \
     * ErrorCode::KEY_USER_NOT_AUTHENTICATED.                                                           \
     *                                                                                                  \
     * Must be hardware-enforced.                                                                       \
     */                                                                                                 \
    KM_DECL_TAG(USER_SECURE_ID, ULONG_REP, 502, userSecureId, NULL, INTEGER, _SET_OF_)                  \
                                                                                                        \
    /**                                                                                                 \
     * Tag::NO_AUTH_REQUIRED specifies that no authentication is required to use this key.  This tag    \
     * is mutually exclusive with Tag::USER_SECURE_ID.                                                  \
     *                                                                                                  \
     * Must be hardware-enforced.                                                                       \
     */                                                                                                 \
    KM_DECL_TAG(NO_AUTH_REQUIRED, BOOL, 503, noAuthRequired, NULL, NULL, _)                             \
                                                                                                        \
    /**                                                                                                 \
     * Tag::USER_AUTH_TYPE specifies the types of user authenticators that may be used to authorize     \
     * this key.                                                                                        \
     *                                                                                                  \
     * The value is one or more values from HardwareAuthenticatorType, ORed together.                   \
     *                                                                                                  \
     * When IKeymasterDevice is requested to perform an operation with a key with this tag, it must     \
     * receive a HardwareAuthToken and one or more bits must be set in both the HardwareAuthToken's     \
     * authenticatorType field and the Tag::USER_AUTH_TYPE value.  That is, it must be true that        \
     *                                                                                                  \
     *    (token.authenticatorType & tag_user_auth_type) != 0                                           \
     *                                                                                                  \
     * where token.authenticatorType is the authenticatorType field of the HardwareAuthToken and        \
     * tag_user_auth_type is the value of Tag::USER_AUTH_TYPE.                                          \
     *                                                                                                  \
     * Must be hardware-enforced.                                                                       \
     */                                                                                                 \
    KM_DECL_TAG(USER_AUTH_TYPE, ENUM, 504, userAuthType, HardwareAuthenticatorType, INTEGER, _)         \
                                                                                                        \
    /**                                                                                                 \
     * Tag::AUTH_TIMEOUT specifies the time in seconds for which the key is authorized for use,         \
     * after user authentication.  If Tag::USER_SECURE_ID is present and this tag is not, then the      \
     * key requires authentication for every usage (see begin() for the details of the                  \
     * authentication-per-operation flow).                                                              \
     *                                                                                                  \
     * The value is a 32-bit integer specifying the time in seconds after a successful                  \
     * authentication of the user specified by Tag::USER_SECURE_ID with the authentication method       \
     * specified by Tag::USER_AUTH_TYPE that the key can be used.                                       \
     *                                                                                                  \
     * Must be hardware-enforced.                                                                       \
     */                                                                                                 \
    KM_DECL_TAG(AUTH_TIMEOUT, UINT, 505, authTimeout, NULL, INTEGER, _)                                 \
                                                                                                        \
    /**                                                                                                 \
     * Tag::ALLOW_WHILE_ON_BODY specifies that the key may be used after authentication timeout if      \
     * device is still on-body (requires on-body sensor).                                               \
     *                                                                                                  \
     * Cannot be hardware-enforced.                                                                     \
     */                                                                                                 \
    KM_DECL_TAG(ALLOW_WHILE_ON_BODY, BOOL, 506, allowWhileOnBody, NULL, NULL, _)                        \
                                                                                                        \
    /**                                                                                                 \
     * Tag::TRUSTED_USER_PRESENCE_REQUIRED is an optional feature that specifies that this key must     \
     * be unusable except when the user has provided proof of physical presence.  Proof of physical     \
     * presence must be a signal that cannot be triggered by an attacker who doesn't have one of:       \
     *                                                                                                  \
     *    a) Physical control of the device or                                                          \
     *                                                                                                  \
     *    b) Control of the secure environment that holds the key.                                      \
     *                                                                                                  \
     * Must be hardware-enforced.                                                                       \
     */                                                                                                 \
    KM_DECL_TAG(TRUSTED_USER_PRESENCE_REQUIRED, BOOL, 507, trustedUserPresenceReq, NULL, NULL, _)       \
                                                                                                        \
    /**                                                                                                 \
     * Tag::TRUSTED_CONFIRMATION_REQUIRED is only applicable to keys with KeyPurpose SIGN, and          \
     * specifies that this key must not be usable unless the user provides confirmation of the data     \
     * to be signed.  Confirmation is proven to keymaster via an approval token.  See                   \
     * CONFIRMATION_TOKEN, as well as the ConfirmationUI HAL.                                           \
     *                                                                                                  \
     * If an attempt to use a key with this tag does not have a cryptographically valid                 \
     * CONFIRMATION_TOKEN provided to finish() or if the data provided to update()/finish() does not    \
     * match the data described in the token, keymaster must return NO_USER_CONFIRMATION.               \
     *                                                                                                  \
     * Must be hardware-enforced.                                                                       \
     */                                                                                                 \
    KM_DECL_TAG(TRUSTED_CONFIRMATION_REQUIRED, BOOL, 508, trustedConfirmationReq, NULL, NULL, _)        \
                                                                                                        \
    /**                                                                                                 \
     * Tag::UNLOCKED_DEVICE_REQUIRED specifies that the key may only be used when the device is         \
     * unlocked.                                                                                        \
     *                                                                                                  \
     * Must be software-enforced.                                                                       \
     */                                                                                                 \
    KM_DECL_TAG(UNLOCKED_DEVICE_REQUIRED, BOOL, 509, unlockedDeviceReq, NULL, NULL, _)                  \
                                                                                                        \
    /**                                                                                                 \
     * Tag::APPLICATION_ID.  When provided to generateKey or importKey, this tag specifies data         \
     * that is necessary during all uses of the key.  In particular, calls to exportKey() and           \
     * getKeyCharacteristics() must provide the same value to the clientId parameter, and calls to      \
     * begin must provide this tag and the same associated data as part of the inParams set.  If        \
     * the correct data is not provided, the method must return ErrorCode::INVALID_KEY_BLOB.            \
     *                                                                                                  \
     * The content of this tag must be bound to the key cryptographically, meaning it must not be       \
     * possible for an adversary who has access to all of the secure world secrets but does not have    \
     * access to the tag content to decrypt the key without brute-forcing the tag content, which        \
     * applications can prevent by specifying sufficiently high-entropy content.                        \
     *                                                                                                  \
     * Must never appear in KeyCharacteristics.                                                         \
     */                                                                                                 \
    KM_DECL_TAG(APPLICATION_ID, BYTES, 601, applicationId, NULL, OCTET_STRING, _)                       \
                                                                                                        \
    /* Internal Samsung tag: key is exportable (doesn't apply to asymmetric i.e. EC and RSA keys).      \
     * Note: Tag::KNOX_OBJECT_PROTECTION_REQUIRED has to be set during key generation/import            \
     * for this one to not be rejected with ErrorCode::INVALID_TAG. */                                  \
    KM_DECL_TAG(EXPORTABLE, BOOL, 602, exportable, NULL, NULL, _)                                       \
                                                                                                        \
    /**                                                                                                 \
     * Tag::APPLICATION_DATA.  When provided to generateKey or importKey, this tag specifies data       \
     * that is necessary during all uses of the key.  In particular, calls to exportKey() and           \
     * getKeyCharacteristics() must provide the same value to the appData parameter, and calls to       \
     * begin must provide this tag and the same associated data as part of the inParams set.  If        \
     * the correct data is not provided, the method must return ErrorCode::INVALID_KEY_BLOB.            \
     *                                                                                                  \
     * The content of this tag must be bound to the key cryptographically, meaning it must not be       \
     * possible for an adversary who has access to all of the secure world secrets but does not have    \
     * access to the tag content to decrypt the key without brute-forcing the tag content, which        \
     * applications can prevent by specifying sufficiently high-entropy content.                        \
     *                                                                                                  \
     * Must never appear in KeyCharacteristics.                                                         \
     */                                                                                                 \
    KM_DECL_TAG(APPLICATION_DATA, BYTES, 700, applicationData, NULL, OCTET_STRING, _)                   \
                                                                                                        \
    /**                                                                                                 \
     * Tag::CREATION_DATETIME specifies the date and time the key was created, in milliseconds since    \
     * January 1, 1970.  This tag is optional and informational only.                                   \
     *                                                                                                  \
     * Tag::CREATION_DATETIME is informational only, and not enforced by anything.  Must be in the      \
     * software-enforced list, if provided.                                                             \
     */                                                                                                 \
    KM_DECL_TAG(CREATION_DATETIME, DATE, 701, creationDateTime, NULL, INTEGER, _)                       \
                                                                                                        \
    /**                                                                                                 \
     * Tag::ORIGIN specifies where the key was created, if known.  This tag must not be specified       \
     * during key generation or import, and must be added to the key characteristics by the             \
     * IKeymasterDevice.  The possible values are defined in the KeyOrigin enum.                        \
     *                                                                                                  \
     * Must be hardware-enforced.                                                                       \
     */                                                                                                 \
    KM_DECL_TAG(ORIGIN, ENUM, 702, keyOrigin, KeyOrigin, INTEGER, _)                                    \
                                                                                                        \
    /* 703 is unused. */                                                                                \
                                                                                                        \
    /**                                                                                                 \
     * Tag::ROOT_OF_TRUST specifies the root of trust, the key used by verified boot to validate the    \
     * operating system booted (if any).  This tag is never provided to or returned from Keymaster      \
     * in the key characteristics.  It exists only to define the tag for use in the attestation         \
     * record.                                                                                          \
     *                                                                                                  \
     * Must never appear in KeyCharacteristics.                                                         \
     */                                                                                                 \
    KM_DECL_TAG(ROOT_OF_TRUST, BYTES, 704, rootOfTrust, NULL, ROOT_OF_TRUST_V3, _)                      \
                                                                                                        \
    /**                                                                                                 \
     * Tag::OS_VERSION specifies the system OS version with which the key may be used.  This tag is     \
     * never sent to the IKeymasterDevice, but is added to the hardware-enforced authorization list     \
     * by the TA.  Any attempt to use a key with a Tag::OS_VERSION value different from the             \
     * currently-running OS version must cause begin(), getKeyCharacteristics() or exportKey() to       \
     * return ErrorCode::KEY_REQUIRES_UPGRADE.  See upgradeKey() for details.                           \
     *                                                                                                  \
     * The value of the tag is an integer of the form MMmmss, where MM is the major version number,     \
     * mm is the minor version number, and ss is the sub-minor version number.  For example, for a      \
     * key generated on Android version 4.0.3, the value would be 040003.                               \
     *                                                                                                  \
     * The IKeymasterDevice HAL must read the current OS version from the system property               \
     * ro.build.version.release and deliver it to the secure environment when the HAL is first          \
     * loaded (mechanism is implementation-defined).  The secure environment must not accept another    \
     * version until after the next boot.  If the content of ro.build.version.release has additional    \
     * version information after the sub-minor version number, it must not be included in               \
     * Tag::OS_VERSION.  If the content is non-numeric, the secure environment must use 0 as the        \
     * system version.                                                                                  \
     *                                                                                                  \
     * Must be hardware-enforced.                                                                       \
     */                                                                                                 \
    KM_DECL_TAG(OS_VERSION, UINT, 705, osVersion, NULL, INTEGER, _)                                     \
                                                                                                        \
    /**                                                                                                 \
     * Tag::OS_PATCHLEVEL specifies the system security patch level with which the key may be used.     \
     * This tag is never sent to the keymaster TA, but is added to the hardware-enforced                \
     * authorization list by the TA.  Any attempt to use a key with a Tag::OS_PATCHLEVEL value          \
     * different from the currently-running system patchlevel must cause begin(),                       \
     * getKeyCharacteristics() or exportKey() to return ErrorCode::KEY_REQUIRES_UPGRADE.  See           \
     * upgradeKey() for details.                                                                        \
     *                                                                                                  \
     * The value of the tag is an integer of the form YYYYMM, where YYYY is the four-digit year of      \
     * the last update and MM is the two-digit month of the last update.  For example, for a key        \
     * generated on an Android device last updated in December 2015, the value would be 201512.         \
     *                                                                                                  \
     * The IKeymasterDevice HAL must read the current system patchlevel from the system property        \
     * ro.build.version.security_patch and deliver it to the secure environment when the HAL is         \
     * first loaded (mechanism is implementation-defined).  The secure environment must not accept      \
     * another patchlevel until after the next boot.                                                    \
     *                                                                                                  \
     * Must be hardware-enforced.                                                                       \
     */                                                                                                 \
    KM_DECL_TAG(OS_PATCHLEVEL, UINT, 706, osPatchLevel, NULL, INTEGER, _)                               \
                                                                                                        \
    /**                                                                                                 \
     * Tag::UNIQUE_ID specifies a unique, time-based identifier.  This tag is never provided to or      \
     * returned from Keymaster in the key characteristics.  It exists only to define the tag for use    \
     * in the attestation record.                                                                       \
     *                                                                                                  \
     * Must be hardware-enforced.                                                                       \
     */                                                                                                 \
    KM_DECL_TAG(UNIQUE_ID, BYTES, 707, uniqueId, NULL, OCTET_STRING, _)                                 \
                                                                                                        \
    /**                                                                                                 \
     * Tag::ATTESTATION_CHALLENGE is used to deliver a "challenge" value to the attestKey() method,     \
     * which must place the value in the KeyDescription SEQUENCE of the attestation extension.  See     \
     * attestKey().                                                                                     \
     *                                                                                                  \
     * Must never appear in KeyCharacteristics.                                                         \
     */                                                                                                 \
    KM_DECL_TAG(ATTESTATION_CHALLENGE, BYTES, 708, attestationChallenge, NULL, OCTET_STRING, _)         \
                                                                                                        \
    /**                                                                                                 \
     * Tag::ATTESTATION_APPLICATION_ID identifies the set of applications which may use a key, used     \
     * only with attestKey().                                                                           \
     *                                                                                                  \
     * Cannot be hardware-enforced.                                                                     \
     */                                                                                                 \
    KM_DECL_TAG(ATTESTATION_APPLICATION_ID, BYTES, 709, attestationApplicationId, NULL,                 \
            OCTET_STRING, _)                                                                            \
                                                                                                        \
    /**                                                                                                 \
     * Tag::ATTESTATION_ID_BRAND provides the device's brand name, as returned by Build.BRAND in        \
     * Android, to attestKey().  This field must be set only when requesting attestation of the         \
     * device's identifiers.                                                                            \
     *                                                                                                  \
     * If the device does not support ID attestation (or destroyAttestationIds() was previously         \
     * called and the device can no longer attest its IDs), any key attestation request that            \
     * includes this tag must fail with ErrorCode::CANNOT_ATTEST_IDS.                                   \
     *                                                                                                  \
     * Must never appear in KeyCharacteristics.                                                         \
     */                                                                                                 \
    KM_DECL_TAG(ATTESTATION_ID_BRAND, BYTES, 710, attestationIdBrand, NULL, OCTET_STRING, _)            \
                                                                                                        \
    /**                                                                                                 \
     * Tag::ATTESTATION_ID_DEVICE provides the device's device name, as returned by Build.DEVICE in     \
     * Android, to attestKey().  This field must be set only when requesting attestation of the         \
     * device's identifiers.                                                                            \
     *                                                                                                  \
     * If the device does not support ID attestation (or destroyAttestationIds() was previously         \
     * called and the device can no longer attest its IDs), any key attestation request that            \
     * includes this tag must fail with ErrorCode::CANNOT_ATTEST_IDS.                                   \
     *                                                                                                  \
     * Must never appear in KeyCharacteristics.                                                         \
     */                                                                                                 \
    KM_DECL_TAG(ATTESTATION_ID_DEVICE, BYTES, 711, attestationIdDevice, NULL, OCTET_STRING, _)          \
                                                                                                        \
    /**                                                                                                 \
     * Tag::ATTESTATION_ID_PRODUCT provides the device's product name, as returned by Build.PRODUCT     \
     * in Android, to attestKey().  This field must be set only when requesting attestation of the      \
     * device's identifiers.                                                                            \
     *                                                                                                  \
     * If the device does not support ID attestation (or destroyAttestationIds() was previously         \
     * called and the device can no longer attest its IDs), any key attestation request that            \
     * includes this tag must fail with ErrorCode::CANNOT_ATTEST_IDS.                                   \
     *                                                                                                  \
     * Must never appear in KeyCharacteristics.                                                         \
     */                                                                                                 \
    KM_DECL_TAG(ATTESTATION_ID_PRODUCT, BYTES, 712, attestationIdProduct, NULL, OCTET_STRING, _)        \
                                                                                                        \
    /**                                                                                                 \
     * Tag::ATTESTATION_ID_SERIAL provides the device's serial number.  This field must be set only     \
     * when requesting attestation of the device's identifiers.                                         \
     *                                                                                                  \
     * If the device does not support ID attestation (or destroyAttestationIds() was previously         \
     * called and the device can no longer attest its IDs), any key attestation request that            \
     * includes this tag must fail with ErrorCode::CANNOT_ATTEST_IDS.                                   \
     *                                                                                                  \
     * Must never appear in KeyCharacteristics.                                                         \
     */                                                                                                 \
    KM_DECL_TAG(ATTESTATION_ID_SERIAL, BYTES, 713, attestationIdSerial, NULL, OCTET_STRING, _)          \
                                                                                                        \
    /**                                                                                                 \
     * Tag::ATTESTATION_ID_IMEI provides the IMEIs for all radios on the device to attestKey().         \
     * This field must be set only when requesting attestation of the device's identifiers.             \
     *                                                                                                  \
     * If the device does not support ID attestation (or destroyAttestationIds() was previously         \
     * called and the device can no longer attest its IDs), any key attestation request that            \
     * includes this tag must fail with ErrorCode::CANNOT_ATTEST_IDS.                                   \
     *                                                                                                  \
     * Must never appear in KeyCharacteristics.                                                         \
     */                                                                                                 \
    KM_DECL_TAG(ATTESTATION_ID_IMEI, BYTES, 714, attestationIdImei, NULL, OCTET_STRING, _)              \
                                                                                                        \
    /**                                                                                                 \
     * Tag::ATTESTATION_ID_MEID provides the MEIDs for all radios on the device to attestKey().         \
     * This field must be set only when requesting attestation of the device's identifiers.             \
     *                                                                                                  \
     * If the device does not support ID attestation (or destroyAttestationIds() was previously         \
     * called and the device can no longer attest its IDs), any key attestation request that            \
     * includes this tag must fail with ErrorCode::CANNOT_ATTEST_IDS.                                   \
     *                                                                                                  \
     * Must never appear in KeyCharacteristics.                                                         \
     */                                                                                                 \
    KM_DECL_TAG(ATTESTATION_ID_MEID, BYTES, 715, attestationIdMeid, NULL, OCTET_STRING, _)              \
                                                                                                        \
    /**                                                                                                 \
     * Tag::ATTESTATION_ID_MANUFACTURER provides the device's manufacturer name, as returned by         \
     * Build.MANUFACTURER in Android, to attestKey().  This field must be set only when requesting      \
     * attestation of the device's identifiers.                                                         \
     *                                                                                                  \
     * If the device does not support ID attestation (or destroyAttestationIds() was previously         \
     * called and the device can no longer attest its IDs), any key attestation request that            \
     * includes this tag must fail with ErrorCode::CANNOT_ATTEST_IDS.                                   \
     *                                                                                                  \
     * Must never appear in KeyCharacteristics.                                                         \
     */                                                                                                 \
    KM_DECL_TAG(ATTESTATION_ID_MANUFACTURER, BYTES, 716, attestationIdManufacturer, NULL,               \
            OCTET_STRING, _)                                                                            \
                                                                                                        \
    /**                                                                                                 \
     * Tag::ATTESTATION_ID_MODEL provides the device's model name, as returned by Build.MODEL in        \
     * Android, to attestKey().  This field must be set only when requesting attestation of the         \
     * device's identifiers.                                                                            \
     *                                                                                                  \
     * If the device does not support ID attestation (or destroyAttestationIds() was previously         \
     * called and the device can no longer attest its IDs), any key attestation request that            \
     * includes this tag must fail with ErrorCode::CANNOT_ATTEST_IDS.                                   \
     *                                                                                                  \
     * Must never appear in KeyCharacteristics.                                                         \
     */                                                                                                 \
    KM_DECL_TAG(ATTESTATION_ID_MODEL, BYTES, 717, attestationIdModel, NULL, OCTET_STRING, _)            \
                                                                                                        \
    /**                                                                                                 \
     * Tag::VENDOR_PATCHLEVEL specifies the vendor image security patch level with which the key may    \
     * be used.  This tag is never sent to the keymaster TA, but is added to the hardware-enforced      \
     * authorization list by the TA.  Any attempt to use a key with a Tag::VENDOR_PATCHLEVEL value      \
     * different from the currently-running system patchlevel must cause begin(),                       \
     * getKeyCharacteristics() or exportKey() to return ErrorCode::KEY_REQUIRES_UPGRADE.  See           \
     * upgradeKey() for details.                                                                        \
     *                                                                                                  \
     * The value of the tag is an integer of the form YYYYMMDD, where YYYY is the four-digit year of    \
     * the last update, MM is the two-digit month and DD is the two-digit day of the last update.       \
     * For example, for a key generated on an Android device last updated on June 5, 2018, the value    \
     * would be 20180605.                                                                               \
     *                                                                                                  \
     * The IKeymasterDevice HAL must read the current vendor patchlevel from the system property        \
     * ro.vendor.build.security_patch and deliver it to the secure environment when the HAL is first    \
     * loaded (mechanism is implementation-defined).  The secure environment must not accept another    \
     * patchlevel until after the next boot.                                                            \
     *                                                                                                  \
     * Must be hardware-enforced.                                                                       \
     */                                                                                                 \
    KM_DECL_TAG(VENDOR_PATCHLEVEL, UINT, 718, vendorPatchLevel, NULL, INTEGER, _)                       \
                                                                                                        \
    /**                                                                                                 \
     * Tag::BOOT_PATCHLEVEL specifies the boot image (kernel) security patch level with which the       \
     * key may be used.  This tag is never sent to the keymaster TA, but is added to the                \
     * hardware-enforced authorization list by the TA.  Any attempt to use a key with a                 \
     * Tag::BOOT_PATCHLEVEL value different from the currently-running system patchlevel must           \
     * cause begin(), getKeyCharacteristics() or exportKey() to return                                  \
     * ErrorCode::KEY_REQUIRES_UPGRADE.  See upgradeKey() for details.                                  \
     *                                                                                                  \
     * The value of the tag is an integer of the form YYYYMMDD, where YYYY is the four-digit year of    \
     * the last update, MM is the two-digit month and DD is the two-digit day of the last update.       \
     * For example, for a key generated on an Android device last updated on June 5, 2018, the value    \
     * would be 20180605.  If the day is not known, 00 may be substituted.                              \
     *                                                                                                  \
     * During each boot, the bootloader must provide the patch level of the boot image to the secure    \
     * environment (mechanism is implementation-defined).                                               \
     *                                                                                                  \
     * Must be hardware-enforced.                                                                       \
     */                                                                                                 \
    KM_DECL_TAG(BOOT_PATCHLEVEL, UINT, 719, bootPatchLevel, NULL, INTEGER, _)                           \
                                                                                                        \
    /* Internal Samsung tag: key is a storage key (e.g. FBE). */                                        \
    KM_DECL_TAG(STORAGE_KEY, BOOL, 722, storageKey, NULL, NULL, _)                                      \
                                                                                                        \
    /* Internal Samsung tag: used to validate datetime requirements in begin(). */                      \
    KM_DECL_TAG(INTERNAL_CURRENT_DATETIME, DATE, 800, internalCurrentDateTime, NULL, INTEGER, _)        \
                                                                                                        \
    /* Internal Samsung tags: mirror of OS/vendor patchlevel stored in the keyblob.                     \
     * Also used by the bootloader to configure keymaster patch level info */                           \
    KM_DECL_TAG(INTERNAL_OS_VERSION, UINT, 805, internalOsVersion, NULL, INTEGER, _)                    \
    KM_DECL_TAG(INTERNAL_OS_PATCHLEVEL, UINT, 806, internalOsPatchLevel, NULL, INTEGER, _)              \
    KM_DECL_TAG(INTERNAL_VENDOR_PATCHLEVEL, UINT, 818, internalVendorPatchLevel, NULL, INTEGER, _)      \
                                                                                                        \
    /**                                                                                                 \
     * Tag::ASSOCIATED_DATA provides "associated data" for AES-GCM encryption or decryption. This       \
     * tag is provided to update and specifies data that is not encrypted/decrypted, but is used in     \
     * computing the GCM tag.                                                                           \
     *                                                                                                  \
     * Must never appear in KeyCharacteristics.                                                         \
     */                                                                                                 \
    KM_DECL_TAG(ASSOCIATED_DATA, BYTES, 1000, associatedData, NULL, OCTET_STRING, _)                    \
                                                                                                        \
    /**                                                                                                 \
     * Tag::NONCE is used to provide or return a nonce or Initialization Vector (IV) for AES-GCM,       \
     * AES-CBC, AES-CTR, or 3DES-CBC encryption or decryption.  This tag is provided to begin during    \
     * encryption and decryption operations.  It is only provided to begin if the key has               \
     * Tag::CALLER_NONCE.  If not provided, an appropriate nonce or IV must be randomly generated by    \
     * Keymaster and returned from begin.                                                               \
     *                                                                                                  \
     * The value is a blob, an arbitrary-length array of bytes.  Allowed lengths depend on the mode:    \
     * GCM nonces are 12 bytes in length; AES-CBC and AES-CTR IVs are 16 bytes in length, 3DES-CBC      \
     * IVs are 8 bytes in length.                                                                       \
     *                                                                                                  \
     * Must never appear in KeyCharacteristics.                                                         \
     */                                                                                                 \
    KM_DECL_TAG(NONCE, BYTES, 1001, nonce, NULL, OCTET_STRING, _)                                       \
                                                                                                        \
    /* Stores a user authentication token for operations that require it. */                            \
    KM_DECL_TAG(AUTH_TOKEN, BYTES, 1002, authToken, NULL, OCTET_STRING, _)                              \
                                                                                                        \
    /**                                                                                                 \
     * Tag::MAC_LENGTH provides the requested length of a MAC or GCM authentication tag, in bits.       \
     *                                                                                                  \
     * The value is the MAC length in bits.  It must be a multiple of 8 and at least as large as the    \
     * value of Tag::MIN_MAC_LENGTH associated with the key.  Otherwise, begin() must return            \
     * ErrorCode::INVALID_MAC_LENGTH.                                                                   \
     *                                                                                                  \
     * Must never appear in KeyCharacteristics.                                                         \
     */                                                                                                 \
    KM_DECL_TAG(MAC_LENGTH, UINT, 1003, macLength, NULL, INTEGER, _)                                    \
                                                                                                        \
    /**                                                                                                 \
     * Tag::RESET_SINCE_ID_ROTATION specifies whether the device has been factory reset since the       \
     * last unique ID rotation.  Used for key attestation.                                              \
     *                                                                                                  \
     * Must never appear in KeyCharacteristics.                                                         \
     */                                                                                                 \
    KM_DECL_TAG(RESET_SINCE_ID_ROTATION, BOOL, 1004, resetSinceIdRotation, NULL, NULL, _)               \
                                                                                                        \
    /**                                                                                                 \
     * Tag::CONFIRMATION_TOKEN is used to deliver a cryptographic token proving that the user           \
     * confirmed a signing request.  The content is a full-length HMAC-SHA256 value.  See the           \
     * ConfirmationUI HAL for details of token computation.                                             \
     *                                                                                                  \
     * Must never appear in KeyCharacteristics.                                                         \
     */                                                                                                 \
    KM_DECL_TAG(CONFIRMATION_TOKEN, BYTES, 1005, confirmationToken, NULL, OCTET_STRING, _)              \
                                                                                                        \
    /** Samsung-specific tags **/                                                                       \
                                                                                                        \
    /* Used to enforce that the key can only be (imported/generated ?) & SAK-attested on                \
     * a samsung-official device with intact trust boot and warranty status.                            \
     * Also used to gate the `EXPORTABLE` tag, for some reason. */                                      \
    KM_DECL_TAG(KNOX_OBJECT_PROTECTION_REQUIRED, BOOL, 2000, knoxObjectProtectionRequired, NULL,        \
            NULL, _)                                                                                    \
                                                                                                        \
    /** Samsung Attestation Key (SAK) attestation tags **/                                              \
                                                                                                        \
    /** Parameters for SAK attestation,                                                                 \
     * with a similar role to Tag::ATTESTATION_CHALLENGE & Tag::ATTESTATION_ID_* */                     \
    KM_DECL_TAG(KNOX_CREATOR_ID, BYTES, 2001, knoxCreatorId, NULL, OCTET_STRING, _)                     \
    KM_DECL_TAG(KNOX_ADMINISTRATOR_ID, BYTES, 2002, knoxAdministratorId, NULL, OCTET_STRING, _)         \
    KM_DECL_TAG(KNOX_ACCESSOR_ID, BYTES, 2003, knoxAccessorId, NULL, OCTET_STRING, _)                   \
                                                                                                        \
    /* Also set this to the string "samsung" to enable ID attestation with SAK                          \
     * (ID attestation is disabled for non-SAK attestations) */                                         \
    KM_DECL_TAG(SAMSUNG_ATTESTATION_ROOT, BYTES, 2102, samsungAttestationRoot, NULL, OCTET_STRING, _)   \
                                                                                                        \
    /* Used to supply an alternative value for the attestation leaf cert's subject                      \
     * other than the default "CN=Android Keystore Key".                                                \
     * Multiple subject name entries may be supplied in the following format:                           \
     *  entry1=value1,entry2=value2, ...                                                                \
     * although note that the entries have to be valid X.509 NAMEs, such as CN, SN, OU, etc.            \
     *                                                                                                  \
     * Can be set both in the key and attestation parameters,                                           \
     * where the one in the attestation params overrides the one in the key.                            \
     * Appears to also work for normal (non-SAK) attestations.                                          \
     */                                                                                                 \
    KM_DECL_TAG(SAMSUNG_CERTIFICATE_SUBJECT, BYTES, 2103, samsungCertificateSubject, NULL,              \
            OCTET_STRING, _)                                                                            \
                                                                                                        \
    /* Used to set an alternative value for the X509v3 keyUsage                                         \
     * critical extension in the attestation leaf cert.                                                 \
     * The value supplied is a mask of the keyUsage values, e.g.                                        \
     *  0x90 for digitalSignature|dataEncipherment (0x80|0x10) */                                       \
    KM_DECL_TAG(SAMSUNG_KEY_USAGE, UINT, 2104, samsungKeyUsage, NULL, INTEGER, _)                       \
                                                                                                        \
    /* Used to set an alternative value for the X509v3 extendedKeyUsage                                 \
     * non-critical extension in the attestation leaf cert.                                             \
     * Multiple keyUsage values may be supplied, either as a name or an OID,                            \
     * separated by a comma, like so:                                                                   \
     *  `serverAuth,codeSigning, ...` OR `1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.3, ...`                     \
     *                                                                                                  \
     * Exclusive to SAK attestations. */                                                                \
    KM_DECL_TAG(SAMSUNG_EXTENDED_KEY_USAGE, BYTES, 2105, samsungExtendedKeyUsage, NULL,                 \
            OCTET_STRING, _)                                                                            \
                                                                                                        \
    /* Used to set an alternative value for the X509v3 subjectAltName                                   \
     * non-critical extension in the attestation leaf cert.                                             \
     * Multiple subject name entries may be supplied in the following format:                           \
     *  entry1=value1,entry2=value2, ...                                                                \
     * although note that the entries can only be the following X.509 alt names:                        \
     *  "rfc822Name", "dNSName", "uniformResourceIdentifier", "iPAddress"                               \
     *                                                                                                  \
     * Exclusive to SAK attestations. */                                                                \
    KM_DECL_TAG(SAMSUNG_SUBJECT_ALTERNATIVE_NAME, BYTES, 2106, samsungSubjectAlternativeName, NULL,     \
            OCTET_STRING, _)                                                                            \
                                                                                                        \
    /** Miscellaneous (attestation?) tags **/                                                           \
                                                                                                        \
    /* Used to securely communitate the results between Trusted Applications                            \
     * inside the TEE - the output can only be `tz_unwrap()`ped by a given TA.                          \
     * In other words, binds the keymaster operation to a given TA identifier. */                       \
    KM_DECL_TAG(SAMSUNG_REQUESTING_TA, BYTES, 2300, samsungRequestingTA, NULL, OCTET_STRING, _)         \
                                                                                                        \
    /* Tag indicating that the root of trust value (Tag::ROOT_OF_TRUST)                                 \
     * should be added to the key parameters before a `begin` operation. */                             \
    KM_DECL_TAG(SAMSUNG_ROT_REQUIRED, BOOL, 2301, samsungRotRequired, NULL, NULL, _)                    \
                                                                                                        \
    /* Set this tag to enable SAK on warranty void ("compromised") devices.                             \
     * Makes the "INTEGRITY" SEQUENCE be added to the hardwareEnforced auth list. */                    \
    KM_DECL_TAG(SAMSUNG_ATTEST_INTEGRITY, BOOL, 2302, samsungAttestIntegrity, NULL, NULL, _)            \
                                                                                                        \
    /* Parameter for SAK KNOX attestation */                                                            \
    KM_DECL_TAG(SAMSUNG_AUTHENTICATE_PACKAGE, BYTES, 2303, samsungAuthPackage, NULL, OCTET_STRING, _)   \
                                                                                                        \
    /* Tag indicating that a "legacy" root of trust value should be used                                \
     * with the key (for unwrapping and attestations).                                                  \
     * Used for old encrypted key blobs in a kind of "compatibility mode".                              \
     * Only available in orange state (unlocked bootloader). */                                         \
    KM_DECL_TAG(SAMSUNG_LEGACY_ROT, BOOL, 2304, samsungLegacyRot, NULL, NULL, _)                        \
                                                                                                        \
    /* Tag indicating that a given key is stored in a StrongBox.                                        \
     * Stored in plain text in the outer encrypted key blob parameters. */                              \
    KM_DECL_TAG(USE_SECURE_PROCESSOR, BOOL, 3000, useSecureProcessor, NULL, NULL, _)                    \
                                                                                                        \
    /** KM Operation tags **/                                                                           \
                                                                                                        \
    /* An internal tag that represents the operation handle returned by `begin()`                       \
     * and used in `update()` and `finish()`. */                                                        \
    KM_DECL_TAG(OPERATION_HANDLE, ULONG, 5011, operationHandle, NULL, INTEGER, _)                       \
                                                                                                        \
    /* An internal parameter tag indicating that the operation requires authentication.                 \
     * Set if any of the following tags are present in the key description:                             \
     *  Tag::AUTH_TIMEOUT, Tag::USER_SECURE_ID */                                                       \
    KM_DECL_TAG(OP_AUTH, BOOL, 5012, opAuth, NULL, NULL, _)                                             \
                                                                                                        \
    /* An internal parameter tag indicating that the key requires authentication.                       \
     * Set if any of the following tags are present in the key description:                             \
     *  SamsungTag::AUTH_TOKEN, Tag::AUTH_TIMEOUT, Tag::USER_AUTH_TYPE, Tag::USER_SECURE_ID */          \
    KM_DECL_TAG(KEY_AUTH, BOOL, 5013, keyAuth, NULL, NULL, _)                                           \
                                                                                                        \
    /* Set this tag to enable SAK attestation */                                                        \
    KM_DECL_TAG(IS_SAMSUNG_KEY, BOOL, 5029, isSamsungKey, NULL, NULL, _)                                \
                                                                                                        \
    /* An internal tag indicating that an operation (`begin()`, `update()`, `finish()`)                 \
     * has failed and should be cleaned up. */                                                          \
    KM_DECL_TAG(OPERATION_FAILED, BOOL, 5030, operationFailed, NULL, NULL, _)                           \
                                                                                                        \
    /* An internal tag that contains a bitmask of:                                                      \
     * "oem flag" (0x01) - the result of an oem-specific check                                          \
     *      (e.g. "SW fuse" blown on QC devices); set if not ok                                         \
     * "trust boot" (0x02) - knox trust boot status; set if not ok                                      \
     * "warranty" (0x04) - knox warranty status; set if void                                            \
     * "eng build type" (0x10) - whether the current system is an engineering binary                    \
     *                                                                                                  \
     * also some flags conditionally enabled at compile time,                                           \
     * used to work around some issues with bootloader API failures                                     \
     * causing the salt value to break (?):                                                             \
     *                                                                                                  \
     * "default trust boot" (0x20) - knox trust boot status for "default" RoT; set if not OK            \
     * "default knox warranty" (0x40) - knox warranty status for "default" RoT; set if void             \
     *                                                                                                  \
     * This value is added to the salt (along with Tag::ROOT_OF_TRUST)                                  \
     * used for all key blob wrapping and unwrapping operations,                                        \
     * so any change in its value render all key blobs unusable. */                                     \
    KM_DECL_TAG(INTEGRITY_STATUS, UINT, 5031, integrityStatus, NULL, INTEGER, _)                        \
                                                                                                        \
    /** Encrypted key blob tags **/                                                                     \
                                                                                                        \
    /* Initialization vector used for AES-256-GCM decryption,                                           \
     * stored in the outer encrypted keyblob parameters in plain text */                                \
    KM_DECL_TAG(EKEY_BLOB_IV, BYTES, 5000, ekeyBlobIV, NULL, OCTET_STRING, _)                           \
                                                                                                        \
    /* AES-256-GCM authentication tag, stored in the outer keyblob in plain text */                     \
    KM_DECL_TAG(EKEY_BLOB_AUTH_TAG, BYTES, 5001, ekeyBlobAuthTag, NULL, OCTET_STRING, _)                \
                                                                                                        \
    /* Usage count tag used to enforce Tag:MAX_USES_PER_BOOT */                                         \
    KM_DECL_TAG(EKEY_BLOB_CURRENT_USES_PER_BOOT, UINT, 5003, ekeyBlobCurrentUsesPerBoot, NULL,          \
            INTEGER, _)                                                                                 \
                                                                                                        \
    /* Time of last operation, used to enforce tags such as                                             \
     * Tag:MIN_SECONDS_BETWEEN_OPS and Tag:AUTH_TIMEOUT */                                              \
    KM_DECL_TAG(EKEY_BLOB_LAST_OP_TIMESTAMP, ULONG, 5004, ekeyBlobLastOpTimestamp, NULL, INTEGER, _)    \
                                                                                                        \
    /* A flag indicating that a key blob is to be upgraded to a new version (`upgradeKey`) */           \
    KM_DECL_TAG(EKEY_BLOB_DO_UPGRADE, UINT, 5005, ekeyBlobDoUpgrade, NULL, INTEGER, _)                  \
                                                                                                        \
    /* Used for some special types of HMAC keys.                                                        \
     * Both of these are themselves HMAC'd to derive a key encryption key,                              \
     * which is set as the blob's APPLICATION_ID. */                                                    \
    KM_DECL_TAG(EKEY_BLOB_PASSWORD, BYTES, 5006, ekeyBlobPassword, NULL, OCTET_STRING, _)               \
    KM_DECL_TAG(EKEY_BLOB_SALT, BYTES, 5007, ekeyBlobSalt, NULL, OCTET_STRING, _)                       \
                                                                                                        \
    /* Encrypted key blob version, stored in the EKEY blob in plain text.                               \
     * Typically `40` for keymaster 4.0 blobs. */                                                       \
    KM_DECL_TAG(EKEY_BLOB_ENC_VER, UINT, 5008, ekeyBlobEncVer, NULL, INTEGER, _)                        \
                                                                                                        \
    /* A tag indicating that the inner encrypted key blob                                               \
     * is not wrapped in an ASN.1 container.                                                            \
     * Originally meant for specific types of HMAC keys,                                                \
     * just like EKEY_BLOB_PASSWORD and EKEY_BLOB_SALT. */                                              \
    KM_DECL_TAG(EKEY_BLOB_RAW, UINT, 5009, ekeyBlobRaw, NULL, INTEGER, _)                               \
                                                                                                        \
    /* A per-encryption unique random value,                                                            \
     * added to the key wrapping salt & AES-256-GCM authentication tag.                                 \
     * Typically stored in the outer encrypted key blob in plain text.                                  \
     *                                                                                                  \
     * Added by Samsung to mitigate the infamous Keymaster TA IV reuse vulnerability */                 \
    KM_DECL_TAG(EKEY_BLOB_UNIQ_KDM, BYTES, 5010, ekeyBlobUniqKDM, NULL, OCTET_STRING, _)                \
                                                                                                        \
    /* Used in computeSharedHmac (stores the HMAC verification token SEQUENCE). */                      \
    KM_DECL_TAG(VERIFICATION_TOKEN, BYTES, 5200, verificationToken, NULL, OCTET_STRING, _)              \
                                                                                                        \
    /* A flag indicating that the usage count                                                           \
     * (Tag:EKEY_BLOB_CURRENT_USES_PER_BOOT, Tag:MAX_USES_PER_BOOT)                                     \
     * should be incremented */                                                                         \
    KM_DECL_TAG(EKEY_BLOB_INC_USE_COUNT, UINT, 5202, ekeyBlobIncUseCount, NULL, INTEGER, _)             \
                                                                                                        \
    /** Keybox provisioning tags **/                                                                    \
                                                                                                        \
    /* Used to label a validation token of the RSA attestation private key */                           \
    KM_DECL_TAG(PROV_GAK_RSA_VTOKEN, BYTES, 5114, provGakRsaVtoken, NULL, OCTET_STRING, _)              \
                                                                                                        \
    /* Used to label a validation token of the EC attestation private key */                            \
    KM_DECL_TAG(PROV_GAK_EC_VTOKEN, BYTES, 5115, provGakEcVtoken, NULL, OCTET_STRING, _)                \
                                                                                                        \
    /* Used to label a validation token of the SAK EC private key */                                    \
    KM_DECL_TAG(PROV_SAK_EC_VTOKEN, BYTES, 5116, provSakEcVtoken, NULL, OCTET_STRING, _)                \
                                                                                                        \
    /* Used to label the RSA attestation private key, and also to provide it to `attestKey` */          \
    KM_DECL_TAG(PROV_GAK_RSA, BYTES, 5117, provGakRsa, NULL, OCTET_STRING, _)                           \
                                                                                                        \
    /* Used to label the EC attestation private key, and also to provide it to `attestKey` */           \
    KM_DECL_TAG(PROV_GAK_EC, BYTES, 5118, provGakEc, NULL, OCTET_STRING, _)                             \
                                                                                                        \
    /* Used to label the SAK private key, and also provide it to `attestKey` */                         \
    KM_DECL_TAG(PROV_SAK_EC, BYTES, 5119, provSakEc, NULL, OCTET_STRING, _)                             \
                                                                                                        \
    /* Used to label the first intermediate cert in the RSA cert chain ("issuer" of the key),           \
     * and also to provide it to `attestKey` */                                                         \
    KM_DECL_TAG(PROV_GAC_RSA1, BYTES, 5120, provGacRsa1, NULL, OCTET_STRING, _)                         \
                                                                                                        \
    /* Used to label the second intermediate cert in the RSA cert chain (the "OEM" cert) */             \
    KM_DECL_TAG(PROV_GAC_RSA2, BYTES, 5121, provGacRsa2, NULL, OCTET_STRING, _)                         \
                                                                                                        \
    /* Used to label the root of the RSA cert chain */                                                  \
    KM_DECL_TAG(PROV_GAC_RSA3, BYTES, 5122, provGacRsa3, NULL, OCTET_STRING, _)                         \
                                                                                                        \
    /* Used to label the first intermediate cert in the EC cert chain ("issuer" of the key),            \
     * and also to provide it to `attestKey` */                                                         \
    KM_DECL_TAG(PROV_GAC_EC1, BYTES, 5123, provGacEc1, NULL, OCTET_STRING, _)                           \
                                                                                                        \
    /* Used to label the second intermediate cert in the EC cert chain (the "OEM" cert) */              \
    KM_DECL_TAG(PROV_GAC_EC2, BYTES, 5124, provGacEc2, NULL, OCTET_STRING, _)                           \
                                                                                                        \
    /* Used to label the root of the EC cert chain */                                                   \
    KM_DECL_TAG(PROV_GAC_EC3, BYTES, 5125, provGacEc3, NULL, OCTET_STRING, _)                           \
                                                                                                        \
    /** StrongBox tags' values are yet to be reverse-engineered. **/                                    \
                                                                                                        \
    /* Used to label the first intermediate cert in the StrongBox EC cert chain */                      \
    /* KM_TAG_PROV_SGAC_EC1 */                                                                          \
                                                                                                        \
    /* Used to label the second intermediate cert in the StrongBox EC cert chain                        \
     * (the "OEM" cert) */                                                                              \
    /* KM_TAG_PROV_SGAC_EC2 */                                                                          \
                                                                                                        \
    /* Used to label the root of the StrongBox EC cert chain */                                         \
    /* KM_TAG_PROV_SGAC_EC3 */                                                                          \
                                                                                                        \
    /* Used to label the first intermediate cert in the StrongBox RSA cert chain                        \
     * ("issuer" of the key) */                                                                         \
    /* KM_TAG_PROV_SGAC_RSA1 */                                                                         \
                                                                                                        \
    /* Used to label the second intermediate cert in the StrongBox RSA cert chain                       \
     * (the "OEM" cert) */                                                                              \
    /* KM_TAG_PROV_SGAC_RSA2 */                                                                         \
                                                                                                        \
    /* Used to label the root of the StrongBox RSA cert chain */                                        \
    /* KM_TAG_PROV_SGAC_RSA3 */                                                                         \

#endif /* KM_TAG_LIST__ */
