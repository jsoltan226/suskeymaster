#define HIDL_DISABLE_INSTRUMENTATION
#include "cli.hpp"
#include "endian.h"
#include <core/int.h>
#include <core/util.h>
#include <hidl/HidlSupport.h>
#ifndef SUSKEYMASTER_BUILD_HOST
#include <libsuskmhal/transport/hidl-hal.h>
#include <libsuskmhal/transport/hidl-base.h>
#include <libsuskmhal/transport/hidl-parcel.h>
#include <libsuskmhal/transport/km-hidl-hal.hpp>
#include <libsuskmhal/transport/km-hidl-types.hpp>
#endif /* SUSKEYMASTER_BUILD_HOST */
#include <android/hardware/keymaster/generic/types.h>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <cinttypes>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

namespace suskeymaster {
namespace cli {
namespace gatekeeper {

static constexpr u8 SYNTHETIC_PASSWORD_VERSION_V1 = 1;
static constexpr u8 SYNTHETIC_PASSWORD_VERSION_V2 = 2;
static constexpr u8 SYNTHETIC_PASSWORD_VERSION_V3 = 3;

static constexpr u8 PROTECTOR_TYPE_LSKF_BASED = 0;
/*
static constexpr u8 PROTECTOR_TYPE_STRONG_TOKEN_BASED = 1;
static constexpr u8 PROTECTOR_TYPE_WEAK_TOKEN_BASED = 2;
*/
static constexpr const char PROTECTOR_SECRET_PERSONALIZATION[] = "application-id";

static int decrypt_keymaster(HidlSusKeymaster& hal, hidl_vec<u8> const& auth_token,
                             hidl_vec<u8> const& keyblob, hidl_vec<u8> const& blob,
                             hidl_vec<u8>& out);

static int decrypt_software(hidl_vec<u8> const& secret, hidl_vec<u8> const& blob,
                            hidl_vec<u8>& out);

static int decrypt_v1_blob(HidlSusKeymaster& hal, hidl_vec<u8> const& auth_token,
                           hidl_vec<u8> const& keyblob, hidl_vec<u8> const& protector_secret,
                           hidl_vec<u8> const& blob, hidl_vec<u8>& out);

static int decrypt_v2_v3_blob(HidlSusKeymaster& hal, hidl_vec<u8> const& auth_token,
                              hidl_vec<u8> const& keyblob, hidl_vec<u8> const& protector_secret,
                              hidl_vec<u8> const& blob, hidl_vec<u8>& out);

/** See "hardware/interfaces/gatekeeper/1.0/types.hal"
 ** and "hardware/interfaces/gatekeeper/1.0/IGatekeeper.hal" **/

enum class GK_HAL_CMD : u32 {
    ENROLL = 1,
    VERIFY = 2,
    DELETE_USER = 3,
    DELETE_ALL_USERS = 4
};

/**
 * Gatekeeper response codes; success >= 0; error < 0
 */
enum class GatekeeperStatusCode : i32 {
    STATUS_REENROLL       =  1,  // success, but upper layers should re-enroll
                                 // the verified password due to a version change
    STATUS_OK             =  0,  // operation is successful
    ERROR_GENERAL_FAILURE = -1,  // operation failed
    ERROR_RETRY_TIMEOUT   = -2,  // operation should be retried after timeout
    ERROR_NOT_IMPLEMENTED = -3,  // operation is not implemented
};
static const char * gatekeeper_status_toString(i32 s);

/**
 * Gatekeeper response to any/all requests has this structure as mandatory part
 */
struct GatekeeperResponse {
    /** request completion status */
    GatekeeperStatusCode code __attribute__((aligned(8)));
    /**
     * retry timeout in ms, if code == ERROR_RETRY_TIMEOUT
     * otherwise unused (0)
     */
    uint32_t timeout __attribute__((aligned(4)));
    /** optional crypto blob. Opaque to Android system. */
    hidl_vec<u8> data __attribute((aligned(8)));
};
static_assert(offsetof(GatekeeperResponse, code) == 0, "wrong offset");
static_assert(offsetof(GatekeeperResponse, timeout) == 4, "wrong offset");
static_assert(offsetof(GatekeeperResponse, data) == 8, "wrong offset");
static_assert(sizeof(GatekeeperResponse) == 24, "wrong size");
static_assert(alignof(GatekeeperResponse) == 8, "wrong alignment");

/* "system/gatekeeper/include/gatekeeper/password_handle.h" */
#define HANDLE_FLAG_THROTTLE_SECURE 1;
#define HANDLE_VERSION_THROTTLE 2;
typedef uint64_t secure_id_t;
typedef uint64_t salt_t;
static constexpr u8 HANDLE_VERSION = 2;
struct __attribute__ ((__packed__)) password_handle_t {
    /* fields included in signature */
    u8 version;
    secure_id_t user_id;

    uint64_t flags;

    /* fields not included in signature */
    salt_t salt;
    u8 signature[32];

    bool hardware_backed;
};

#ifndef SUSKEYMASTER_BUILD_HOST
static int read_gatekeeper_response(const struct kmhal_hidl_parcel *p,
                                    size_t *off_p,
                                    const void **out, size_t out_size);

static constexpr const char *gatekeeper_fqname = "android.hardware.gatekeeper@1.0::IGatekeeper";
static constexpr const char *gatekeeper_instname = "default";
#endif /* SUSKEYMASTER_BUILD_HOST */

gk_hal::gk_hal() {
    this->owns = false;
    this->hal_sp = nullptr;

#ifndef SUSKEYMASTER_BUILD_HOST
    this->hal_sp = kmhal_hidl_hal_sp_new_get(gatekeeper_fqname, gatekeeper_instname, nullptr, false);
    if (this->hal_sp == nullptr) {
        std::cerr << "Couldn't obtain a handle to the Gatekeeper HAL" << std::endl;
        return;
    }

    std::cout << "Successfully initialized Gatekeeper HAL" << std::endl;
    this->owns = true;
#else
    std::cerr << "Gatekeeper HAL not supported on host build" << std::endl;
#endif /* SUSKEYMASTER_BUILD_HOST */
}

gk_hal::gk_hal(HidlSusKeymaster& kmhal) {
    this->owns = false;
    this->hal_sp = nullptr;

    /* Reuse the binder device from the already initialized keymaster HAL */

#ifndef SUSKEYMASTER_BUILD_HOST
    struct kmhal_hidl_hal_sp *kmhal_sp = kmhal.getHalSp();
    if (kmhal_sp == nullptr) {
        std::cerr << "Keymaster HAL handle is NULL!" << std::endl;
        return;
    }

    this->hal_sp = kmhal_hidl_hal_sp_new_get(gatekeeper_fqname, gatekeeper_instname,
            kmhal_hidl_hal_get_binder(kmhal_sp, nullptr), false);
    if (this->hal_sp == nullptr) {
        std::cerr << "Couldn't obtain a handle to the Gatekeeper HAL" << std::endl;
        return;
    }

    std::cout << "Successfully initialized Gatekeeper HAL" << std::endl;
    this->owns = true;
#else
    std::cerr << "Gatekeeper HAL not supported on host build" << std::endl;
#endif /* SUSKEYMASTER_BUILD_HOST */
}

gk_hal::~gk_hal() {
#ifndef SUSKEYMASTER_BUILD_HOST
    if (this->owns)
        kmhal_hidl_hal_sp_destroy(&this->hal_sp);
#endif /* SUSKEYMASTER_BUILD_HOST */
}

int verify(HidlSusKeymaster& kmhal, u32 uid, u64 challenge, hidl_vec<u8> const& cred,
           hidl_vec<u8> const& handle, hidl_vec<u8>& out,
           gk_hal *opt_gk_hal)
{
    gk_hal gk_hal(opt_gk_hal ? *opt_gk_hal : kmhal);
    if (!gk_hal.is_ok()) {
        std::cerr << "Failed to initialize the Gatekeeper HAL" << std::endl;
        return EXIT_FAILURE;
    }

    GatekeeperResponse res;

    {
#ifndef SUSKEYMASTER_BUILD_HOST
        u32 uid_ = uid;
        u64 challenge = 0;
        hidl_vec<u8> pwd_handle = handle;
        hidl_vec<u8> gk_password = cred;

        const GatekeeperResponse *res_p = nullptr;

        const struct kmhal_hidl_hal_arg_write_desc in_args[] = {
            { "uid", &uid_, sizeof(u32), kmhal_hidl_hal_arg_write_u32 },
            { "challenge", &challenge, sizeof(u64), kmhal_hidl_hal_arg_write_u64 },
            { "enrolledPasswordHandle", &pwd_handle, sizeof(hidl_vec<u8>),
                write_vec_of_primitive<u8> },
            { "providedPassword", &gk_password, sizeof(hidl_vec<u8>),
                write_vec_of_primitive<u8> }
        };
        struct kmhal_hidl_hal_arg_parse_desc out_args[] = {
            { "response", reinterpret_cast<const void **>(&res_p),
                sizeof(GatekeeperResponse), read_gatekeeper_response }
        };

        std::cout << "Calling IGatekeeper::Verify..." << std::endl;
        if (kmhal_hidl_hal_call(gk_hal.get_hal_sp(), static_cast<u32>(GK_HAL_CMD::VERIFY),
                        in_args, u_arr_size(in_args), out_args, u_arr_size(out_args)))
        {
            std::cerr << "Gatekeeper HAL call failed" << std::endl;
            return EXIT_FAILURE;
        }

        res = *res_p;
#else
        std::cerr << "Gatekeeper HAL not supported on host build" << std::endl;
        res.code = GatekeeperStatusCode::ERROR_NOT_IMPLEMENTED;
#endif /* SUSKEYMASTER_BUILD_HOST */
    }

    i32 c = static_cast<i32>(res.code);
    std::cout << "Gatekeeper call result status: " << c
        << " (" << gatekeeper_status_toString(c) << ")" << std::endl;

    if (res.code == GatekeeperStatusCode::STATUS_OK)
        out = res.data;

    return res.code == GatekeeperStatusCode::STATUS_OK ? EXIT_SUCCESS : EXIT_FAILURE;
}

int read_pwd_data(hidl_vec<u8> const& pwd_data, sp_pwd_data& out, bool log)
{
    u32 salt_len = 0, handle_len = 0;

    u32 min_size = sizeof(out.type) +
        sizeof(out.N) + sizeof(out.R) + sizeof(out.P)
        + sizeof(salt_len);

    if (pwd_data.size() < min_size) {
        std::cerr << "Data too small" << std::endl;
        return 1;
    }

    const unsigned char *p = pwd_data.data();

    /* Credential type */
    memcpy(&out.type, pwd_data.data(), sizeof(u32));
    out.type = static_cast<sp_pwd_data::credential_type>(be32toh(static_cast<u32>(out.type)));
    p += sizeof(u32);
    if (log)
        std::printf("Credential type: %" PRIu32 " (0x%" PRIx32 ") - %s\n",
                static_cast<u32>(out.type), static_cast<u32>(out.type),
                sp_pwd_data::credential_type_toString(static_cast<u32>(out.type)));

    /* Scrypt N, R, P */
    memcpy(&out.N, p, sizeof(u8)); p += sizeof(u8);
    memcpy(&out.R, p, sizeof(u8)); p += sizeof(u8);
    memcpy(&out.P, p, sizeof(u8)); p += sizeof(u8);
    if (log) {
        std::printf("Scrypt N: %" PRIu8 " (0x%" PRIx8 ")\n", out.N, out.N);
        std::printf("Scrypt R: %" PRIu8 " (0x%" PRIx8 ")\n", out.R, out.R);
        std::printf("Scrypt P: %" PRIu8 " (0x%" PRIx8 ")\n", out.P, out.P);
    }
    if (out.N != sp_pwd_data::PASSWORD_SCRYPT_LOG_N)
        std::cerr << "WARNING: Scrypt `N` parameter " << out.N << " not the AOSP default " <<
            static_cast<int>(sp_pwd_data::PASSWORD_SCRYPT_LOG_N) << std::endl;
    if (out.R != sp_pwd_data::PASSWORD_SCRYPT_LOG_R)
        std::cerr << "WARNING: Scrypt `R` parameter " << out.N << " not the AOSP default " <<
            static_cast<int>(sp_pwd_data::PASSWORD_SCRYPT_LOG_R) << std::endl;
    if (out.P != sp_pwd_data::PASSWORD_SCRYPT_LOG_P)
        std::cerr << "WARNING: Scrypt `P` parameter " << out.N << " not the AOSP default " <<
            static_cast<int>(sp_pwd_data::PASSWORD_SCRYPT_LOG_P) << std::endl;

    /* Scrypt salt length */
    memcpy(&salt_len, p, sizeof(u32));
    salt_len = be32toh(salt_len);
    p += sizeof(u32);
    if (log)
        std::printf("Scrypt salt length: %" PRIu32 " (0x%" PRIx32 ")\n", salt_len, salt_len);
    if (salt_len > 10000) {
        std::cerr << "Bogus scrypt salt length" << std::endl;
        return 1;
    } else if (salt_len != sp_pwd_data::PASSWORD_SALT_LENGTH) {
        std::cerr << "WARNING: Salt length " << salt_len << "not the AOSP default" << std::endl;
    }

    /* Scrypt salt */

    min_size += salt_len + sizeof(handle_len);
    if (pwd_data.size() < min_size) {
        std::cerr << "Data too small" << std::endl;
        return 1;
    }

    out.salt.resize(salt_len);
    memcpy(out.salt.data(), p, salt_len);
    p += salt_len;
    if (log) {
        std::printf("Scrypt salt: ");
        for (u8 b : out.salt) {
            std::printf("%02x", (unsigned)b);
        }
        std::putchar('\n');
    }

    /* Handle length */
    memcpy(&handle_len, p, sizeof(u32));
    handle_len = be32toh(handle_len);
    p += sizeof(u32);
    if (log)
        std::printf("Handle length: %" PRIu32 " (0x%" PRIx32 ")\n",
                handle_len, handle_len);
    if (handle_len > 10000) {
        std::cerr << "Bogus handle length" << std::endl;
        return 1;
    }

    /* Handle */

    min_size += handle_len;
    if (pwd_data.size() < min_size) {
        std::cerr << "Data too small" << std::endl;
        return 1;
    }

    out.handle.resize(handle_len);
    memcpy(out.handle.data(), p, handle_len);
    p += handle_len;
    if (log) {
        std::printf("Handle: ");
        for (u8 b : out.handle) {
            std::printf("%02x", (unsigned)b);
        }
        std::putchar('\n');
    }

    /* PIN length for autoconfirm (might not be there) */
    min_size += sizeof(i32);
    if (pwd_data.size() < min_size) {
        out.pin_length = sp_pwd_data::PIN_LENGTH_UNAVAILABLE;
    } else {
        memcpy(&out.pin_length, p, sizeof(i32));
        out.pin_length = be32toh(out.pin_length);
    }
    if (log) {
        std::printf("PIN length (for autoconfirm): %" PRIi32 " (0x%" PRIx32 ")%s\n",
                out.pin_length, out.pin_length,
                out.pin_length == sp_pwd_data::PIN_LENGTH_UNAVAILABLE ? " (unavailable)" : "");
    }
    if (out.pin_length != sp_pwd_data::PIN_LENGTH_UNAVAILABLE &&
            out.pin_length < sp_pwd_data::MIN_AUTO_PIN_REQUIREMENT_LENGTH)
        std::cerr << "WARNING: PIN length too small for autoconfirm (min: "
            << sp_pwd_data::MIN_AUTO_PIN_REQUIREMENT_LENGTH << ")" << std::endl;

    if (pwd_data.size() > min_size)
        std::cerr << "WARNING: trailing data at the end of blob" << std::endl;

    return 0;
}

int stretch_lskf(hidl_vec<u8> const& credential, sp_pwd_data const& pwd,
                 hidl_vec<u8>& out, bool warn_if_default_password)
{
    if (pwd.salt.size() == 0) {
        std::cerr << "Invalid pwd data salt" << std::endl;
        return -1;
    }

    hidl_vec<u8> password;
    if (credential.size() == 0) {
        password.resize(sizeof(DEFAULT_PASSWORD));
        memcpy(password.data(), DEFAULT_PASSWORD, sizeof(DEFAULT_PASSWORD));
        if (warn_if_default_password)
            std::cerr << "WARNING: Using default-password" << std::endl;
    } else {
        password = credential;
    }

    out.resize(STRETCHED_LSKF_LENGTH);
    if (!EVP_PBE_scrypt(reinterpret_cast<const char *>(password.data()), password.size(),
                pwd.salt.data(), pwd.salt.size(),
                1 << pwd.N, 1 << pwd.R, 1 << pwd.P, -1, out.data(), STRETCHED_LSKF_LENGTH))
    {
        std::cerr << "Scrypt stretching failed" << std::endl;
        return 1;
    }

    return 0;
}

int unwrap_sp_blob(HidlSusKeymaster& kmhal, u32 uid, hidl_vec<u8> const& keystore_key_blob,
                   hidl_vec<u8> const& stretched_cred, hidl_vec<u8> const& secdiscardable,
                   hidl_vec<u8> const& sp_blob, hidl_vec<u8>& out, u8& out_blob_version,
                   hidl_vec<u8> const& gk_pwd_handle)
{
    if (sp_blob.size() < 2) {
        std::cerr << "Invalid SP blob" << std::endl;
        return EXIT_FAILURE;
    }

    u8 spblob_ver = sp_blob[0], protector_type = sp_blob[1];
    hidl_vec<u8> spblob_content(sp_blob.begin() + 2, sp_blob.end());

    std::cout << "SP blob version: " << static_cast<int>(spblob_ver) << std::endl;
    if (spblob_ver != SYNTHETIC_PASSWORD_VERSION_V1 &&
        spblob_ver != SYNTHETIC_PASSWORD_VERSION_V2 &&
        spblob_ver != SYNTHETIC_PASSWORD_VERSION_V3)
    {
        std::cerr << "Invalid SP or unsupported SP blob version" << std::endl;
        return EXIT_FAILURE;
    }
    if (protector_type != PROTECTOR_TYPE_LSKF_BASED) {
        std::cerr << "Invalid or unsupported SP protector type: "
            << static_cast<int>(protector_type) <<
            " (expected 0 - PROTECTOR_TYPE_LSKF_BASED)" << std::endl;
        return EXIT_FAILURE;
    }
    out_blob_version = spblob_ver;

    static constexpr const char PERSONALIZATION_SECDISCARDABLE[] = "secdiscardable-transform";
    hidl_vec<u8> secdiscardable_hash;
    if (util::personalized_hash(secdiscardable, PERSONALIZATION_SECDISCARDABLE,
                secdiscardable_hash))
    {
        std::cerr << "Failed to hash secdiscardable" << std::endl;
        return EXIT_FAILURE;
    }

    /* Protector secret = Secdiscardable hash || LSKF data */
    hidl_vec<u8> protector_secret(stretched_cred.size() + secdiscardable_hash.size());
    memcpy(protector_secret.data(), stretched_cred.data(), stretched_cred.size());
    memcpy(protector_secret.data() + stretched_cred.size(), secdiscardable_hash.data(),
            secdiscardable_hash.size());

    hidl_vec<u8> auth_token{};
    if (gk_pwd_handle.size() > 0) {
        if (gk_pwd_handle.size() < sizeof(password_handle_t)) {
            std::cerr << "Invalid password handle" << std::endl;
            return EXIT_FAILURE;
        }
        password_handle_t pwd_handle;
        memcpy(&pwd_handle, gk_pwd_handle.data(), sizeof(pwd_handle));
        if (pwd_handle.version != HANDLE_VERSION)
            std::cerr << "WARNING: Unexpected password handle version: "
                << static_cast<int>(pwd_handle.version) << std::endl;

        std::cout << "userSecureId: " << pwd_handle.user_id << std::endl;

        static constexpr const char PERSONALIZATION_USER_GK_AUTH[] = "user-gk-authentication";
        hidl_vec<u8> gk_password;
        if (util::personalized_hash(stretched_cred, PERSONALIZATION_USER_GK_AUTH, gk_password)) {
            std::cerr << "Failed to derive Gatekeeper password from stretched LSKF" << std::endl;
            return 1;
        }

        gk_hal gk_hal(kmhal);
        if (!gk_hal.is_ok()) {
            std::cerr << "Failed to initialize the Gatekeeper HAL" << std::endl;
            return EXIT_FAILURE;
        }

        std::cout << std::endl << "Authenticating with Gatekeeper..." << std::endl;
        if (verify(kmhal, uid + 100000 /* `fakeUserId` */, UINT64_C(0), gk_password,
                    gk_pwd_handle, auth_token, &gk_hal))
        {
            std::cerr << "Gatekeeper credential verification failed" << std::endl;
            return EXIT_FAILURE;
        }
    }

    hidl_vec<u8> km_blob = util::keystore_blob_to_km_blob(keystore_key_blob);
    if (spblob_ver == SYNTHETIC_PASSWORD_VERSION_V1)
        return decrypt_v1_blob(kmhal, auth_token,
                km_blob, protector_secret, spblob_content, out);
    else
        return decrypt_v2_v3_blob(kmhal, auth_token,
                km_blob, protector_secret, spblob_content, out);

    return EXIT_SUCCESS;
}

int validate_synthetic_password(HidlSusKeymaster& kmhal, u32 uid,
                                hidl_vec<u8> const& synthetic_password, u8 sp_blob_ver,
                                hidl_vec<u8> const& null_pwd_handle)
{
    if (sp_blob_ver != SYNTHETIC_PASSWORD_VERSION_V1 &&
        sp_blob_ver != SYNTHETIC_PASSWORD_VERSION_V2 &&
        sp_blob_ver != SYNTHETIC_PASSWORD_VERSION_V3)
    {
        std::cerr << "Invalid or unsupported SP blob version" << std::endl;
        return EXIT_FAILURE;
    }

    hidl_vec<u8> gk_password;
    static constexpr const char PERSONALIZATION_SP_GK_AUTH[] = "sp-gk-authentication";
    if (derive_synthetic_password_subkey(synthetic_password, sp_blob_ver,
                PERSONALIZATION_SP_GK_AUTH, gk_password))
    {
        std::cerr << "Failed to derive gatekeeper password from synthetic password" << std::endl;
        return EXIT_FAILURE;
    }

    hidl_vec<u8> auth_token;
    if (verify(kmhal, uid, UINT64_C(0), gk_password, null_pwd_handle, auth_token)) {
        std::cerr << "Gatekeeper authentication w/ synthetic password failed!" << std::endl;
        std::cerr << "Invalid synthetic password for given user and password handle!"
            << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int derive_synthetic_password_subkey(hidl_vec<u8> const& synthetic_password, u8 sp_blob_ver,
                                     const char *personalization, hidl_vec<u8>& out)
{
    if (sp_blob_ver == SYNTHETIC_PASSWORD_VERSION_V3) {
        static constexpr const char PERSONALIZATION_CONTEXT[] =
            "android-synthetic-password-personalization-context";
        if (util::sp800_derive_with_context(synthetic_password,
                    personalization, strlen(personalization),
                    PERSONALIZATION_CONTEXT, sizeof(PERSONALIZATION_CONTEXT) - 1,
                    out))
        {
            std::cerr << "Failed to derive key from synthetic password using SP800" << std::endl;
            return EXIT_FAILURE;
        }
    } else if (sp_blob_ver == SYNTHETIC_PASSWORD_VERSION_V2 ||
               sp_blob_ver == SYNTHETIC_PASSWORD_VERSION_V1)
    {
        if (util::personalized_hash(synthetic_password, personalization, out)) {
            std::cerr << "Failed to derive key from synthetic password using personalized hash"
                << std::endl;
            return EXIT_FAILURE;
        }
    } else {
        std::cerr << "Invalid or unsupported SP blob version: " << static_cast<int>(sp_blob_ver)
            << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

static int decrypt_keymaster(HidlSusKeymaster& hal, hidl_vec<u8> const& auth_token,
                             hidl_vec<u8> const& keyblob, hidl_vec<u8> const& blob,
                             hidl_vec<u8>& out)
{
    hidl_vec<u8> iv, ciphertext_with_tag;
    if (util::extract_gcm_data(blob, iv, ciphertext_with_tag))
        return 1;

    hidl_vec<KeyParameter> params(3);
    params[0].tag = Tag::NONCE;
    params[0].blob = iv;
    params[1].tag = Tag::AUTH_TOKEN;
    params[1].blob = auth_token;
    params[2].tag = Tag::MAC_LENGTH;
    params[2].f.integer = 8 * util::AES_GCM_TAG_SIZE;
    return hal_ops::crypto::decrypt(hal, ciphertext_with_tag, keyblob, params, out);
}

static int decrypt_software(hidl_vec<u8> const& secret, hidl_vec<u8> const& blob,
                            hidl_vec<u8>& out)
{
    hidl_vec<u8> derived_key;
    if (util::personalized_hash(secret, PROTECTOR_SECRET_PERSONALIZATION, derived_key)) {
        std::cerr << "Failed to hash the protector secret" << std::endl;
        return 1;
    }
    derived_key.resize(util::AES_GCM_KEY_SIZE);

    return util::aes256gcm_software_decrypt(derived_key, blob, out);
}

static int decrypt_v1_blob(HidlSusKeymaster& hal, hidl_vec<u8> const& auth_token,
                           hidl_vec<u8> const& keyblob, hidl_vec<u8> const& protector_secret,
                           hidl_vec<u8> const& blob, hidl_vec<u8>& out)
{
    hidl_vec<u8> intermediate;
    std::cout << std::endl << "Performing intermediate decryption (with software)..."
        << std::endl;
    if (decrypt_software(protector_secret, blob, intermediate)) {
        std::cerr << "Intermediate decryption with software AES-256-GCM failed" << std::endl;
        return 1;
    }
    std::cout << "Intermediate decryption OK" << std::endl;

    std::cout << std::endl << "Performing final decryption (with keymaster)..." << std::endl;
    if (decrypt_keymaster(hal, auth_token, keyblob, intermediate, out)) {
        std::cerr << "Final decryption with Keymaster failed" << std::endl;
        return 1;
    }
    std::cout << "Final decryption OK" << std::endl << std::endl;

    std::cout << "Successfully decrypted V1 SP blob" << std::endl;
    return 0;
}

static int decrypt_v2_v3_blob(HidlSusKeymaster& hal, hidl_vec<u8> const& auth_token,
                              hidl_vec<u8> const& keyblob, hidl_vec<u8> const& protector_secret,
                              hidl_vec<u8> const& blob, hidl_vec<u8>& out)
{
    hidl_vec<u8> intermediate;
    std::cout << std::endl << "Performing intermediate decryption (with keymaster)..."
        << std::endl;
    if (decrypt_keymaster(hal, auth_token, keyblob, blob, intermediate)) {
        std::cerr << "Intermediate decryption with Keymaster failed" << std::endl;
        return 1;
    }
    std::cout << "Intermediate decryption OK" << std::endl;

    std::cout << std::endl << "Performing final decryption (with software)..." << std::endl;
    if (decrypt_software(protector_secret, intermediate, out)) {
        std::cerr << "Final decryption with software AES-256-GCM failed" << std::endl;
        return 1;
    }
    std::cout << "Final decryption OK" << std::endl << std::endl;

    std::cout << "Successfully decrypted SP blob" << std::endl;
    return 0;
}

static const char * gatekeeper_status_toString(i32 s)
{
    switch (static_cast<GatekeeperStatusCode>(s)) {
        case GatekeeperStatusCode::STATUS_REENROLL: return "GK_STATUS_REENROLL";
        case GatekeeperStatusCode::STATUS_OK: return "GK_STATUS_OK";
        case GatekeeperStatusCode::ERROR_GENERAL_FAILURE: return "GK_ERROR_GENERAL_FAILURE";
        case GatekeeperStatusCode::ERROR_RETRY_TIMEOUT: return "GK_ERROR_RETRY_TIMEOUT";
        case GatekeeperStatusCode::ERROR_NOT_IMPLEMENTED: return "GK_ERROR_NOT_IMPLEMENTED";
        default: return "(unknown)";
    }
}

#ifndef SUSKEYMASTER_BUILD_HOST
static int read_gatekeeper_response(const struct kmhal_hidl_parcel *p,
                                    size_t *off_p,
                                    const void **out, size_t out_size)
{
    if (out == nullptr || out_size != sizeof(GatekeeperResponse)) {
        std::cerr << __func__ << ": Invalid parameters" << std::endl;
        return -1;
    }

    u32 exp_flags = 0;
    kmhal_hidl_parcel_obj_t ref;
    if (kmhal_hidl_parcel_read_buffer_obj(p, off_p, sizeof(GatekeeperResponse),
                &exp_flags, nullptr, nullptr, out, &ref))
    {
        std::cerr << __func__ << ": Failed to read the GatekeeperResponse buffer object"
            << std::endl;
        return 1;
    }

    const GatekeeperResponse *const gkr_p = reinterpret_cast<const GatekeeperResponse *>(*out);
    if (kmhal_hidl_vec_read_embedded(nullptr, nullptr, p, off_p,
                reinterpret_cast<const struct kmhal_hidl_vec *>(&gkr_p->data), sizeof(u8),
                ref, offsetof(GatekeeperResponse, data)))
    {
        std::cerr << __func__ << ": Failed to read the GatekeeperResponse's embedded "
            "data HIDL vec buffer object" << std::endl;
        return 1;
    }

    return 0;
}
#endif /* SUSKEYMASTER_BUILD_HOST */

} /* namespace gatekeeper */
} /* namespace cli */
} /* namespace suskeymaster */
