#include "pwd-blob.hpp"
#include "endian.h"
#include <libsuskmhal/keymaster-types-cpp.hpp>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <cinttypes>
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace suskeymaster {
namespace cli {
namespace auth {

pwd_blob::pwd_blob()
{
    salt.resize(PASSWORD_SALT_LENGTH);
    if (!RAND_bytes(salt.data(), PASSWORD_SALT_LENGTH)) {
        std::cerr << "RAND_bytes() failed" << std::endl;
        std::abort();
    }
}

pwd_blob::pwd_blob(const password_handle_t& gk_handle) : pwd_blob()
{
    handle.resize(sizeof(password_handle_t));
    std::memcpy(handle.data(), &gk_handle, sizeof(password_handle_t));
}

pwd_blob::pwd_blob(const std::vector<u8>& in, bool log)
{
    mDeserializationOk = false;
    u32 salt_len = 0, handle_len = 0;

    u32 min_size = sizeof(type) +
        sizeof(N) + sizeof(R) + sizeof(P)
        + sizeof(salt_len);

    if (in.size() < min_size) {
        std::cerr << "Data too small" << std::endl;
        return;
    } else if (in.size() > 10000) {
        std::cerr << "Bogus data size (" << in.size() << "); "
            "most likely not a pwd blob" << std::endl;
        return;
    }

    const unsigned char *p = in.data();

    /* Credential type */
    memcpy(&type, in.data(), sizeof(u32));
    type = static_cast<credential_type>(be32toh(static_cast<u32>(type)));
    p += sizeof(u32);
    if (log)
        std::printf("Credential type: %" PRIu32 " (0x%" PRIx32 ") - %s\n",
                static_cast<u32>(type), static_cast<u32>(type), toString(type));

    /* Scrypt N, R, P */
    memcpy(&N, p, sizeof(u8)); p += sizeof(u8);
    memcpy(&R, p, sizeof(u8)); p += sizeof(u8);
    memcpy(&P, p, sizeof(u8)); p += sizeof(u8);
    if (log) {
        std::printf("Scrypt N: %" PRIu8 " (0x%" PRIx8 ")\n", N, N);
        std::printf("Scrypt R: %" PRIu8 " (0x%" PRIx8 ")\n", R, R);
        std::printf("Scrypt P: %" PRIu8 " (0x%" PRIx8 ")\n", P, P);
    }

    if (N != PASSWORD_SCRYPT_LOG_N && N != PASSWORD_SCRYPT_LOG_N_OLD) {
        std::cerr << "WARNING: Scrypt `N` parameter " << static_cast<int>(N)
            << " not any of the AOSP defaults: " <<
            static_cast<int>(PASSWORD_SCRYPT_LOG_N) << " or " <<
            static_cast<int>(PASSWORD_SCRYPT_LOG_N_OLD) << std::endl;
    }
    if (R != PASSWORD_SCRYPT_LOG_R) {
        std::cerr << "WARNING: Scrypt `R` parameter " << static_cast<int>(R)
            << " not the AOSP default " << static_cast<int>(PASSWORD_SCRYPT_LOG_R) << std::endl;
    }
    if (P != PASSWORD_SCRYPT_LOG_P) {
        std::cerr << "WARNING: Scrypt `P` parameter " << static_cast<int>(P)
            << " not the AOSP default " << static_cast<int>(PASSWORD_SCRYPT_LOG_P) << std::endl;
    }

    /* Scrypt salt length */
    memcpy(&salt_len, p, sizeof(u32));
    salt_len = be32toh(salt_len);
    p += sizeof(u32);
    if (log)
        std::printf("Scrypt salt length: %" PRIu32 " (0x%" PRIx32 ")\n", salt_len, salt_len);
    if (salt_len > 10000) {
        std::cerr << "Bogus scrypt salt length" << std::endl;
        return;
    } else if (salt_len != PASSWORD_SALT_LENGTH) {
        std::cerr << "WARNING: Salt length " << salt_len << " not the AOSP default "
            "(" << static_cast<int>(PASSWORD_SALT_LENGTH) << ")" << std::endl;
    }

    /* Scrypt salt */

    min_size += salt_len + sizeof(handle_len);
    if (in.size() < min_size) {
        std::cerr << "Data too small" << std::endl;
        return;
    }

    salt.resize(salt_len);
    memcpy(salt.data(), p, salt_len);
    p += salt_len;
    if (log) {
        std::printf("Scrypt salt: %s", salt.empty() ? "(empty)" : "");
        for (u8 b : salt) {
            std::printf("%02x", (unsigned)b);
        }
        std::putchar('\n');
    }

    /* Handle length */
    memcpy(&handle_len, p, sizeof(u32));
    handle_len = be32toh(handle_len);
    p += sizeof(u32);
    if (log)
        std::printf("GK Handle length: %" PRIu32 " (0x%" PRIx32 ")\n",
                handle_len, handle_len);
    if (handle_len > 10000) {
        std::cerr << "Bogus Gatekeeper handle length" << std::endl;
        return;
    } else if (handle_len > 0 && handle_len != sizeof(password_handle_t)) {
        std::cerr << "Gatekeeper handle length " << handle_len
            << " is invalid (expected " << sizeof(password_handle_t) << ")" << std::endl;
        return;
    }


    /* Handle */

    min_size += handle_len;
    if (in.size() < min_size) {
        std::cerr << "Data too small" << std::endl;
        return;
    }

    handle.resize(handle_len);
    memcpy(handle.data(), p, handle_len);
    p += handle_len;
    if (log) {
        std::printf("GK Handle: ");
        for (u8 b : handle) {
            std::printf("%02x", (unsigned)b);
        }
        std::putchar('\n');
    }

    /* PIN length for autoconfirm (might not be there) */
    min_size += sizeof(i32);
    if (in.size() < min_size) {
        pin_length = PIN_LENGTH_UNAVAILABLE;
    } else {
        memcpy(&pin_length, p, sizeof(i32));
        pin_length = be32toh(pin_length);
    }
    if (log) {
        std::printf("PIN length (for autoconfirm): %" PRIi32 " (0x%" PRIx32 ")%s\n",
                pin_length, pin_length,
                pin_length == PIN_LENGTH_UNAVAILABLE ? " (unavailable)" : "");
    }
    if (pin_length != PIN_LENGTH_UNAVAILABLE &&
            pin_length < MIN_AUTO_PIN_REQUIREMENT_LENGTH)
        std::cerr << "WARNING: PIN length too small for autoconfirm (min: "
            << MIN_AUTO_PIN_REQUIREMENT_LENGTH << ")" << std::endl;

    if (in.size() > min_size)
        std::cerr << "WARNING: trailing data at the end of blob" << std::endl;

    mDeserializationOk = true;
    return;
}

void pwd_blob::serialize(std::vector<u8>& out) const
{
    out.resize(0);

    /* Credential type */
    out.resize(out.size() + sizeof(u32));
    memcpy((out.data() + out.size()) - sizeof(u32), &type, sizeof(u32));

    /* Scrypt N,R,P */
    out.push_back(N);
    out.push_back(R);
    out.push_back(P);

    /* Salt length */
    out.resize(out.size() + sizeof(u32));
    u32 tmp = salt.size();
    memcpy((out.data() + out.size()) - sizeof(u32), &tmp, sizeof(u32));

    /* Salt */
    out.resize(out.size() + salt.size());
    memcpy((out.data() + out.size()) - salt.size(), salt.data(), salt.size());

    /* Handle length */
    out.resize(out.size() + sizeof(u32));
    tmp = handle.size();
    memcpy((out.data() + out.size()) - sizeof(u32), &tmp, sizeof(u32));

    /* Handle */
    out.resize(out.size() + handle.size());
    memcpy((out.data() + out.size()) - handle.size(), handle.data(), handle.size());

    /* PIN length for autoconfirm */
    out.resize(out.size() + sizeof(i32));
    memcpy((out.data() + out.size()) - sizeof(u32), &pin_length, sizeof(u32));
}

int pwd_blob::stretch_lskf(const std::vector<u8>& lskf, std::vector<u8>& out,
                           bool warn_if_default_password) const
{
    if (salt.size() == 0) {
        std::cerr << "Invalid pwd data salt" << std::endl;
        return -1;
    }

    std::vector<u8> password;
    /* If provided credential is empty, use default password */
    if (lskf.size() == 0) {
        password.resize(sizeof(DEFAULT_PASSWORD));
        memcpy(password.data(), DEFAULT_PASSWORD, sizeof(DEFAULT_PASSWORD));
        if (warn_if_default_password)
            std::cerr << "WARNING: Using default-password" << std::endl;
    } else {
        password = lskf;
    }

    out.resize(STRETCHED_LSKF_LENGTH);
    if (!EVP_PBE_scrypt(reinterpret_cast<const char *>(password.data()), password.size(),
                salt.data(), salt.size(),
                1 << N, 1 << R, 1 << P, -1, out.data(), STRETCHED_LSKF_LENGTH))
    {
        std::cerr << "Scrypt stretching failed" << std::endl;
        return 1;
    }

    return 0;
}

const char * toString(pwd_blob::credential_type ct)
{
    switch (ct) {
        case pwd_blob::credential_type::NONE: return "CREDENTIAL_TYPE_NONE";
        case pwd_blob::credential_type::PATTERN: return "CREDENTIAL_TYPE_PATTERN";
        case pwd_blob::credential_type::PASSWORD_OR_PIN: return "CREDENTIAL_TYPE_PASSWORD_OR_PIN";
        case pwd_blob::credential_type::PIN: return "CREDENTIAL_TYPE_PIN";
        case pwd_blob::credential_type::PASSWORD: return "CREDENTIAL_TYPE_PASSWORD";
        default: return "(unknown)";
    }
}

} /* namespace auth */
} /* namespace cli */
} /* namespace suskeymaster */
