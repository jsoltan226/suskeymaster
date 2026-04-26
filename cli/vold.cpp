#define OPENSSL_API_COMPAT 0x10002000L
#define HIDL_DISABLE_INSTRUMENTATION
#include "cli.hpp"
#include <openssl/sha.h>
#include <cstring>

namespace suskeymaster {
namespace cli {
namespace vold {

int generate_app_id(hidl_vec<uint8_t> const& in_secdiscardable,
        hidl_vec<uint8_t>& out_app_id)
{
    /* AOSP constants */
    static constexpr size_t SHA512_BLOCK_SIZE = 128;
    static const char* HASH_PREFIX = "Android secdiscardable SHA512";

    SHA512_CTX ctx;

    if (!SHA512_Init(&ctx)) {
        std::cerr << "SHA512_Init failed" << std::endl;
        return 1;
    }

    uint8_t prefix[SHA512_BLOCK_SIZE];
    std::memset(prefix, 0, sizeof(prefix));

    size_t prefix_len = std::strlen(HASH_PREFIX);
    if (prefix_len > sizeof(prefix)) {
        std::cerr << "Prefix too long" << std::endl;
        return 1;
    }

    std::memcpy(prefix, HASH_PREFIX, prefix_len);

    if (!SHA512_Update(&ctx, prefix, sizeof(prefix))) {
        std::cerr << "SHA512_Update (prefix) failed" << std::endl;
        return 1;
    }

    if (!SHA512_Update(&ctx, in_secdiscardable.data(), in_secdiscardable.size())) {
        std::cerr << "SHA512_Update (input) failed" << std::endl;
        return 1;
    }

    out_app_id.resize(SHA512_DIGEST_LENGTH);

    if (!SHA512_Final(out_app_id.data(), &ctx)) {
        std::cerr << "SHA512_Final failed" << std::endl;
        return 1;
    }

    return 0;
}

} /* namespace vold */
} /* namespace cli */
} /* namespace suskeymaster */
