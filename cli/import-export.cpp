#include "cli.hpp"
#include "hidl-hal.hpp"
#include <libgenericutil/util.h>
#include <libgenericutil/km-params.hpp>
#include <libgenericutil/atomic-wrapper.h>
#include <android/hardware/keymaster/4.0/types.h>
#include <android/hardware/keymaster/4.0/IKeymasterDevice.h>
#include <cstdbool>
#include <iostream>
#include <semaphore.h>

namespace suskeymaster {
namespace cli {
namespace hidl_ops {

using namespace ::android::hardware::keymaster::V4_0;
using ::android::hardware::hidl_vec;

int import_key(HidlSusKeymaster4& hal, hidl_vec<uint8_t> const& priv_pkcs8,
        Algorithm alg, hidl_vec<KeyParameter> const& in_import_params,
        hidl_vec<uint8_t>& out_keyblob
)
{
    if (alg != Algorithm::EC && alg != Algorithm::RSA) {
        std::cerr << "Unsupported key algorithm: "
            << static_cast<int32_t>(alg) << " (" << toString(alg) << ")" << std::endl;
        return -1;
    }

    hidl_vec<KeyParameter> params(in_import_params);
    util::init_default_params(params, { { Tag::ALGORITHM, alg } });

    KeyCharacteristics c;
    ErrorCode e = hal.importKey(params, KeyFormat::PKCS8, priv_pkcs8, out_keyblob, c);
    if (e != ErrorCode::OK) {
        std::cerr << "importKey operation failed: "
            << static_cast<int32_t>(e) << " (" << toString(e) << ")" << std::endl;
        return 1;
    }

    std::cout << "Successfully imported an " << toString(alg)
        << " private key into KeyMaster" << std::endl;
    return 0;
}

int export_key(HidlSusKeymaster4& hal,
        const hidl_vec<uint8_t>& key, hidl_vec<uint8_t>& out_public_key_x509)
{
    ErrorCode e = hal.exportKey(KeyFormat::X509, key, {}, {}, out_public_key_x509);

    if (e != ErrorCode::OK) {
        std::cerr << "exportKey operation failed: "
            << static_cast<int32_t>(e) << " (" << toString(e) << ")" << std::endl;
        return 1;
    }

    std::cout << "Successfully exported public key from KeyMaster" << std::endl;
    return 0;
}

} /* namespace hidl_ops */
} /* namespace cli */
} /* namespace suskeymaster */
