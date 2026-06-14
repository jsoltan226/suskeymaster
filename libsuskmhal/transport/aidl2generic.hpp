#ifndef SUSKEYMASTER_BUILD_HOST

#ifndef SUSKEYMASTER_KMHAL_TRANSPORT_AIDL2GENERIC_H_
#define SUSKEYMASTER_KMHAL_TRANSPORT_AIDL2GENERIC_H_

#include <vector>
#include "keymint-types-aidl.h"
#include "../keymaster-types-cpp.hpp"

/**
 * This file supplies utilities which
 *
 * 1) Convert from a `generic` Keymaster type to a const AIDL KeyMint struct
 *  by performing as little copying as possible, preferably e.g. assigning pointers instead,
 *  returning it in a unique_ptr so that any necessary destruction happens automatically
 *
 * 2) Convert from a return AIDL KeyMint struct into a new generic Keymaster type,
 *  cleaning up the AIDL struct in the process.
 */

namespace suskeymaster {
namespace kmhal {
namespace transport {

using namespace generic;

template <typename AidlT, typename GenericT,
          void (*Destructor)(AidlT *)>
class AidlView {
public:
    static AidlT toAidlView(const GenericT& generic);

    explicit AidlView(const GenericT& generic) {
        aidl = toAidlView(generic);
    }
    ~AidlView() {
        Destructor(&aidl);
    }

    AidlView(const AidlView&) = delete;
    AidlView& operator=(const AidlView&) = delete;

    AidlView(AidlView&&) = delete;
    AidlView& operator=(AidlView&&) = delete;

    AidlT* get() { return &aidl; }
    const AidlT* get() const { return &aidl; }

private:
    AidlT aidl;
};


/* vec<u8> */
using AidlVecOfU8View = AidlView<aidl_vec_of_u8, std::vector<u8>, destroy_aidl_vec_of_u8>;
std::vector<u8> fromAidlDestroy(aidl_vec_of_u8&);

/* KeyParameter */
using AidlKeyParameterView = AidlView<aidl_key_parameter, KeyParameter,
                                      destroy_aidl_key_parameter>;
KeyParameter fromAidlDestroy(aidl_key_parameter&);

/* vec<KeyParameter> */
using AidlVecOfKeyParameterView = AidlView<aidl_vec_of_key_parameter, std::vector<KeyParameter>,
                                           destroy_aidl_vec_of_key_parameter>;
std::vector<KeyParameter> fromAidlDestroy(aidl_vec_of_key_parameter&);

/* HardwareAuthToken */
using AidlHardwareAuthTokenView = AidlView<aidl_hardware_auth_token, HardwareAuthToken,
                                           destroy_aidl_hardware_auth_token>;
HardwareAuthToken fromAidlDestroy(aidl_hardware_auth_token&);

/* vec<Certificate> AKA vec<vec<u8>> */
std::vector<std::vector<u8>> fromAidlDestroy(aidl_vec_of_certificate&);

} /* namespace transport */
} /* namespace kmhal */
} /* namespace suskeymaster */

#endif /* SUSKEYMASTER_KMHAL_TRANSPORT_AIDL2GENERIC_H_ */

#endif /* SUSKEYMASTER_BUILD_HOST */
