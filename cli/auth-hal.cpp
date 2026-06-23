#include "auth-hal.hpp"
#include <core/int.h>
#ifndef SUSKEYMASTER_BUILD_HOST
#include "endian.h"
#include <core/log.h>
#include <core/util.h>
#include <libsuskmhal/suskmhal.hpp>
#include <libsuskmhal/transport/parcel.h>
#include <libsuskmhal/transport/hal.h>
#include <libsuskmhal/transport/aidl-util.h>
#include <libsuskmhal/transport/hidl-base.h>
#include <libsuskmhal/transport/hidl-types.h>
#include <libsuskmhal/transport/aidl2generic.hpp>
#include <libsuskmhal/transport/keymint-types-aidl.h>
#include <libsuskmhal/transport/aosp-hidl-support.hpp>
#include <cstring>
#endif /* SUSKEYMASTER_BUILD_HOST */
#include <libsuskmhal/keymaster-types-cpp.hpp>
#include <cstdint>

namespace suskeymaster {
namespace cli {
namespace auth {

using namespace kmhal;
using namespace kmhal::generic;

auth_hal::auth_hal(const char *aidl_fqname, const char *hidl_fqname, const char *instname,
                  kmhal::SusKMHal* opt_kmhal) :
    hal_sp(nullptr),
    owns(false)
{
#ifndef SUSKEYMASTER_BUILD_HOST
    struct kmhal_binder_ctx *kmhal_binder = opt_kmhal ?
                                            kmhal_get_binder(opt_kmhal->getHalSp(), nullptr) :
                                            nullptr;
    struct kmhal_binder_ctx *existing_binder_aidl = nullptr, *existing_binder_hidl = nullptr;

    /* HIDL operates on /dev/hwbinder, while AIDL operates on /dev/(vnd)binder,
     * which means that there's no way their binder devices will be compatible. */
    if (kmhal_binder) {
        if (kmhal_binder_get_domain(kmhal_binder) == KMHAL_BINDER_DEV_HWBINDER) {
            existing_binder_aidl = nullptr;
            existing_binder_hidl = kmhal_binder;
        } else {
            existing_binder_aidl = kmhal_binder;
            existing_binder_hidl = nullptr;
        }
    }

    /* Disable verbose logging while initializing HAL */
    enum s_log_level prev_level = s_get_log_level();
    s_configure_log_level(S_LOG_WARNING);

    /* Try AIDL first */
    hal_sp = kmhal_aidl_sp_new_get(aidl_fqname, instname, existing_binder_aidl, false);
    if (hal_sp == nullptr) {
        /* Fall back to HIDL if needed */
        hal_sp = kmhal_hidl_sp_new_get(hidl_fqname, instname, existing_binder_hidl, false);
        if (hal_sp == nullptr) {
            std::cerr << "Couldn't initialize HAL (tried both AIDL and HIDL)" << std::endl;
            s_configure_log_level(prev_level);
            return;
        }
    }

    if (kmhal_get_is_aidl(hal_sp)) {
        std::cout << "Successfully initialized AIDL HAL "
            "\"" << aidl_fqname << "/" << instname << "\"" << std::endl;
    } else {
        std::cout << "Successfully initialized HIDL HAL "
            "\"" << hidl_fqname << "/" << instname << "\"" << std::endl;
    }
    owns = true;
    s_configure_log_level(prev_level);
#else
    (void) aidl_fqname; (void) hidl_fqname; (void) instname; (void) opt_kmhal;
    std::cerr << "HAL not supported on host build" << std::endl;
#endif /* SUSKEYMASTER_BUILD_HOST */
}

auth_hal::~auth_hal()
{
#ifndef SUSKEYMASTER_BUILD_HOST
    if (owns && hal_sp != nullptr)
        kmhal_sp_destroy(&hal_sp);
#endif /* SUSKEYMASTER_BUILD_HOST */

    owns = false;
    hal_sp = nullptr;
}

GatekeeperHAL::GatekeeperHAL(SusKMHal *opt_kmhal) :
    auth_hal("android.hardware.gatekeeper.IGatekeeper",
             "android.hardware.gatekeeper@1.0::IGatekeeper",
             "default",
             opt_kmhal)
{
}

WeaverHAL::WeaverHAL(SusKMHal *opt_kmhal) :
    auth_hal("android.hardware.weaver.IWeaver",
             "android.hardware.weaver@1.0::IWeaver",
             "default",
             opt_kmhal)
{
}

#ifndef SUSKEYMASTER_BUILD_HOST

/** See "hardware/interfaces/gatekeeper/1.0/types.hal"
 ** and "hardware/interfaces/gatekeeper/1.0/IGatekeeper.hal" **/
enum class GK_HIDL_HAL_CMD : u32 {
    ENROLL = 1,
    VERIFY = 2,
    DELETE_USER = 3,
    DELETE_ALL_USERS = 4
};

/** See "hardware/interfaces/gatekeeper/aidl/android/hardware/gatekeeper/IGatekeeper.aidl"
 ** and "hardware/interfaces/gatekeeper/aidl/android/hardware/gatekeeper/GatekeeperVerifyResponse.aidl" **/
enum class GK_AIDL_HAL_CMD : u32 {
    DELETE_ALL_USERS = 1,
    DELETE_USER = 2,
    ENROLL = 3,
    VERIFY = 4
};

/**
 * Gatekeeper response to any/all requests has this structure as mandatory part
 */
struct hidl_GatekeeperResponse {
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
static_assert(offsetof(hidl_GatekeeperResponse, code) == 0, "wrong offset");
static_assert(offsetof(hidl_GatekeeperResponse, timeout) == 4, "wrong offset");
static_assert(offsetof(hidl_GatekeeperResponse, data) == 8, "wrong offset");
static_assert(sizeof(hidl_GatekeeperResponse) == 24, "wrong size");
static_assert(alignof(hidl_GatekeeperResponse) == 8, "wrong alignment");
static int read_hidl_gatekeeper_response(const struct kmhal_parcel *p, size_t *off_p,
                                         const void **out, size_t out_size);

static HardwareAuthToken fromHidl(const std::vector<u8>& data);

struct aidl_GatekeeperEnrollResponse {
    GatekeeperStatusCode code;
    u32 timeout_ms;
    u64 secure_user_id;
    struct aidl_vec_of_u8 data;
};
static void destroy_aidl_gatekeeper_enroll_response(aidl_GatekeeperEnrollResponse *res);
static int read_aidl_gatekeeper_enroll_response(const struct kmhal_parcel *p, size_t *off_p,
                                                void *out, size_t out_size);

GatekeeperEnrollResponse fromAidlDestroy(aidl_GatekeeperEnrollResponse &res);

struct aidl_GatekeeperVerifyResponse {
    GatekeeperStatusCode code;
    u32 timeout_ms;
    struct aidl_hardware_auth_token hardware_auth_token;
};
static void destroy_aidl_gatekeeper_verify_response(aidl_GatekeeperVerifyResponse *res);
static int read_aidl_gatekeeper_verify_response(const struct kmhal_parcel *p, size_t *off_p,
                                                void *out, size_t out_size);

GatekeeperVerifyResponse fromAidlDestroy(aidl_GatekeeperVerifyResponse& res);

GatekeeperEnrollResponse
GatekeeperHAL::enroll(u32 uid, const std::vector<u8>& currentPasswordHandle,
                      const std::vector<u8>& currentPassword,
                      const std::vector<u8>& desiredPassword)
{
    if (!this->is_ok()) {
        std::cerr << __func__ << ": HAL is not OK" << std::endl;
        return { GatekeeperStatusCode::ERROR_GENERAL_FAILURE, UINT32_C(0), UINT64_C(0), {} };
    }

    using kmhal::transport::init_write_p, kmhal::transport::init_write_i,
        kmhal::transport::init_write_b, kmhal::transport::init_parse_i,
        kmhal::transport::init_parse_b;

    if (kmhal_get_is_aidl(this->get_hal_sp())) {
        using kmhal::transport::AidlVecOfU8View;

        AidlVecOfU8View aidl_currentPasswordHandle(currentPasswordHandle);
        AidlVecOfU8View aidl_currentPassword(currentPassword);
        AidlVecOfU8View aidl_desiredPassword(desiredPassword);

        const struct kmhal_arg_write_desc in_args[] = {
            init_write_p("uid", uid, kmhal_arg_write_u32),
            init_write_i("currentPasswordHandle",
                         aidl_currentPasswordHandle.get(), write_aidl_vec_of_u8),
            init_write_i("currentPassword",
                         aidl_currentPassword.get(), write_aidl_vec_of_u8),
            init_write_i("desiredPassword",
                         aidl_desiredPassword.get(), write_aidl_vec_of_u8)
        };
        const size_t n_in_args = u_arr_size(in_args);

        aidl_GatekeeperEnrollResponse res{};
        struct kmhal_arg_parse_desc out_args[] = {
            init_parse_i("GatekeeperEnrollResponse", &res,
                         read_aidl_gatekeeper_enroll_response)
        };
        const size_t n_out_args = u_arr_size(out_args);

        GatekeeperStatusCode aidl_status = GatekeeperStatusCode::ERROR_GENERAL_FAILURE;
        if (kmhal_call(this->get_hal_sp(), static_cast<u32>(GK_AIDL_HAL_CMD::ENROLL),
                    in_args, n_in_args, out_args, n_out_args,
                    reinterpret_cast<u32 *>(&aidl_status)))
        {
            std::cerr << __func__ << ": AIDL call failed" << std::endl;
            destroy_aidl_gatekeeper_enroll_response(&res);
            return { GatekeeperStatusCode::ERROR_GENERAL_FAILURE, UINT32_C(0), UINT64_C(0), {} };
        } else if (static_cast<i32>(aidl_status) < 0) {
            destroy_aidl_gatekeeper_enroll_response(&res);
            return { GatekeeperStatusCode::ERROR_GENERAL_FAILURE, UINT32_C(0), UINT64_C(0), {} };
        }

        return fromAidlDestroy(res);
    } else {
        const hidl_vec<u8> hidl_currentPasswordHandle = toHidlView(currentPasswordHandle);
        const hidl_vec<u8> hidl_currentPassword = toHidlView(currentPassword);
        const hidl_vec<u8> hidl_desiredPassword = toHidlView(desiredPassword);

        const hidl_GatekeeperResponse *res_p = nullptr;

        const struct kmhal_arg_write_desc in_args[] = {
            init_write_p("uid", uid, kmhal_arg_write_u32),
            init_write_b("currentPasswordHandle", &hidl_currentPasswordHandle,
                         kmhal_hidl_arg_write_vec_of_u8),
            init_write_b("currentPassword", &hidl_currentPassword,
                         kmhal_hidl_arg_write_vec_of_u8),
            init_write_b("desiredPassword", &hidl_desiredPassword,
                         kmhal_hidl_arg_write_vec_of_u8),
        };
        struct kmhal_arg_parse_desc out_args[] = {
            init_parse_b("response", &res_p, read_hidl_gatekeeper_response)
        };

        if (kmhal_call(this->get_hal_sp(), static_cast<u32>(GK_HIDL_HAL_CMD::ENROLL),
                        in_args, u_arr_size(in_args), out_args, u_arr_size(out_args), nullptr))
        {
            std::cerr << __func__ << ": HIDL call failed" << std::endl;
            return { GatekeeperStatusCode::ERROR_GENERAL_FAILURE, UINT32_C(0), UINT64_C(0), {} };
        }

        return { res_p->code, res_p->timeout, UINT64_C(0), res_p->data };
    }
}

GatekeeperVerifyResponse
GatekeeperHAL::verify(u32 uid, u64 challenge,
                      const std::vector<u8>& enrolledPasswordHandle,
                      const std::vector<u8>& providedPassword)
{
    if (!this->is_ok()) {
        std::cerr << __func__ << ": HAL is not OK" << std::endl;
        return { GatekeeperStatusCode::ERROR_GENERAL_FAILURE, UINT32_C(0), {} };
    }

    using kmhal::transport::init_write_p, kmhal::transport::init_write_i,
        kmhal::transport::init_write_b, kmhal::transport::init_parse_i,
        kmhal::transport::init_parse_b;

    if (kmhal_get_is_aidl(this->get_hal_sp())) {
        using kmhal::transport::AidlVecOfU8View;

        AidlVecOfU8View aidl_enrolledPasswordHandle(enrolledPasswordHandle);
        AidlVecOfU8View aidl_providedPassword(providedPassword);

        const struct kmhal_arg_write_desc in_args[] = {
            init_write_p("uid", uid, kmhal_arg_write_u32),
            init_write_p("challenge", challenge, kmhal_arg_write_u64),
            init_write_i("enrolledPasswordHandle",
                         aidl_enrolledPasswordHandle.get(), write_aidl_vec_of_u8),
            init_write_i("providedPassword",
                         aidl_providedPassword.get(), write_aidl_vec_of_u8),
        };
        const size_t n_in_args = u_arr_size(in_args);

        aidl_GatekeeperVerifyResponse res{};
        struct kmhal_arg_parse_desc out_args[] = {
            init_parse_i("GatekeeperVerifyResponse", &res,
                         read_aidl_gatekeeper_verify_response)
        };
        const size_t n_out_args = u_arr_size(out_args);

        GatekeeperStatusCode aidl_status = GatekeeperStatusCode::ERROR_GENERAL_FAILURE;
        if (kmhal_call(this->get_hal_sp(), static_cast<u32>(GK_AIDL_HAL_CMD::VERIFY),
                    in_args, n_in_args, out_args, n_out_args,
                    reinterpret_cast<u32 *>(&aidl_status)))
        {
            std::cerr << __func__ << ": AIDL call failed" << std::endl;
            destroy_aidl_gatekeeper_verify_response(&res);
            return { GatekeeperStatusCode::ERROR_GENERAL_FAILURE, UINT32_C(0), {} };
        } else if (static_cast<i32>(aidl_status) < 0) {
            destroy_aidl_gatekeeper_verify_response(&res);
            return { GatekeeperStatusCode::ERROR_GENERAL_FAILURE, UINT32_C(0), {} };
        }

        return fromAidlDestroy(res);
    } else {
        const hidl_vec<u8> hidl_enrolledPasswordHandle = toHidlView(enrolledPasswordHandle);
        const hidl_vec<u8> hidl_providedPassword = toHidlView(providedPassword);

        const hidl_GatekeeperResponse *res_p = nullptr;

        const struct kmhal_arg_write_desc in_args[] = {
            init_write_p("uid", uid, kmhal_arg_write_u32),
            init_write_p("challenge", challenge, kmhal_arg_write_u64),
            init_write_b("enrolledPasswordHandle", &hidl_enrolledPasswordHandle,
                         kmhal_hidl_arg_write_vec_of_u8),
            init_write_b("providedPassword", &hidl_providedPassword,
                         kmhal_hidl_arg_write_vec_of_u8),
        };
        struct kmhal_arg_parse_desc out_args[] = {
            init_parse_b("response", &res_p, read_hidl_gatekeeper_response)
        };

        if (kmhal_call(this->get_hal_sp(), static_cast<u32>(GK_HIDL_HAL_CMD::VERIFY),
                        in_args, u_arr_size(in_args), out_args, u_arr_size(out_args), nullptr))
        {
            std::cerr << __func__ << ": HIDL call failed" << std::endl;
            return { GatekeeperStatusCode::ERROR_GENERAL_FAILURE, UINT32_C(0), {} };
        }

        return { res_p->code, res_p->timeout, fromHidl(res_p->data) };
    }

}

GatekeeperStatusCode GatekeeperHAL::deleteUser(u32 uid)
{
    if (!this->is_ok()) {
        std::cerr << __func__ << ": HAL is not OK" << std::endl;
        return GatekeeperStatusCode::ERROR_GENERAL_FAILURE;
    }

    using kmhal::transport::init_write_p, kmhal::transport::init_write_b,
          kmhal::transport::init_parse_b;

    if (kmhal_get_is_aidl(this->get_hal_sp())) {
        const struct kmhal_arg_write_desc in_args[] = {
            init_write_p("uid", uid, kmhal_arg_write_u32),
        };
        const size_t n_in_args = u_arr_size(in_args);

        struct kmhal_arg_parse_desc *const out_args = nullptr;
        const size_t n_out_args = 0;

        GatekeeperStatusCode ret = GatekeeperStatusCode::ERROR_GENERAL_FAILURE;
        if (kmhal_call(this->get_hal_sp(), static_cast<u32>(GK_AIDL_HAL_CMD::DELETE_USER),
                    in_args, n_in_args, out_args, n_out_args,
                    reinterpret_cast<u32 *>(&ret)))
        {
            std::cerr << __func__ << ": AIDL call failed" << std::endl;
            return GatekeeperStatusCode::ERROR_GENERAL_FAILURE;
        }

        return ret;
    } else {
        const hidl_GatekeeperResponse *res_p = nullptr;

        const struct kmhal_arg_write_desc in_args[] = {
            init_write_p("uid", uid, kmhal_arg_write_u32),
        };
        const size_t n_in_args = u_arr_size(in_args);

        struct kmhal_arg_parse_desc out_args[] = {
            init_parse_b("response", &res_p, read_hidl_gatekeeper_response)
        };
        const size_t n_out_args = u_arr_size(out_args);

        if (kmhal_call(this->get_hal_sp(), static_cast<u32>(GK_HIDL_HAL_CMD::DELETE_USER),
                    in_args, n_in_args, out_args, n_out_args, nullptr))
        {
            std::cerr << __func__ << ": HIDL call failed" << std::endl;
            return GatekeeperStatusCode::ERROR_GENERAL_FAILURE;
        }

        return res_p->code;
    }
}

GatekeeperStatusCode GatekeeperHAL::deleteAllUsers(void)
{
    if (!this->is_ok()) {
        std::cerr << __func__ << ": HAL is not OK" << std::endl;
        return GatekeeperStatusCode::ERROR_GENERAL_FAILURE;
    }

    using kmhal::transport::init_parse_b;

    if (kmhal_get_is_aidl(this->get_hal_sp())) {

        GatekeeperStatusCode ret = GatekeeperStatusCode::ERROR_GENERAL_FAILURE;
        if (kmhal_call(this->get_hal_sp(), static_cast<u32>(GK_AIDL_HAL_CMD::DELETE_ALL_USERS),
                    nullptr, 0, nullptr, 0, reinterpret_cast<u32 *>(&ret)))
        {
            std::cerr << __func__ << ": AIDL call failed" << std::endl;
            return GatekeeperStatusCode::ERROR_GENERAL_FAILURE;
        }

        return ret;
    } else {
        const hidl_GatekeeperResponse *res_p = nullptr;

        const struct kmhal_arg_write_desc *const in_args = nullptr;
        const size_t n_in_args = 0;

        struct kmhal_arg_parse_desc out_args[] = {
            init_parse_b("response", &res_p, read_hidl_gatekeeper_response)
        };
        const size_t n_out_args = u_arr_size(out_args);

        if (kmhal_call(this->get_hal_sp(), static_cast<u32>(GK_HIDL_HAL_CMD::DELETE_ALL_USERS),
                    in_args, n_in_args, out_args, n_out_args, nullptr))
        {
            std::cerr << __func__ << ": HIDL call failed" << std::endl;
            return GatekeeperStatusCode::ERROR_GENERAL_FAILURE;
        }

        return res_p->code;
    }
}

WeaverStatus WeaverHAL::getConfig(WeaverConfig& out_config)
{
    (void) out_config;
    std::cerr << __func__ << ": Not implemented yet" << std::endl;
    return WeaverStatus::FAILED;
}

WeaverStatus write(u32 slotId, const std::vector<u8>& key, const std::vector<u8>& value)
{
    (void) slotId; (void) key; (void) value;
    std::cerr << __func__ << ": Not implemented yet" << std::endl;
    return WeaverStatus::FAILED;
}

WeaverStatus WeaverHAL::read(u32 slotId, const std::vector<u8>& key,
                             WeaverReadResponse& out_readResponse)
{
    (void) slotId; (void) key; (void) out_readResponse;
    std::cerr << __func__ << ": Not implemented yet" << std::endl;
    return WeaverStatus::FAILED;
}

static int read_hidl_gatekeeper_response(const struct kmhal_parcel *p, size_t *off_p,
                                         const void **out, size_t out_size)
{
    if (out == nullptr || out_size != sizeof(hidl_GatekeeperResponse)) {
        std::cerr << __func__ << ": Invalid parameters" << std::endl;
        return -1;
    }

    u32 exp_flags = 0;
    kmhal_parcel_obj_t ref;
    if (kmhal_parcel_read_buffer_obj(p, off_p, sizeof(hidl_GatekeeperResponse),
                &exp_flags, nullptr, nullptr, out, &ref))
    {
        std::cerr << __func__ << ": Failed to read the GatekeeperResponse buffer object"
            << std::endl;
        return 1;
    }

    const hidl_GatekeeperResponse *const gkr_p =
        reinterpret_cast<const hidl_GatekeeperResponse *>(*out);
    if (kmhal_hidl_vec_read_embedded(nullptr, nullptr, p, off_p,
                reinterpret_cast<const struct kmhal_hidl_vec *>(&gkr_p->data), sizeof(u8),
                ref, offsetof(hidl_GatekeeperResponse, data)))
    {
        std::cerr << __func__ << ": Failed to read the GatekeeperResponse's embedded "
            "data HIDL vec buffer object" << std::endl;
        return 1;
    }

    return 0;
}

static HardwareAuthToken fromHidl(const std::vector<u8>& data)
{
    if (data.empty())
        return {};

    static constexpr size_t TOKEN_MAC_LENGTH =
        static_cast<size_t>(kmhal::Constants::AUTH_TOKEN_MAC_LENGTH);

    /* "hardware/libhardware/include_all/hardware/hw_auth_token.h" */
    typedef struct __attribute__((__packed__)) {
        uint8_t version;  // Current version is 0
        uint64_t challenge;
        uint64_t user_id;             // secure user ID, not Android user ID
        uint64_t authenticator_id;    // secure authenticator ID
        uint32_t authenticator_type;  // hw_authenticator_type_t, in network order
        uint64_t timestamp;           // in network order
        std::array<uint8_t, TOKEN_MAC_LENGTH> hmac;
    } hw_auth_token_t;
    hw_auth_token_t at;
    if (data.size() != sizeof(at)) {
        std::cerr << __func__ << ": Received invalid AuthToken from Gatekeeper" << std::endl;
        return {};
    }

    memcpy(&at, data.data(), sizeof(at));
    if (at.version != 0) {
        std::cerr << "WARNING: auth_token version "
            "(" << at.version << ") is not 0" << std::endl;
    }

    return {
        at.challenge,
        at.user_id,
        at.authenticator_id,
        static_cast<HardwareAuthenticatorType>(be32toh(at.authenticator_type)),
        be64toh(at.timestamp),
        std::vector<u8>(at.hmac.begin(), at.hmac.end())
    };
}

static void destroy_aidl_gatekeeper_enroll_response(aidl_GatekeeperEnrollResponse *res)
{
    if (res == nullptr)
        return;

    res->code = GatekeeperStatusCode::ERROR_GENERAL_FAILURE;
    res->timeout_ms = UINT32_C(0);
    res->secure_user_id = UINT64_C(0);
    destroy_aidl_vec_of_u8(&res->data);
}

static int read_aidl_gatekeeper_enroll_response(const struct kmhal_parcel *p, size_t *off_p,
                                                void *out, size_t out_size)
{
    if (out == nullptr || out_size != sizeof(aidl_GatekeeperEnrollResponse)) {
        std::cerr << __func__ << ": Invalid parameters" << std::endl;
        return -1;
    }

    size_t start = 0;
    i32 size = 0;
    if (kmhal_aidl_parse_parcelable_header(p, off_p, &start, false, &size)) {
        std::cerr << "Failed to read the GatekeeperEnrollResponse parcelable header" << std::endl;
        return 1;
    }

    auto *const res = reinterpret_cast<aidl_GatekeeperEnrollResponse *>(out);

    if (kmhal_parcel_read_u32(p, off_p, reinterpret_cast<u32 *>(&res->code))) {
        std::cerr << "Failed to read the GatekeeperEnrollResponse code" << std::endl;
        return 1;
    }

    if (kmhal_parcel_read_u32(p, off_p, &res->timeout_ms)) {
        std::cerr << "Failed to read the GatekeeperEnrollResponse timeoutMs field" << std::endl;
        return 1;
    }

    if (kmhal_parcel_read_u64(p, off_p, &res->secure_user_id)) {
        std::cerr << "Failed to read the GatekeeperEnrollResponse secureUserId field" << std::endl;
        return 1;
    }

    if (parse_aidl_vec_of_u8(p, off_p, &res->data, sizeof(aidl_vec_of_u8))) {
        std::cerr << "Failed to parse the GatekeeperEnrollResponse data vec" << std::endl;
        return 1;
    }

    if (kmhal_aidl_validate_parcelable_size(start, *off_p, size)) {
        std::cerr << "GatekeeperEnrollResponse parcelable size mismatch" << std::endl;
        return 1;
    }

    return 0;
}

GatekeeperEnrollResponse fromAidlDestroy(aidl_GatekeeperEnrollResponse &res)
{
    GatekeeperEnrollResponse out;

    out.code = res.code;
    out.timeout = res.timeout_ms;
    out.secureUserId = res.secure_user_id;
    out.data = transport::fromAidlDestroy(res.data);

    destroy_aidl_gatekeeper_enroll_response(&res);
    return out;
}

static void destroy_aidl_gatekeeper_verify_response(aidl_GatekeeperVerifyResponse *res)
{
    if (res == nullptr)
        return;

    res->code = GatekeeperStatusCode::ERROR_GENERAL_FAILURE;
    res->timeout_ms = UINT32_C(0);
    destroy_aidl_hardware_auth_token(&res->hardware_auth_token);
}

static int read_aidl_gatekeeper_verify_response(const struct kmhal_parcel *p, size_t *off_p,
                                                void *out, size_t out_size)
{
    if (out == nullptr || out_size != sizeof(aidl_GatekeeperVerifyResponse)) {
        std::cerr << __func__ << ": Invalid parameters" << std::endl;
        return -1;
    }

    size_t start = 0;
    i32 size = 0;
    if (kmhal_aidl_parse_parcelable_header(p, off_p, &start, false, &size)) {
        std::cerr << "Failed to read the GatekeeperVerifyResponse parcelable header" << std::endl;
        return 1;
    }

    auto *const res = reinterpret_cast<aidl_GatekeeperVerifyResponse *>(out);

    if (kmhal_parcel_read_u32(p, off_p, reinterpret_cast<u32 *>(&res->code))) {
        std::cerr << "Failed to read the GatekeeperVerifyResponse code" << std::endl;
        return 1;
    }

    if (kmhal_parcel_read_u32(p, off_p, &res->timeout_ms)) {
        std::cerr << "Failed to read the GatekeeperVerifyResponse timeoutMs field" << std::endl;
        return 1;
    }

    if (parse_aidl_hardware_auth_token(p, off_p, &res->hardware_auth_token,
                sizeof(aidl_hardware_auth_token)))
    {
        std::cerr << "Failed to parse the GatekeeperVerifyResponse hardwareAuthToken"
            << std::endl;
        return 1;
    }

    if (kmhal_aidl_validate_parcelable_size(start, *off_p, size)) {
        std::cerr << "GatekeeperVerifyResponse parcelable size mismatch" << std::endl;
        return 1;
    }

    return 0;
}

GatekeeperVerifyResponse fromAidlDestroy(aidl_GatekeeperVerifyResponse& res)
{
    GatekeeperVerifyResponse out;

    out.code = res.code;
    out.timeout = res.timeout_ms;
    out.authToken = transport::fromAidlDestroy(res.hardware_auth_token);

    destroy_aidl_gatekeeper_verify_response(&res);
    return out;
}

#else

GatekeeperEnrollResponse
GatekeeperHAL::enroll(u32, const std::vector<u8>&, const std::vector<u8>&, const std::vector<u8>&)
{
    std::cerr << __func__ << ": Not supported on host build" << std::endl;
    return { GatekeeperStatusCode::ERROR_NOT_IMPLEMENTED, UINT32_C(0), UINT64_C(0), {} };
}

GatekeeperVerifyResponse
GatekeeperHAL::verify(u32, u64, const std::vector<u8>&, const std::vector<u8>&)
{
    std::cerr << __func__ << ": Not supported on host build" << std::endl;
    return { GatekeeperStatusCode::ERROR_NOT_IMPLEMENTED, UINT32_C(0), {} };
}

GatekeeperStatusCode GatekeeperHAL::deleteUser(u32)
{
    std::cerr << __func__ << ": Not supported on host build" << std::endl;
    return GatekeeperStatusCode::ERROR_NOT_IMPLEMENTED;
}

GatekeeperStatusCode GatekeeperHAL::deleteAllUsers(void)
{
    std::cerr << __func__ << ": Not supported on host build" << std::endl;
    return GatekeeperStatusCode::ERROR_NOT_IMPLEMENTED;
}

WeaverStatus WeaverHAL::getConfig(WeaverConfig&)
{
    std::cerr << __func__ << ": Not supported on host build" << std::endl;
    return WeaverStatus::FAILED;
}

WeaverStatus write(u32, const std::vector<u8>&, const std::vector<u8>&)
{
    std::cerr << __func__ << ": Not supported on host build" << std::endl;
    return WeaverStatus::FAILED;
}

WeaverStatus WeaverHAL::read(u32, const std::vector<u8>&, WeaverReadResponse&)
{
    std::cerr << __func__ << ": Not supported on host build" << std::endl;
    return WeaverStatus::FAILED;
}

#endif /* SUSKEYMASTER_BUILD_HOST */

const char * toString(GatekeeperStatusCode s)
{
    switch (s) {
        case GatekeeperStatusCode::STATUS_REENROLL: return "GK_STATUS_REENROLL";
        case GatekeeperStatusCode::STATUS_OK: return "GK_STATUS_OK";
        case GatekeeperStatusCode::ERROR_GENERAL_FAILURE: return "GK_ERROR_GENERAL_FAILURE";
        case GatekeeperStatusCode::ERROR_RETRY_TIMEOUT: return "GK_ERROR_RETRY_TIMEOUT";
        case GatekeeperStatusCode::ERROR_NOT_IMPLEMENTED: return "GK_ERROR_NOT_IMPLEMENTED";
        default: return "(unknown)";
    }
}

const char * toString(WeaverStatus s)
{
    switch (s) {
        case WeaverStatus::OK: return "WEAVER_STATUS_OK";
        case WeaverStatus::FAILED: return "WEAVER_STATUS_FAILED";
        case WeaverStatus::READ_INCORRECT_KEY: return "WEAVER_READ_INCORRECT_KEY";
        case WeaverStatus::READ_THROTTLE: return "WEAVER_READ_THROTTLE";
        default: return "(unknown)";
    }
}

} /* namespace auth */
} /* namespace cli */
} /* namespace suskeymaster */
