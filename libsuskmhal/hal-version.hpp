#pragma once

#include <core/int.h>
#include <string>

namespace suskeymaster {
namespace kmhal {

enum hal_version : u16 {
    /* Invalid value */
    HAL_NONE = 0x0000,

    /* No HAL needed at all */
    HAL_NOT_NEEDED = 0x0001,

    HAL_KEYMASTER_3_0 = 0x0010,
    HAL_KEYMASTER_4_0 = 0x0020,
    HAL_KEYMASTER_4_1 = 0x0040,

    /* Any Keymaster HAL */
    HAL_KEYMASTER_ANY = HAL_KEYMASTER_3_0 | HAL_KEYMASTER_4_0 | HAL_KEYMASTER_4_1,

    HAL_KEYMINT_1_0 = 0x0100,
    HAL_KEYMINT_2_0 = 0x0200,
    HAL_KEYMINT_3_0 = 0x0400,
    HAL_KEYMINT_4_0 = 0x0800,

    /* Any KeyMint HAL */
    HAL_KEYMINT_ANY = HAL_KEYMINT_1_0 | HAL_KEYMINT_2_0 |
                      HAL_KEYMINT_3_0 | HAL_KEYMINT_4_0,

    /* Any HAL, but not no HAL at all */
    HAL_ANY = HAL_KEYMASTER_ANY | HAL_KEYMINT_ANY,

    HAL_MIN = HAL_KEYMASTER_3_0,
    HAL_MAX = HAL_KEYMINT_4_0
};

static constexpr hal_version ordered_hal_versions[] = {
    hal_version::HAL_KEYMASTER_3_0,
    hal_version::HAL_KEYMASTER_4_0,
    hal_version::HAL_KEYMASTER_4_1,
    hal_version::HAL_KEYMINT_1_0,
    hal_version::HAL_KEYMINT_2_0,
    hal_version::HAL_KEYMINT_3_0,
    hal_version::HAL_KEYMINT_4_0
};
template <hal_version min, hal_version max = HAL_MAX>
struct hal_version_range {
private:
    static constexpr int version2idx(hal_version v)
    {
        switch (v) {
            case hal_version::HAL_KEYMASTER_3_0: return 0;
            case hal_version::HAL_KEYMASTER_4_0: return 1;
            case hal_version::HAL_KEYMASTER_4_1: return 2;
            case hal_version::HAL_KEYMINT_1_0: return 3;
            case hal_version::HAL_KEYMINT_2_0: return 4;
            case hal_version::HAL_KEYMINT_3_0: return 5;
            case hal_version::HAL_KEYMINT_4_0: return 6;
            default: return -1;
        }
    }

public:
    static constexpr hal_version value = []
    {
        hal_version ret = HAL_NONE;

        constexpr int r_min = version2idx(min);
        constexpr int r_max = version2idx(max);

        static_assert(r_min != -1, "Invalid minimum HAL version");
        static_assert(r_max != -1, "Invalid maximum HAL version");

        for (int i = r_min; i <= r_max; i++) {
            ret = static_cast<hal_version>(
                static_cast<u16>(ret) |
                static_cast<u16>(ordered_hal_versions[i])
            );
        }

        return ret;
    }();
};

constexpr auto SINCE_KEYMASTER_4_0 = hal_version_range<HAL_KEYMASTER_4_0>::value;
constexpr auto UNTIL_KEYMASTER_4_1 = hal_version_range<HAL_MIN, HAL_KEYMASTER_4_1>::value;

static inline hal_version fromString(const std::string& str)
{
    if (str == "KEYMASTER_3_0") return HAL_KEYMASTER_3_0;
    if (str == "KEYMASTER_4_0") return HAL_KEYMASTER_4_0;
    if (str == "KEYMASTER_4_1") return HAL_KEYMASTER_4_1;

    if (str == "KEYMINT_1_0") return HAL_KEYMINT_1_0;
    if (str == "KEYMINT_2_0") return HAL_KEYMINT_2_0;
    if (str == "KEYMINT_3_0") return HAL_KEYMINT_3_0;
    if (str == "KEYMINT_4_0") return HAL_KEYMINT_4_0;

    if (str == "KEYMASTER")
        return hal_version_range<HAL_KEYMASTER_3_0, HAL_KEYMASTER_4_1>::value;
    if (str == "KEYMINT")
        return hal_version_range<HAL_KEYMINT_1_0, HAL_KEYMINT_4_0>::value;

    return HAL_NONE;
}

static inline const char * toString(hal_version v)
{
    switch (v) {
    case HAL_KEYMASTER_3_0: return "Keymaster 3.0";
    case HAL_KEYMASTER_4_0: return "Keymaster 4.0";
    case HAL_KEYMASTER_4_1: return "Keymaster 4.1";
    case HAL_KEYMINT_1_0: return "KeyMint 1.0";
    case HAL_KEYMINT_2_0: return "KeyMint 2.0";
    case HAL_KEYMINT_3_0: return "KeyMint 3.0";
    case HAL_KEYMINT_4_0: return "KeyMint 4.0";
    default: return "(unknown)";
    }
}

static constexpr int hal_version_major(hal_version ver) {
    if (ver >= HAL_KEYMINT_1_0)
        return (static_cast<u16>(ver) & 0xFF00) >> 8;
    else
        return (static_cast<u16>(ver) & 0x00F0) >> 4;
}
static constexpr int hal_version_minor(hal_version ver) {
    return (static_cast<uint16_t>(ver) & 0x000F);
}

} /* namespace kmhal */
} /* namespace suskeymaster */
