#define HIDL_DISABLE_INSTRUMENTATION
#include "km-params.hpp"
#include "../keymaster-types-c.h"
#include <hidl/HidlSupport.h>
#include <android/hardware/keymaster/4.0/types.h>
#include <string>
#include <strings.h>
#include <vector>
#include <sstream>
#include <iostream>
#include <charconv>
#include <system_error>
#include <unordered_map>

namespace suskeymaster {
namespace kmhal {
namespace util {

using ::android::hardware::hidl_vec;
using namespace ::android::hardware::keymaster::V4_0;

static void parse_key_values(const char *arg_,
        std::vector<std::pair<std::string, std::string>>& out);

static Tag find_tag_type_by_name(std::string const& name);

static int parse_tag_value(Tag t, std::string const& value,
        KeyParameter &out);

static int b64decode(std::string const& in, std::vector<uint8_t> &out);

static int parse_enum_value(Tag t, std::string const& value,
        KeyParameter &out);

static int parse_algorithm(std::string const& value, Algorithm& out);
static int parse_block_mode(std::string const& value, BlockMode& out);
static int parse_padding_mode(std::string const& value, PaddingMode& out);
static int parse_digest(std::string const& value, Digest& out);
static int parse_ec_curve(std::string const& value, EcCurve& out);
static int parse_key_origin(std::string const& value, KeyOrigin& out);
static int parse_key_blob_usage_requirements(std::string const& value,
        KeyBlobUsageRequirements& out);
static int parse_key_purpose(std::string const& value, KeyPurpose& out);
static int parse_key_derivation_function(std::string const& value, KeyDerivationFunction& out);

static TagType get_tag_type(Tag t);

static bool is_valid_intval_for_enum(Tag t, uint32_t val);

int parse_km_tag_params(const char *arg, hidl_vec<KeyParameter>& out)
{
    std::vector<std::pair<std::string, std::string>> key_value_pairs;

    parse_key_values(arg, key_value_pairs);

    for (auto const& p : key_value_pairs) {
        std::string const& key = p.first;
        std::string const& value = p.second;

        Tag t = find_tag_type_by_name(key);
        if (t == Tag::INVALID) {
            std::cerr << "Invalid tag name: \"" << key << "\"" << std::endl;
            return 1;
        }

        KeyParameter new_param;
        if (parse_tag_value(t, value, new_param)) {
            std::cerr << "Invalid value \"" << value << "\" for tag \"" << key << "\"" << std::endl;
            return 1;
        }

        out.resize(out.size() + 1);
        out[out.size() - 1] = new_param;
    }

    return 0;
}

km_default::km_default(Tag t, Algorithm a) {
    KeyParameter kp;
    kp.tag = t;
    kp.f.algorithm = a;
    this->val = { kp };
}
km_default::km_default(Tag t, std::vector<BlockMode> const& bm) {
    for (BlockMode b : bm) {
        KeyParameter kp;
    kp.tag = t;
        kp.f.blockMode = b;
        this->val.push_back(kp);
    }
}
km_default::km_default(Tag t, std::vector<PaddingMode> const& pm) {
    for (PaddingMode p : pm) {
        KeyParameter kp;
    kp.tag = t;
        kp.f.paddingMode = p;
        this->val.push_back(kp);
    }
}
km_default::km_default(Tag t, std::vector<Digest> const& ds) {
    for (Digest d : ds) {
        KeyParameter kp;
    kp.tag = t;
        kp.f.digest = d;
        this->val.push_back(kp);
    }
}
km_default::km_default(Tag t, EcCurve e) {
    KeyParameter kp;
    kp.tag = t;
    kp.f.ecCurve = e;
    this->val = { kp };
}
km_default::km_default(Tag t, KeyOrigin o) {
    KeyParameter kp;
    kp.tag = t;
    kp.f.origin = o;
    this->val = { kp };
}
km_default::km_default(Tag t, KeyBlobUsageRequirements ureq) {
    KeyParameter kp;
    kp.tag = t;
    kp.f.keyBlobUsageRequirements = ureq;
    this->val = { kp };
}
km_default::km_default(Tag t, std::vector<KeyPurpose> const& ps) {
    for (KeyPurpose p : ps) {
        KeyParameter kp;
    kp.tag = t;
        kp.f.purpose = p;
        this->val.push_back(kp);
    }
}
km_default::km_default(Tag t, std::vector<KeyDerivationFunction> const& kdfs) {
    for (KeyDerivationFunction kdf : kdfs) {
        KeyParameter kp;
    kp.tag = t;
        kp.f.keyDerivationFunction = kdf;
        this->val.push_back(kp);
    }
}
km_default::km_default(Tag t, HardwareAuthenticatorType h) {
    KeyParameter kp;
    kp.tag = t;
    kp.f.hardwareAuthenticatorType = h;
    this->val = { kp };
}
km_default::km_default(Tag t, SecurityLevel s) {
    KeyParameter kp;
    kp.tag = t;
    kp.f.integer = static_cast<uint32_t>(s);
    this->val = { kp };
}
km_default::km_default(Tag t, bool b) {
    KeyParameter kp;
    kp.tag = t;
    kp.f.boolValue = b;
    this->val = { kp };
}
km_default::km_default(Tag t, uint32_t i) {
    KeyParameter kp;
    kp.tag = t;
    kp.f.integer = i;
    this->val = { kp };
}
km_default::km_default(Tag t, int i) {
    KeyParameter kp;
    kp.tag = t;
    kp.f.integer = i;
    this->val = { kp };
}
km_default::km_default(Tag t, long l) {
    KeyParameter kp;
    kp.tag = t;
    kp.f.longInteger = l;
    this->val = { kp };
}
km_default::km_default(Tag t, uint64_t l) {
    KeyParameter kp;
    kp.tag = t;
    kp.f.longInteger = l;
    this->val = { kp };
}
km_default::km_default(Tag t, std::vector<uint8_t> b) {
    KeyParameter kp;
    kp.tag = t;
    kp.blob = hidl_vec<uint8_t>(b);
    this->val = { kp };
}

void init_default_params(hidl_vec<KeyParameter>& params,
    std::vector<struct km_default> const& defaults)
{
    std::unordered_map<Tag, km_default> map;
    for (km_default d : defaults) {
        if (d.val.size() == 0)
            continue;
        Tag t = d.val[0].tag;

        map.insert(std::pair<Tag, km_default>(t, d));
    }

    for (uint32_t i = 0; i < params.size(); i ++) {
        KeyParameter const& curr = params[i];

        auto it = map.find(curr.tag);
        if (it != map.end())
            it->second.found = true;
    }

    /* Populate the defaults values that weren't already found in `params` */
    for (auto const& kv : map) {
        Tag key = kv.first;
        bool param_found = kv.second.found;
        std::vector<KeyParameter> const& vals = kv.second.val;

        if (!param_found) {
            const uint32_t old_base = params.size();
            params.resize(params.size() + vals.size());

            for (uint32_t i = 0; i < vals.size(); i++) {
                params[old_base + i].tag = key;
                memcpy(&params[old_base + i].f, &vals[i].f, sizeof(KeyParameter::IntegerParams));
                params[old_base + i].blob = std::move(vals[i].blob);
            }
        }
    }
}

static void parse_key_values(const char *arg,
        std::vector<std::pair<std::string, std::string>>& out)
{
    std::istringstream ss(arg);

    std::string token;
    while (ss >> token) {
        std::string key;
        std::string value;

        auto pos = token.find("=");
        if (pos == std::string::npos) {
            /* Treat the tag as a boolean (present at all = value TRUE) */
            key = token;
            value = "true";
        } else {
            key = token.substr(0, pos);
            value = token.substr(pos + 1);
        }

        out.emplace_back(key, value);
    }
}

static Tag find_tag_type_by_name(std::string const& name)
{
    if (name == "INVALID") return Tag::INVALID;
    if (name == "PURPOSE") return Tag::PURPOSE;
    if (name == "ALGORITHM") return Tag::ALGORITHM;
    if (name == "KEY_SIZE") return Tag::KEY_SIZE;
    if (name == "BLOCK_MODE") return Tag::BLOCK_MODE;
    if (name == "DIGEST") return Tag::DIGEST;
    if (name == "PADDING") return Tag::PADDING;
    if (name == "CALLER_NONCE") return Tag::CALLER_NONCE;
    if (name == "MIN_MAC_LENGTH") return Tag::MIN_MAC_LENGTH;
    if (name == "EC_CURVE") return Tag::EC_CURVE;
    if (name == "RSA_PUBLIC_EXPONENT") return Tag::RSA_PUBLIC_EXPONENT;
    if (name == "INCLUDE_UNIQUE_ID") return Tag::INCLUDE_UNIQUE_ID;
    if (name == "BLOB_USAGE_REQUIREMENTS") return Tag::BLOB_USAGE_REQUIREMENTS;
    if (name == "BOOTLOADER_ONLY") return Tag::BOOTLOADER_ONLY;
    if (name == "ROLLBACK_RESISTANCE") return Tag::ROLLBACK_RESISTANCE;
    if (name == "HARDWARE_TYPE") return Tag::HARDWARE_TYPE;
    if (name == "ACTIVE_DATETIME") return Tag::ACTIVE_DATETIME;
    if (name == "ORIGINATION_EXPIRE_DATETIME") return Tag::ORIGINATION_EXPIRE_DATETIME;
    if (name == "USAGE_EXPIRE_DATETIME") return Tag::USAGE_EXPIRE_DATETIME;
    if (name == "MIN_SECONDS_BETWEEN_OPS") return Tag::MIN_SECONDS_BETWEEN_OPS;
    if (name == "MAX_USES_PER_BOOT") return Tag::MAX_USES_PER_BOOT;
    if (name == "USER_ID") return Tag::USER_ID;
    if (name == "USER_SECURE_ID") return Tag::USER_SECURE_ID;
    if (name == "NO_AUTH_REQUIRED") return Tag::NO_AUTH_REQUIRED;
    if (name == "USER_AUTH_TYPE") return Tag::USER_AUTH_TYPE;
    if (name == "AUTH_TIMEOUT") return Tag::AUTH_TIMEOUT;
    if (name == "ALLOW_WHILE_ON_BODY") return Tag::ALLOW_WHILE_ON_BODY;
    if (name == "TRUSTED_USER_PRESENCE_REQUIRED") return Tag::TRUSTED_USER_PRESENCE_REQUIRED;
    if (name == "TRUSTED_CONFIRMATION_REQUIRED") return Tag::TRUSTED_CONFIRMATION_REQUIRED;
    if (name == "UNLOCKED_DEVICE_REQUIRED") return Tag::UNLOCKED_DEVICE_REQUIRED;
    if (name == "APPLICATION_ID") return Tag::APPLICATION_ID;
    if (name == "APPLICATION_DATA") return Tag::APPLICATION_DATA;
    if (name == "CREATION_DATETIME") return Tag::CREATION_DATETIME;
    if (name == "ORIGIN") return Tag::ORIGIN;
    if (name == "ROOT_OF_TRUST") return Tag::ROOT_OF_TRUST;
    if (name == "OS_VERSION") return Tag::OS_VERSION;
    if (name == "OS_PATCHLEVEL") return Tag::OS_PATCHLEVEL;
    if (name == "UNIQUE_ID") return Tag::UNIQUE_ID;
    if (name == "ATTESTATION_CHALLENGE") return Tag::ATTESTATION_CHALLENGE;
    if (name == "ATTESTATION_APPLICATION_ID") return Tag::ATTESTATION_APPLICATION_ID;
    if (name == "ATTESTATION_ID_BRAND") return Tag::ATTESTATION_ID_BRAND;
    if (name == "ATTESTATION_ID_DEVICE") return Tag::ATTESTATION_ID_DEVICE;
    if (name == "ATTESTATION_ID_PRODUCT") return Tag::ATTESTATION_ID_PRODUCT;
    if (name == "ATTESTATION_ID_SERIAL") return Tag::ATTESTATION_ID_SERIAL;
    if (name == "ATTESTATION_ID_IMEI") return Tag::ATTESTATION_ID_IMEI;
    if (name == "ATTESTATION_ID_MEID") return Tag::ATTESTATION_ID_MEID;
    if (name == "ATTESTATION_ID_MANUFACTURER") return Tag::ATTESTATION_ID_MANUFACTURER;
    if (name == "ATTESTATION_ID_MODEL") return Tag::ATTESTATION_ID_MODEL;
    if (name == "VENDOR_PATCHLEVEL") return Tag::VENDOR_PATCHLEVEL;
    if (name == "BOOT_PATCHLEVEL") return Tag::BOOT_PATCHLEVEL;
    if (name == "ASSOCIATED_DATA") return Tag::ASSOCIATED_DATA;
    if (name == "NONCE") return Tag::NONCE;
    if (name == "MAC_LENGTH") return Tag::MAC_LENGTH;
    if (name == "RESET_SINCE_ID_ROTATION") return Tag::RESET_SINCE_ID_ROTATION;
    if (name == "CONFIRMATION_TOKEN") return Tag::CONFIRMATION_TOKEN;

    if (name == "AUTH_TOKEN") return SamsungTag::AUTH_TOKEN;
    if (name == "VERIFICATION_TOKEN") return SamsungTag::VERIFICATION_TOKEN;
    if (name == "ALL_USERS") return SamsungTag::ALL_USERS;
    if (name == "ECIES_SINGLE_HASH_MODE") return SamsungTag::ECIES_SINGLE_HASH_MODE;
    if (name == "KDF") return SamsungTag::KDF;
    if (name == "EXPORTABLE") return SamsungTag::EXPORTABLE;
    if (name == "KEY_AUTH") return SamsungTag::KEY_AUTH;
    if (name == "OP_AUTH") return SamsungTag::OP_AUTH;
    if (name == "OPERATION_HANDLE") return SamsungTag::OPERATION_HANDLE;
    if (name == "OPERATION_FAILED") return SamsungTag::OPERATION_FAILED;
    if (name == "INTERNAL_CURRENT_DATETIME") return SamsungTag::INTERNAL_CURRENT_DATETIME;
    if (name == "EKEY_BLOB_IV") return SamsungTag::EKEY_BLOB_IV;
    if (name == "EKEY_BLOB_AUTH_TAG") return SamsungTag::EKEY_BLOB_AUTH_TAG;
    if (name == "EKEY_BLOB_CURRENT_USES_PER_BOOT") return SamsungTag::EKEY_BLOB_CURRENT_USES_PER_BOOT;
    if (name == "EKEY_BLOB_LAST_OP_TIMESTAMP") return SamsungTag::EKEY_BLOB_LAST_OP_TIMESTAMP;
    if (name == "EKEY_BLOB_DO_UPGRADE") return SamsungTag::EKEY_BLOB_DO_UPGRADE;
    if (name == "EKEY_BLOB_PASSWORD") return SamsungTag::EKEY_BLOB_PASSWORD;
    if (name == "EKEY_BLOB_SALT") return SamsungTag::EKEY_BLOB_SALT;
    if (name == "EKEY_BLOB_ENC_VER") return SamsungTag::EKEY_BLOB_ENC_VER;
    if (name == "EKEY_BLOB_RAW") return SamsungTag::EKEY_BLOB_RAW;
    if (name == "EKEY_BLOB_UNIQ_KDM") return SamsungTag::EKEY_BLOB_UNIQ_KDM;
    if (name == "EKEY_BLOB_INC_USE_COUNT") return SamsungTag::EKEY_BLOB_INC_USE_COUNT;
    if (name == "SAMSUNG_REQUESTING_TA") return SamsungTag::SAMSUNG_REQUESTING_TA;
    if (name == "SAMSUNG_ROT_REQUIRED") return SamsungTag::SAMSUNG_ROT_REQUIRED;
    if (name == "SAMSUNG_LEGACY_ROT") return SamsungTag::SAMSUNG_LEGACY_ROT;
    if (name == "USE_SECURE_PROCESSOR") return SamsungTag::USE_SECURE_PROCESSOR;
    if (name == "STORAGE_KEY") return SamsungTag::STORAGE_KEY;
    if (name == "IS_SAMSUNG_KEY") return SamsungTag::IS_SAMSUNG_KEY;
    if (name == "SAMSUNG_ATTESTATION_ROOT") return SamsungTag::SAMSUNG_ATTESTATION_ROOT;
    if (name == "INTEGRITY_STATUS") return SamsungTag::INTEGRITY_STATUS;
    if (name == "SAMSUNG_ATTEST_INTEGRITY") return SamsungTag::SAMSUNG_ATTEST_INTEGRITY;
    if (name == "KNOX_OBJECT_PROTECTION_REQUIRED") return SamsungTag::KNOX_OBJECT_PROTECTION_REQUIRED;
    if (name == "KNOX_CREATOR_ID") return SamsungTag::KNOX_CREATOR_ID;
    if (name == "KNOX_ADMINISTRATOR_ID") return SamsungTag::KNOX_ADMINISTRATOR_ID;
    if (name == "KNOX_ACCESSOR_ID") return SamsungTag::KNOX_ACCESSOR_ID;
    if (name == "SAMSUNG_AUTHENTICATE_PACKAGE") return SamsungTag::SAMSUNG_AUTHENTICATE_PACKAGE;
    if (name == "SAMSUNG_CERTIFICATE_SUBJECT") return SamsungTag::SAMSUNG_CERTIFICATE_SUBJECT;
    if (name == "SAMSUNG_KEY_USAGE") return SamsungTag::SAMSUNG_KEY_USAGE;
    if (name == "SAMSUNG_EXTENDED_KEY_USAGE") return SamsungTag::SAMSUNG_EXTENDED_KEY_USAGE;
    if (name == "SAMSUNG_SUBJECT_ALTERNATIVE_NAME") return SamsungTag::SAMSUNG_SUBJECT_ALTERNATIVE_NAME;
    if (name == "PROV_GAC_EC1") return SamsungTag::PROV_GAC_EC1;
    if (name == "PROV_GAC_EC2") return SamsungTag::PROV_GAC_EC2;
    if (name == "PROV_GAC_EC3") return SamsungTag::PROV_GAC_EC3;
    if (name == "PROV_GAK_EC") return SamsungTag::PROV_GAK_EC;
    if (name == "PROV_GAK_EC_VTOKEN") return SamsungTag::PROV_GAK_EC_VTOKEN;
    if (name == "PROV_GAC_RSA1") return SamsungTag::PROV_GAC_RSA1;
    if (name == "PROV_GAC_RSA2") return SamsungTag::PROV_GAC_RSA2;
    if (name == "PROV_GAC_RSA3") return SamsungTag::PROV_GAC_RSA3;
    if (name == "PROV_GAK_RSA") return SamsungTag::PROV_GAK_RSA;
    if (name == "PROV_GAK_RSA_VTOKEN") return SamsungTag::PROV_GAK_RSA_VTOKEN;
    if (name == "PROV_SAK_EC") return SamsungTag::PROV_SAK_EC;
    if (name == "PROV_SAK_EC_VTOKEN") return SamsungTag::PROV_SAK_EC_VTOKEN;

    return Tag::INVALID;
}

static int parse_tag_value(Tag t, std::string const& value,
        KeyParameter &out)
{
    TagType type = get_tag_type(t);

    const char *end = value.data() + value.size();
    std::from_chars_result res;

    std::vector<uint8_t> tmp;

    out.tag = t;

    switch (type) {
        case TagType::ENUM:
        case TagType::ENUM_REP:
            return parse_enum_value(t, value, out);

        case TagType::UINT:
        case TagType::UINT_REP:
            res = std::from_chars(value.data(), end, out.f.integer);
            if (res.ec != std::errc() || res.ptr != end) {
                std::cerr << "Couldn't parse uint value from \"" << value << "\"" << std::endl;
                return 1;
            }
            return 0;

        case TagType::ULONG:
        case TagType::ULONG_REP:
            res = std::from_chars(value.data(), end, out.f.longInteger);
            if (res.ec != std::errc() || res.ptr != end) {
                std::cerr << "Couldn't parse ulong value from \"" << value << "\"" << std::endl;
                return 1;
            }
            return 0;

        case TagType::DATE:
            res = std::from_chars(value.data(), end, out.f.dateTime);
            if (res.ec != std::errc() || res.ptr != end) {
                std::cerr << "Couldn't parse datetime value from \"" << value << "\"" << std::endl;
                return 1;
            }
            return 0;

        case TagType::BOOL:
            if (value == "0" || !strcasecmp(value.c_str(), "false")) {
                out.f.boolValue = false;
                return 0;
            } else if (value == "1" || !strcasecmp(value.c_str(), "true")) {
                out.f.boolValue = true;
                return 0;
            } else {
                std::cerr << "Invalid boolean value \"" << value << "\"" << std::endl;
                return 1;
            }

        case TagType::BIGNUM:
        case TagType::BYTES:
            /* Allow 0-length blobs */
            if (value.length() == 0) {
                out.blob = hidl_vec<uint8_t>(0);
                return 0;
            }

            if (b64decode(value, tmp)) {
                std::cerr << "Couldn't decode base64 value \"" << value << "\" "
                    << "for tag type " << toString(type) << std::endl;
                return 1;
            }
            out.blob = hidl_vec<uint8_t>(tmp.data(), tmp.data() + tmp.size());
            return 0;

        case TagType::INVALID:
            std::cerr << "Invalid tag type for tag " << static_cast<uint32_t>(t) <<
                " (" << toString(t) << ")" << std::endl;
            return 1;
    }

    return 1;
}

// Source - https://stackoverflow.com/a/41094722
// Posted by GaspardP, modified by community. See post 'Timeline' for change history
// Retrieved 2026-03-20, License - CC BY-SA 4.0

static const int B64index[256] = { 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 62, 63, 62, 62, 63, 52, 53, 54, 55,
56, 57, 58, 59, 60, 61,  0,  0,  0,  0,  0,  0,  0,  0,  1,  2,  3,  4,  5,  6,
7,  8,  9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,  0,
0,  0,  0, 63,  0, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51 };

static int b64decode(std::string const& in, std::vector<uint8_t> &out)
{

    if (in.length() == 0 || in.empty()) {
        std::cerr << "Empty string!" << std::endl;
        return 1;
    }

    unsigned char* p = (unsigned char*)in.data();
    int pad = (in.length() % 4 || p[in.length() - 1] == '=');
    const size_t L = ((in.length() + 3) / 4 - pad) * 4;

    out.resize(L / 4 * 3 + pad, '\0');

    for (size_t i = 0, j = 0; i < L; i += 4)
    {
        int n = B64index[p[i]] << 18 | B64index[p[i + 1]] << 12 | B64index[p[i + 2]] << 6 | B64index[p[i + 3]];
        out[j++] = n >> 16;
        out[j++] = n >> 8 & 0xFF;
        out[j++] = n & 0xFF;
    }
    if (pad)
    {
        int n = B64index[p[L]] << 18 | B64index[p[L + 1]] << 12;
        out[out.size() - 1] = n >> 16;

        if (in.length() > L + 2 && p[L + 2] != '=')
        {
            n |= B64index[p[L + 2]] << 6;
            out.push_back(n >> 8 & 0xFF);
        }
    }
    return 0;
}

static int parse_enum_value(Tag t, std::string const& value,
        KeyParameter &out)
{
    uint32_t uint_val = 0;
    const char *end = value.data() + value.size();

    auto [ptr, ec] = std::from_chars(value.data(), end, uint_val);
    if (ec == std::errc() && ptr == end) {
        if (!is_valid_intval_for_enum(t, uint_val)) {
            std::cerr << "Invalid integer value " << uint_val
                << " for Tag::" << toString(t) << std::endl;
            return 1;
        }

        out.f.integer = uint_val;
        return 0;
    }

    switch (t) {
        case Tag::ALGORITHM: return parse_algorithm(value, out.f.algorithm);
        case Tag::BLOCK_MODE: return parse_block_mode(value, out.f.blockMode);
        case Tag::PADDING: return parse_padding_mode(value, out.f.paddingMode);
        case Tag::DIGEST: return parse_digest(value, out.f.digest);
        case Tag::EC_CURVE: return parse_ec_curve(value, out.f.ecCurve);
        case Tag::ORIGIN: return parse_key_origin(value, out.f.origin);
        case Tag::BLOB_USAGE_REQUIREMENTS:
            return parse_key_blob_usage_requirements(value, out.f.keyBlobUsageRequirements);
        case Tag::PURPOSE: return parse_key_purpose(value, out.f.purpose);

        case SamsungTag::KDF:
            return parse_key_derivation_function(value, out.f.keyDerivationFunction);

        default:
            std::cerr << "Invalid enum tag: " << toString(t) << std::endl;
            return 1;
    }
}

static int parse_algorithm(std::string const& value, Algorithm& out)
{
    if (value == "RSA") {
        out = Algorithm::RSA;
        return 0;
    }
    if (value == "EC") {
        out = Algorithm::EC;
        return 0;
    }
    if (value == "AES") {
        out = Algorithm::AES;
        return 0;
    }
    if (value == "TRIPLE_DES") {
        out = Algorithm::TRIPLE_DES;
        return 0;
    }
    if (value == "HMAC") {
        out = Algorithm::HMAC;
        return 0;
    }

    return 1;
}

static int parse_block_mode(std::string const& value, BlockMode& out)
{
    if (value == "ECB") {
        out = BlockMode::ECB;
        return 0;
    }
    if (value == "CBC") {
        out = BlockMode::CBC;
        return 0;
    }
    if (value == "CTR") {
        out = BlockMode::CTR;
        return 0;
    }
    if (value == "GCM") {
        out = BlockMode::GCM;
        return 0;
    }

    return 1;
}

static int parse_padding_mode(std::string const& value, PaddingMode& out)
{
    if (value == "NONE") {
        out = PaddingMode::NONE;
        return 0;
    }
    if (value == "RSA_OAEP") {
        out = PaddingMode::RSA_OAEP;
        return 0;
    }
    if (value == "RSA_PSS") {
        out = PaddingMode::RSA_PSS;
        return 0;
    }
    if (value == "RSA_PKCS1_1_5_ENCRYPT") {
        out = PaddingMode::RSA_PKCS1_1_5_ENCRYPT;
        return 0;
    }
    if (value == "RSA_PKCS1_1_5_SIGN") {
        out = PaddingMode::RSA_PKCS1_1_5_SIGN;
        return 0;
    }
    if (value == "PKCS7") {
        out = PaddingMode::PKCS7;
        return 0;
    }

    return 1;
}

static int parse_digest(std::string const& value, Digest& out)
{
    if (value == "NONE") {
        out = Digest::NONE;
        return 0;
    }
    if (value == "MD5") {
        out = Digest::MD5;
        return 0;
    }
    if (value == "SHA1") {
        out = Digest::SHA1;
        return 0;
    }
    if (value == "SHA_2_224") {
        out = Digest::SHA_2_224;
        return 0;
    }
    if (value == "SHA_2_256") {
        out = Digest::SHA_2_256;
        return 0;
    }
    if (value == "SHA_2_384") {
        out = Digest::SHA_2_384;
        return 0;
    }
    if (value == "SHA_2_512") {
        out = Digest::SHA_2_512;
        return 0;
    }

    return 1;
}

static int parse_ec_curve(std::string const& value, EcCurve& out)
{
    if (value == "P_224") {
        out = EcCurve::P_224;
        return 0;
    }
    if (value == "P_256") {
        out = EcCurve::P_256;
        return 0;
    }
    if (value == "P_384") {
        out = EcCurve::P_384;
        return 0;
    }
    if (value == "P_521") {
        out = EcCurve::P_521;
        return 0;
    }

    return 1;
}

static int parse_key_origin(std::string const& value, KeyOrigin& out)
{
    if (value == "GENERATED") {
        out = KeyOrigin::GENERATED;
        return 0;
    }
    if (value == "DERIVED") {
        out = KeyOrigin::DERIVED;
        return 0;
    }
    if (value == "IMPORTED") {
        out = KeyOrigin::IMPORTED;
        return 0;
    }
    if (value == "UNKNOWN") {
        out = KeyOrigin::UNKNOWN;
        return 0;
    }
    if (value == "SECURELY_IMPORTED") {
        out = KeyOrigin::SECURELY_IMPORTED;
        return 0;
    }

    return 1;
}

static int parse_key_blob_usage_requirements(std::string const& value,
        KeyBlobUsageRequirements& out)
{
    if (value == "STANDALONE") {
        out = KeyBlobUsageRequirements::STANDALONE;
        return 0;
    }
    if (value == "REQUIRES_FILE_SYSTEM") {
        out = KeyBlobUsageRequirements::REQUIRES_FILE_SYSTEM;
        return 0;
    }

    return 1;
}

static int parse_key_purpose(std::string const& value, KeyPurpose& out)
{
    if (value == "ENCRYPT") {
        out = KeyPurpose::ENCRYPT;
        return 0;
    }
    if (value == "DECRYPT") {
        out = KeyPurpose::DECRYPT;
        return 0;
    }
    if (value == "SIGN") {
        out = KeyPurpose::SIGN;
        return 0;
    }
    if (value == "VERIFY") {
        out = KeyPurpose::VERIFY;
        return 0;
    }
    if (value == "WRAP_KEY") {
        out = KeyPurpose::WRAP_KEY;
        return 0;
    }

    return 1;
}

static int parse_key_derivation_function(std::string const& value, KeyDerivationFunction& out)
{
    if (value == "NONE") {
        out = KeyDerivationFunction::NONE;
        return 0;
    }
    if (value == "RFC5869_SHA256") {
        out = KeyDerivationFunction::RFC5869_SHA256;
        return 0;
    }
    if (value == "ISO18033_2_KDF1_SHA1") {
        out = KeyDerivationFunction::ISO18033_2_KDF1_SHA1;
        return 0;
    }
    if (value == "ISO18033_2_KDF1_SHA256") {
        out = KeyDerivationFunction::ISO18033_2_KDF1_SHA256;
        return 0;
    }
    if (value == "ISO18033_2_KDF2_SHA1") {
        out = KeyDerivationFunction::ISO18033_2_KDF2_SHA1;
        return 0;
    }
    if (value == "ISO18033_2_KDF2_SHA256") {
        out = KeyDerivationFunction::ISO18033_2_KDF2_SHA256;
        return 0;
    }

    return 1;
}

static TagType get_tag_type(Tag t_)
{
    const uint32_t m = static_cast<uint32_t>(t_) & 0xFF000000;

    /* All `Tag`s are defined such that only one of these is ORed in */
    if (m == static_cast<uint32_t>(TagType::ENUM)) return TagType::ENUM;
    if (m == static_cast<uint32_t>(TagType::ENUM_REP)) return TagType::ENUM_REP;
    if (m == static_cast<uint32_t>(TagType::UINT)) return TagType::UINT;
    if (m == static_cast<uint32_t>(TagType::UINT_REP)) return TagType::UINT_REP;
    if (m == static_cast<uint32_t>(TagType::ULONG)) return TagType::ULONG;
    if (m == static_cast<uint32_t>(TagType::DATE)) return TagType::DATE;
    if (m == static_cast<uint32_t>(TagType::BOOL)) return TagType::BOOL;
    if (m == static_cast<uint32_t>(TagType::BIGNUM)) return TagType::BIGNUM;
    if (m == static_cast<uint32_t>(TagType::BYTES)) return TagType::BYTES;
    if (m == static_cast<uint32_t>(TagType::ULONG_REP)) return TagType::ULONG_REP;

    return TagType::INVALID;
}

static bool is_valid_intval_for_enum(Tag t, uint32_t val)
{
    switch (t) {
        case Tag::ALGORITHM:
            return
                val == static_cast<uint32_t>(Algorithm::RSA) ||
                val == static_cast<uint32_t>(Algorithm::EC) ||
                val == static_cast<uint32_t>(Algorithm::AES) ||
                val == static_cast<uint32_t>(Algorithm::TRIPLE_DES) ||
                val == static_cast<uint32_t>(Algorithm::HMAC);
        case Tag::BLOCK_MODE:
            return
                val == static_cast<uint32_t>(BlockMode::ECB) ||
                val == static_cast<uint32_t>(BlockMode::CBC) ||
                val == static_cast<uint32_t>(BlockMode::CTR) ||
                val == static_cast<uint32_t>(BlockMode::GCM);
        case Tag::PADDING:
            return
                val == static_cast<uint32_t>(PaddingMode::NONE) ||
                val == static_cast<uint32_t>(PaddingMode::RSA_OAEP) ||
                val == static_cast<uint32_t>(PaddingMode::RSA_PSS) ||
                val == static_cast<uint32_t>(PaddingMode::RSA_PKCS1_1_5_ENCRYPT) ||
                val == static_cast<uint32_t>(PaddingMode::RSA_PKCS1_1_5_SIGN) ||
                val == static_cast<uint32_t>(PaddingMode::PKCS7);
        case Tag::DIGEST:
            return
                val == static_cast<uint32_t>(Digest::NONE) ||
                val == static_cast<uint32_t>(Digest::MD5) ||
                val == static_cast<uint32_t>(Digest::SHA1) ||
                val == static_cast<uint32_t>(Digest::SHA_2_224) ||
                val == static_cast<uint32_t>(Digest::SHA_2_256) ||
                val == static_cast<uint32_t>(Digest::SHA_2_384) ||
                val == static_cast<uint32_t>(Digest::SHA_2_512);
        case Tag::EC_CURVE:
            return
                val == static_cast<uint32_t>(EcCurve::P_224) ||
                val == static_cast<uint32_t>(EcCurve::P_256) ||
                val == static_cast<uint32_t>(EcCurve::P_384) ||
                val == static_cast<uint32_t>(EcCurve::P_521);
        case Tag::ORIGIN:
            return
                val == static_cast<uint32_t>(KeyOrigin::GENERATED) ||
                val == static_cast<uint32_t>(KeyOrigin::DERIVED) ||
                val == static_cast<uint32_t>(KeyOrigin::IMPORTED) ||
                val == static_cast<uint32_t>(KeyOrigin::UNKNOWN) ||
                val == static_cast<uint32_t>(KeyOrigin::SECURELY_IMPORTED);
        case Tag::BLOB_USAGE_REQUIREMENTS:
            return
                val == static_cast<uint32_t>(KeyBlobUsageRequirements::STANDALONE) ||
                val == static_cast<uint32_t>(KeyBlobUsageRequirements::REQUIRES_FILE_SYSTEM);
        case Tag::PURPOSE:
            return
                val == static_cast<uint32_t>(KeyPurpose::ENCRYPT) ||
                val == static_cast<uint32_t>(KeyPurpose::DECRYPT) ||
                val == static_cast<uint32_t>(KeyPurpose::SIGN) ||
                val == static_cast<uint32_t>(KeyPurpose::VERIFY) ||
                val == static_cast<uint32_t>(KeyPurpose::WRAP_KEY);
        default:
            std::cerr << "Invalid enum tag: " << toString(t) << std::endl;
            return false;
    }
}

void key_params_2_auth_list(hidl_vec<KeyParameter> const& params,
        struct KM_AuthorizationList_v3 *out)
{
    /* holy macro */
#define push_enum(type_, field_, val_) do {                     \
    if (out->field_ == NULL)  {                                 \
        out->field_ = vector_new(type_);                        \
    }                                                           \
    out->__##field_##_present = true;                           \
    vector_push_back(&out->field_, (type_)val_);                \
} while (0)
#define push_long(field_, kp_) do {                         \
    if (out->field_ == NULL)                                \
        *(uint64_t **)&out->field_ = vector_new(uint64_t);  \
    out->__##field_##_present = true;                       \
    vector_push_back(&out->field_, kp_.f.longInteger);      \
} while (0)
#define copy_bytes(field_, kp_) do {                            \
    if (out->field_ == NULL)                                    \
        out->field_ = vector_new(u8);                           \
    out->__##field_##_present = true;                           \
    vector_resize(&out->field_, kp_.blob.size());               \
    memcpy(out->field_, kp_.blob.data(), kp_.blob.size());      \
} while (0)
#define assign_enum(type_, field_, val_) do {   \
    out->__##field_##_present = true;           \
    out->field_ = (type_)val_;                  \
} while (0)
#define assign_int(field_, kp_) do {        \
    out->__##field_##_present = true;       \
    out->field_ = kp_.f.integer;            \
} while (0)
#define assign_long(field_, kp_) do {       \
    out->__##field_##_present = true;       \
    out->field_ = kp_.f.longInteger;        \
} while (0)
#define assign_bool(field_, kp_) do {       \
    out->__##field_##_present = true;       \
    out->field_ = kp_.f.boolValue;          \
} while (0)
#define assign_datetime(field_, kp_) do {   \
    out->__##field_##_present = true;       \
    out->field_ = kp_.f.dateTime;           \
} while (0)

    for (auto const& kp : params) {
        switch (kp.tag) {
        case Tag::PURPOSE: push_enum(KM_KeyPurpose, purpose, kp.f.purpose); break;
        case Tag::ALGORITHM: assign_enum(KM_Algorithm, algorithm, kp.f.algorithm); break;
        case Tag::KEY_SIZE: assign_int(keySize, kp); break;
        case Tag::BLOCK_MODE: push_enum(KM_BlockMode, blockMode, kp.f.blockMode); break;
        case Tag::DIGEST: push_enum(KM_Digest, digest, kp.f.digest); break;
        case Tag::PADDING: push_enum(KM_PaddingMode, padding, kp.f.paddingMode); break;
        case Tag::CALLER_NONCE: assign_bool(callerNonce, kp); break;
        case Tag::MIN_MAC_LENGTH: assign_int(minMacLength, kp); break;
        case Tag::EC_CURVE: assign_enum(KM_EcCurve, ecCurve, kp.f.ecCurve); break;
        case Tag::RSA_PUBLIC_EXPONENT: assign_long(rsaPublicExponent, kp); break;
        case Tag::INCLUDE_UNIQUE_ID: assign_bool(includeUniqueId, kp); break;
        case Tag::BLOB_USAGE_REQUIREMENTS:
            assign_enum(KM_KeyBlobUsageRequirements,
                    keyBlobUsageRequirements, kp.f.keyBlobUsageRequirements);
            break;
        case Tag::BOOTLOADER_ONLY: assign_bool(bootloaderOnly, kp); break;
        case Tag::ROLLBACK_RESISTANCE: assign_bool(rollbackResistance, kp); break;
        case Tag::HARDWARE_TYPE: assign_int(hardwareType, kp); break;
        case Tag::ACTIVE_DATETIME: assign_datetime(activeDateTime, kp); break;
        case Tag::ORIGINATION_EXPIRE_DATETIME:
            assign_datetime(originationExpireDateTime, kp);
            break;
        case Tag::USAGE_EXPIRE_DATETIME: assign_datetime(usageExpireDateTime, kp); break;
        case Tag::MIN_SECONDS_BETWEEN_OPS: assign_int(minSecondsBetweenOps, kp); break;
        case Tag::MAX_USES_PER_BOOT: assign_int(maxUsesPerBoot, kp); break;
        case Tag::USER_ID: assign_int(userId, kp); break;
        case Tag::USER_SECURE_ID: push_long(userSecureId, kp); break;
        case Tag::NO_AUTH_REQUIRED: assign_bool(noAuthRequired, kp); break;
        case Tag::USER_AUTH_TYPE: assign_long(userAuthType, kp); break;
        case Tag::AUTH_TIMEOUT: assign_int(authTimeout, kp); break;
        case Tag::ALLOW_WHILE_ON_BODY: assign_bool(allowWhileOnBody, kp); break;
        case Tag::TRUSTED_USER_PRESENCE_REQUIRED: assign_bool(trustedUserPresenceReq, kp); break;
        case Tag::TRUSTED_CONFIRMATION_REQUIRED: assign_bool(trustedConfirmationReq, kp); break;
        case Tag::UNLOCKED_DEVICE_REQUIRED: assign_bool(unlockedDeviceReq, kp); break;
        case Tag::APPLICATION_ID: copy_bytes(applicationId, kp); break;
        case Tag::APPLICATION_DATA: copy_bytes(applicationData, kp); break;
        case Tag::CREATION_DATETIME: assign_datetime(creationDateTime, kp); break;
        case Tag::ORIGIN: assign_enum(KM_KeyOrigin, keyOrigin, kp.f.origin); break;
        case Tag::ROOT_OF_TRUST:
            std::cerr << "WARNING: ROOT_OF_TRUST value in parameters; "
                "setting `rootOfTrustBytes` instead of `rootOfTrust`" << std::endl;
            copy_bytes(rootOfTrustBytes, kp);
            break;
        case Tag::OS_VERSION: assign_int(osVersion, kp); break;
        case Tag::OS_PATCHLEVEL: assign_int(osPatchLevel, kp); break;
        case Tag::UNIQUE_ID: copy_bytes(uniqueId, kp); break;
        case Tag::ATTESTATION_CHALLENGE: copy_bytes(attestationChallenge, kp); break;
        case Tag::ATTESTATION_APPLICATION_ID: copy_bytes(attestationApplicationId, kp); break;
        case Tag::ATTESTATION_ID_BRAND: copy_bytes(attestationIdBrand, kp); break;
        case Tag::ATTESTATION_ID_DEVICE: copy_bytes(attestationIdDevice, kp); break;
        case Tag::ATTESTATION_ID_PRODUCT: copy_bytes(attestationIdProduct, kp); break;
        case Tag::ATTESTATION_ID_SERIAL: copy_bytes(attestationIdSerial, kp); break;
        case Tag::ATTESTATION_ID_IMEI: copy_bytes(attestationIdImei, kp); break;
        case Tag::ATTESTATION_ID_MEID: copy_bytes(attestationIdMeid, kp); break;
        case Tag::ATTESTATION_ID_MANUFACTURER: copy_bytes(attestationIdManufacturer, kp); break;
        case Tag::ATTESTATION_ID_MODEL: copy_bytes(attestationIdModel, kp); break;
        case Tag::VENDOR_PATCHLEVEL: assign_int(vendorPatchLevel, kp); break;
        case Tag::BOOT_PATCHLEVEL: assign_int(bootPatchLevel, kp); break;
        case Tag::ASSOCIATED_DATA: copy_bytes(associatedData, kp); break;
        case Tag::NONCE: copy_bytes(nonce, kp); break;
        case Tag::MAC_LENGTH: assign_int(macLength, kp); break;
        case Tag::RESET_SINCE_ID_ROTATION: assign_bool(resetSinceIdRotation, kp); break;
        case Tag::CONFIRMATION_TOKEN: copy_bytes(confirmationToken, kp); break;

#undef push_enum
#undef push_long
#undef copy_bytes
#undef assign_enum
#undef assign_bool
#undef assign_int
#undef assign_long
#undef assign_datetime

#define push_enum(type_, field_, val_) do {                     \
    if (out->samsung.field_ == NULL)  {                         \
        &out->samsung.field_ = vector_new(type_));              \
    }                                                           \
    out->samsung.__##field_##_present = true;                   \
    vector_push_back(&out->samsung.field_, val_);               \
} while (0)
#define push_long(field_, kp_) do {                                 \
    if (out->samsungfield_ == NULL)                                 \
        *(uint64_t **)&out->samsungfield_ = vector_new(uint64_t);   \
    out->samsung.__##field_##_present = true;                       \
    vector_push_back(&out->samsung.field_, kp_.f.longInteger);      \
} while (0)
#define copy_bytes(field_, kp_) do {                                    \
    out->samsung.__##field_##_present = true;                           \
    if (out->samsung.field_ == NULL)                                    \
        out->samsung.field_ = vector_new(u8);                           \
    vector_resize(&out->samsung.field_, kp_.blob.size());               \
    memcpy(out->samsung.field_, kp_.blob.data(), kp_.blob.size());      \
} while (0)
#define assign_enum(type_, field_, val_) do {   \
    out->samsung.__##field_##_present = true;   \
    out->samsung.field_ = (type_)val_;          \
} while (0)
#define assign_int(field_, kp_) do {            \
    out->samsung.__##field_##_present = true;   \
    out->samsung.field_ = kp_.f.integer;        \
} while (0)
#define assign_long(field_, kp_) do {           \
    out->samsung.__##field_##_present = true;   \
    out->samsung.field_ = kp_.f.longInteger;    \
} while (0)
#define assign_bool(field_, kp_) do {           \
    out->samsung.__##field_##_present = true;   \
    out->samsung.field_ = kp_.f.boolValue;      \
} while (0)
#define assign_datetime(field_, kp_) do {       \
    out->samsung.__##field_##_present = true;   \
    out->samsung.field_ = kp_.f.dateTime;       \
} while (0)

        case SamsungTag::AUTH_TOKEN: copy_bytes(authToken, kp); break;
        case SamsungTag::VERIFICATION_TOKEN: copy_bytes(verificationToken, kp); break;
        case SamsungTag::ALL_USERS: assign_bool(allUsers, kp); break;
        case SamsungTag::ECIES_SINGLE_HASH_MODE: assign_bool(eciesSingleHashMode, kp); break;
        case SamsungTag::KDF:
            assign_enum(KM_KeyDerivationFunction, kdf, kp.f.keyDerivationFunction);
            break;
        case SamsungTag::EXPORTABLE: assign_bool(exportable, kp); break;
        case SamsungTag::KEY_AUTH: assign_bool(keyAuth, kp); break;
        case SamsungTag::OP_AUTH: assign_bool(opAuth, kp); break;
        case SamsungTag::OPERATION_HANDLE: assign_long(operationHandle, kp); break;
        case SamsungTag::OPERATION_FAILED: assign_bool(operationFailed, kp); break;
        case SamsungTag::INTERNAL_CURRENT_DATETIME:
            assign_datetime(internalCurrentDateTime, kp);
            break;
        case SamsungTag::EKEY_BLOB_IV: copy_bytes(ekeyBlobIV, kp); break;
        case SamsungTag::EKEY_BLOB_AUTH_TAG: copy_bytes(ekeyBlobAuthTag, kp); break;
        case SamsungTag::EKEY_BLOB_CURRENT_USES_PER_BOOT:
            assign_int(ekeyBlobCurrentUsesPerBoot, kp);
            break;
        case SamsungTag::EKEY_BLOB_LAST_OP_TIMESTAMP:
            assign_long(ekeyBlobLastOpTimestamp, kp);
            break;
        case SamsungTag::EKEY_BLOB_DO_UPGRADE: assign_int(ekeyBlobDoUpgrade, kp); break;
        case SamsungTag::EKEY_BLOB_PASSWORD: copy_bytes(ekeyBlobPassword, kp); break;
        case SamsungTag::EKEY_BLOB_SALT: copy_bytes(ekeyBlobSalt, kp); break;
        case SamsungTag::EKEY_BLOB_ENC_VER: assign_int(ekeyBlobEncVer, kp); break;
        case SamsungTag::EKEY_BLOB_RAW: assign_int(ekeyBlobRaw, kp); break;
        case SamsungTag::EKEY_BLOB_UNIQ_KDM: copy_bytes(ekeyBlobUniqKDM, kp); break;
        case SamsungTag::EKEY_BLOB_INC_USE_COUNT: assign_int(ekeyBlobIncUseCount, kp); break;
        case SamsungTag::SAMSUNG_REQUESTING_TA: copy_bytes(samsungRequestingTA, kp); break;
        case SamsungTag::SAMSUNG_ROT_REQUIRED: assign_bool(samsungRotRequired, kp); break;
        case SamsungTag::USE_SECURE_PROCESSOR: assign_bool(useSecureProcessor, kp); break;
        case SamsungTag::STORAGE_KEY: assign_bool(storageKey, kp); break;
        case SamsungTag::INTEGRITY_STATUS: assign_int(integrityStatus, kp); break;
        case SamsungTag::IS_SAMSUNG_KEY: assign_bool(isSamsungKey, kp); break;
        case SamsungTag::SAMSUNG_ATTESTATION_ROOT: copy_bytes(samsungAttestationRoot, kp); break;
        case SamsungTag::SAMSUNG_ATTEST_INTEGRITY: assign_bool(samsungAttestIntegrity, kp); break;
        case SamsungTag::KNOX_OBJECT_PROTECTION_REQUIRED:
            assign_bool(knoxObjectProtectionRequired, kp);
            break;
        case SamsungTag::KNOX_CREATOR_ID: copy_bytes(knoxCreatorId, kp); break;
        case SamsungTag::KNOX_ADMINISTRATOR_ID: copy_bytes(knoxAdministratorId, kp); break;
        case SamsungTag::KNOX_ACCESSOR_ID: copy_bytes(knoxAccessorId, kp); break;
        case SamsungTag::SAMSUNG_AUTHENTICATE_PACKAGE: copy_bytes(samsungAuthPackage, kp); break;
        case SamsungTag::SAMSUNG_CERTIFICATE_SUBJECT:
            copy_bytes(samsungCertificateSubject, kp);
            break;
        case SamsungTag::SAMSUNG_KEY_USAGE: assign_int(samsungKeyUsage, kp); break;
        case SamsungTag::SAMSUNG_EXTENDED_KEY_USAGE: copy_bytes(samsungExtendedKeyUsage, kp); break;
        case SamsungTag::SAMSUNG_SUBJECT_ALTERNATIVE_NAME:
            copy_bytes(samsungSubjectAlternativeName, kp);
            break;
        case SamsungTag::PROV_GAC_EC1: copy_bytes(provGacEc1, kp); break;
        case SamsungTag::PROV_GAC_EC2: copy_bytes(provGacEc2, kp); break;
        case SamsungTag::PROV_GAC_EC3: copy_bytes(provGacEc3, kp); break;
        case SamsungTag::PROV_GAK_EC: copy_bytes(provGakEc, kp); break;
        case SamsungTag::PROV_GAK_EC_VTOKEN: copy_bytes(provGakEcVtoken, kp); break;
        case SamsungTag::PROV_GAC_RSA1: copy_bytes(provGacRsa1, kp); break;
        case SamsungTag::PROV_GAC_RSA2: copy_bytes(provGacRsa2, kp); break;
        case SamsungTag::PROV_GAC_RSA3: copy_bytes(provGacRsa3, kp); break;
        case SamsungTag::PROV_GAK_RSA: copy_bytes(provGakRsa, kp); break;
        case SamsungTag::PROV_GAK_RSA_VTOKEN: copy_bytes(provGakRsaVtoken, kp); break;
        case SamsungTag::PROV_SAK_EC: copy_bytes(provSakEc, kp); break;
        case SamsungTag::PROV_SAK_EC_VTOKEN: copy_bytes(provSakEcVtoken, kp); break;

#undef push_enum
#undef push_long
#undef copy_bytes
#undef assign_enum
#undef assign_bool
#undef assign_int
#undef assign_long
#undef assign_datetime

        default:
            std::cerr << "Invalid KeyMaster tag: " << static_cast<uint32_t>(kp.tag) << std::endl;
            continue;
        }
    }
}

} /* namespace util */
} /* namespace kmhal */
} /* namespace suskeymaster */
