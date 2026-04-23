#define HIDL_DISABLE_INSTRUMENTATION
#include "km-params.hpp"
#include "keymaster-types-c.h"
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
#include <openssl/asn1.h>

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

int b64decode(std::string const& in, std::vector<uint8_t> &out)
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

static int push_int(STACK_OF(ASN1_INTEGER) **st, uint64_t val)
{
    if (*st == NULL) {
        *st = sk_ASN1_INTEGER_new_null();
        if (*st == NULL) {
            std::cerr << "Failed to allocate a new STACK_OF ASN1_INTEGERs";
            return 1;
        }
    }

    ASN1_INTEGER *i = ASN1_INTEGER_new();
    if (i == NULL) {
        std::cerr << "Failed to allocate a new ASN.1 INTEGER";
        return 1;
    }

    if (!ASN1_INTEGER_set_uint64(i, val)) {
        ASN1_INTEGER_free(i);
        std::cerr << "Failed to set the value of an ASN.1 INTEGER";
        return 1;
    }

    if (sk_ASN1_INTEGER_push(*st, i) <= 0) {
        ASN1_INTEGER_free(i);
        std::cerr << "Failed to push an ASN1_INTEGER to the stack";
        return 1;
    }

    return 0;
}

static int assign_int(ASN1_INTEGER **i, uint64_t val)
{
    if (*i != NULL) {
        std::cerr << "INTEGER value already exists!" << std::endl;
        return 1;
    }

    *i = ASN1_INTEGER_new();
    if (*i == NULL) {
        std::cerr << "Failed to allocate a new ASN.1 INTEGER" << std::endl;
        return 1;
    }

    if (!ASN1_INTEGER_set_uint64(*i, val)) {
        std::cerr << "Failed to set the value of an ASN.1 INTEGER";
        return 1;
    }

    return 0;
}

static int assign_octet_string(ASN1_OCTET_STRING **s, hidl_vec<uint8_t> const& bytes)
{
    if (*s != NULL) {
        std::cerr << "OCTET_STRING value already exists!" << std::endl;
        return 1;
    }

    *s = ASN1_OCTET_STRING_new();
    if (*s == NULL) {
        std::cerr << "Failed to allocate a new ASN.1 OCTET_STRING" << std::endl;
        return 1;
    }

    /* copies the data from `bytes` so no need to duplicate */
    if (!ASN1_OCTET_STRING_set(*s, bytes.data(), (int)bytes.size())) {
        std::cerr << "Failed to set the value of an ASN.1 OCTET_STRING";
        return 1;
    }

    return 0;
}

static int assign_bool(ASN1_NULL **b)
{
    if (*b != NULL) {
        std::cerr << "Value already exists!" << std::endl;
        return 1;
    }

    if ((*b = ASN1_NULL_new()), *b == NULL) {
        std::cerr << "Failed to allocate a new ASN.1 NULL (KM boolean value)" << std::endl;
        return 1;
    }

    return 0;
}

KM_PARAM_LIST * key_params_2_param_list(hidl_vec<KeyParameter> const& params)
{
    KM_PARAM_LIST *ret = KM_PARAM_LIST_new();
    if (ret == NULL) {
        std::cerr << "Failed to allocate a new param list" << std::endl;
        goto err;
    }

    for (auto const& kp : params) {

#define try_push_int(field_) do {                                                   \
    if (push_int(&ret->field_, kp.f.longInteger)) {                                 \
        std::cerr << "Failed to push a repeatable INTEGER tag \""                   \
            << toString(kp.tag) << "\" value " << kp.f.longInteger << std::endl;    \
        goto err;                                                                   \
    }                                                                               \
} while (0)

#define try_assign_int(field_) do {                                                 \
    if (assign_int(&ret->field_, kp.f.longInteger)) {                               \
        std::cerr << "Failed to assign an INTEGER tag \""                           \
            << toString(kp.tag) << "\" value " << kp.f.longInteger << std::endl;    \
        goto err;                                                                   \
    }                                                                               \
} while (0)

#define try_assign_bytes(field_) do {                                               \
    if (assign_octet_string(&ret->field_, kp.blob)) {                               \
        std::cerr << "Failed to assign an OCTET_STRING tag \""                      \
            << toString(kp.tag) << "\" value " << std::endl;                        \
        goto err;                                                                   \
    }                                                                               \
} while (0)

#define try_assign_bool(field_) do {                                                \
    /* only create ASN1_NULL boolean values if `true` */                            \
    if (kp.f.boolValue && assign_bool(&ret->field_)) {                              \
        std::cerr << "Failed to assign a BOOLEAN tag \""                            \
            << toString(kp.tag) << "\" value" << std::endl;                         \
        goto err;                                                                   \
    }                                                                               \
} while (0)

        switch (kp.tag) {
        case Tag::PURPOSE: try_push_int(purpose); break;
        case Tag::ALGORITHM: try_assign_int(algorithm); break;
        case Tag::KEY_SIZE: try_assign_int(keySize); break;
        case Tag::BLOCK_MODE: try_push_int(blockMode); break;
        case Tag::DIGEST: try_push_int(digest); break;
        case Tag::PADDING: try_push_int(padding); break;
        case Tag::CALLER_NONCE: try_assign_bool(callerNonce); break;
        case Tag::MIN_MAC_LENGTH: try_assign_int(minMacLength); break;
        case Tag::EC_CURVE: try_assign_int(ecCurve); break;
        case Tag::RSA_PUBLIC_EXPONENT: try_assign_int(rsaPublicExponent); break;
        case Tag::INCLUDE_UNIQUE_ID: try_assign_bool(includeUniqueId); break;
        case Tag::BLOB_USAGE_REQUIREMENTS: try_assign_int(keyBlobUsageRequirements); break;
        case Tag::BOOTLOADER_ONLY: try_assign_bool(bootloaderOnly); break;
        case Tag::ROLLBACK_RESISTANCE: try_assign_bool(rollbackResistance); break;
        case Tag::HARDWARE_TYPE: try_assign_int(hardwareType); break;
        case Tag::ACTIVE_DATETIME: try_assign_int(activeDateTime); break;
        case Tag::ORIGINATION_EXPIRE_DATETIME: try_assign_int(originationExpireDateTime); break;
        case Tag::USAGE_EXPIRE_DATETIME: try_assign_int(usageExpireDateTime); break;
        case Tag::MIN_SECONDS_BETWEEN_OPS: try_assign_int(minSecondsBetweenOps); break;
        case Tag::MAX_USES_PER_BOOT: try_assign_int(maxUsesPerBoot); break;
        case Tag::USER_ID: try_assign_int(userId); break;
        case Tag::USER_SECURE_ID: try_push_int(userSecureId); break;
        case Tag::NO_AUTH_REQUIRED: try_assign_bool(noAuthRequired); break;
        case Tag::USER_AUTH_TYPE: try_assign_int(userAuthType); break;
        case Tag::AUTH_TIMEOUT: try_assign_int(authTimeout); break;
        case Tag::ALLOW_WHILE_ON_BODY: try_assign_bool(allowWhileOnBody); break;
        case Tag::TRUSTED_USER_PRESENCE_REQUIRED: try_assign_bool(trustedUserPresenceReq); break;
        case Tag::TRUSTED_CONFIRMATION_REQUIRED: try_assign_bool(trustedConfirmationReq); break;
        case Tag::UNLOCKED_DEVICE_REQUIRED: try_assign_bool(unlockedDeviceReq); break;
        case Tag::APPLICATION_ID: try_assign_bytes(applicationId); break;
        case Tag::APPLICATION_DATA: try_assign_bytes(applicationData); break;
        case Tag::CREATION_DATETIME: try_assign_int(creationDateTime); break;
        case Tag::ORIGIN: try_assign_int(keyOrigin); break;
        case Tag::ROOT_OF_TRUST:
        {
            if (ret->rootOfTrust != NULL) {
                std::cerr << "rootOfTrust value already exists!" << std::endl;
                goto err;
            }

            std::cerr << "WARNING: Tag::ROOT_OF_TRUST value; "
                "attempting to deserialize `kp.blob`..." << std::endl;

            const unsigned char *p = kp.blob.data();
            const unsigned char *const end = kp.blob.data() + kp.blob.size();

            ret->rootOfTrust = d2i_KM_ROOT_OF_TRUST_V3(NULL, &p, kp.blob.size());
            if (ret->rootOfTrust == NULL || p != end) {
                std::cerr << "Failed to deserialize ROOT_OF_TRUST DER" << std::endl;
                goto err;
            }

            break;
        }
        case Tag::OS_VERSION: try_assign_int(osVersion); break;
        case Tag::OS_PATCHLEVEL: try_assign_int(osPatchLevel); break;
        case Tag::UNIQUE_ID: try_assign_bytes(uniqueId); break;
        case Tag::ATTESTATION_CHALLENGE: try_assign_bytes(attestationChallenge); break;
        case Tag::ATTESTATION_APPLICATION_ID: try_assign_bytes(attestationApplicationId); break;
        case Tag::ATTESTATION_ID_BRAND: try_assign_bytes(attestationIdBrand); break;
        case Tag::ATTESTATION_ID_DEVICE: try_assign_bytes(attestationIdDevice); break;
        case Tag::ATTESTATION_ID_PRODUCT: try_assign_bytes(attestationIdProduct); break;
        case Tag::ATTESTATION_ID_SERIAL: try_assign_bytes(attestationIdSerial); break;
        case Tag::ATTESTATION_ID_IMEI: try_assign_bytes(attestationIdImei); break;
        case Tag::ATTESTATION_ID_MEID: try_assign_bytes(attestationIdMeid); break;
        case Tag::ATTESTATION_ID_MANUFACTURER: try_assign_bytes(attestationIdManufacturer); break;
        case Tag::ATTESTATION_ID_MODEL: try_assign_bytes(attestationIdModel); break;
        case Tag::VENDOR_PATCHLEVEL: try_assign_int(vendorPatchLevel); break;
        case Tag::BOOT_PATCHLEVEL: try_assign_int(bootPatchLevel); break;
        case Tag::ASSOCIATED_DATA: try_assign_bytes(associatedData); break;
        case Tag::NONCE: try_assign_bytes(nonce); break;
        case Tag::MAC_LENGTH: try_assign_int(macLength); break;
        case Tag::RESET_SINCE_ID_ROTATION: try_assign_bool(resetSinceIdRotation); break;
        case Tag::CONFIRMATION_TOKEN: try_assign_bytes(confirmationToken); break;
        case SamsungTag::AUTH_TOKEN: try_assign_bytes(authToken); break;
        case SamsungTag::VERIFICATION_TOKEN: try_assign_bytes(verificationToken); break;
        case SamsungTag::ALL_USERS: try_assign_bool(allUsers); break;
        case SamsungTag::ECIES_SINGLE_HASH_MODE: try_assign_bool(eciesSingleHashMode); break;
        case SamsungTag::KDF: try_assign_int(kdf); break;
        case SamsungTag::EXPORTABLE: try_assign_bool(exportable); break;
        case SamsungTag::KEY_AUTH: try_assign_bool(keyAuth); break;
        case SamsungTag::OP_AUTH: try_assign_bool(opAuth); break;
        case SamsungTag::OPERATION_HANDLE: try_assign_int(operationHandle); break;
        case SamsungTag::OPERATION_FAILED: try_assign_bool(operationFailed); break;
        case SamsungTag::INTERNAL_CURRENT_DATETIME:
            try_assign_int(internalCurrentDateTime);
            break;
        case SamsungTag::EKEY_BLOB_IV: try_assign_bytes(ekeyBlobIV); break;
        case SamsungTag::EKEY_BLOB_AUTH_TAG: try_assign_bytes(ekeyBlobAuthTag); break;
        case SamsungTag::EKEY_BLOB_CURRENT_USES_PER_BOOT:
            try_assign_int(ekeyBlobCurrentUsesPerBoot);
            break;
        case SamsungTag::EKEY_BLOB_LAST_OP_TIMESTAMP:
            try_assign_int(ekeyBlobLastOpTimestamp);
            break;
        case SamsungTag::EKEY_BLOB_DO_UPGRADE: try_assign_int(ekeyBlobDoUpgrade); break;
        case SamsungTag::EKEY_BLOB_PASSWORD: try_assign_bytes(ekeyBlobPassword); break;
        case SamsungTag::EKEY_BLOB_SALT: try_assign_bytes(ekeyBlobSalt); break;
        case SamsungTag::EKEY_BLOB_ENC_VER: try_assign_int(ekeyBlobEncVer); break;
        case SamsungTag::EKEY_BLOB_RAW: try_assign_int(ekeyBlobRaw); break;
        case SamsungTag::EKEY_BLOB_UNIQ_KDM: try_assign_bytes(ekeyBlobUniqKDM); break;
        case SamsungTag::EKEY_BLOB_INC_USE_COUNT: try_assign_int(ekeyBlobIncUseCount); break;
        case SamsungTag::SAMSUNG_REQUESTING_TA: try_assign_bytes(samsungRequestingTA); break;
        case SamsungTag::SAMSUNG_ROT_REQUIRED: try_assign_bool(samsungRotRequired); break;
        case SamsungTag::USE_SECURE_PROCESSOR: try_assign_bool(useSecureProcessor); break;
        case SamsungTag::STORAGE_KEY: try_assign_bool(storageKey); break;
        case SamsungTag::INTEGRITY_STATUS: try_assign_int(integrityStatus); break;
        case SamsungTag::IS_SAMSUNG_KEY: try_assign_bool(isSamsungKey); break;
        case SamsungTag::SAMSUNG_ATTESTATION_ROOT:
            try_assign_bytes(samsungAttestationRoot);
            break;
        case SamsungTag::SAMSUNG_ATTEST_INTEGRITY:
            try_assign_bool(samsungAttestIntegrity);
            break;
        case SamsungTag::KNOX_OBJECT_PROTECTION_REQUIRED:
            try_assign_bool(knoxObjectProtectionRequired);
            break;
        case SamsungTag::KNOX_CREATOR_ID: try_assign_bytes(knoxCreatorId); break;
        case SamsungTag::KNOX_ADMINISTRATOR_ID: try_assign_bytes(knoxAdministratorId); break;
        case SamsungTag::KNOX_ACCESSOR_ID: try_assign_bytes(knoxAccessorId); break;
        case SamsungTag::SAMSUNG_AUTHENTICATE_PACKAGE:
            try_assign_bytes(samsungAuthPackage);
            break;
        case SamsungTag::SAMSUNG_CERTIFICATE_SUBJECT:
            try_assign_bytes(samsungCertificateSubject);
            break;
        case SamsungTag::SAMSUNG_KEY_USAGE: try_assign_int(samsungKeyUsage); break;
        case SamsungTag::SAMSUNG_EXTENDED_KEY_USAGE:
            try_assign_bytes(samsungExtendedKeyUsage);
            break;
        case SamsungTag::SAMSUNG_SUBJECT_ALTERNATIVE_NAME:
            try_assign_bytes(samsungSubjectAlternativeName); break;
            break;
        case SamsungTag::PROV_GAC_EC1: try_assign_bytes(provGacEc1); break;
        case SamsungTag::PROV_GAC_EC2: try_assign_bytes(provGacEc2); break;
        case SamsungTag::PROV_GAC_EC3: try_assign_bytes(provGacEc3); break;
        case SamsungTag::PROV_GAK_EC: try_assign_bytes(provGakEc); break;
        case SamsungTag::PROV_GAK_EC_VTOKEN: try_assign_bytes(provGakEcVtoken); break;
        case SamsungTag::PROV_GAC_RSA1: try_assign_bytes(provGacRsa1); break;
        case SamsungTag::PROV_GAC_RSA2: try_assign_bytes(provGacRsa2); break;
        case SamsungTag::PROV_GAC_RSA3: try_assign_bytes(provGacRsa3); break;
        case SamsungTag::PROV_GAK_RSA: try_assign_bytes(provGakRsa); break;
        case SamsungTag::PROV_GAK_RSA_VTOKEN: try_assign_bytes(provGakRsaVtoken); break;
        case SamsungTag::PROV_SAK_EC: try_assign_bytes(provSakEc); break;
        case SamsungTag::PROV_SAK_EC_VTOKEN: try_assign_bytes(provSakEcVtoken); break;

        default:
            std::cerr << "Invalid KeyMaster tag: " << static_cast<uint32_t>(kp.tag) << std::endl;
            goto err;
        }

#undef try_push_int
#undef try_assign_int
#undef try_assign_bytes
#undef try_assign_bool

    }

    return ret;

err:
    if (ret != NULL) {
        KM_PARAM_LIST_free(ret);
        ret = NULL;
    }

    return NULL;
}

} /* namespace util */
} /* namespace kmhal */
} /* namespace suskeymaster */
