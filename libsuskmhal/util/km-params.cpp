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

static Tag find_tag_by_name(std::string const& name);

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

        Tag t = find_tag_by_name(key);
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

static Tag find_tag_by_name(std::string const& name)
{
#define KM_DECL_TAG(name_, type, tag_val, param_list_field, bound_enum, asn1_type, asn1_rep)    \
    if (name == #name_) return static_cast<Tag>(KM_TAG_##name_);

    KM_TAG_LIST__
#undef KM_DECL_TAG

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

        case Tag::KDF:
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

#define try_assign_SET_OF_INTEGER(field_) do {                                      \
    if (push_int(&ret->field_, kp.f.longInteger)) {                                 \
        std::cerr << "Failed to push a repeatable INTEGER tag \""                   \
            << toString(kp.tag) << "\" value " << kp.f.longInteger << std::endl;    \
        goto err;                                                                   \
    }                                                                               \
} while (0)

#define try_assign_INTEGER(field_) do {                                             \
    if (assign_int(&ret->field_, kp.f.longInteger)) {                               \
        std::cerr << "Failed to assign an INTEGER tag \""                           \
            << toString(kp.tag) << "\" value " << kp.f.longInteger << std::endl;    \
        goto err;                                                                   \
    }                                                                               \
} while (0)

#define try_assign_OCTET_STRING(field_) do {                                        \
    if (assign_octet_string(&ret->field_, kp.blob)) {                               \
        std::cerr << "Failed to assign an OCTET_STRING tag \""                      \
            << toString(kp.tag) << "\" value " << std::endl;                        \
        goto err;                                                                   \
    }                                                                               \
} while (0)

#define try_assign_NULL(field_) do {                                                \
    /* only create ASN1_NULL boolean values if `true` */                            \
    if (kp.f.boolValue && assign_bool(&ret->field_)) {                              \
        std::cerr << "Failed to assign a BOOLEAN tag \""                            \
            << toString(kp.tag) << "\" value" << std::endl;                         \
        goto err;                                                                   \
    }                                                                               \
} while (0)

        if (kp.tag == Tag::ROOT_OF_TRUST) {
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
        }

#define try_assign_ROOT_OF_TRUST_V3(field_) do { (void)ret->field_; } while (0)

        switch (static_cast<KM_Tag>(kp.tag)) {
#define KM_DECL_TAG(name_, type, tag_val, param_list_field, bound_enum, asn1_type, asn1_rep)    \
            case KM_TAG_##name_: try_assign##asn1_rep##asn1_type(param_list_field); break;
        KM_TAG_LIST__
#undef KM_DECL_TAG
            default:
                std::cerr << "Invalid KeyMaster tag: " << static_cast<uint32_t>(kp.tag) << std::endl;
                goto err;
        }

#undef try_assign_ROOT_OF_TRUST_V3

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
