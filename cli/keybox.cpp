#include "suskeymaster.hpp"
#include <libsuscertsign/keybox.h>
#include <core/util.h>
#include <core/vector.h>
#include <array>
#include <ctime>
#include <string>
#include <iosfwd>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cstddef>
#include <fstream>
#include <iostream>

static VECTOR(uint8_t) read_file(std::string const& path);
static int write_file(std::string const& path, VECTOR(uint8_t const) data);
static std::string utc_to_string(std::time_t ts);

namespace suskeymaster {

int make_keybox(
    std::vector<std::string> const& ec_cert_paths, std::string const& ec_wrapped_key_path,
    std::vector<std::string> const& rsa_cert_paths, std::string const& rsa_wrapped_key_path,
    std::string const& out_file_path)
{
    VECTOR(VECTOR(uint8_t)) ec_cert_chain = NULL;
    VECTOR(VECTOR(uint8_t)) rsa_cert_chain = NULL;
    VECTOR(uint8_t) ec_key = NULL;
    VECTOR(uint8_t) rsa_key = NULL;
    struct keybox *new_kb = NULL;
    VECTOR(uint8_t) out_data = NULL;

    int ret = 1;

    ec_cert_chain = vector_new(VECTOR(uint8_t));
    rsa_cert_chain = vector_new(VECTOR(uint8_t));
    vector_reserve(&ec_cert_chain, ec_cert_paths.size());
    vector_reserve(&rsa_cert_chain, rsa_cert_paths.size());

    for (std::string const& path : ec_cert_paths) {
        VECTOR(uint8_t) cert = read_file(path);
        if (cert == NULL) {
            std::cerr << "Failed to read EC cert \"" << path << "\"" << std::endl;
            goto out;
        }

        vector_push_back(&ec_cert_chain, cert);
    }
    for (std::string const& path : rsa_cert_paths) {
        VECTOR(uint8_t) cert = read_file(path);
        if (cert == NULL) {
            std::cerr << "Failed to read RSA cert \"" << path << "\"" << std::endl;
            goto out;
        }

        vector_push_back(&rsa_cert_chain, cert);
    }

    ec_key = read_file(ec_wrapped_key_path);
    if (ec_key == NULL) {
        std::cerr << "Failed to read the wrapped EC key file \""
            << ec_wrapped_key_path << "\"" << std::endl;
        goto out;
    }

    rsa_key = read_file(rsa_wrapped_key_path);
    if (rsa_key == NULL) {
        std::cerr << "Failed to read the wrapped RSA key file \""
            << rsa_wrapped_key_path << "\"" << std::endl;
        goto out;
    }

    new_kb = keybox_init(ec_cert_chain, ec_key, rsa_cert_chain, rsa_key, false);
    if (new_kb == NULL) {
        std::cerr << "Couldn't initialize a keybox structure " <<
            "with the provided cert chains & keys" << std::endl;
        goto out;
    }

    out_data = keybox_store(new_kb);
    if (out_data == NULL) {
        std::cerr << "Failed to serialize the new keybox" << std::endl;
        goto out;
    }

    if (write_file(out_file_path, out_data)) {
        std::cerr << "Failed to write the new keybox to disk" << std::endl;
        goto out;
    }

    std::cout << "Successfully made new keybox" << std::endl;
    ret = 0;

out:
    vector_destroy(&out_data);
    keybox_destroy(&new_kb);

    for (uint32_t i = 0; i < vector_size(ec_cert_chain); i++)
        vector_destroy(&ec_cert_chain[i]);
    vector_destroy(&ec_cert_chain);

    for (uint32_t i = 0; i < vector_size(rsa_cert_chain); i++)
        vector_destroy(&rsa_cert_chain[i]);
    vector_destroy(&rsa_cert_chain);

    vector_destroy(&ec_key);
    vector_destroy(&rsa_key);

    return ret;
}

const std::array<std::pair<enum sus_key_variant, const char *>, 2> algs({
        std::pair(SUS_KEY_EC, "ec"),
        std::pair(SUS_KEY_RSA, "rsa")
});
int dump_keybox(
    std::string const& keybox_path,

    std::string const& out_dir_path
)
{
    VECTOR(u8) keybox_data = NULL;
    struct keybox *kb = NULL;
    char path_buf[128] = { 0 };
    int ret = EXIT_FAILURE;

    keybox_data = read_file(keybox_path);
    if (keybox_data == NULL) {
        std::cerr << "Failed to read the keybox file" << std::endl;
        goto fail;
    }

    kb = keybox_load(keybox_data);
    if (kb == NULL) {
        std::cerr << "Failed to deserialize the keybox file" << std::endl;
        goto fail;
    }

    for (auto a : algs) {
        VECTOR(u8 const) tmp_blob = NULL;
        VECTOR(VECTOR(u8 const) const) tmp_cert_chain = NULL;

        const enum sus_key_variant variant = a.first;
        const char *name = a.second;

        tmp_cert_chain = keybox_get_cert_chain(kb, variant);
        if (vector_size(tmp_cert_chain) == 0) {
            std::cerr << "Failed to retrieve the " << name <<
                " cert chain from the keybox" << std::endl;
            goto fail;
        }
        for (uint32_t i = 0; i < vector_size(tmp_cert_chain); i++) {
            std::memset(path_buf, 0, sizeof(path_buf));
            std::snprintf(path_buf, sizeof(path_buf), "%s/cert%u-%s.der",
                    out_dir_path.c_str(), i, name);

            if (write_file(std::string(path_buf), tmp_cert_chain[i])) {
                tmp_cert_chain = NULL;
                std::cerr << "Failed to write " << name << " cert no. "
                    << i << " to disk" << std::endl;
                goto fail;
            }
        }
        tmp_cert_chain = NULL;

        tmp_blob = keybox_get_wrapped_key(kb, variant);
        if (tmp_blob == NULL) {
            std::cerr << "Failed to retrieve the " << name <<
                " wrapped key blob from the keybox" << std::endl;
            goto fail;
        }
        std::memset(path_buf, 0, sizeof(path_buf));
        std::snprintf(path_buf, sizeof(path_buf), "%s/key-%s.bin",
                out_dir_path.c_str(), name);
        if (write_file(std::string(path_buf), tmp_blob)) {
            tmp_blob = NULL;
            std::cerr << "Failed to write the " << name <<
                "wrapped key blob to disk" << std::endl;
            goto fail;
        }
        tmp_blob = NULL;

        tmp_blob = keybox_get_batch_key_serial(kb, variant);
        if (tmp_blob == NULL) {
            std::cerr << "Failed to retrieve the " << name <<
                " batch key serial string from the keybox" << std::endl;
            goto fail;
        }

        VECTOR(char) tmp_str = (VECTOR(char))vector_clone((void *)tmp_blob);
        vector_push_back(&tmp_str, '\0');
        std::cout << name << " serial number: \"" << tmp_str << "\"" << std::endl;
        vector_destroy(&tmp_str);

        i64 notafter = 0;
        if (keybox_get_not_after(&notafter, kb, variant)) {
            std::cerr << "Failed to retrieve the notAfter value from the "
                << name << " certificate" << std::endl;
            goto fail;
        }
        std::cout << name << " notAfter: " << notafter <<
            " (" << utc_to_string(notafter) << ")" << std::endl;

        tmp_cert_chain = NULL;
        tmp_blob = NULL;
        std::memset(path_buf, 0, sizeof(path_buf));
    }

    std::cout << "Successfully dumped keybox \"" << keybox_path
        << "\" to \"" << out_dir_path << "\"" << std::endl;
    ret = EXIT_SUCCESS;

fail:
    keybox_destroy(&kb);
    vector_destroy(&keybox_data);

    return ret;
}

} /* namespace suskeymaster */

static VECTOR(uint8_t) read_file(std::string const& path)
{
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f.is_open()) {
        std::cerr << "Failed to open file \"" << path << "\" for reading" << std::endl;
        return NULL;
    }

    std::streampos pos = f.tellg();
    if (pos < 0) {
        std::cerr << "Couldn't determine the size of file \"" << path << "\"" << std::endl;
        f.close();
        return NULL;
    }
    size_t file_size = static_cast<size_t>(pos);

    f.seekg(0, std::ios::beg);
    if (f.fail()) {
        std::cerr << "Couldn't seek in file \"" << path << "\": " << std::endl;
        f.close();
        return NULL;
    }

    VECTOR(uint8_t) ret = vector_new(uint8_t);
    vector_resize(&ret, file_size);

    if (!f.read(reinterpret_cast<char *>(ret), file_size)) {
        std::cerr << "Failed to read from file \"" << path << "\": " << std::endl;
        f.close();
        vector_destroy(&ret);
        return NULL;
    }

    f.close();
    std::cout << "Successfully read \"" << path << "\"" << std::endl;
    return ret;
}

static int write_file(std::string const& path, VECTOR(uint8_t const) data)
{
    std::ofstream f(path, std::ios::binary);
    if (!f.is_open()) {
        std::cerr << "Failed to open file \"" << path << "\" for writing" << std::endl;
        return 1;
    }

    if (!f.write(reinterpret_cast<const char *>(data), vector_size(data))) {
        std::cerr << "Failed to write to the file \"" << path << "\"" << std::endl;
        f.close();
        return 1;
    }

    f.close();
    std::cout << "Successfully wrote \"" << path << "\"" << std::endl;
    return 0;
}

static std::string utc_to_string(std::time_t ts)
{
    std::tm tm{};
    gmtime_r(&ts, &tm);
    char buf[64];

    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", &tm);

    return std::string(buf);
}
