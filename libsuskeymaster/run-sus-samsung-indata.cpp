#define HIDL_DISABLE_INSTRUMENTATION
#include "run-sus-samsung-indata.hpp"
#include <core/int.h>
#include <core/log.h>
#include <core/util.h>
#include <core/vector.h>
#include <libsuskmhal/keymaster-types-c.h>
#include <libsuskmhal/util/samsung-sus-indata.hpp>
#include <dlfcn.h>
#include <unistd.h>
#include <mutex>
#include <cstring>
#include <openssl/asn1.h>

#define MODULE_NAME "run-sus-samsung-indata"

namespace suskeymaster {

#define SHARED_MEM_BUF_MAX_SIZE 0x19000

#define INDATA_VER 0x3
#define INDATA_KM_VER 40

extern "C" {
struct qsee_shared_mem;

typedef struct qsee_shared_mem * (*shared_mem_get_in_mem_fn_t)(void);
typedef struct qsee_shared_mem * (*shared_mem_get_out_mem_fn_t)(void);

typedef int (*shared_mem_set_buf_length_fn_t)(struct qsee_shared_mem *, uint32_t);
typedef int (*shared_mem_get_buf_ptr_fn_t)(struct qsee_shared_mem *,
        uint8_t **, uint32_t *);

typedef int (*nwd_tz_run_cmd_fn_t)(void);

static struct km_helper_fns {
    std::mutex mtx;
    bool inited_;
#define MAX_FAILCNT 10
    unsigned int failcnt;

    shared_mem_get_in_mem_fn_t shared_mem_get_in_mem;
    shared_mem_get_out_mem_fn_t shared_mem_get_out_mem;
    shared_mem_set_buf_length_fn_t shared_mem_set_buf_length;
    shared_mem_get_buf_ptr_fn_t shared_mem_get_buf_ptr;
    nwd_tz_run_cmd_fn_t nwd_tz_run_cmd;
} g_km_helper_lib;

}

static int try_init_g_km_helper_lib(void);

static int fill_indata_defaults(const VECTOR(u8) in_old_indata,
        hidl_vec<uint8_t>& out_new_indata);

static int send_command(const hidl_vec<uint8_t>& indata);
static int recv_command(hidl_vec<uint8_t>& outdata);

int run_sus_samsung_indata(const VECTOR(u8) indata,
            hidl_vec<hidl_vec<uint8_t>>& out_cert_chain)
{
    using namespace kmhal::util;

    out_cert_chain.resize(2);
    out_cert_chain[0].resize(0);
    out_cert_chain[1].resize(0);

    send_indata_err err = UNKNOWN_ERROR;
    hidl_vec<uint8_t> final_indata;

    if (indata == NULL || vector_size(indata) == 0) {
        err = INVALID_ARGUMENT;
        goto_error("Invalid parameters!");
    }

    if (fill_indata_defaults(indata, final_indata)) {
        err = FILL_SERIALIZE_INDATA_FAILED;
        goto_error("Failed to fill in & serialize the KM_INDATA struct");
    }

    if (try_init_g_km_helper_lib()) {
        err = DLOPEN_KM_HELPER_FAILED;
        goto_error("Failed to load keymaster helper library");
    }

    if (send_command(final_indata)) {
        err = TEE_SEND_FAILED;
        goto_error("Failed to send the command to the TEE");
    }

    if (recv_command(out_cert_chain[1])) {
        err = TEE_RECV_FAILED;
        goto_error("Failed to receive the command results from the TEE");
    }

    s_log_info("Successfully ran raw SKeymaster TEE command");
    err = OK;

err:
    if (serialize_send_indata_err(out_cert_chain[0], err)) {
        s_log_error("Failed to serialize the send_indata_err sequence");
        return -1;
    }

    return 0;
}


static int try_init_g_km_helper_lib(void)
{
    std::lock_guard<std::mutex> lock(g_km_helper_lib.mtx);

    if (g_km_helper_lib.inited_)
        return 0;

    if (g_km_helper_lib.failcnt > MAX_FAILCNT) {
        s_log_error("Maximum fail count (%d) exceeded; not loading!", MAX_FAILCNT);
        return 1;
    }

    g_km_helper_lib.shared_mem_get_in_mem = reinterpret_cast<shared_mem_get_in_mem_fn_t>
        (dlsym(NULL, "shared_mem_get_in_mem"));
    if (g_km_helper_lib.shared_mem_get_in_mem == nullptr)
        goto_error("Failed to load `shared_mem_get_in_mem`: %s", dlerror());

    g_km_helper_lib.shared_mem_get_out_mem = reinterpret_cast<shared_mem_get_out_mem_fn_t>
        (dlsym(NULL, "shared_mem_get_out_mem"));
    if (g_km_helper_lib.shared_mem_get_out_mem == nullptr)
        goto_error("Failed to load `shared_mem_get_out_mem`: %s", dlerror());

    g_km_helper_lib.shared_mem_set_buf_length = reinterpret_cast<shared_mem_set_buf_length_fn_t>
        (dlsym(NULL, "shared_mem_set_buf_length"));
    if (g_km_helper_lib.shared_mem_set_buf_length == nullptr)
        goto_error("Failed to load `shared_mem_set_buf_length`: %s", dlerror());

    g_km_helper_lib.shared_mem_get_buf_ptr = reinterpret_cast<shared_mem_get_buf_ptr_fn_t>
        (dlsym(NULL, "shared_mem_get_buf_ptr"));
    if (g_km_helper_lib.shared_mem_get_buf_ptr == nullptr)
        goto_error("Failed to load `shared_mem_get_buf_ptr`: %s", dlerror());

    g_km_helper_lib.nwd_tz_run_cmd = reinterpret_cast<nwd_tz_run_cmd_fn_t>
        (dlsym(NULL, "nwd_tz_run_cmd"));
    if (g_km_helper_lib.nwd_tz_run_cmd == nullptr)
        goto_error("Failed to load `nwd_tz_run_cmd`: %s", dlerror());

    s_log_info("Successfully loaded libkeymaster_helper functions (failcnt: %u)",
            g_km_helper_lib.failcnt);
    g_km_helper_lib.inited_ = true;
    return 0;

err:
    g_km_helper_lib.failcnt++;
    return 1;
}

static int fill_indata_defaults(const VECTOR(u8) in_old_indata,
        hidl_vec<uint8_t>& out_new_indata)
{
    int ret = -1;
    KM_SAMSUNG_INDATA *indata = NULL;
    const unsigned char *p = in_old_indata;
    out_new_indata.resize(0);

    indata = d2i_KM_SAMSUNG_INDATA(NULL, &p, vector_size(in_old_indata));
    if (indata == NULL || p != in_old_indata + vector_size(in_old_indata))
        goto_error("Failed to d2i the KM_INDATA");

    if (ASN1_INTEGER_get(indata->ver) == 0) {
        if (!ASN1_INTEGER_set(indata->ver, INDATA_VER))
            goto_error("Failed to set the KM_INDATA blob version INTEGER");

        s_log_info("Set indata->ver = 0x%x", INDATA_VER);
    }

    if (ASN1_INTEGER_get(indata->km_ver) == 0) {
        if (!ASN1_INTEGER_set(indata->km_ver, INDATA_KM_VER))
            goto_error("Failed to set the skeymaster version INTEGER");

        s_log_info("Set indata->km_ver = %u", INDATA_KM_VER);
    }

    /* `cmd` is mandated to be specified by the caller */

    if (ASN1_INTEGER_get(indata->pid) == 0) {
        if (!ASN1_INTEGER_set(indata->pid, getpid()))
            goto_error("Failed to set the skeymaster version INTEGER");

        s_log_info("Set indata->pid = %u", getpid());
    }

    {
        int length = i2d_KM_SAMSUNG_INDATA(indata, NULL);
        if (length <= 0)
            goto_error("Failed to measure the length of the new KM_INDATA DER");

        out_new_indata.resize(length);
        unsigned char *p = out_new_indata.data();
        if (i2d_KM_SAMSUNG_INDATA(indata, &p) != length ||
                p != out_new_indata.data() + length)
        {
            out_new_indata.resize(0);
            goto_error("Failed to serialize the new KM_INDATA DER");
        }
    }

    ret = 0;

err:
    if (indata != NULL) {
        KM_SAMSUNG_INDATA_free(indata);
        indata = NULL;
    }

    return ret;
}

static int send_command(const hidl_vec<uint8_t>& indata)
{
    struct qsee_shared_mem *in_shmem = NULL;
    uint8_t *in_shmem_ptr = NULL;
    uint32_t in_shmem_length = 0;

    in_shmem = g_km_helper_lib.shared_mem_get_in_mem();
    if (in_shmem == NULL)
        goto_error("Couldn't get input shared memory handle");

    if (g_km_helper_lib.shared_mem_set_buf_length(in_shmem, indata.size()))
        goto_error("Couldn't set input shared memory buffer length");

    if (g_km_helper_lib.shared_mem_get_buf_ptr(in_shmem,
                &in_shmem_ptr, &in_shmem_length) ||
        in_shmem_length != indata.size())
    {
        goto_error("Couldn't get input shared memory buffer pointer");
    }

    std::memcpy(in_shmem_ptr, indata.data(), indata.size());

    if (g_km_helper_lib.nwd_tz_run_cmd())
        goto_error("Failed to run command");

    std::memset(in_shmem_ptr, 0, indata.size());
    return 0;

err:
    return 1;
}

static int recv_command(hidl_vec<uint8_t>& outdata)
{
    struct qsee_shared_mem *out_shmem = NULL;
    uint8_t *out_shmem_ptr = NULL;
    uint32_t out_shmem_length = 0;

    out_shmem = g_km_helper_lib.shared_mem_get_out_mem();
    if (out_shmem == NULL)
        goto_error("Couldn't get output shared memory handle");

    if (g_km_helper_lib.shared_mem_get_buf_ptr(out_shmem,
                &out_shmem_ptr, &out_shmem_length))
    {
        goto_error("Couldn't get output shared memory buffer pointer");
    }
    s_log_info("output length: %lu bytes", (long unsigned)out_shmem_length);

    outdata.resize(out_shmem_length);
    std::memcpy(outdata.data(), out_shmem_ptr, out_shmem_length);

    return 0;

err:
    return 1;
}

} /* namespace suskeymaster */
