#define _GNU_SOURCE
#include "keybox.h"
#include <core/int.h>
#include <core/log.h>
#include <core/util.h>
#include <core/vector.h>
#include <errno.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <pthread.h>

#define MODULE_NAME "keybox-mgmt"

static pthread_rwlock_t g_rwlock = PTHREAD_RWLOCK_INITIALIZER;
static const struct keybox *g_curr_keybox = NULL;

static VECTOR(u8) load_file(const char *path);

static inline i32 read_lock_current(void)
{
    i32 r = pthread_rwlock_rdlock(&g_rwlock);
    if (r != 0) {
        s_log_error("Failed to read-lock the current keybox: %d (%s)",
                r, strerror(r));
        return 1;
    }

    return 0;

}

i32 keybox_read_lock_current(const struct keybox **out)
{
    if (out == NULL) {
        s_log_error("Invalid parameters!");
        return 1;
    }

    if (read_lock_current())
        return 1;

    if (g_curr_keybox == NULL) {
        s_log_info("Current keybox is not initialized; "
                "attempting to load from \"%s\"...", KEYBOX_LOAD_PATH);

        VECTOR(u8) data = load_file(KEYBOX_LOAD_PATH);
        if (data == NULL) {
try_builtin:
            s_log_error("Failed to load the keybox from file \"%s\"; "
                    "trying built-in one...", KEYBOX_LOAD_PATH);

            const struct keybox *const kb = keybox_get_builtin();
            if (kb == NULL) {
                s_log_error("Failed to load the built-in keybox!");
                goto err_out_unlock;
            }

            s_log_info("Loaded the built-in keybox; setting it as current");
            keybox_unlock_current(NULL);
            if (keybox_set_current(kb)) {
                s_log_error("Failed to set the current keybox");
                goto err_out;
            }
            if (read_lock_current())
                goto err_out;


        } else if (data != NULL) {
            const struct keybox *const kb = keybox_load(data);
            if (kb == NULL) {
                s_log_error("Failed to deserialize the loaded keybox!");
                vector_destroy(&data);
                goto try_builtin;
            }

            vector_destroy(&data);
            s_log_info("Loaded keybox from file \"%s\"; "
                    "setting it as current", KEYBOX_LOAD_PATH);

            keybox_unlock_current(NULL);
            if (keybox_set_current(kb)) {
                s_log_error("Failed to set the current keybox");
                goto err_out;
            }
            if (read_lock_current())
                goto err_out;
        }
    }

    *out = g_curr_keybox;
    return 0;

err_out_unlock:
    keybox_unlock_current(NULL);
err_out:
    return 1;
}

void keybox_unlock_current(const struct keybox **kb_p)
{
    if (kb_p != NULL)
        *kb_p = NULL;

    i32 r = pthread_rwlock_unlock(&g_rwlock);
    if (r != 0)
        s_log_error("Failed to unlock the current keybox: %d (%s)",
                r, strerror(r));
}

i32 keybox_set_current(const struct keybox *kb)
{
    i32 r = pthread_rwlock_wrlock(&g_rwlock);
    if (r != 0) {
        s_log_error("Failed to write-lock the current keybox: %d (%s)",
                r, strerror(r));
        return 1;
    }

    g_curr_keybox = kb;

    r = pthread_rwlock_unlock(&g_rwlock);
    if (r != 0) {
        s_log_error("Failed to unlock the current keybox: %d (%s)",
                r, strerror(r));
        return 1;
    }

    return 0;
}

static VECTOR(u8) load_file(const char *path)
{
    FILE *fp = NULL;
    VECTOR(u8) ret = NULL;

    fp = fopen(path, "rb");
    if (fp == NULL)
        goto_error("Couldn't open \"%s\": %d (%s)",
                path, errno, strerror(errno));

    if (fseek(fp, 0, SEEK_END) == -1)
        goto_error("Couldn't seek to the end in \"%s\": %d (%s)",
                path, errno, strerror(errno));

    i64 size = ftell(fp);
    if (size == -1)
        goto_error("Couldn't ftell() the stream position in \"%s\": %d (%s)",
                path, errno, strerror(errno));
    else if (size > UINT32_MAX)
        goto_error("File size (of \"%s\") %lld too big!", path, size);

    if (fseek(fp, 0, SEEK_SET))
        goto_error("Couldn't seek to the beginning in \"%s\": %d (%s)",
                path, errno, strerror(errno));

    ret = vector_new(u8);
    vector_resize(&ret, size);

    i32 r = fread(ret, size, 1, fp);
    if (r != 1) {
        if (feof(fp))
            goto_error("Couldn't read from \"%s\": file too small", path);
        else if (ferror(fp))
            goto_error("Couldn't read from \"%s\": %d (%s)",
                    path, errno, strerror(errno));
    }

    if (fclose(fp))
        goto_error("Couldn't close \"%s\": %d (%s)",
                path, errno, strerror(errno));
    fp = NULL;

    s_log_info("Successfully read %lld bytes from file \"%s\"", size, path);
    return ret;


err:
    vector_destroy(&ret);

    if (fp != NULL) {
        if (fclose(fp)) {
            s_log_error("Couldn't close \"%s\": %d (%s)",
                    path, errno, strerror(errno));
        }
        fp = NULL;
    }

    return NULL;
}
