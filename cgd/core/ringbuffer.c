#include "ringbuffer.h"
#include "int.h"
#include "log.h"
#include "util.h"
#include "spinlock.h"
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>

#define MODULE_NAME "ringbuffer"

struct ringbuffer * ringbuffer_init(u64 buf_size)
{
    u_check_params(buf_size >= 1);

    struct ringbuffer *ret = malloc(sizeof(struct ringbuffer));
    s_assert(ret != NULL, "malloc failed for new ringbuffer");

    atomic_store(&ret->initialized_, true);

    ret->buf = calloc(buf_size, 1);
    if (ret->buf == NULL) {
        s_log_error("Failed to allocate a %llu-byte ringbuffer", buf_size);
        free (ret);
        return NULL;
    }

    ret->buf_size = buf_size;
    ret->write_index = 0;
    spinlock_init(&ret->write_lock);

    return ret;
}

void ringbuffer_destroy(struct ringbuffer **buf_p)
{
    if (buf_p == NULL || *buf_p == NULL) return;
    struct ringbuffer *const buf = *buf_p;

    if (!atomic_exchange(&buf->initialized_, false))
        return;

    /* Wait for anyone else to finish writing and then reset the spinlock */
    spinlock_acquire(&buf->write_lock);
    spinlock_release(&buf->write_lock);

    if (buf->buf != NULL) {
        free(buf->buf);
        buf->buf = NULL;
    }
    buf->buf_size = 0;
    buf->write_index = 0;

    free(*buf_p);
    *buf_p = NULL;
}

void ringbuffer_write_string(struct ringbuffer *buf, const char *string)
{
    u_check_params(buf != NULL && string != NULL);
    s_assert(atomic_load(&buf->initialized_) &&
        buf->buf != NULL && buf->buf_size >= 1 &&
        buf->write_index <= buf->buf_size,
        "Attempt to write to an invalid or uninitialized ringbuffer");

    u64 chars_to_write = strlen(string) + 1;
    if (chars_to_write == 1)
        return; /* We would just be overwriting the '\0' @ write_index
                    with another NULL terminator and not moving forward */

    spinlock_acquire(&buf->write_lock);
    {
        /* Keep space for a NULL terminator at the end of the membuf
         * if someone decides to print it out like a normal string */
        const u64 usable_buf_size = buf->buf_size - 1;
        buf->buf[buf->buf_size - 1] = '\0';

        /* If the message is so long that it would loop over itself,
         * we might as well skip the chars that will be overwritten anyway */
        if (chars_to_write > usable_buf_size) {
            const u64 d = chars_to_write - usable_buf_size;
            string += d;
            chars_to_write = usable_buf_size;

            /* Move the write index accordingly */
            buf->write_index += d % usable_buf_size;
        }

        /* If the message is too long, write the part that would fit
         * and set the write index back to the beginning of the buffer */
        if (chars_to_write + buf->write_index > usable_buf_size) {
            const u64 first_chunk = usable_buf_size - buf->write_index;
            memcpy(buf->buf + buf->write_index, string, first_chunk);
            chars_to_write -= first_chunk;
            string += first_chunk;
            buf->write_index = 0;
        }

        memcpy(buf->buf + buf->write_index, string, chars_to_write);
        /* Place the write index *ON* the NULL terminator, not after it */
        if (chars_to_write != 0) {
            buf->write_index += chars_to_write - 1;
        } else {
            /* Go back to the end */
            buf->write_index = usable_buf_size;
        }
    }
    spinlock_release(&buf->write_lock);
}
