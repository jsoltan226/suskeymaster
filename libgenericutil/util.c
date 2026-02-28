#define _GNU_SOURCE
#include "util.h"
#include <time.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <semaphore.h>
#include <stdatomic.h>

int prepare_timeout(struct timespec *ts, int offset_seconds,
        print_error_proc_t print_error_proc)
{
    memset(ts, 0, sizeof(struct timespec));

    if (clock_gettime(CLOCK_REALTIME, ts)) {
        print_error_proc("Couldn't get the current time: %d (%s)",
                errno, strerror(errno));
        return 1;
    }

    ts->tv_sec += offset_seconds;

    return 0;
}

int wait_on_sem(sem_t *sem, const char *name, const struct timespec *ts,
        print_error_proc_t print_error_proc)
{
    int rc = 0;
    do {
        rc = sem_timedwait(sem, ts);
    } while (rc != 0 && errno == EINTR);

    if (rc != 0 && errno == ETIMEDOUT) {
        print_error_proc("Timed out while waiting for %s!", name);
        return 1;
    } else if (rc != 0) {
        print_error_proc(
                "Failed to wait on the %s semaphore: %d (%s)",
                name, errno, strerror(errno)
        );
        return 1;
    }

    return 0;
}

void try_post_g_sem(sem_t *g_sem, _Atomic int *g_sem_inited_p,
        print_error_proc_t print_error_proc)
{
    if (!atomic_load(g_sem_inited_p)) {
        print_error_proc("Attempt to post the global semaphore "
                "while not initialized!");
        return;
    }

    if (sem_post(g_sem)) {
        print_error_proc("Failed to post the global semaphore: %d (%s)",
                errno, strerror(errno));
        return;
    }
}

int try_init_g_sem(sem_t *g_sem, _Atomic int *g_sem_inited_p,
        print_error_proc_t print_error_proc)
{
    if (atomic_exchange(g_sem_inited_p, true)) {
        print_error_proc("Global semaphore already initialized!");
        return -1;
    }

    if (sem_init(g_sem, false, 0)) {
        print_error_proc("Failed to initialize the global semaphore: %d (%s)",
                errno, strerror(errno));
        return 1;
    }

    return 0;
}

void destroy_g_sem(sem_t *g_sem, _Atomic int *g_sem_inited_p,
        print_error_proc_t print_error_proc)
{
    if (g_sem == NULL || g_sem_inited_p == NULL)
        return;

    if (atomic_exchange(g_sem_inited_p, false)){
        if (sem_destroy(g_sem)) {
            print_error_proc("Failed to destroy the global semaphore: %d (%s)",
                    errno, strerror(errno));
        }
    }
}
