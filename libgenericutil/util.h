#ifndef SUS_CERT_SIGN_UTIL_H_
#define SUS_CERT_SIGN_UTIL_H_

#include <unistd.h>
#include <stdbool.h>
#include <semaphore.h>

#ifdef __cplusplus
namespace suskeymaster {
namespace util {
extern "C" {
#endif /* __cplusplus */

typedef void (*print_error_proc_t)(const char *fmt, ...);

int prepare_timeout(struct timespec *ts, int offset_seconds,
        print_error_proc_t);

int wait_on_sem(sem_t *sem, const char *name, const struct timespec *ts,
        print_error_proc_t);

void try_post_g_sem(sem_t *g_sem, _Atomic int *g_sem_inited_p,
        print_error_proc_t);

int try_init_g_sem(sem_t *g_sem, _Atomic int *g_sem_inited_p,
        print_error_proc_t);
void destroy_g_sem(sem_t *g_sem, _Atomic int *g_sem_inited_p,
        print_error_proc_t);

#ifdef __cplusplus
} /* extern "C" */
} /* namespace util */
} /* namespace suskeymaster */
#endif /* __cplusplus */

#endif /* SUS_CERT_SIGN_UTIL_H_ */
