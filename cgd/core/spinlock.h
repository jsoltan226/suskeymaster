#ifndef SPINLOCK_H_
#define SPINLOCK_H_

#ifdef __cplusplus
#include <atomic>
#else
#include <stdatomic.h>
#endif /* __cplusplus */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "int.h"

#ifdef __cplusplus
typedef std::atomic_flag spinlock_t;
#else
typedef atomic_flag spinlock_t;
#endif /* __cplusplus */

#define SPINLOCK_INIT ATOMIC_FLAG_INIT
void spinlock_init(spinlock_t *lock);

void spinlock_acquire(spinlock_t *lock);
void spinlock_release(spinlock_t *lock);

i32 spinlock_try_acquire(spinlock_t *lock);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* SPINLOCK_H_ */
