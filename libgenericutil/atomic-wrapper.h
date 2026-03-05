#ifndef SUSKEYMASTER_GENERIC_UTIL_ATOMIC_WRAPPER_H_
#define SUSKEYMASTER_GENERIC_UTIL_ATOMIC_WRAPPER_H_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

int util_atomic_load_int(const _Atomic int *a);
void util_atomic_store_int(_Atomic int *a, int value);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /*  SUSKEYMASTER_GENERIC_UTIL_ATOMIC_WRAPPER_H_ */
