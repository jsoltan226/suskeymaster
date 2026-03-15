#ifndef SUSKEYMASTER_GENERIC_UTIL_ATOMIC_WRAPPER_H_
#define SUSKEYMASTER_GENERIC_UTIL_ATOMIC_WRAPPER_H_

#ifdef __cplusplus
namespace suskeymaster {
namespace util {
extern "C" {
#endif /* __cplusplus */

int do_atomic_load_int(const _Atomic int *a);
void do_atomic_store_int(_Atomic int *a, int value);

#ifdef __cplusplus
} /* namespace util */
} /* namespace suskeymaster */
} /* extern "C" */
#endif /* __cplusplus */

#endif /*  SUSKEYMASTER_GENERIC_UTIL_ATOMIC_WRAPPER_H_ */
