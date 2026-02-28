#ifndef U_INT_H_
#define U_INT_H_

#include "static-tests.h"

#include <stdint.h>
#include <assert.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;

typedef float f32;
typedef double f64;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* U_INT_H_ */
