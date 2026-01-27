#ifndef HEX2ASCII_H_
#define HEX2ASCII_H_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "int.h"

/* The length of the longest string possibly returned by `u_hex2ascii` */
#define MAX_HEX2ASCII_STR_LEN 5

const char *u_hex2ascii(u8 byte);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* HEX2ASCII_H_ */
