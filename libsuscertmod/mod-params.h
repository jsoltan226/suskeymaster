#ifndef SUS_CERT_MOD_PARAMS_H_
#define SUS_CERT_MOD_PARAMS_H_

#include "keymaster-types.h"
#include <core/int.h>

/** Top-level Key Description modifications **/
#define MOD_KEYDESC_ATTESTATION_SEC_LVL KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT
#define MOD_KEYDESC_KEYMASTER_SEC_LVL KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT


/** Authorization list modifications **/

/* Patch levels & os version */

#define MOD_AUTHLIST_OS_VERSION 140000

#define MOD_AUTHLIST_OS_PATCH_LEVEL 202601
#define MOD_AUTHLIST_VENDOR_PATCH_LEVEL 20260101
#define MOD_AUTHLIST_BOOT_PATCH_LEVEL 20260101


/* Root of Trust modifications */
#define MOD_AUTHLIST_ROT_VERIFIED_BOOT_KEY (u8[]) { \
    0x69, 0x83, 0x25, 0x06, 0xfc, 0x28, 0xde, 0x08, \
    0xa0, 0x99, 0x36, 0x59, 0x01, 0xd7, 0x6d, 0x62, \
    0xeb, 0x1b, 0x64, 0x83, 0xfb, 0x79, 0x86, 0xce, \
    0xcd, 0x7d, 0xee, 0x69, 0xcd, 0x28, 0x9a, 0xc8, \
}

#define MOD_AUTHLIST_ROT_DEVICE_LOCKED 1
#define MOD_AUTHLIST_ROT_VB_STATE KM_VERIFIED_BOOT_VERIFIED

#define MOD_AUTHLIST_ROT_VERIFIED_BOOT_HASH (u8[]) {    \
    0x4d, 0x52, 0x3d, 0x58, 0x4a, 0x73, 0x42, 0x87,     \
    0xb1, 0xee, 0x2d, 0xcf, 0x37, 0x14, 0x46, 0x2b,     \
    0xcc, 0x4c, 0xb2, 0x59, 0xd7, 0x12, 0xe0, 0x04,     \
    0xd4, 0x6c, 0x9e, 0x3e, 0x26, 0x42, 0xc3, 0xb0,     \
}

/* Don't change the vbmeta if using a properly signed ROM */
#undef MOD_AUTHLIST_ROT_VERIFIED_BOOT_HASH

#endif /* SUS_CERT_MOD_PARAMS_H_ */
