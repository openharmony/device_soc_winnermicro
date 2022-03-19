#ifndef __BLE_UTIL_H__
#define __BLE_UTIL_H__
#include <stdio.h>
#include <stdint.h>


#define BLE_IF_DBG 1

#ifndef BLE_IF_DBG
#define BLE_IF_DBG 0
#endif

#if BLE_IF_DBG
#define BLE_IF_DEBUG(fmt, ...)  \
    do{\
        if(1) \
            printf("%s(L%d): " fmt, __FUNCTION__, __LINE__,  ## __VA_ARGS__); \
    }while(0)
#define BLE_IF_PRINTF(fmt, ...)  \
    do{\
        if(1) \
            printf(fmt, ## __VA_ARGS__); \
    }while(0)    
#else
#define BLE_IF_DEBUG(param, ...)
#define BLE_IF_PRINTF(param, ...)
#endif

#ifndef MIN
#define MIN(a,b) (((a) < (b)) ? (a) : (b))
#endif
extern const char *tls_bt_gap_evt_2_str(uint32_t event);
extern void tls_bt_dump_hexstring(const char *info, uint8_t *p, int length);


#endif
