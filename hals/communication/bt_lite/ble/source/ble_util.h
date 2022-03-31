/*
 * Copyright (c) 2022 Winner Microelectronics Co., Ltd. All rights reserved.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
