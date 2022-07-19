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

/**
 * @file    wm_bt_config.h
 *
 * @brief   WM bluetooth model configure
 *
 * @author  winnermicro
 *
 * Copyright (c) 2015 Winner Microelectronics Co., Ltd.
 */
#ifndef __WM_BLUETOOTH_CONFIG_H__
#define __WM_BLUETOOTH_CONFIG_H__

#include "wm_config.h"

#if (TLS_CONFIG_BR_EDR == CFG_ON)
    #define WM_BTA_AV_SINK_INCLUDED    CFG_ON
    #define WM_BTA_HFP_HSP_INCLUDED    CFG_ON
    #define WM_BTA_SPPS_INCLUDED       CFG_ON
    #define WM_BTA_SPPC_INCLUDED       CFG_ON
#else
    #define WM_BTA_AV_SINK_INCLUDED    CFG_OFF
    #define WM_BTA_HFP_HSP_INCLUDED    CFG_OFF
    #define WM_BTA_SPPS_INCLUDED       CFG_OFF
    #define WM_BTA_SPPC_INCLUDED       CFG_OFF
#endif

#if (TLS_CONFIG_BLE == CFG_ON)
    #define WM_BLE_PERIPHERAL_INCLUDED CFG_ON
    #define WM_BLE_CENTRAL_INCLUDED    CFG_ON
#else
    #define WM_BLE_PERIPHERAL_INCLUDED CFG_OFF
    #define WM_BLE_CENTRAL_INCLUDED    CFG_OFF
#endif

#if (WM_BTA_AV_SINK_INCLUDED == CFG_ON) || (WM_BTA_HFP_HSP_INCLUDED == CFG_ON) || (WM_BTA_SPPS_INCLUDED == CFG_ON) || (WM_BTA_SPPC_INCLUDED == CFG_ON)
    #define WM_BT_INCLUDED                CFG_ON
#else
    #define WM_BT_INCLUDED                CFG_OFF
#endif

#if (WM_BLE_PERIPHERAL_INCLUDED == CFG_ON) || (WM_BLE_CENTRAL_INCLUDED == CFG_ON)
#if NIMBLE_FTR
    #define WM_BLE_INCLUDED                 CFG_OFF
    #define WM_NIMBLE_INCLUDED              CFG_ON
#else
    #define WM_BLE_INCLUDED                 CFG_ON
    #define WM_NIMBLE_INCLUDED              CFG_OFF
#endif
#else
    #define WM_BLE_INCLUDED                CFG_OFF
    #define WM_NIMBLE_INCLUDE              CFG_OFF
#endif

#if (WM_BLE_CENTRAL_INCLUDED == CFG_ON)
    #if (WM_BT_INCLUDED == CFG_ON)
    #define WM_BLE_MAX_CONNECTION       1
    #else
    #define WM_BLE_MAX_CONNECTION       7
    #endif
#else
    #define WM_BLE_MAX_CONNECTION       1 
#endif

#endif /*__WM_WIFI_CONFIG_H__*/

