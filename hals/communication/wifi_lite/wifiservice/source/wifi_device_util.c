/*
 * Copyright (c) 2020 HiHope Community.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "wifi_device_util.h"

#include <stdio.h>

#include "cmsis_os2.h"
#include "ohos_init.h"
#include "wifi_hotspot_config.h"
#include "wm_type_def.h"
#include "wm_wifi.h"

#define WIFI_MUTEX_TIMEOUT osWaitForever

static osMutexId_t g_wifiGlobalLock = NULL;
static osMutexId_t g_wifiEventLock = NULL;

static void InitWifiGlobalLock(void)
{
    if (g_wifiGlobalLock == NULL) {
        osMutexAttr_t globalMutexAttr = {
            "WifiGloablLock",
            osMutexRecursive | osMutexPrioInherit,
            NULL,
            0U
        };
        g_wifiGlobalLock = osMutexNew(&globalMutexAttr);
    }
}

static void InitWifiEventLock(void)
{
    if (g_wifiEventLock == NULL) {
        osMutexAttr_t eventMutexAttr = {
            "WifiEventLock",
            osMutexRecursive | osMutexPrioInherit,
            NULL,
            0U
        };
        g_wifiEventLock = osMutexNew(&eventMutexAttr);
    }
}

WifiErrorCode LockWifiGlobalLock(void)
{
    if (g_wifiGlobalLock == NULL) {
        InitWifiGlobalLock();
    }

    osStatus_t ret = osMutexAcquire(g_wifiGlobalLock, WIFI_MUTEX_TIMEOUT);
    if (ret != osOK) {
        printf("[wifi_service] osMutexAcquire failed \n");
        return ERROR_WIFI_UNKNOWN;
    }

    return WIFI_SUCCESS;
}

WifiErrorCode UnlockWifiGlobalLock(void)
{
    if (g_wifiGlobalLock == NULL) {
        return ERROR_WIFI_UNKNOWN;
    }

    osStatus_t ret = osMutexRelease(g_wifiGlobalLock);
    if (ret != osOK) {
        printf("[wifi_service] osMutexUnlock failed \n");
        return ERROR_WIFI_UNKNOWN;
    }

    return WIFI_SUCCESS;
}

WifiErrorCode LockWifiEventLock(void)
{
    if (g_wifiEventLock == NULL) {
        InitWifiEventLock();
    }

    osStatus_t ret = osMutexAcquire(g_wifiEventLock, WIFI_MUTEX_TIMEOUT);
    if (ret != osOK) {
        printf("[wifi_service] osMutexAcquire event failed \n");
        return ERROR_WIFI_UNKNOWN;
    }

    return WIFI_SUCCESS;
}

WifiErrorCode UnlockWifiEventLock(void)
{
    if (g_wifiEventLock == NULL) {
        return ERROR_WIFI_UNKNOWN;
    }

    osStatus_t ret = osMutexRelease(g_wifiEventLock);
    if (ret != osOK) {
        printf("[wifi_service] osMutexUnlock event failed \n");
        return ERROR_WIFI_UNKNOWN;
    }

    return WIFI_SUCCESS;
}

WifiSecurityType WmSec2HoSec(int mode)
{
    switch (mode) {
        case IEEE80211_ENCRYT_NONE:
            return WIFI_SEC_TYPE_OPEN;
        case IEEE80211_ENCRYT_WEP40:
        case IEEE80211_ENCRYT_WEP104:
            return WIFI_SEC_TYPE_WEP;
        case IEEE80211_ENCRYT_TKIP_WPA:
        case IEEE80211_ENCRYT_CCMP_WPA:
        case IEEE80211_ENCRYT_TKIP_WPA2:
        case IEEE80211_ENCRYT_CCMP_WPA2:
        case IEEE80211_ENCRYT_AUTO_WPA:
        case IEEE80211_ENCRYT_AUTO_WPA2:
            return WIFI_SEC_TYPE_PSK;
        // case /*  */:
        //     return WIFI_SEC_TYPE_SAE;
        default:
            return -1;
    }
}

WifiSecurityType WmAuth2HoSec(int mode)
{
    switch (mode) {
        case WM_WIFI_AUTH_MODE_OPEN:
            return WIFI_SEC_TYPE_OPEN;
        case WM_WIFI_AUTH_MODE_WEP_AUTO:
            return WIFI_SEC_TYPE_WEP;
        case WM_WIFI_AUTH_MODE_WPA_PSK_TKIP:
        case WM_WIFI_AUTH_MODE_WPA_PSK_CCMP:
        case WM_WIFI_AUTH_MODE_WPA_PSK_AUTO:
        case WM_WIFI_AUTH_MODE_WPA2_PSK_TKIP:
        case WM_WIFI_AUTH_MODE_WPA2_PSK_CCMP:
        case WM_WIFI_AUTH_MODE_WPA2_PSK_AUTO:
        case WM_WIFI_AUTH_MODE_WPA_WPA2_PSK_TKIP:
        case WM_WIFI_AUTH_MODE_WPA_WPA2_PSK_CCMP:
        case WM_WIFI_AUTH_MODE_WPA_WPA2_PSK_AUTO:
            return WIFI_SEC_TYPE_PSK;
        case WM_WIFI_AUTH_MODE_UNKNOWN:
            return -1;
    }
    return -1;
}

int HoSec2WmSec(WifiSecurityType type)
{
    switch (type) {
        case WIFI_SEC_TYPE_OPEN:
            return IEEE80211_ENCRYT_NONE;
        case WIFI_SEC_TYPE_WEP:
            return IEEE80211_ENCRYT_WEP40;
        case WIFI_SEC_TYPE_PSK:
            return IEEE80211_ENCRYT_CCMP_WPA2;
        // case WIFI_SEC_TYPE_SAE:
        //     return IEEE80211_ENCRYT_AUTO_WPA2;
        default:
            return -1;
    }
}
