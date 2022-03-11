/*
 * Copyright (c) 2020, HiHope Community.
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

#include "wifi_hotspot.h"
#include "wifi_device_util.h"

#include <string.h>
#include <securec.h>
#include "wm_type_def.h"
#include "wm_wifi.h"

#define RSSI_LEVEL_4_2_G (-65)
#define RSSI_LEVEL_3_2_G (-75)
#define RSSI_LEVEL_2_2_G (-82)
#define RSSI_LEVEL_1_2_G (-88)

#define RSSI_LEVEL_4_5_G (-65)
#define RSSI_LEVEL_3_5_G (-72)
#define RSSI_LEVEL_2_5_G (-79)
#define RSSI_LEVEL_1_5_G (-85)

#define W800_MAX_STA_NUM 8

static int g_wifiApStatus = WIFI_HOTSPOT_NOT_ACTIVE;
static HotspotConfig g_wifiApConfig = {0};

WifiErrorCode SetHotspotConfig(const HotspotConfig* config)
{
    if (config == NULL) {
        return ERROR_WIFI_INVALID_ARGS;
    }

    if (LockWifiGlobalLock() != WIFI_SUCCESS) {
        return ERROR_WIFI_UNKNOWN;
    }
    errno_t err = memcpy_s(&g_wifiApConfig, sizeof(g_wifiApConfig), config, sizeof(*config));
    if (UnlockWifiGlobalLock() != WIFI_SUCCESS) {
        return ERROR_WIFI_UNKNOWN;
    }
    if (err != EOK) {
        printf("[wifi_service]:SetHotspotConfig memcpy fail, err = %d\n", err);
        return ERROR_WIFI_UNKNOWN;
    }
    return WIFI_SUCCESS;
}

WifiErrorCode GetHotspotConfig(HotspotConfig* result)
{
    if (result == NULL) {
        return ERROR_WIFI_INVALID_ARGS;
    }

    if (LockWifiGlobalLock() != WIFI_SUCCESS) {
        return ERROR_WIFI_UNKNOWN;
    }
    errno_t err = memcpy_s(result, sizeof(*result), &g_wifiApConfig, sizeof(g_wifiApConfig));
    if (UnlockWifiGlobalLock() != WIFI_SUCCESS) {
        return ERROR_WIFI_UNKNOWN;
    }
    if (err != EOK) {
        printf("[wifi_service]:SetHotspotConfig memcpy fail, err = %d\n", err);
        return ERROR_WIFI_UNKNOWN;
    }
    return WIFI_SUCCESS;
}

WifiErrorCode EnableHotspot()
{
    if (LockWifiGlobalLock() != WIFI_SUCCESS) {
        return ERROR_WIFI_UNKNOWN;
    }
    if (g_wifiApStatus == WIFI_HOTSPOT_ACTIVE) {
        if (UnlockWifiGlobalLock() != WIFI_SUCCESS) {
            return ERROR_WIFI_UNKNOWN;
        }
        return ERROR_WIFI_BUSY;
    }

    struct tls_softap_info_t apinfo = {0};
    strcpy(apinfo.ssid, g_wifiApConfig.ssid);
    // errno_t err = strcpy_s(apinfo.ssid, sizeof(apinfo.ssid), g_wifiApConfig.ssid);
    apinfo.encrypt = HoSec2WmSec(g_wifiApConfig.securityType);
    apinfo.channel = g_wifiApConfig.channelNum;
    strcpy(apinfo.keyinfo.key, g_wifiApConfig.preSharedKey);
    // err += strcpy_s(apinfo.keyinfo.key, sizeof(apinfo.keyinfo.key), g_wifiApConfig.preSharedKey);
    apinfo.keyinfo.key_len = strlen(g_wifiApConfig.preSharedKey);
    apinfo.keyinfo.format = 1;  // 0-hex, 1-ascii
    if (g_wifiApConfig.securityType == WIFI_SEC_TYPE_WEP) {
        apinfo.keyinfo.index = 1; // 1-4 (only wep)
    }
    // if (err != EOK) {
    //     printf("[wifi_service]:EnableHotspot memset fail, err = %d\n", err);
    //     if (UnlockWifiGlobalLock() != WIFI_SUCCESS) {
    //         return ERROR_WIFI_UNKNOWN;
    //     }
    //     return ERROR_WIFI_UNKNOWN;
    // }


    // TODO(xu): add API to set AP's ipinfo
    struct tls_ip_info_t ipinfo = {0};
    ipinfo.ip_addr[0] = 192;
    ipinfo.ip_addr[1] = 168;
    ipinfo.ip_addr[2] = 1;
    ipinfo.ip_addr[3] = 1;
    ipinfo.netmask[0] = 255;
    ipinfo.netmask[1] = 255;
    ipinfo.netmask[2] = 255;
    ipinfo.netmask[3] = 0;
    int retval = tls_wifi_softap_create(&apinfo, &ipinfo);
    if (retval != WM_SUCCESS) {
        printf("[wifi_service]:EnableHotspot tls_wifi_softap_create fail, err = %d\n", retval);
        if (UnlockWifiGlobalLock() != WIFI_SUCCESS) {
            return ERROR_WIFI_UNKNOWN;
        }
    }

    g_wifiApStatus = WIFI_HOTSPOT_ACTIVE;
    if (UnlockWifiGlobalLock() != WIFI_SUCCESS) {
        return ERROR_WIFI_UNKNOWN;
    }
    return WIFI_SUCCESS;
}

WifiErrorCode DisableHotspot()
{
    if (LockWifiGlobalLock() != WIFI_SUCCESS) {
        return ERROR_WIFI_UNKNOWN;
    }
    if (g_wifiApStatus == WIFI_HOTSPOT_NOT_ACTIVE) {
        if (UnlockWifiGlobalLock() != WIFI_SUCCESS) {
            return ERROR_WIFI_UNKNOWN;
        }
        return ERROR_WIFI_NOT_STARTED;
    }

    tls_wifi_softap_destroy();
    g_wifiApStatus = WIFI_HOTSPOT_NOT_ACTIVE;

    if (UnlockWifiGlobalLock() != WIFI_SUCCESS) {
        return ERROR_WIFI_UNKNOWN;
    }
    return WIFI_SUCCESS;
}

int IsHotspotActive(void)
{
    if (LockWifiGlobalLock() != WIFI_SUCCESS) {
        return ERROR_WIFI_UNKNOWN;
    }
    int ret = g_wifiApStatus;
    if (UnlockWifiGlobalLock() != WIFI_SUCCESS) {
        return ERROR_WIFI_UNKNOWN;
    }

    return ret;
}

WifiErrorCode GetStationList(StationInfo* result, unsigned int* size)
{
    if (result == NULL || size == NULL || *size == 0) {
        return ERROR_WIFI_INVALID_ARGS;
    }

    struct tls_sta_info_t staList[W800_MAX_STA_NUM] = {0};
    unsigned int staNum = 0;

    tls_wifi_get_authed_sta_info(&staNum, staList, sizeof(staList));

    if (*size < staNum) {
        return ERROR_WIFI_INVALID_ARGS;
    }

    for (unsigned int i = 0; i < staNum; i++) {
        errno_t err = memcpy_s(result[i].macAddress, WIFI_MAC_LEN, staList[i].mac_addr, ETH_ALEN);
        if (err != EOK) {
            printf("[wifi_service]:GetStationList memcpy fail, err = %d\n", err);
            return ERROR_WIFI_UNKNOWN;
        }
    }

    *size = staNum;
    return WIFI_SUCCESS;
}

int GetSignalLevel(int rssi, int band)
{
    if (band == HOTSPOT_BAND_TYPE_2G) {
        if (rssi >= RSSI_LEVEL_4_2_G) {
            return RSSI_LEVEL_4;
        }
        if (rssi >= RSSI_LEVEL_3_2_G) {
            return RSSI_LEVEL_3;
        }
        if (rssi >= RSSI_LEVEL_2_2_G) {
            return RSSI_LEVEL_2;
        }
        if (rssi >= RSSI_LEVEL_1_2_G) {
            return RSSI_LEVEL_1;
        }
    }

    if (band == HOTSPOT_BAND_TYPE_5G) {
        if (rssi >= RSSI_LEVEL_4_5_G) {
            return RSSI_LEVEL_4;
        }
        if (rssi >= RSSI_LEVEL_3_5_G) {
            return RSSI_LEVEL_3;
        }
        if (rssi >= RSSI_LEVEL_2_5_G) {
            return RSSI_LEVEL_2;
        }
        if (rssi >= RSSI_LEVEL_1_5_G) {
            return RSSI_LEVEL_1;
        }
    }

    return ERROR_WIFI_INVALID_ARGS;
}

WifiErrorCode SetBand(int band)
{
    if (band != HOTSPOT_BAND_TYPE_2G) {
        return ERROR_WIFI_NOT_SUPPORTED;
    }

    if (LockWifiGlobalLock() != WIFI_SUCCESS) {
        return ERROR_WIFI_UNKNOWN;
    }
    g_wifiApConfig.band = band;
    if (UnlockWifiGlobalLock() != WIFI_SUCCESS) {
        return ERROR_WIFI_UNKNOWN;
    }
    return WIFI_SUCCESS;
}

WifiErrorCode GetBand(int* result)
{
    if (result == NULL) {
        return ERROR_WIFI_INVALID_ARGS;
    }

    if (LockWifiGlobalLock() != WIFI_SUCCESS) {
        return ERROR_WIFI_UNKNOWN;
    }
    if (g_wifiApConfig.band == 0) {
        if (UnlockWifiGlobalLock() != WIFI_SUCCESS) {
            return ERROR_WIFI_UNKNOWN;
        }
        return ERROR_WIFI_NOT_AVAILABLE;
    }
    if (UnlockWifiGlobalLock() != WIFI_SUCCESS) {
        return ERROR_WIFI_UNKNOWN;
    }
    *result = HOTSPOT_BAND_TYPE_2G;
    return WIFI_SUCCESS;
}

WifiErrorCode DisassociateSta(unsigned char* mac, int macLen) {
    if (mac == NULL) {
        printf("[wifi_service]: MAC is NULL\r\n");
        return ERROR_WIFI_INVALID_ARGS;
    }
    int ret = tls_wifi_softap_del_station(mac);
    if (ret != WIFI_SUCCESS) {
        printf("[wifi_service]: remove station device failed.\r\n");
        return ERROR_WIFI_UNKNOWN;
    }
    return WIFI_SUCCESS;
}

WifiErrorCode AddTxPowerInfo(int power) {
    printf("Neptune not support.\r\n");
    return ERROR_WIFI_UNKNOWN;
}