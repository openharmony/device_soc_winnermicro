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

/* From w800 sdk */
#include "wm_type_def.h"
#include "wm_wifi.h"
#include "wm_params.h"
#include "wm_mem.h"
#include "wm_efuse.h"
#include "kv_store.h"

/* Why we doing this?
 * Symbol @WIFI_DISCONNECTED conflict with OHOS wifiservice,
 * locate in foundation/communication/interfaces/kits/wifi_lite/wifiservice/wifi_linked_info.h
 * They have different types. to avoid this confliction, redefine this macro with another name.
 */
#ifdef WIFI_DISCONNECTED
#undef WIFI_DISCONNECTED // avoid conflict with wifi_linked_info.h
#endif

#include "wifi_error_code.h"
#include "wifi_device.h"
#include "wifi_event.h"
#include "wifi_linked_info.h"
#include "securec.h"

#include <stdio.h>

#define BSS_BUFFER_SIZE (2048)
#define TLS_SSID_MAX_LEN (32) /* see wifi/wm_wifi.h ssid definition */

static WifiDeviceConfig gWifiConfigs[WIFI_MAX_CONFIG_SIZE] = {{{0}, {0}, {0}, 0, WIFI_CONFIG_INVALID, 0, 0}};
static int gWifiStaStatus = WIFI_STA_NOT_ACTIVE;
static WifiEvent* gWifiEvents[WIFI_MAX_EVENT_SIZE] = {0};
static u8 gWifiScanDone = FALSE;

static volatile u8 g_connectStatus = 0;
// 0x1: NETIF_WIFI_JOIN_SUCCESS, 0x2: NETIF_WIFI_JOIN_FAILED, 0x3: NETIF_WIFI_DISCONNECTED

u8 g_hasConnected = 0;

/* Store Scanned AP count
 * TODO: Use lock to protect Scan result.
 */
#define KV_FILE_NAME  "/data"
#define WIFI_CFG_INFO   "wifi_cfg_info"

static int gScannedAPCount;
static u8* gScannedBuffer;

#define MAX_WIFI_KV_NAME_LEN  (32)

#define MAX_WIFI_KV_STRING_LEN  (160)
static u8 kvstring[MAX_WIFI_KV_STRING_LEN];
static u8 keystring[MAX_WIFI_KV_NAME_LEN];
static u8 keynew = 0;
static u8 keyold  = 0;

// #ifndef DEBUG
#define DEBUG (1)
// #endif

#define debug_wifi(fmt, ...)            \
    do {                                \
        if (DEBUG) {                    \
            printf(fmt, ##__VA_ARGS__); \
        }                               \
    } while (0)
/*
 * w800 doesn't support enable/disable wifi sta function
 * always return success.
 */

WifiErrorCode EnableWifi(void)
{
    if (LockWifiGlobalLock() != WIFI_SUCCESS) {
        return ERROR_WIFI_UNKNOWN;
    }

    if (gWifiStaStatus == WIFI_STA_ACTIVE) {
        if (UnlockWifiGlobalLock() != WIFI_SUCCESS) {
            return ERROR_WIFI_UNKNOWN;
        }
        return ERROR_WIFI_BUSY;
    }
    tls_wifi_init();
    gWifiStaStatus = WIFI_STA_ACTIVE;

    if (UnlockWifiGlobalLock() != WIFI_SUCCESS) {
        /* FIXME: Should reset gWifiStaStatus here? */
        return ERROR_WIFI_UNKNOWN;
    }
    return WIFI_SUCCESS;
}

WifiErrorCode DisableWifi(void)
{
    if (LockWifiGlobalLock() != WIFI_SUCCESS) {
        return ERROR_WIFI_UNKNOWN;
    }

    if (gWifiStaStatus == WIFI_STA_NOT_ACTIVE) {
        if (UnlockWifiGlobalLock() != WIFI_SUCCESS) {
            return ERROR_WIFI_UNKNOWN;
        }
        return ERROR_WIFI_NOT_STARTED;
    }

    gWifiStaStatus = WIFI_STA_NOT_ACTIVE;

    if (UnlockWifiGlobalLock() != WIFI_SUCCESS) {
        return ERROR_WIFI_UNKNOWN;
    }
    return WIFI_SUCCESS;
}

int IsWifiActive(void)
{
    int ret;
    if (LockWifiGlobalLock() != WIFI_SUCCESS) {
        return ERROR_WIFI_UNKNOWN;
    }

    ret = gWifiStaStatus;

    if (UnlockWifiGlobalLock() != WIFI_SUCCESS) {
        return ERROR_WIFI_UNKNOWN;
    }

    return ret;
}

static void DispatchScanStateChangeEvent(const WifiEvent* event, WifiEventState state)
{
    int bssCount = 0;
    if (event == NULL || event->OnWifiScanStateChanged == NULL) {
        return;
    }

    if (state == WIFI_STATE_NOT_AVALIABLE) {
        event->OnWifiScanStateChanged(state, bssCount);
        return;
    }

    if (state == WIFI_STATE_AVAILABLE) {
        bssCount = gScannedAPCount;
        if (bssCount < 0) {
            printf("Get scanned count failed.\n");
            bssCount = 0;
        }
        event->OnWifiScanStateChanged(state, bssCount);
        return;
    }
}

static void DispatchConnectEvent(int state, WifiLinkedInfo* info)
{
    for (int i = 0; i < WIFI_MAX_EVENT_SIZE; ++i) {
        if (gWifiEvents[i] != NULL && gWifiEvents[i]->OnWifiConnectionChanged != NULL) {
            gWifiEvents[i]->OnWifiConnectionChanged(state, info);
        }
    }
}

static void DispatchHotspotStateChangedEvent(int state)
{
    for (int i = 0; i < WIFI_MAX_EVENT_SIZE; ++i) {
        if (gWifiEvents[i] != NULL && gWifiEvents[i]->OnHotspotStateChanged != NULL) {
            gWifiEvents[i]->OnHotspotStateChanged(state);
        }
    }
}

static void DispatchJoinEvent(StationInfo* info)
{
    if (!info) return;

    for (int i = 0; i < WIFI_MAX_EVENT_SIZE; ++i) {
        if (gWifiEvents[i] != NULL && gWifiEvents[i]->OnHotspotStaJoin != NULL) {
            gWifiEvents[i]->OnHotspotStaJoin(info);
        }
    }
}

static void DispatchLeaveEvent(StationInfo* info)
{
    if (!info) return;

    for (int i = 0; i < WIFI_MAX_EVENT_SIZE; ++i) {
        if (gWifiEvents[i] != NULL && gWifiEvents[i]->OnHotspotStaLeave != NULL) {
            gWifiEvents[i]->OnHotspotStaLeave(info);
        }
    }
}

static void WifiScanHandler(void)
{
    int ret;
    struct tls_scan_bss_t *scanRes = NULL;

    if (gScannedBuffer == NULL) {
        printf("[wifi_device]: scan buffer is NULL!\n");
        
        gWifiScanDone = TRUE;
        return;
    }

    ret = tls_wifi_get_scan_rslt(gScannedBuffer, BSS_BUFFER_SIZE);
    if (ret == WM_FAILED) {
        printf("[wifi_device]: get scan result failed.\n");
        tls_mem_free(gScannedBuffer);
        gScannedBuffer = NULL;

        gWifiScanDone = TRUE;
        return;
    }

    scanRes = (struct tls_scan_bss_t *)gScannedBuffer;
    gScannedAPCount = scanRes->count;

    LockWifiEventLock();

    printf("[wifi_service]: dispatch scan event.\n");
    for (int i = 0; i < WIFI_MAX_EVENT_SIZE; ++i) {
        if (gWifiEvents[i] != NULL) {
            DispatchScanStateChangeEvent(gWifiEvents[i], WIFI_STATE_AVAILABLE);
        }
    }
    UnlockWifiEventLock();
    gWifiScanDone = TRUE;
}

WifiErrorCode Scan(void)
{
    /* Check wifi station status */
    if (LockWifiGlobalLock() != WIFI_SUCCESS) {
        return ERROR_WIFI_UNKNOWN;
    }

    if (gWifiStaStatus == WIFI_STA_NOT_ACTIVE) {
        if (UnlockWifiGlobalLock() != WIFI_SUCCESS) {
            return ERROR_WIFI_UNKNOWN;
        }
        return ERROR_WIFI_NOT_STARTED;
    }

    if (UnlockWifiGlobalLock() != WIFI_SUCCESS) {
        return ERROR_WIFI_UNKNOWN;
    }

    if (LockWifiEventLock() != WIFI_SUCCESS) {
        return ERROR_WIFI_UNKNOWN;
    }

    for (int i = 0; i < WIFI_MAX_EVENT_SIZE; ++i) {
        if (gWifiEvents[i] == NULL) {
            continue;
        }
        DispatchScanStateChangeEvent(gWifiEvents[i], WIFI_STATE_NOT_AVALIABLE);
    }

    if (UnlockWifiEventLock() != WIFI_SUCCESS) {
        return ERROR_WIFI_UNKNOWN;
    }

    if (gScannedBuffer != NULL) {
        memset(gScannedBuffer, 0, BSS_BUFFER_SIZE);
    } else {
        gScannedBuffer = tls_mem_alloc(BSS_BUFFER_SIZE);
        if (gScannedBuffer == NULL) {
            printf("[wifi_device]: Scan allocate memory failed.\n");
            return ERROR_WIFI_UNKNOWN;
        }
    }

    tls_wifi_scan_result_cb_register(WifiScanHandler);
    if (tls_wifi_scan() != WM_SUCCESS) {
        printf("[wifi_service]:Scan failed to start sta scan.\n");
        tls_wifi_scan_result_cb_register(NULL);
        return ERROR_WIFI_UNKNOWN;
    }

    while (gWifiScanDone == FALSE) {
        osDelay(50); /* 500 ms */
    }
    gWifiScanDone = FALSE; /* Reset scan flag */

    return WIFI_SUCCESS;
}

static void WifiEventCallback(u8 status)
{
    switch (status) {
        case NETIF_WIFI_JOIN_SUCCESS:
            debug_wifi("WifiEventCallback status = WIFI_JOIN_SUCCESS\n");
            WifiLinkedInfo info = {0};
            WifiErrorCode err = GetLinkedInfo(&info);
            if (err != WIFI_SUCCESS) {
                DispatchConnectEvent(WIFI_STATE_NOT_AVALIABLE, NULL);
            } else {
                DispatchConnectEvent(WIFI_STATE_AVAILABLE, &info);
            }
            break;
        case NETIF_WIFI_JOIN_FAILED:
            debug_wifi("WifiEventCallback status = WIFI_JOIN_FAILED\n");
            DispatchConnectEvent(WIFI_STATE_NOT_AVALIABLE, NULL);
            break;
        case NETIF_WIFI_DISCONNECTED:
            debug_wifi("WifiEventCallback status = WIFI_DISCONNECTED\n");
            DispatchConnectEvent(WIFI_STATE_NOT_AVALIABLE, NULL);
            break;
        case NETIF_WIFI_SOFTAP_SUCCESS: /* ap */
            debug_wifi("WifiEventCallback status = WIFI_SOFTAP_SUCCESS\n");
            DispatchHotspotStateChangedEvent(WIFI_HOTSPOT_ACTIVE);
            break;
        case NETIF_WIFI_SOFTAP_FAILED:
            debug_wifi("WifiEventCallback status = WIFI_SOFTAP_FAILED\n");
            DispatchHotspotStateChangedEvent(WIFI_HOTSPOT_NOT_ACTIVE);
            break;
        case NETIF_WIFI_SOFTAP_CLOSED:
            debug_wifi("WifiEventCallback status = WIFI_SOFTAP_CLOSED\n");
            DispatchHotspotStateChangedEvent(WIFI_HOTSPOT_NOT_ACTIVE);
            break;
        default:
            debug_wifi("WifiEventCallback invalid status: %d\n", status);
            break;
    }
}

static void WifiHotspotEventCallback(u8 *mac, enum tls_wifi_client_event_type event)
{
    StationInfo info = {0};
    memcpy(info.macAddress, mac, sizeof(info.macAddress));

    switch (event) {
        case WM_WIFI_CLIENT_EVENT_ONLINE:
            debug_wifi("WifiHotspotEventCallback event = ONLINE\n");
            DispatchJoinEvent(&info);
            break;
        case WM_WIFI_CLIENT_EVENT_OFFLINE:
            debug_wifi("WifiHotspotEventCallback event = OFFLINE\n");
            DispatchLeaveEvent(&info);
            break;
    }
}

WifiErrorCode RegisterWifiEvent(WifiEvent* event)
{
    int i;

    if (event == NULL) {
        return ERROR_WIFI_INVALID_ARGS;
    }

    if (LockWifiEventLock() != WIFI_SUCCESS) {
        printf("[wifi_device]: RegisterWifiEvent lock wifi event lock failed.\n");
        return ERROR_WIFI_UNKNOWN;
    }

    for (i = 0; i < WIFI_MAX_EVENT_SIZE; ++i) {
        if (gWifiEvents[i] == event) {
            printf("[wifi_device]: event already registered.\n");
            if (UnlockWifiEventLock() != WIFI_SUCCESS) {
                return ERROR_WIFI_UNKNOWN;
            }
            return ERROR_WIFI_INVALID_ARGS;
        }
        if (gWifiEvents[i] == NULL) {
            gWifiEvents[i] = event;
            break;
        }
    }
    if (UnlockWifiEventLock() != WIFI_SUCCESS) {
        return ERROR_WIFI_UNKNOWN;
    }

    err_t err = tls_wifi_netif_add_status_event(WifiEventCallback);
    if (err != 0) {
        printf("[wifi_device]: tls_netif_add_status_event failed.\n");
        return ERROR_WIFI_UNKNOWN;
    }

    tls_wifi_softap_client_event_register(WifiHotspotEventCallback);
    return WIFI_SUCCESS;
}

WifiErrorCode UnRegisterWifiEvent(const WifiEvent* event)
{
    int i;
    if (event == NULL) {
        printf("[wifi_device]: UnRegisterWifiEvent event is null.\n");
        return ERROR_WIFI_INVALID_ARGS;
    }

    if (LockWifiEventLock() != WIFI_SUCCESS) {
        printf("[wifi_device]: UnRegisterWifiEvent lock wifi event lock failed.\n");
        return ERROR_WIFI_UNKNOWN;
    }

    for (i = 0; i < WIFI_MAX_EVENT_SIZE; ++i) {
        if (gWifiEvents[i] == event) {
            gWifiEvents[i] = NULL;
            UnlockWifiEventLock();
            return WIFI_SUCCESS;
        }
    }
    UnlockWifiEventLock();

    err_t err = tls_wifi_netif_remove_status_event(WifiEventCallback);
    if (err != 0) {
        printf("[wifi_device]: tls_netif_add_status_event failed.\n");
        return ERROR_WIFI_UNKNOWN;
    }

    printf("UnRegisterWifiEvent wifi event is not registered\n");
    return ERROR_WIFI_UNKNOWN;
}

WifiErrorCode AdvanceScan(WifiScanParams *params)
{
    if (params == NULL) {
        return ERROR_WIFI_UNKNOWN;
    }

    if (params->scanType == WIFI_FREQ_SCAN && params->freqs == 0) {
        return ERROR_WIFI_UNKNOWN;
    }

    if (params->scanType == WIFI_SSID_SCAN && (params->ssidLen == 0 || strlen(params->ssid) == 0)) {
        printf("[wifi_service] WIFI_SSID_SCAN, but ssid empty!\n");
        return ERROR_WIFI_UNKNOWN;
    }

    char emptyBssid[WIFI_MAC_LEN] = {0};
    if (params->scanType == WIFI_BSSID_SCAN && memcmp(params->bssid, emptyBssid, sizeof(emptyBssid)) == 0) {
        printf("[wifi_service] WIFI_BSSID_SCAN, but bssid empty!\n");
        return ERROR_WIFI_UNKNOWN;
    }

    if (params->scanType == WIFI_BAND_SCAN && params->band == 0) {
        // /FIXME: test case code logic error, but we follow it, need update when test code update.
        printf("[wifi_service] WIFI_BAND_SCAN, but band = %d invalid!\n", params->band);
    }

    if (params->scanType < 0 || params->scanType > WIFI_BAND_SCAN) {
        printf("[wifi_service] scanType invalid!\n");
    }

    if (LockWifiGlobalLock() != WIFI_SUCCESS) {
        return ERROR_WIFI_UNKNOWN;
    }
    if (gWifiStaStatus == WIFI_STA_NOT_ACTIVE) {
        if (UnlockWifiGlobalLock() != WIFI_SUCCESS) {
            return ERROR_WIFI_UNKNOWN;
        }
        return ERROR_WIFI_NOT_STARTED;
    }

    if (UnlockWifiGlobalLock() != WIFI_SUCCESS) {
        return ERROR_WIFI_UNKNOWN;
    }

    if (LockWifiEventLock() != WIFI_SUCCESS) {
        return ERROR_WIFI_UNKNOWN;
    }
    for (int i = 0; i < WIFI_MAX_EVENT_SIZE; i++) {
        if (gWifiEvents[i] == NULL) {
            continue;
        }
        DispatchScanStateChangeEvent(gWifiEvents[i], WIFI_STATE_NOT_AVALIABLE);
    }
    if (UnlockWifiEventLock() != WIFI_SUCCESS) {
        return ERROR_WIFI_UNKNOWN;
    }

    // TODO(xu): filter scan result by params
    return Scan();
}

WifiErrorCode GetScanInfoList(WifiScanInfo* result, unsigned int* size)
{
    struct tls_scan_bss_t *scanRes = NULL;
    struct tls_bss_info_t *bssInfo;
    u32 scanCount, i;

    if (result == NULL || size == NULL || *size == 0) {
        return ERROR_WIFI_INVALID_ARGS;
    }

    /*
     * scan result already stored in gScannedBuffer
     * from scan callbcak.
     */
    if (gScannedBuffer == NULL) {
        printf("[wifi_device]: no cached scan result.\n");
        *size = 0;
        return WIFI_SUCCESS;
    }

    scanRes = (struct tls_scan_bss_t *)gScannedBuffer;
    bssInfo = scanRes->bss;
    scanCount = scanRes->count;

    if (scanCount > *size) {
        printf("[wifi_device]: scan count overflow.\n");
        return ERROR_WIFI_INVALID_ARGS;
    }

    if (scanCount > WIFI_SCAN_HOTSPOT_LIMIT) {
        printf("[wifi_device]: too many scan results.\n");
        printf("[wifi_device]: limit to %d\n", WIFI_SCAN_HOTSPOT_LIMIT);
        scanCount = WIFI_SCAN_HOTSPOT_LIMIT;
    }

    for (i = 0; i < scanCount; ++i) {
        int cpyErr = memcpy_s(result[i].ssid, WIFI_MAX_SSID_LEN, bssInfo->ssid, bssInfo->ssid_len);
        if (cpyErr != EOK) {
            printf("[wifi_device]: copy ssid of scan result failed\n");
            return ERROR_WIFI_UNKNOWN;
        }

        cpyErr = memcpy_s(result[i].bssid, WIFI_MAC_LEN, bssInfo->bssid, ETH_ALEN);
        if (cpyErr != EOK) {
            printf("[wifi_device]: copy bssid from scan result failed\n");
            return ERROR_WIFI_UNKNOWN;
        }

        /* FIXME: should do some conversion.
         * make sure w800 security type compat to OHOS security type.
         * Fix this later.
         */
        result[i].securityType = WmAuth2HoSec(bssInfo->privacy);
        result[i].rssi = (char)bssInfo->rssi;

        /* FIXME: @frequency with unit MHZ.
         * @max_data_rate with unit Mbps.
         * Should do unit conversion. Fix this later.
         */
        result[i].frequency = bssInfo->max_data_rate;
        bssInfo++;
    }

    /*
     * Free gScannedBuffer here.
     * Since We've already copied scan result to user.
     * This is not useful anymore. free the memory
     * The @Scan triggered again will re-allocate the memory.
     */

    tls_mem_free(gScannedBuffer);
    gScannedBuffer = NULL;
    *size = scanCount;

    return WIFI_SUCCESS;
}

WifiErrorCode GetDeviceMacAddress(unsigned char* result)
{
    if (result == NULL) {
        return ERROR_WIFI_INVALID_ARGS;
    }

    if (tls_get_mac_addr((u8 *)result) != TLS_EFUSE_STATUS_OK) {
        printf("GetDeviceMacAddress get mac address failed");
        return ERROR_WIFI_UNKNOWN;
    }
    return WIFI_SUCCESS;
}

WifiErrorCode AddDeviceConfig(const WifiDeviceConfig* config, int* result)
{
    int netId = WIFI_CONFIG_INVALID;
    int i;
    int ret = 0;

    if (config == NULL || result == NULL) {
        printf("[wifi_device]:add device config invalid argument.\n");
        return ERROR_WIFI_INVALID_ARGS;
    }

    if (LockWifiGlobalLock() != WIFI_SUCCESS) {
        printf("[wifi_device]:Lock wifi global lock failed.\n");
        return ERROR_WIFI_UNKNOWN;
    }
    for (i = 0; i < WIFI_MAX_CONFIG_SIZE; i++) {
        if (gWifiConfigs[i].netId != i) {
            netId = i;
            break;
        }
    }

    if (netId == WIFI_CONFIG_INVALID) {
        printf("[wifi_service]:AddDeviceConfig wifi config is full, delete one first\n");
        if (UnlockWifiGlobalLock() != WIFI_SUCCESS) {
            return ERROR_WIFI_UNKNOWN;
        }
        return ERROR_WIFI_BUSY;
    }

    UtilsSetEnv(KV_FILE_NAME);
    memset(kvstring, 0, MAX_WIFI_KV_STRING_LEN);
    memset(keystring, 0, MAX_WIFI_KV_NAME_LEN);
    memcpy(kvstring, config, sizeof(WifiDeviceConfig));
    kvstring[sizeof(WifiDeviceConfig)] = '\0';

    sprintf(keystring, WIFI_CFG_INFO"_%d", netId);
    ret = UtilsSetValue(keystring, kvstring);
    if (ret < 0 ) {
        return ERROR_WIFI_BUSY;
    }

    int cpyErr = memcpy_s(&gWifiConfigs[netId], sizeof(WifiDeviceConfig), config, sizeof(WifiDeviceConfig));
    if (cpyErr != EOK) {
        printf("[wifi_service]:AddDeviceConfig memcpy failed, err = %d\n", cpyErr);
        if (UnlockWifiGlobalLock() != WIFI_SUCCESS) {
            printf("[wifi_device] Unlock wifi global lock failed.\n");
        }
        return ERROR_WIFI_UNKNOWN;
    }

    gWifiConfigs[netId].netId = netId;
    if (UnlockWifiGlobalLock() != WIFI_SUCCESS) {
        printf("[wifi_device] Unlock wifi global lock failed after copy config.\n");
        return ERROR_WIFI_UNKNOWN;
    }

    *result = netId;
    return WIFI_SUCCESS;
}

WifiErrorCode GetDeviceConfigs(WifiDeviceConfig* result, unsigned int* size)
{
    unsigned int retIndex = 0;
    int i = 0;
    int cpyErr;
    int validflag = -1;

    if (result == NULL || size == NULL || *size == 0) {
        return ERROR_WIFI_INVALID_ARGS;
    }
    // printf("\r\nGetDeviceConfigs, *size=%d, caller addr=%p\n", *size, __builtin_return_address(0));

    if (LockWifiGlobalLock() != WIFI_SUCCESS) {
        printf("[wifi_device]: Unlock wifi global lock failed in get device config.\n");
        return ERROR_WIFI_UNKNOWN;
    }

    UtilsSetEnv(KV_FILE_NAME);
    for (i = 0; i < WIFI_MAX_CONFIG_SIZE; i++) {
        memset(keystring, 0, MAX_WIFI_KV_NAME_LEN);
        sprintf(keystring, WIFI_CFG_INFO"_%d", i);
        int ret = UtilsGetValue(keystring, &gWifiConfigs[i], sizeof(WifiDeviceConfig));
        if (ret == 0) {
            validflag = 1;
        }
    }

    if (validflag < 0 ) {
        printf("\r\n read wifi cfg info fail");
        if (UnlockWifiGlobalLock() != WIFI_SUCCESS) {
            printf("[wifi_device] Unlock wifi global lock failed in get device config.\n");
        }
        return ERROR_WIFI_NOT_AVAILABLE;
    } else {
        // printf("\r\n read wifi cfg info ok");
    }

    for (i = 0; i < WIFI_MAX_CONFIG_SIZE; ++i) {
        if (gWifiConfigs[i].netId != i) {
            continue;
        }

        cpyErr = memcpy_s(&result[retIndex], sizeof(WifiDeviceConfig), &gWifiConfigs[i], sizeof(WifiDeviceConfig));
        if (cpyErr != EOK) {
            printf("[wifi_service]: GetDeviceConfig memcpy failed, err = %d\n", cpyErr);
            if (UnlockWifiGlobalLock() != WIFI_SUCCESS) {
                printf("[wifi_device] Unlock wifi global lock failed in get device config.\n");
            }
            return ERROR_WIFI_UNKNOWN;
        }

        retIndex++;
        if (*size < retIndex) {
            printf("[wifi_service: wifi device config overflow.\n");
            return UnlockWifiGlobalLock() != WIFI_SUCCESS ? ERROR_WIFI_UNKNOWN : ERROR_WIFI_INVALID_ARGS;
        }
    }

    if (UnlockWifiGlobalLock() != WIFI_SUCCESS) {
        printf("[wifi_service: sem unlock failed.\n");
        return ERROR_WIFI_UNKNOWN;
    }

    if (retIndex == 0) {
        printf("[wifi_service: ERROR_WIFI_NOT_AVAILABLE.\n");
        return ERROR_WIFI_NOT_AVAILABLE;
    }

    *size = retIndex;
    return WIFI_SUCCESS;
}

WifiErrorCode Disconnect(void)
{
    printf("\r\nDisconnect: g_connectStatus=%d", g_connectStatus);

    tls_wifi_disconnect();

    if (g_connectStatus != NETIF_WIFI_JOIN_SUCCESS) {
        return ERROR_WIFI_UNKNOWN;
    }
    g_connectStatus = NETIF_WIFI_DISCONNECTED;
    return WIFI_SUCCESS;
}

WifiErrorCode RemoveDevice(int networkId)
{
    if (networkId >= WIFI_MAX_CONFIG_SIZE || networkId < 0) {
        printf("[wifi_service]:removeDevice invalid param: networkId=%d\n", networkId);
        return ERROR_WIFI_INVALID_ARGS;
    }

    if (LockWifiGlobalLock() != WIFI_SUCCESS) {
        return ERROR_WIFI_UNKNOWN;
    }
    if (memset_s(&gWifiConfigs[networkId], sizeof(WifiDeviceConfig), \
                 0, sizeof(WifiDeviceConfig)) != EOK) {
        printf("[wifi_service]:removeDevice memset failed\n");
    }
    gWifiConfigs[networkId].netId = WIFI_CONFIG_INVALID;
    
    gWifiStaStatus = WIFI_STA_NOT_ACTIVE;
    g_connectStatus = 0;
    g_hasConnected = 0;

#if 1
    UtilsSetEnv(KV_FILE_NAME);
    memset(keystring, 0, MAX_WIFI_KV_NAME_LEN);
    sprintf(keystring, WIFI_CFG_INFO"_%d", networkId);
    int ret = UtilsDeleteValue(keystring);
    if (ret < 0 ) {
        printf("\r\n clear wifi cfg info fail");
    } else {
    }
#else
    extern void HalFlashFileDeInit(void);
    HalFlashFileDeInit();
#endif

    if (UnlockWifiGlobalLock() != WIFI_SUCCESS) {
        return ERROR_WIFI_UNKNOWN;
    }
    return WIFI_SUCCESS;
}

WifiErrorCode GetLinkedInfo(WifiLinkedInfo* result)
{
    struct tls_curr_bss_t *bss;
    int cpyErr;
    WifiErrorCode retCode = WIFI_SUCCESS;
    if (result == NULL) {
        return ERROR_WIFI_INVALID_ARGS;
    }

    enum tls_wifi_states wifi_states; /* wifi states */

    wifi_states = tls_wifi_get_state();
    bss = tls_mem_alloc(sizeof(struct tls_curr_bss_t));
    if (!bss) {
        printf("[wifi_device]: GetLinkedInfo allocate memory failed.\n");
        return ERROR_WIFI_UNKNOWN;
    }

    (void)memset_s(bss, sizeof(struct tls_curr_bss_t), 0x00, sizeof(struct tls_curr_bss_t));
    tls_wifi_get_current_bss(bss);

    cpyErr = memcpy_s(result->ssid, WIFI_MAX_SSID_LEN, bss->ssid, TLS_SSID_MAX_LEN + 1);
    if (cpyErr != EOK) {
        printf("[wifi_device]: GetLinkedInfo copy ssid failed. err = %d.\n", cpyErr);
        tls_mem_free(bss);
        return ERROR_WIFI_UNKNOWN;
    }

    cpyErr = memcpy_s(result->bssid, WIFI_MAC_LEN, bss->bssid, ETH_ALEN);
    if (cpyErr != EOK) {
        printf("[wifi_device]: GetLinkedInfo copy bssid failed. err = %d.\n", cpyErr);
        tls_mem_free(bss);
        return ERROR_WIFI_UNKNOWN;
    }

    switch (wifi_states) {
        case WM_WIFI_DISCONNECTED:
            result->connState = WIFI_DISCONNECTED;
            break;
        case WM_WIFI_JOINED:
            result->connState = WIFI_CONNECTED;
            result->rssi = (signed char)(0 - bss->rssi);
            break;
        case WM_WIFI_SCANNING: /* fall through */
        case WM_WIFI_JOINING:
            printf("[wifi_device]: connecting is in progroess.\n");
            retCode = ERROR_WIFI_BUSY; /* Mark Wi-Fi is busy. Is it reasonable? */
            break;
        default:
            printf("[wifi_device]: GetLinkedInfo, unknown wifi states.\n");
            retCode = ERROR_WIFI_INVALID_ARGS;
            break;
    }

    tls_mem_free(bss);
    return retCode;
}

static void InitWifiConfig(void)
{
    u8 wireless_protocol = 0;
    struct tls_param_ip *ip_param = NULL;

    debug_wifi("InitWifiConfig, disconnect wifi...\n");
    tls_wifi_disconnect();
    tls_param_get(TLS_PARAM_ID_WPROTOCOL, (void *) &wireless_protocol, TRUE);
    if (TLS_PARAM_IEEE80211_INFRA != wireless_protocol) {
        debug_wifi("InitWifiConfig, destroy softap...\n");
        tls_wifi_softap_destroy();
        osDelay(10);
        wireless_protocol = TLS_PARAM_IEEE80211_INFRA;
        tls_param_set(TLS_PARAM_ID_WPROTOCOL, (void *) &wireless_protocol, TRUE); // FALSE
    }

    ip_param = tls_mem_alloc(sizeof(struct tls_param_ip));
    if (ip_param != NULL) {
        tls_param_get(TLS_PARAM_ID_IP, ip_param, FALSE);
        ip_param->dhcp_enable = TRUE;
        tls_param_set(TLS_PARAM_ID_IP, ip_param, FALSE);
        tls_mem_free(ip_param);
    } else {
        debug_wifi("InitWifiConfig, alloc memory failed.\n");
    }
}

static void WifiStatusHandler(u8 status)
{
    printf("\r\n WifiStatusHandler status=%d", status);
    g_connectStatus = status;
}

WifiErrorCode ConnectTo(int networkId)
{
    if (networkId >= WIFI_MAX_CONFIG_SIZE || networkId < 0) {
        return ERROR_WIFI_INVALID_ARGS;
    }

    InitWifiConfig();

    if (LockWifiGlobalLock() != WIFI_SUCCESS) {
        printf("[wifi_device]: ConnectTo lock wifi global lock failed.\n");
        return ERROR_WIFI_UNKNOWN;
    }

    if (gWifiConfigs[networkId].netId != networkId) {
        printf("[wifi_device]: Connectto network id %d is not valid.\n", networkId);
        if (UnlockWifiGlobalLock() != WIFI_SUCCESS) {
            printf("[wifi_device]: ConnectTo unlock wifi global lock failed.\n");
            return ERROR_WIFI_UNKNOWN;
        }
        return ERROR_WIFI_NOT_AVAILABLE;
    }

    if (gWifiConfigs[networkId].preSharedKey[0] == '\0') {
        debug_wifi("[wifi_device]: Connectto PSK is empty, auth mode is OPEN.\n");
    }
    printf("wifi device connect to SSID:%s, KEY:%s\r\n", gWifiConfigs[networkId].ssid, \
           gWifiConfigs[networkId].preSharedKey);

    if (gWifiConfigs[networkId].wapiPskType == WIFI_PSK_TYPE_HEX) {
        debug_wifi("[wifi_device]: psk type is HEX type.\n");
    }

    WifiDeviceConfig connConfig = gWifiConfigs[networkId];
    if (tls_wifi_connect((u8*)connConfig.ssid, strlen(connConfig.ssid),
        (u8*)connConfig.preSharedKey, strlen(connConfig.preSharedKey)) != WM_SUCCESS) {
#if TLS_CONFIG_DEBUG
        printf("[wifi_device]: connect to %s failed.\n", connConfig.ssid);
#endif
        UnlockWifiGlobalLock();
        return ERROR_WIFI_UNKNOWN;
    }

    if (UnlockWifiGlobalLock() != WIFI_SUCCESS) {
        return ERROR_WIFI_UNKNOWN;
    }

    g_connectStatus = 0;
    err_t err = tls_wifi_netif_add_status_event(WifiStatusHandler);
    if (err != 0) {
        printf("[wifi_device]: tls_netif_add_status_event for ConnectTo failed.\n");
        return ERROR_WIFI_UNKNOWN;
    }

    while (g_connectStatus == 0) {
        osDelay(10);
    }
#if TLS_CONFIG_DEBUG
    debug_wifi("Connect to %s done, status = %d!\n", connConfig.ssid, g_connectStatus);
#endif
    if (g_connectStatus == NETIF_WIFI_JOIN_SUCCESS) {
        g_hasConnected = 1;
        return WIFI_SUCCESS;
    }

    err = tls_wifi_netif_remove_status_event(WifiStatusHandler);
    if (err != 0) {
        printf("[wifi_device]: tls_netif_remove_status_event for ConnectTo failed.\n");
        return ERROR_WIFI_UNKNOWN;
    }
    printf("[wifi_device]: ConnectTo failed due to unknown reason.\n");
    return ERROR_WIFI_UNKNOWN;
}
