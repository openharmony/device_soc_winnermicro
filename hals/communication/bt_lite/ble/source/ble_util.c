/*
 * Copyright (c) 2021 WinnerMicro Co., Ltd.
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

#include <stdio.h>
#include <stdint.h>
#include "host/ble_hs.h"

#include "ble_util.h"

#ifndef CASE_RETURN_STR
#define CASE_RETURN_STR(const) case const: return #const;
#endif

const char *tls_bt_gap_evt_2_str(uint32_t event)
{
    switch (event) {
        CASE_RETURN_STR(BLE_GAP_EVENT_CONNECT)
        CASE_RETURN_STR(BLE_GAP_EVENT_DISCONNECT)
        CASE_RETURN_STR(BLE_GAP_EVENT_CONN_UPDATE)
        CASE_RETURN_STR(BLE_GAP_EVENT_CONN_UPDATE_REQ)
        CASE_RETURN_STR(BLE_GAP_EVENT_L2CAP_UPDATE_REQ)
        CASE_RETURN_STR(BLE_GAP_EVENT_TERM_FAILURE)
        CASE_RETURN_STR(BLE_GAP_EVENT_DISC)
        CASE_RETURN_STR(BLE_GAP_EVENT_DISC_COMPLETE)
        CASE_RETURN_STR(BLE_GAP_EVENT_ADV_COMPLETE)
        CASE_RETURN_STR(BLE_GAP_EVENT_ENC_CHANGE)
        CASE_RETURN_STR(BLE_GAP_EVENT_PASSKEY_ACTION)
        CASE_RETURN_STR(BLE_GAP_EVENT_NOTIFY_RX)
        CASE_RETURN_STR(BLE_GAP_EVENT_NOTIFY_TX)
        CASE_RETURN_STR(BLE_GAP_EVENT_SUBSCRIBE)
        CASE_RETURN_STR(BLE_GAP_EVENT_MTU)
        CASE_RETURN_STR(BLE_GAP_EVENT_IDENTITY_RESOLVED)
        CASE_RETURN_STR(BLE_GAP_EVENT_REPEAT_PAIRING)
        CASE_RETURN_STR(BLE_GAP_EVENT_PHY_UPDATE_COMPLETE)
        CASE_RETURN_STR(BLE_GAP_EVENT_EXT_DISC)
        CASE_RETURN_STR(BLE_GAP_EVENT_PERIODIC_SYNC)
        CASE_RETURN_STR(BLE_GAP_EVENT_PERIODIC_REPORT)
        CASE_RETURN_STR(BLE_GAP_EVENT_PERIODIC_SYNC_LOST)
        CASE_RETURN_STR(BLE_GAP_EVENT_SCAN_REQ_RCVD)
        CASE_RETURN_STR(BLE_GAP_EVENT_PERIODIC_TRANSFER)

        default:
            return "unkown bt host evt";
    }
}
void tls_bt_dump_hexstring(const char *info, uint8_t *p, int length)
{
    int i = 0, j = 0;
    printf("%s\r\n", info);
    for (i=0; i<length; i++) {
        j++;
        printf("%02x ", p[i]);
        if ((j%16)==0) {
            printf("\r\n");
        }
    }
    printf("\r\n");
}