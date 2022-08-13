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

/*
 * INCLUDE FILES
 ****************************************************************************************
 */

#include <string.h>
#include <stdio.h>
#include <stdint.h>

#include "my_stdbool.h"
#include "ohos_bt_gatt.h"
#include "ohos_bt_gatt_server.h"
#include "ohos_bt_gatt_client.h"

#include "host/ble_hs.h"
#include "host/util/util.h"

#include "wm_ble.h"
#include "wm_bt_def.h"
#include "ble_util.h"
#include "nble_server.h"

/*
 * GLOBAL VARIABLE DEFINITIONS
 ****************************************************************************************
 */

static volatile tls_bt_state_t bt_adapter_state = WM_BT_STATE_OFF;
static volatile bool ble_system_state_on = false;

/* back up the structure function pointer */
static BtGattClientCallbacks *gattc_struct_func_ptr_cb = NULL;
static BtGattServerCallbacks *gatts_struct_func_ptr_cb = NULL;
static BtGattCallbacks       *gap_func_ptr_cb = NULL;

static StartAdvRawData       g_adv_raw_data;
static BleAdvParams          g_adv_param;
static uint16_t              g_conn_handle;

typedef enum {
    WM_BT_SYSTEM_ACTION_IDLE,
    WM_BT_SYSTEM_ACTION_ENABLING,
    WM_BT_SYSTEM_ACTION_DISABLING
} bt_system_action_t;
static volatile bt_system_action_t bt_system_action = WM_BT_SYSTEM_ACTION_IDLE;

/*
 * LOCAL FUNCTION DECLARATIONS
 ****************************************************************************************
 */

static void on_svr_register_cb(struct ble_gatt_register_ctxt *ctxt, void *arg);
static int gap_event(struct ble_gap_event *event, void *arg);

/*
 * LOCAL FUNCTION DEFINITIONS
 ****************************************************************************************
 */

static void app_adapter_state_changed_callback(tls_bt_state_t status)
{
    BLE_IF_DEBUG("adapter status = %s\r\n", status==WM_BT_STATE_ON?"bt_state_on":"bt_state_off");

    bt_adapter_state = status;

#if (TLS_CONFIG_BLE == CFG_ON)

    if (status == WM_BT_STATE_ON) {
        BLE_IF_PRINTF("init base application\r\n");
        ble_server_init();
    } else {
        BLE_IF_PRINTF("deinit base application\r\n");
    }
#endif
}

static void on_sync(void)
{
    /* Make sure we have proper identity address set (public preferred) */

    app_adapter_state_changed_callback(WM_BT_STATE_ON);
}
static void on_reset(int reason)
{
    BLE_IF_DEBUG("Resetting state; reason=%d\r\n", reason);
    app_adapter_state_changed_callback(WM_BT_STATE_OFF);
}

static void on_svr_register_cb(struct ble_gatt_register_ctxt *ctxt, void *arg)
{
    BtUuid btuuid;
    char buf[BLE_UUID_STR_LEN];
    uint16_t server_if;
    uint16_t service_handle;

    switch (ctxt->op) {
        case BLE_GATT_REGISTER_OP_SVC:
            ble_server_retrieve_id_by_uuid(ctxt->svc.svc_def->uuid, &server_if);
            BLE_IF_DEBUG("service,uuid16 %s handle=%d (%04X), server_if=%d\r\n", \
                         ble_uuid_to_str(ctxt->svc.svc_def->uuid, buf), ctxt->svc.handle, ctxt->svc.handle, server_if);
            ble_server_update_svc_handle(ctxt->svc.svc_def->uuid, ctxt->svc.handle);
            if (gatts_struct_func_ptr_cb) {
                btuuid.uuidLen = ctxt->svc.svc_def->uuid->type;
                ble_uuid_flat(ctxt->svc.svc_def->uuid, buf);
                btuuid.uuid = buf;

                if (gatts_struct_func_ptr_cb->serviceAddCb) {
                    gatts_struct_func_ptr_cb->serviceAddCb(0 /* Always success */, server_if /* */, \
                        &btuuid, ctxt->svc.handle);
                }
            }
            break;

        case BLE_GATT_REGISTER_OP_CHR:
            service_handle = (uint16_t)*(uint16_t *)ctxt->chr.chr_def->arg;
            ble_server_retrieve_id_by_service_id(service_handle, &server_if);
            BLE_IF_DEBUG("charact,uuid16 %s arg %d def_handle=%d (%04X) val_handle=%d (%04X), \
                         svc_handle=%d, server_if=%d, arg=0x%08x\r\n",
                ble_uuid_to_str(ctxt->chr.chr_def->uuid, buf),
                (int)ctxt->chr.chr_def->arg,
                ctxt->chr.def_handle, ctxt->chr.def_handle,
                ctxt->chr.val_handle, ctxt->chr.val_handle, service_handle, server_if, (int)ctxt->chr.chr_def->arg);

            if (gatts_struct_func_ptr_cb) {
                btuuid.uuidLen = ctxt->chr.chr_def->uuid->type;
                ble_uuid_flat(ctxt->chr.chr_def->uuid, buf);
                btuuid.uuid = buf;
                if (gatts_struct_func_ptr_cb->characteristicAddCb) {
                    gatts_struct_func_ptr_cb->characteristicAddCb(0 /* Always success */, server_if /* */, &btuuid , \
                        service_handle /* msg->ser_add_char.service_id */, ctxt->chr.val_handle);
                }
            }

            break;

        case BLE_GATT_REGISTER_OP_DSC:
            service_handle = (uint16_t)*(uint16_t *)ctxt->dsc.dsc_def->arg;
            ble_server_retrieve_id_by_service_id(service_handle, &server_if);
            BLE_IF_DEBUG("descrip, uuid16 %s arg %d handle=%d (%04X) svc_handle=%d, server_if=%d\r\n",
                ble_uuid_to_str(ctxt->dsc.dsc_def->uuid, buf),
                (int)ctxt->dsc.dsc_def->arg,
                ctxt->dsc.handle, ctxt->dsc.handle, service_handle, server_if);
            if (gatts_struct_func_ptr_cb) {
                btuuid.uuidLen = ctxt->dsc.dsc_def->uuid->type;
                ble_uuid_flat(ctxt->dsc.dsc_def->uuid, buf);
                btuuid.uuid = buf;
                if (gatts_struct_func_ptr_cb->descriptorAddCb) {
                    gatts_struct_func_ptr_cb->descriptorAddCb(0 /* Always success */, server_if /* */, &btuuid , \
                        service_handle /* msg->ser_add_char.service_id */, ctxt->dsc.handle);
                }
            }
            break;
    }
    return;
}

static void conn_param_update_cb(uint16_t conn_handle, int status, void *arg)
{
    BLE_IF_DEBUG("conn param update complete; conn_handle=%d status=%d\n", conn_handle, status);
}

static void ble_server_conn_param_update_slave(void)
{
    int rc;
    struct ble_l2cap_sig_update_params params;

    params.itvl_min = 26;
    params.itvl_max = 42;
    params.slave_latency = 0;
    params.timeout_multiplier = 500;
    rc = ble_l2cap_sig_update(g_conn_handle, &params, conn_param_update_cb, NULL);
    BLE_IF_DEBUG("ble_l2cap_sig_update, rc=%d\n", rc);
}
static int ble_server_start_adv(void)
{
    int rc;
    uint8_t own_addr_type;
    ble_addr_t peer_addr;

    BLE_IF_DEBUG("\r\n BleStartAdvEx enter: caller addr=0x%x, self task=%s, \
                 bt_adapter_state=%d, bt_system_action=%d\r\n", \
                 __builtin_return_address(0), LOS_CurTaskNameGet(), bt_adapter_state, bt_system_action);

    if (bt_adapter_state == WM_BT_STATE_OFF || bt_system_action != WM_BT_SYSTEM_ACTION_IDLE) \
        return OHOS_BT_STATUS_NOT_READY;

    struct ble_gap_adv_params adv_params;

    /* Figure out address to use while advertising (no privacy for now) */
    rc = ble_hs_id_infer_auto(0, &own_addr_type);
    if (rc != 0) {
        BLE_IF_PRINTF("error determining address type; rc=%d\r\n", rc);
        return rc;
    }
    /* set adv parameters */
    memset_s(&adv_params, sizeof(&adv_params), 0, sizeof(adv_params));

    adv_params.itvl_max = g_adv_param.maxInterval;
    adv_params.itvl_min = g_adv_param.minInterval;
    adv_params.channel_map = g_adv_param.channelMap;
    adv_params.filter_policy = g_adv_param.advFilterPolicy;

    switch (g_adv_param.advType) {
        case OHOS_BLE_ADV_IND:
                adv_params.conn_mode = BLE_GAP_CONN_MODE_UND;
                adv_params.disc_mode = BLE_GAP_DISC_MODE_GEN;
            break;
        case OHOS_BLE_ADV_NONCONN_IND:
                adv_params.conn_mode = BLE_GAP_CONN_MODE_NON;
                adv_params.disc_mode = BLE_GAP_DISC_MODE_NON;
            break;
        case OHOS_BLE_ADV_SCAN_IND:
                adv_params.conn_mode = BLE_GAP_CONN_MODE_NON;
                adv_params.disc_mode = BLE_GAP_DISC_MODE_GEN; // LTD same as GEN;
            break;
        case OHOS_BLE_ADV_DIRECT_IND_HIGH:
                adv_params.high_duty_cycle = 1;
        case OHOS_BLE_ADV_DIRECT_IND_LOW:
                adv_params.conn_mode = BLE_GAP_CONN_MODE_DIR;
                adv_params.disc_mode = BLE_GAP_DISC_MODE_GEN;
            break;
    }

    peer_addr.type = g_adv_param.peerAddrType;
    memcpy_s(&peer_addr.val[0], sizeof(&peer_addr.val), &g_adv_param.peerAddr.addr[0], 6);

    BLE_IF_DEBUG("Starting advertising\r\n");

    /* As own address type we use hard-coded value, because we generate
          NRPA and by definition it's random */
    /* NOTE: own_addr_type, we actually used, not specified by param->ownaddType */
    rc = ble_gap_adv_start(own_addr_type, &peer_addr, g_adv_param.duration?g_adv_param.duration:BLE_HS_FOREVER,
                           &adv_params, gap_event, NULL);
    if (rc) {
        BLE_IF_PRINTF("Starting advertising failed, rc=%d\r\n", rc);
    }

    return OHOS_BT_STATUS_SUCCESS;
}

static int gap_event(struct ble_gap_event *event, void *arg)
{
    int rc;
    struct ble_gap_conn_desc desc;
    BdAddr bdaddr;

    BLE_IF_DEBUG("%s, event->type=%s(%d)\r\n", __FUNCTION__, tls_bt_gap_evt_2_str(event->type), event->type);

    if (gatts_struct_func_ptr_cb == NULL) return 0;

    switch (event->type) {
        case BLE_GAP_EVENT_CONNECT:
            BLE_IF_DEBUG("connected handle=%d, status=%d\r\n", event->connect.conn_handle, event->connect.status);
            if (event->connect.status == 0) {
                rc = ble_gap_conn_find(event->connect.conn_handle, &desc);
                assert(rc == 0);
                memcpy_s(bdaddr.addr, sizeof(bdaddr.addr), desc.peer_id_addr.val, 6);
                g_conn_handle = event->connect.conn_handle;
                /* see nble_server.c ble_server_gap_event will handle this callback */
                if (gatts_struct_func_ptr_cb->connectServerCb) {
                    gatts_struct_func_ptr_cb->connectServerCb(event->connect.conn_handle, \
                        0 /* Always 0,nimble does not care server if */, &bdaddr);
                }
                /* 200 ticks later, perform l2cap level connect param update */
            }
            if (event->connect.status != 0) {
                /* Connection failed; resume advertising. */
                ble_server_start_adv();
            }
            break;
        case BLE_GAP_EVENT_DISCONNECT:
            BLE_IF_DEBUG("disconnect reason=%d\r\n", event->disconnect.reason);

            memcpy_s(bdaddr.addr, sizeof(bdaddr.addr), event->disconnect.conn.peer_id_addr.val, 6);
            /* see nble_server.c ble_server_gap_event will handle this callback */
            if (gatts_struct_func_ptr_cb->disconnectServerCb) {
                gatts_struct_func_ptr_cb->disconnectServerCb(event->disconnect.conn.conn_handle, \
                    0 /* Always 0, nimble does not care server if */, &bdaddr);
            }

            if (event->disconnect.reason == 534) {
                // hci error code:  0x16 + 0x200 = 534; // local host terminate the connection;
            } else {
                ble_server_start_adv();
            }
            break;
        case BLE_GAP_EVENT_NOTIFY_TX:
            if (event->notify_tx.status == BLE_HS_EDONE) {
                // Note, the first param conn__handle, conn_id???  all servcie share one conn_id, so it is not proper
                if (gatts_struct_func_ptr_cb->indicationSentCb) {
                    gatts_struct_func_ptr_cb->indicationSentCb(event->notify_tx.conn_handle, \
                        0 /* event->notify_tx.status */);
                }
            } else {
                /* Application will handle other cases */
            }
            break;
        case BLE_GAP_EVENT_SUBSCRIBE:
            BLE_IF_DEBUG("subscribe indicate(%d,%d),attr_handle=%d\r\n", \
                         event->subscribe.prev_indicate, event->subscribe.cur_indicate, event->subscribe.attr_handle);
            if (event->subscribe.cur_indicate || event->subscribe.cur_notify) {
                ble_server_conn_param_update_slave();
            }
            break;
        case BLE_GAP_EVENT_MTU:
            BLE_IF_DEBUG("mtu changed to(%d)\r\n", event->mtu.value);
            if (gatts_struct_func_ptr_cb->mtuChangeCb) {
                gatts_struct_func_ptr_cb->mtuChangeCb(event->mtu.conn_handle, event->mtu.value);
            }
            break;
        case BLE_GAP_EVENT_REPEAT_PAIRING:
            /* We already have a bond with the peer, but it is attempting to
                     * establish a new secure link.  This app sacrifices security for
                     * convenience: just throw away the old bond and accept the new link.
                     */
            /* Delete the old bond. */
            rc = ble_gap_conn_find(event->repeat_pairing.conn_handle, &desc);
            assert(rc == 0);
            ble_store_util_delete_peer(&desc.peer_id_addr);

            return BLE_GAP_REPEAT_PAIRING_RETRY;

        case BLE_GAP_EVENT_PASSKEY_ACTION:
            return 0;
        case BLE_GAP_EVENT_ADV_COMPLETE:
            if (gap_func_ptr_cb && gap_func_ptr_cb->advDisableCb) \
                gap_func_ptr_cb->advDisableCb(0, event->adv_complete.reason);
            return 0;
        case BLE_GAP_EVENT_ENC_CHANGE:
            {
                rc = ble_gap_conn_find(event->enc_change.conn_handle, &desc);
                assert(rc == 0);
                memcpy_s(bdaddr.addr, sizeof(bdaddr.addr), desc.peer_id_addr.val, 6);
                if (gap_func_ptr_cb && gap_func_ptr_cb->securityRespondCb)gap_func_ptr_cb->securityRespondCb(&bdaddr);
                return 0;
            }
        default:
            break;
    }

    return 0;
}

/*
 * EXPORTED FUNCTION DEFINITIONS
 ****************************************************************************************
 */

int InitBtStack(void)
{
    return OHOS_BT_STATUS_UNSUPPORTED;
}

int EnableBtStack(void)
{
    BLE_IF_DEBUG("\r\n EnableBtStack enter: caller addr=0x%x\r\n", __builtin_return_address(0));

    if (bt_adapter_state == WM_BT_STATE_ON) {
        return OHOS_BT_STATUS_SUCCESS;
    }

    if (bt_system_action != WM_BT_SYSTEM_ACTION_IDLE) return OHOS_BT_STATUS_BUSY;
    bt_system_action = WM_BT_SYSTEM_ACTION_ENABLING;

    memset_s(&ble_hs_cfg, sizeof(&ble_hs_cfg), 0, sizeof(ble_hs_cfg));

    /* * Security manager settings. */
    ble_hs_cfg.sm_io_cap = MYNEWT_VAL(BLE_SM_IO_CAP),
    ble_hs_cfg.sm_oob_data_flag = MYNEWT_VAL(BLE_SM_OOB_DATA_FLAG),
    ble_hs_cfg.sm_bonding = MYNEWT_VAL(BLE_SM_BONDING),
    ble_hs_cfg.sm_mitm = MYNEWT_VAL(BLE_SM_MITM),
    ble_hs_cfg.sm_sc = MYNEWT_VAL(BLE_SM_SC),
    ble_hs_cfg.sm_keypress = MYNEWT_VAL(BLE_SM_KEYPRESS),
    ble_hs_cfg.sm_our_key_dist = MYNEWT_VAL(BLE_SM_OUR_KEY_DIST),
    ble_hs_cfg.sm_their_key_dist = MYNEWT_VAL(BLE_SM_THEIR_KEY_DIST),

    ble_hs_cfg.sync_cb = on_sync;
    ble_hs_cfg.reset_cb = on_reset;
    ble_hs_cfg.shutdown_cb = on_reset; /* same callback as on_reset */
    ble_hs_cfg.gatts_register_cb = on_svr_register_cb;
    ble_hs_cfg.store_status_cb = ble_store_util_status_rr;

    /* Initialize all packages. */
    nimble_port_init();

    /* Application levels code entry */

    /* Initialize the vuart interface and enable controller */
    ble_hci_vuart_init(0xFF);

    /* As the last thing, process events from default event queue. */
    tls_nimble_start();

    while (bt_adapter_state != WM_BT_STATE_ON) {
        tls_os_time_delay(100);
    }

    bt_system_action = WM_BT_SYSTEM_ACTION_IDLE;
    BLE_IF_DEBUG("\r\n EnableBtStack exit\r\n");
    return OHOS_BT_STATUS_SUCCESS;
}

int DisableBtStack(void)
{
    int rc = 0;

    BLE_IF_DEBUG("\r\n DisableBtStack enter: caller addr=0x%x, self task=%s\r\n", \
                 __builtin_return_address(0), LOS_CurTaskNameGet());

    if (bt_adapter_state == WM_BT_STATE_OFF) {
        BLE_IF_DEBUG("\r\n DisableBtStack exit because of BLE_HS_EALREADY \r\n");
        return OHOS_BT_STATUS_DONE;
    }

    if (bt_system_action != WM_BT_SYSTEM_ACTION_IDLE) return BLE_HS_EBUSY;

    bt_system_action = WM_BT_SYSTEM_ACTION_DISABLING;

    /* Stop hs system */
    rc = nimble_port_stop();
    assert(rc == 0);

    /* Stop controller and free vuart resource */
    rc = ble_hci_vuart_deinit();
    assert(rc == 0);

    /* Free hs system resource */
    nimble_port_deinit();

    /* Free task stack ptr and free hs task */
    tls_nimble_stop();

    /* Application levels resource cleanup */
    while (bt_adapter_state == WM_BT_STATE_ON) {
        tls_os_time_delay(10);
    }

    bt_system_action = WM_BT_SYSTEM_ACTION_IDLE;

    BLE_IF_DEBUG("\r\n DisableBtStack exit\r\n");

    return OHOS_BT_STATUS_SUCCESS;
}

int SetDeviceName(const char *name, unsigned int len)
{
    int rc;

    rc = ble_svc_gap_device_name_set(name);
    if (rc == 0) {
        return OHOS_BT_STATUS_SUCCESS;
    } else {
        return OHOS_BT_STATUS_FAIL;
    }
}

int BleStopAdv(int advId)
{
    int rc;
    BLE_IF_DEBUG("\r\n BleStopAdv enter: caller addr=0x%x, self task=%s,bt_adapter_state=%d, bt_system_action=%d\r\n",
        __builtin_return_address(0), LOS_CurTaskNameGet(), bt_adapter_state, bt_system_action);
    (void)advId;

    if (bt_adapter_state == WM_BT_STATE_OFF || bt_system_action != WM_BT_SYSTEM_ACTION_IDLE) \
        return OHOS_BT_STATUS_NOT_READY;

    rc = ble_gap_adv_stop();
    if (rc != 0) {
        BLE_IF_DEBUG("\r\n BleStopAdv exit, rc=%d\r\n", rc);

        return OHOS_BT_STATUS_FAIL;
    }

    return OHOS_BT_STATUS_SUCCESS;
}

int BleGattcRegister(BtUuid appUuid)
{
    (void)appUuid;

    return OHOS_BT_STATUS_UNSUPPORTED;
}

int BleGattcUnRegister(int clientId)
{
    (void)clientId;

    return OHOS_BT_STATUS_UNSUPPORTED;
}

int BleSetSecurityIoCap(BleIoCapMode mode)
{
    BLE_IF_DEBUG("BleSetSecurityIoCap, BleIoCapMode=%d\r\n", mode);

    ble_hs_cfg.sm_io_cap = mode;

    return OHOS_BT_STATUS_SUCCESS;
}

int BleSetSecurityAuthReq(BleAuthReqMode mode)
{
    BLE_IF_DEBUG("BleSetSecurityAuthReq, BleAuthReqMode=%d\r\n", mode);

    if ((mode&OHOS_BLE_AUTH_BOND) || (mode&OHOS_BLE_AUTH_REQ_SC_BOND) || (mode&OHOS_BLE_AUTH_REQ_SC_MITM_BOND)) {
        ble_hs_cfg.sm_bonding = 1;
    } else {
    }

    if ((mode&OHOS_BLE_AUTH_REQ_MITM) || (mode&OHOS_BLE_AUTH_REQ_SC_MITM) || (mode&OHOS_BLE_AUTH_REQ_SC_MITM_BOND)) {
        ble_hs_cfg.sm_mitm = 1;
    } else {
        ble_hs_cfg.sm_mitm = 0;
    }

    if ((mode&OHOS_BLE_AUTH_REQ_SC_ONLY) || (mode&OHOS_BLE_AUTH_REQ_SC_BOND) || (mode&OHOS_BLE_AUTH_REQ_SC_MITM) || \
        (mode&OHOS_BLE_AUTH_REQ_SC_MITM_BOND)) {
        ble_hs_cfg.sm_sc = 1;
    } else {
    }

    return OHOS_BT_STATUS_SUCCESS;
}

int BleGattSecurityRsp(BdAddr bdAddr, bool accept)
{
    (void)bdAddr;

    BLE_IF_DEBUG("BleGattSecurityRsp, accept=%hhu\r\n", accept);
    return OHOS_BT_STATUS_SUCCESS;
}

int BleGattsDisconnect(int serverId, BdAddr bdAddr, int connId)
{
    int rc;
    (void)serverId;
    (void)bdAddr;

    rc = ble_gap_terminate(connId, BLE_ERR_REM_USER_CONN_TERM);
    if (!rc) {
        return OHOS_BT_STATUS_SUCCESS;
    } else {
        return OHOS_BT_STATUS_FAIL;
    }
}

int BleGattsSetEncryption(BdAddr bdAddr, BleSecAct secAct)
{
    int rc;
    (void)bdAddr;

    BLE_IF_DEBUG("BleGattsSetEncryption, secAct=%d\r\n", secAct);

    rc = ble_gap_security_initiate(g_conn_handle);
    if (!rc) {
        return OHOS_BT_STATUS_SUCCESS;
    } else {
        return OHOS_BT_STATUS_FAIL;
    }
}

int BleGattsRegister(BtUuid appUuid)
{
    (void)appUuid;

    return OHOS_BT_STATUS_UNSUPPORTED;
}

int BleGattsUnRegister(int serverId)
{
    (void)serverId;

    return OHOS_BT_STATUS_UNSUPPORTED;
}

int BleGattsAddService(int serverId, BtUuid srvcUuid, bool isPrimary, int number)
{
    (void)serverId;
    (void)srvcUuid;
    (void)isPrimary;
    (void)number;

    return OHOS_BT_STATUS_UNSUPPORTED;
}

int BleGattsDeleteService(int serverId, int srvcHandle)
{
    (void)serverId;
    (void)srvcHandle;

    return OHOS_BT_STATUS_UNSUPPORTED;
}

int BleGattsAddCharacteristic(int serverId, int srvcHandle, BtUuid characUuid,
                              int properties, int permissions)
{
    (void)serverId;
    (void)srvcHandle;
    (void)characUuid;
    (void)permissions;
    (void)properties;

    return OHOS_BT_STATUS_UNSUPPORTED;
}

int BleGattsAddDescriptor(int serverId, int srvcHandle, BtUuid descUuid, int permissions)
{
    (void)serverId;
    (void)srvcHandle;
    (void)descUuid;
    (void)permissions;

    return OHOS_BT_STATUS_UNSUPPORTED;
}

int BleGattsStartService(int serverId, int srvcHandle)
{
    (void)serverId;
    (void)srvcHandle;

    return OHOS_BT_STATUS_UNSUPPORTED;
}

int BleGattsStopService(int serverId, int srvcHandle)
{
    (void)serverId;
    (void)srvcHandle;

    return OHOS_BT_STATUS_UNSUPPORTED;
}

int BleGattsSendResponse(int serverId, GattsSendRspParam *param)
{
    (void)serverId;
    (void)param;

    return OHOS_BT_STATUS_UNSUPPORTED;
}

int BleGattsSendIndication(int serverId, GattsSendIndParam *param)
{
    int rc;
    struct os_mbuf *om;
    (void)serverId;

    BLE_IF_DEBUG("Indicate to app:conn_id[%d],attr_handle[%d],data_length[%d]\r\n", \
                 param->connectId, param->attrHandle, param->valueLen);
    if (param->valueLen<=0 || param->value== NULL) {
        return OHOS_BT_STATUS_PARM_INVALID;
    }

    om = ble_hs_mbuf_from_flat(param->value, param->valueLen);
    if (!om) {
        return OHOS_BT_STATUS_NOMEM;
    }

    if (param->confirm) {
        rc = ble_gattc_indicate_custom(param->connectId, param->attrHandle, om);
    } else {
        rc = ble_gattc_notify_custom(param->connectId, param->attrHandle, om);
    }

    if (rc == 0) {
        rc = OHOS_BT_STATUS_SUCCESS;
    } else {
        rc = OHOS_BT_STATUS_UNHANDLED;
    }

    return rc;
}

int ReadBtMacAddr(unsigned char *mac, unsigned int len)
{
    if (len != 6) {
        return OHOS_BT_STATUS_PARM_INVALID;
    }

    tls_get_bt_mac_addr(mac);

    return OHOS_BT_STATUS_SUCCESS;
}

int BleGattcRegisterCallbacks(BtGattClientCallbacks *func)
{
    (void)func;
    return OHOS_BT_STATUS_SUCCESS;
}

int BleGattsRegisterCallbacks(BtGattServerCallbacks *func)
{
    gatts_struct_func_ptr_cb = func;

    return OHOS_BT_STATUS_SUCCESS;
}

int BleGattRegisterCallbacks(BtGattCallbacks *func)
{
    gap_func_ptr_cb = func;

    return OHOS_BT_STATUS_SUCCESS;
}

int BleStartAdvEx(int *advId, const StartAdvRawData rawData, BleAdvParams advParam)
{
    (void)advId;
    int rc;
    uint8_t own_addr_type;
    ble_addr_t peer_addr;

    BLE_IF_DEBUG("\r\n BleStartAdvEx enter: caller addr=0x%x, self task=%s,\
                 bt_adapter_state=%d, bt_system_action=%d\r\n", \
                 __builtin_return_address(0), LOS_CurTaskNameGet(), \
                 bt_adapter_state, bt_system_action);

    if (bt_adapter_state == WM_BT_STATE_OFF || bt_system_action != WM_BT_SYSTEM_ACTION_IDLE) \
        return OHOS_BT_STATUS_NOT_READY;

    // first back up the adv information;
    g_adv_raw_data = rawData;
    g_adv_param = advParam;

    struct ble_gap_adv_params adv_params;

    if (rawData.advDataLen) {
        rc = ble_gap_adv_set_data(rawData.advData, rawData.advDataLen);
        assert(rc == 0);
    }

    if (rawData.rspDataLen) {
        rc = ble_gap_adv_rsp_set_data(rawData.rspData, rawData.rspDataLen);
        assert(rc == 0);
    }

    /* Figure out address to use while advertising (no privacy for now) */
    rc = ble_hs_id_infer_auto(0, &own_addr_type);
    if (rc != 0) {
        BLE_IF_PRINTF("error determining address type; rc=%d\r\n", rc);
        return rc;
    }
    /* set adv parameters */
    memset_s(&adv_params, sizeof(&adv_params), 0, sizeof(adv_params));

    adv_params.itvl_max = advParam.maxInterval;
    adv_params.itvl_min = advParam.minInterval;
    adv_params.channel_map = advParam.channelMap;
    adv_params.filter_policy = advParam.advFilterPolicy;

    switch (advParam.advType) {
        case OHOS_BLE_ADV_IND:
                adv_params.conn_mode = BLE_GAP_CONN_MODE_UND;
                adv_params.disc_mode = BLE_GAP_DISC_MODE_GEN;
            break;
        case OHOS_BLE_ADV_NONCONN_IND:
                adv_params.conn_mode = BLE_GAP_CONN_MODE_NON;
                adv_params.disc_mode = BLE_GAP_DISC_MODE_NON;
            break;
        case OHOS_BLE_ADV_SCAN_IND:
                adv_params.conn_mode = BLE_GAP_CONN_MODE_NON;
                adv_params.disc_mode = BLE_GAP_DISC_MODE_GEN; //  LTD same as GEN;
            break;
        case OHOS_BLE_ADV_DIRECT_IND_HIGH:
                adv_params.high_duty_cycle = 1;
        case OHOS_BLE_ADV_DIRECT_IND_LOW:
                adv_params.conn_mode = BLE_GAP_CONN_MODE_DIR;
                adv_params.disc_mode = BLE_GAP_DISC_MODE_GEN;
            break;
    }

    peer_addr.type = advParam.peerAddrType;
    memcpy_s(&peer_addr.val[0], sizeof(&peer_addr.val), &advParam.peerAddr.addr[0], 6);

    BLE_IF_DEBUG("Starting advertising\r\n");

    /* As own address type we use hard-coded value, because we generate
          NRPA and by definition it's random */
    /* NOTE: own_addr_type, we actually used, not specified by param->ownaddType */
    rc = ble_gap_adv_start(own_addr_type, &peer_addr, advParam.duration?advParam.duration:BLE_HS_FOREVER,
                           &adv_params, gap_event, NULL);
    if (rc) {
        BLE_IF_PRINTF("Starting advertising failed, rc=%d\r\n", rc);
    }

    return OHOS_BT_STATUS_SUCCESS;
}

int BleGattsStartServiceEx(int *srvcHandle, BleGattService *srvcInfo)
{
    int rc = 0;
    int server_if = 0;
    int adv_active = 0;
    uint16_t service_handle_r = 0;

    if (bt_adapter_state == WM_BT_STATE_OFF || bt_system_action != WM_BT_SYSTEM_ACTION_IDLE) \
    return OHOS_BT_STATUS_NOT_READY;

    BLE_IF_DEBUG("BleGattsStartServiceEx\r\n");
    adv_active = ble_gap_adv_active();
    if (adv_active) {
        rc = ble_gap_adv_stop();
    }

    rc = ble_gatts_reset();
    if (rc != 0) {
        BLE_IF_PRINTF("!!!BleGattsStartServiceEx failed!!! rc=%d\r\n", rc);
        return rc;
    }

    server_if = ble_server_alloc(srvcInfo);
    *srvcHandle  = server_if;

    ble_server_start_service();

    if (adv_active) {
        ble_server_start_adv();
    }

    // report servcie startcb
    if (gatts_struct_func_ptr_cb) {
        if (gatts_struct_func_ptr_cb->serviceStartCb) {
            ble_server_retrieve_service_handle_by_server_id(server_if, &service_handle_r);
            gatts_struct_func_ptr_cb->serviceStartCb(0 /* Always success */, server_if, service_handle_r);
        }
    }

    BLE_IF_DEBUG("ble server alloc return=%d\r\n", server_if);
    return OHOS_BT_STATUS_SUCCESS;
}

int BleGattsStopServiceEx(int srvcHandle)
{
    uint16_t service_handle_r = 0;

    if (bt_adapter_state == WM_BT_STATE_OFF || bt_system_action != WM_BT_SYSTEM_ACTION_IDLE) \
        return OHOS_BT_STATUS_NOT_READY;

    ble_gap_adv_stop();

    ble_server_free(srvcHandle);

    if (gatts_struct_func_ptr_cb) {
        if (gatts_struct_func_ptr_cb->serviceStopCb) {
            ble_server_retrieve_service_handle_by_server_id(srvcHandle /* actually, this is server_if */, \
                &service_handle_r);
            gatts_struct_func_ptr_cb->serviceStopCb(0 /* Always success */, srvcHandle /* server_if */, \
                service_handle_r);
        }
    }
    return OHOS_BT_STATUS_SUCCESS;
}

