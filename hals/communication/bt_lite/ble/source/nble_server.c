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

#include <string.h>
#include <stdio.h>
#include <stdint.h>

#include "my_stdbool.h"
#include "ohos_bt_gatt_server.h"

#include "wm_mem.h"
#include "wm_ble.h"
#include "wm_bt_def.h"
#include "list.h"
#include "ble_util.h"

#include "host/ble_hs.h"
#include "host/util/util.h"

/*
 * STRUCTURE DEFINITIONS
 ****************************************************************************************
 */

typedef struct{
    struct dl_list list;
    BleAttribType attr_type;
    uint16_t attr_handle;
    ble_uuid_any_t uuid;
    BleGattOperateFunc func;
    struct ble_npl_mutex service_mutex;
} service_elem_t;

typedef struct{
    struct dl_list list;
    uint16_t server_id;
    uint8_t srvc_count;
    void *priv_data;
    service_elem_t srvc_list;
    struct ble_npl_mutex server_mutex;
} server_elem_t;

typedef struct{
    struct dl_list list;
    struct ble_gatt_svc_def *svc;
} nim_service_t;

/*
 * GLOBAL VARIABLE DEFINITIONS
 ****************************************************************************************
 */

static uint16_t g_server_id;
static server_elem_t server_list;
static nim_service_t nim_service_list;

/*
 * LOCAL FUNCTION DEFINITIONS
 ****************************************************************************************
 */

void ble_server_gap_event(struct ble_gap_event *event, void *arg)
{
    BdAddr bdaddr;
    struct ble_gap_conn_desc desc;
    server_elem_t *svr_item = NULL;
    BtGattServerCallbacks *gatts_struct_func_ptr_cb = (BtGattServerCallbacks *)arg;
    
    switch(event->type) {
        case BLE_GAP_EVENT_CONNECT:
            if (event->connect.status == 0) {
                int rc = ble_gap_conn_find(event->connect.conn_handle, &desc);
                assert(rc == 0);
                memcpy(bdaddr.addr, desc.peer_id_addr.val, 6);

                if (gatts_struct_func_ptr_cb && gatts_struct_func_ptr_cb->connectServerCb) {
                    
                    dl_list_for_each(svr_item, &server_list.list, server_elem_t, list)
                    gatts_struct_func_ptr_cb->connectServerCb(event->connect.conn_handle, svr_item->server_id,&bdaddr);
                }
            }
            break;
        case BLE_GAP_EVENT_DISCONNECT:
            memcpy(bdaddr.addr, event->disconnect.conn.peer_id_addr.val, 6);
            if (gatts_struct_func_ptr_cb && gatts_struct_func_ptr_cb->disconnectServerCb) {      
                dl_list_for_each(svr_item, &server_list.list, server_elem_t, list)
                gatts_struct_func_ptr_cb->disconnectServerCb(event->disconnect.conn.conn_handle, svr_item->server_id,&bdaddr);
            }    
            break;
         default:
            break;
    }
}

void ble_server_retrieve_id_by_uuid(ble_uuid_t *uuid, uint16_t *server_id)
{
    server_elem_t *svr_item = NULL;
    service_elem_t *svc_item = NULL;
    dl_list_for_each(svr_item, &server_list.list, server_elem_t, list)
    {
        svc_item = dl_list_first(&svr_item->srvc_list.list, service_elem_t, list);

        if (ble_uuid_cmp(uuid,&svc_item->uuid) == 0) {
            *server_id = svr_item->server_id;
        }
    }
}

void ble_server_retrieve_id_by_service_id(uint16_t svc_handle, uint16_t *server_id)
{
    server_elem_t *svr_item = NULL;
    service_elem_t *svc_item = NULL;
    dl_list_for_each(svr_item, &server_list.list, server_elem_t, list)
    {
        svc_item = dl_list_first(&svr_item->srvc_list.list, service_elem_t, list);

        if (svc_item->attr_handle == svc_handle) {
            *server_id = svr_item->server_id;
        }
    }
}

void ble_server_retrieve_service_handle_by_server_id(uint16_t server_id, uint16_t *service_handle)
{
    server_elem_t *svr_item = NULL;
    service_elem_t *svc_item = NULL;
    dl_list_for_each(svr_item, &server_list.list, server_elem_t, list)
    {

        if (svr_item->server_id == server_id) {
        
            svc_item = dl_list_first(&svr_item->srvc_list.list, service_elem_t, list);

            if (svc_item)
            {
                *service_handle = svc_item->attr_handle;
            }
        }
    }
}

void ble_server_update_svc_handle(ble_uuid_t *uuid, uint16_t attr_handle)
{
    server_elem_t *svr_item = NULL;
    service_elem_t *svc_item = NULL;
    dl_list_for_each(svr_item, &server_list.list, server_elem_t, list)
    {
        svc_item = dl_list_first(&svr_item->srvc_list.list, service_elem_t, list);

        if (ble_uuid_cmp(uuid,&svc_item->uuid) == 0) {
            svc_item->attr_handle = attr_handle;
        }
    }
}

void ble_server_func_by_attr_handle(uint16_t attr_handle ,uint8_t op, uint8_t *data, int *len)
{
    server_elem_t *svr_item = NULL;
    service_elem_t *svc_item = NULL;

    /* match the attr_handle and do the callback */
    dl_list_for_each(svr_item, &server_list.list, server_elem_t, list)
    {
        dl_list_for_each(svc_item, &svr_item->srvc_list.list, service_elem_t, list)
        {
            if (svc_item->attr_handle == attr_handle) {
                switch (op) {
                    case BLE_GATT_ACCESS_OP_WRITE_CHR:
                        if (svc_item->func.write) {
                            #if BLE_IF_DBG
                            #endif
                            svc_item->func.write(data, (int)*len);
                        }
                        break;
                    case BLE_GATT_ACCESS_OP_READ_CHR:
                        if (svc_item->func.read) {
                            svc_item->func.read(data, len);
                            #if BLE_IF_DBG
                            tls_bt_dump_hexstring("To  Remote:", data, *len);
                            #endif
                        }
                        break;
                   default:
                        break;
                }
            }
        }  
    }
}

static uint8_t cache_buffer[512];

static int ble_server_gatt_svc_access_func(uint16_t conn_handle, uint16_t attr_handle,
                               struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    int length = 0;
    int offset = 0;
    struct os_mbuf *om = ctxt->om;

    BLE_IF_DEBUG("%s, op=%d,attr_handle=%d\r\n", __FUNCTION__, ctxt->op,attr_handle);
    switch (ctxt->op) {
        case BLE_GATT_ACCESS_OP_WRITE_CHR:
            {
            while (om) {
                length =  om->om_len;
                memcpy(cache_buffer+offset, om->om_data, length);
                offset += length;
                assert(offset <= sizeof(cache_buffer));
                om = SLIST_NEXT(om, om_next);
            }
            if (offset>0)ble_server_func_by_attr_handle(attr_handle, ctxt->op, cache_buffer, &offset);
                return 0;
            }
        case BLE_GATT_ACCESS_OP_READ_CHR:
            {
            ble_server_func_by_attr_handle(attr_handle, ctxt->op, cache_buffer, &length);
            if (length>0) { 
                int rc = os_mbuf_append(ctxt->om, &cache_buffer[0],length);
                return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
            }
            return 0;
            }
        default:
            return BLE_ATT_ERR_UNLIKELY;
    }
}

int ble_server_uuid_init_from_buf(ble_uuid_any_t *uuid, const void *buf, size_t len)
{
    switch (len) {
        case OHOS_UUID_TYPE_16_BIT:
            uuid->u.type = BLE_UUID_TYPE_16;
            uuid->u16.value = get_le16(buf);
            return 0;
        case OHOS_UUID_TYPE_32_BIT:
            uuid->u.type = BLE_UUID_TYPE_32;
            uuid->u32.value = get_le32(buf);
            return 0;
        case OHOS_UUID_TYPE_128_BIT:
            uuid->u.type = BLE_UUID_TYPE_128;
            memcpy(uuid->u128.value, buf, 16);
            return 0;
    }

    return BLE_HS_EINVAL;
}

/*
 * EXPORTED FUNCTION DEFINITIONS
 ****************************************************************************************
 */

int ble_server_alloc(BleGattService *srvcinfo)
{
    int i = 0;

    uint8_t srvc_counter = 0;
    uint8_t char_counter = 0;
    uint8_t desc_counter = 0;

    service_elem_t *srvc_elem = NULL;
    service_elem_t *srvc_sub_elem = NULL;   

    struct ble_gatt_svc_def *gatt_svc_array = NULL;
    struct ble_gatt_chr_def *gatt_chr_array = NULL;
    struct ble_gatt_dsc_def *gatt_dsc_array = NULL;
    
    assert(srvcinfo != NULL);
    
    server_elem_t *serv_elem = (server_elem_t *)tls_mem_alloc(sizeof(server_elem_t));
    assert(serv_elem != NULL);
    memset(serv_elem, 0, sizeof(server_elem_t));
    /* init the service list attached to the server element */
    dl_list_init(&serv_elem->srvc_list.list);

    serv_elem->server_id = g_server_id++;
    serv_elem->srvc_count = 0;

    // presearch to get the counter of character and descriptor;
    for(i = 0; i<srvcinfo->attrNum; i++) {
        if (srvcinfo->attrList[i].attrType == OHOS_BLE_ATTRIB_TYPE_SERVICE) {
            srvc_counter++;
        } else if (srvcinfo->attrList[i].attrType == OHOS_BLE_ATTRIB_TYPE_CHAR) {
            char_counter++;
            BLE_IF_DEBUG("CHAR PROP=0x%02x, PERM=0x%02x\r\n",srvcinfo->attrList[i].properties, srvcinfo->attrList[i].permission);
            
        } else if (srvcinfo->attrList[i].attrType == OHOS_BLE_ATTRIB_TYPE_CHAR_USER_DESCR) {
            desc_counter++;
            BLE_IF_DEBUG("DESC PROP=0x%02x, PERM=0x%02x\r\n",srvcinfo->attrList[i].properties, srvcinfo->attrList[i].permission);
        }
    }
    assert(srvc_counter == 1);
    assert(char_counter >= 1);

    BLE_IF_DEBUG("Adding service srvc=%d, char=%d, dsc=%d\r\n",srvc_counter,char_counter, desc_counter);

    /* alloc service array */
    gatt_svc_array = (struct ble_gatt_svc_def *)tls_mem_alloc(2*sizeof(struct ble_gatt_svc_def));
    assert(gatt_svc_array != NULL);
    memset(gatt_svc_array, 0, 2*sizeof(struct ble_gatt_svc_def));

    /* prealloc charactertistic array */
    gatt_chr_array = (struct ble_gatt_chr_def *)tls_mem_alloc((1+char_counter) * sizeof(struct ble_gatt_chr_def));
    assert(gatt_chr_array != NULL);
    memset(gatt_chr_array, 0, (1+char_counter) * sizeof(struct ble_gatt_chr_def));

    /* preappending to character array */
    gatt_svc_array[0].characteristics = gatt_chr_array;

    /* create a service item and appending it to the servcie array */
    nim_service_t *nim_service = (nim_service_t *)tls_mem_alloc(sizeof(nim_service_t));
    assert(nim_service != NULL);
    memset(nim_service, 0, sizeof(nim_service_t));
    nim_service->svc = gatt_svc_array;
    dl_list_add_tail(&nim_service_list.list, &nim_service->list);
    
    for(i = 0; i<srvcinfo->attrNum; i++) {
        if (srvcinfo->attrList[i].attrType == OHOS_BLE_ATTRIB_TYPE_SERVICE) {  
            srvc_elem = (service_elem_t *)tls_mem_alloc(sizeof(service_elem_t));
            assert(srvc_elem != NULL);
            srvc_elem->attr_type = srvcinfo->attrList[i].attrType;
            ble_server_uuid_init_from_buf(&srvc_elem->uuid,srvcinfo->attrList[i].uuid, srvcinfo->attrList[i].uuidType);
            srvc_elem->attr_handle = 0xFFFF;
            dl_list_add_tail(&serv_elem->srvc_list.list, &srvc_elem->list);
            // first fill with element used for nimble stack;
            gatt_svc_array[0].type = BLE_GATT_SVC_TYPE_PRIMARY;
            gatt_svc_array[0].uuid=  &srvc_elem->uuid;
        } else if (srvcinfo->attrList[i].attrType == OHOS_BLE_ATTRIB_TYPE_CHAR) {
            srvc_sub_elem = (service_elem_t *)tls_mem_alloc(sizeof(service_elem_t));
            assert(srvc_sub_elem != NULL);
            srvc_sub_elem->attr_type = srvcinfo->attrList[i].attrType;
            ble_server_uuid_init_from_buf(&srvc_sub_elem->uuid,srvcinfo->attrList[i].uuid, srvcinfo->attrList[i].uuidType);
            srvc_sub_elem->func = srvcinfo->attrList[i].func;
            dl_list_add_tail(&serv_elem->srvc_list.list, &srvc_sub_elem->list);

            /* process stack env */
            gatt_chr_array[serv_elem->srvc_count].uuid = &srvc_sub_elem->uuid;
            gatt_chr_array[serv_elem->srvc_count].access_cb = ble_server_gatt_svc_access_func;
            gatt_chr_array[serv_elem->srvc_count].flags = srvcinfo->attrList[i].properties;
            gatt_chr_array[serv_elem->srvc_count].min_key_size = 16;
            gatt_chr_array[serv_elem->srvc_count].val_handle = &srvc_sub_elem->attr_handle; 
            gatt_chr_array[serv_elem->srvc_count].arg = (void*)&srvc_elem->attr_handle;   // give the service handle as arg, char added callback will handle it;
            serv_elem->srvc_count++;
        } else if (srvcinfo->attrList[i].attrType == OHOS_BLE_ATTRIB_TYPE_CHAR_USER_DESCR) {
      
            // stack will handle the cccd
            serv_elem->srvc_count--;   // fill with descriptor attached to this character 
            
            srvc_sub_elem = (service_elem_t *)tls_mem_alloc(sizeof(service_elem_t));
            assert(srvc_sub_elem != NULL);
            srvc_sub_elem->attr_type = srvcinfo->attrList[i].attrType;
            ble_server_uuid_init_from_buf(&srvc_sub_elem->uuid,srvcinfo->attrList[i].uuid, srvcinfo->attrList[i].uuidType);
            srvc_sub_elem->func = srvcinfo->attrList[i].func;
            dl_list_add_tail(&serv_elem->srvc_list.list, &srvc_sub_elem->list);

            if (gatt_chr_array[serv_elem->srvc_count].flags & BLE_GATT_CHR_F_NOTIFY || gatt_chr_array[serv_elem->srvc_count].flags & BLE_GATT_CHR_F_INDICATE) {
               // NimBLE stack will auto add the cccd. 
            } else {
                gatt_dsc_array = (struct ble_gatt_dsc_def *)tls_mem_alloc(2*sizeof(struct ble_gatt_dsc_def));
                memset(gatt_dsc_array, 0, 2*sizeof(struct ble_gatt_dsc_def));
                gatt_dsc_array[0].uuid = &srvc_sub_elem->uuid;
                gatt_dsc_array[0].access_cb = ble_server_gatt_svc_access_func;
                gatt_dsc_array[0].att_flags = srvcinfo->attrList[i].properties |srvcinfo->attrList[i].permission<<8;
                gatt_dsc_array[0].min_key_size = 16;
                gatt_dsc_array[0].arg = (void*)&srvc_elem->attr_handle;   // give the service handle as arg, char added callback will handle it;
                gatt_chr_array[serv_elem->srvc_count].descriptors = gatt_dsc_array;
            }
               
            serv_elem->srvc_count++; // restore it;
        }
    }

    serv_elem->priv_data = (void*)nim_service;

    // appending the server elem to the server list;
    dl_list_add_tail(&server_list.list, &serv_elem->list);

    return serv_elem->server_id;
}

int ble_server_free(int server_id)
{
    int d = 0;
    nim_service_t *nim_service_item = NULL;
    server_elem_t *svr_item = NULL;
    server_elem_t *svr_item_next = NULL;    
    service_elem_t *svc_item = NULL;
    service_elem_t *svc_item_next = NULL;
    struct ble_gatt_svc_def *svc_array = NULL;
    struct ble_gatt_chr_def *chr_array = NULL;

    // free list entry for application level
    dl_list_for_each_safe(svr_item, svr_item_next, &server_list.list, server_elem_t, list)
    {
        if (svr_item->server_id == server_id) {
            nim_service_item = (nim_service_t *)svr_item->priv_data; // the svc_array to be freed;
      
            dl_list_for_each_safe(svc_item, svc_item_next, &svr_item->srvc_list.list, service_elem_t, list)
            {
                dl_list_del(&svc_item->list);
                tls_mem_free(svc_item);
            }

            dl_list_del(&svr_item->list);
            tls_mem_free(svr_item);
            break;
        }
    }

    // free servcie array used for nimble stack;
    if (nim_service_item) {
        svc_array = nim_service_item->svc;
        if (svc_array) {
            if (svc_array->characteristics != NULL) {
                for (int c = 0; svc_array->characteristics[c].uuid != NULL; c++) {
                    chr_array = svc_array->characteristics + c;

                    if (chr_array->descriptors != NULL) {
                        tls_mem_free(chr_array->descriptors);
                    }
                }

                tls_mem_free(svc_array->characteristics);
            }

            tls_mem_free(svc_array);
        }

        dl_list_del(&nim_service_item->list);
        tls_mem_free(nim_service_item); 
    }
}

void ble_server_start_service()
{
    nim_service_t *svc_item = NULL;
  
    if (!dl_list_empty(&nim_service_list.list)) {
        int rc;
        dl_list_for_each(svc_item, &nim_service_list.list, nim_service_t, list)
        {
            if (svc_item == NULL) {
                BLE_IF_PRINTF("ERROR, LIST ERROR\r\n");
                return;
            }
            rc = ble_gatts_count_cfg(svc_item->svc);
            assert(rc == 0);

            rc = ble_gatts_add_svcs(svc_item->svc);
            assert(rc == 0);
        }
        
        rc = ble_gatts_start();
        assert(rc == 0);
    }
}

void ble_server_init()
{
    memset(&server_list, 0, sizeof(server_elem_t));
    dl_list_init(&server_list.list);
    dl_list_init(&nim_service_list.list); 
}