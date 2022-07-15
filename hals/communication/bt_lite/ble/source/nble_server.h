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

#ifndef __NBLE_SERVER_H__
#define __NBLE_SERVER_H__

/*Initialize the list for ble server*/
extern void ble_server_init();

/*Enable the all service stored in the servcie list one by one*/
extern void ble_server_start_service();

/*Free servcie by server id*/
extern int ble_server_free(int server_id);

/*Register one service, and return server if*/
extern int ble_server_alloc(BleGattService *srvcinfo);

extern void ble_server_gap_event(struct ble_gap_event *event, void *arg);

/*Internal function*/
extern void ble_server_update_svc_handle(ble_uuid_t *uuid, uint16_t attr_handle);
extern void ble_server_retrieve_id_by_service_id(uint16_t svc_handle, uint16_t *server_id);
extern void ble_server_retrieve_id_by_uuid(ble_uuid_t *uuid, uint16_t *server_id);
extern void ble_server_retrieve_service_handle_by_server_id(uint16_t server_id, uint16_t *service_handle);

#endif
