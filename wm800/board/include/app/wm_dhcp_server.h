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

#ifndef WM_DHCP_SERVER_H
#define WM_DHCP_SERVER_H

/**
 * @defgroup APP_APIs APP APIs
 * @brief APP APIs
 */

/**
 * @addtogroup APP_APIs
 * @{
 */

/**
 * @defgroup DHCPS_APIs DHCPS APIs
 * @brief DHCP server APIs
 */

/**
 * @addtogroup DHCPS_APIs
 * @{
 */

/**
 * @brief          This function is used to start DHCP Server for a network
                   interface
 *
 * @param          None
 *
 * @retval         WM_SUCCESS     success
 * @retval         WM_FAILED	  failed
 *
 * @note           None
 */
s8 tls_dhcps_start(void);

/**
 * @brief          This function is used to stop DHCP server
 *
 * @param[in]      None
 *
 * @return         None
 *
 * @note           None
 */
void tls_dhcps_stop(void);

/**
 * @brief          This function is used to get station's IP address by
                   MAC address
 *
 * @param[in]      *mac  STA's MAC address
 *
 * @retval         ip_addr     STA's IP address
 * @retval         NULL		   Not found match IP with MAC address
 *
 * @note           None
 */
ip_addr_t *tls_dhcps_getip(const u8 *mac);

/**
 * @brief          This function is used to set DHCP server's DNS address
 *
 * @param[in]      numdns    the index of the DNS server to set must be 0 or 1
 *
 * @return         None
 *
 * @note           None
 */
void tls_dhcps_setdns(u8 numdns);

/**
 * @}
 */

/**
 * @}
 */

#endif /* WM_DHCP_SERVER_H */

