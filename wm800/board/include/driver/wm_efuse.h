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
 * @file    wm_efuse.h
 *
 * @brief   virtual efuse Driver Module
 *
 * @author  dave
 *
 * Copyright (c) 2014 Winner Microelectronics Co., Ltd.
 */
#ifndef WM_EFUSE_H
#define WM_EFUSE_H

#define TLS_EFUSE_STATUS_OK      (0)
#define TLS_EFUSE_STATUS_EINVALID      (1)
#define TLS_EFUSE_STATUS_EIO      (2)

enum {
    CMD_WIFI_MAC = 0x01,
    CMD_BT_MAC,
    CMD_TX_DC,
    CMD_RX_DC,
    CMD_TX_IQ_GAIN,
    CMD_RX_IQ_GAIN,
    CMD_TX_IQ_PHASE,
    CMD_RX_IQ_PHASE,
    CMD_TX_GAIN,
    CMD_ALL,
};

#define FREQERR_ADDR  (FT_MAGICNUM_ADDR + sizeof(FT_PARAM_ST))
#define FREQERR_LEN  (4)
#define CAL_FLAG_ADDR  (FT_MAGICNUM_ADDR + sizeof(FT_PARAM_ST)+4)
#define CAL_FLAG_LEN    (4)

#define TX_GAIN_LEN   (28*3)

/**
 * @defgroup Driver_APIs Driver APIs
 * @brief Driver APIs
 */

/**
 * @addtogroup Driver_APIs
 * @{
 */

/**
 * @defgroup EFUSE_Driver_APIs EFUSE Driver APIs
 * @brief EFUSE driver APIs
 */

/**
 * @addtogroup EFUSE_Driver_APIs
 * @{
 */

/**
* @brief 	This function is used to init ft param.
*
* @param[in]	None
*
* @retval	 	TRUE			init success
* @retval		FALSE			init failed
*/
int tls_ft_param_init(void);

/**
* @brief 	This function is used to write ft_param.
*
* @param[in]	opnum  ft cmd
* @param[in]	data   data pointer
* @param[in]	len  len to write data
*
* @retval	 	TLS_EFUSE_STATUS_OK			set success
* @retval		TLS_EFUSE_STATUS_EIO			set failed
*/
int tls_ft_param_set(unsigned int opnum, void *data, unsigned int len);

/**
* @brief 	This function is used to read ft_param.
*
* @param[in]	opnum  ft cmd
* @param[in]	data   data pointer
* @param[in]	len  len to read data
*
* @retval	 	TLS_EFUSE_STATUS_OK			get success
* @retval		TLS_EFUSE_STATUS_EIO			get failed
*/
int tls_ft_param_get(unsigned int opnum, void *data, unsigned int rdlen);

/**
* @brief 	This function is used to get mac addr
*
* @param[in]	mac		mac addr,6 byte
*
* @retval	 	TLS_EFUSE_STATUS_OK			get success
* @retval		TLS_EFUSE_STATUS_EIO			get failed
*/
int tls_get_mac_addr(u8 *mac);

/**
* @brief 	This function is used to set mac addr
*
* @param[in]	mac		mac addr,6 byte
*
* @retval	 	TLS_EFUSE_STATUS_OK			set success
* @retval		TLS_EFUSE_STATUS_EIO			set failed
*/
int tls_set_mac_addr(u8 *mac);
/**
* @brief 	This function is used to get bluetooth mac addr
*
* @param[in]	mac		mac addr,6 byte
*
* @retval	 	TLS_EFUSE_STATUS_OK			get success
* @retval		TLS_EFUSE_STATUS_EIO			get failed
*/
int tls_get_bt_mac_addr(u8 *mac);

/**
* @brief 	This function is used to set bluetooth mac addr
*
* @param[in]	mac		mac addr,6 byte
*
* @retval	 	TLS_EFUSE_STATUS_OK			set success
* @retval		TLS_EFUSE_STATUS_EIO			set failed
*/
int tls_set_bt_mac_addr(u8 *mac);

/**
* @brief 	This function is used to get tx gain
*
* @param[in]	txgain		tx gain,12 byte
*
* @retval	 	TLS_EFUSE_STATUS_OK			get success
* @retval		TLS_EFUSE_STATUS_EIO		get failed
*/
int tls_get_tx_gain(u8 *txgain);

/**
* @brief 	This function is used to set tx gain
*
* @param[in]	txgain		tx gain,12 byte
*
* @retval	 	TLS_EFUSE_STATUS_OK			set success
* @retval		TLS_EFUSE_STATUS_EIO		set failed
*/
int tls_set_tx_gain(u8 *txgain);

/**
* @brief 	This function is used to get tx lod
*
* @param[in]	txlo		tx lod
*
* @retval	 	TLS_EFUSE_STATUS_OK			get success
* @retval		TLS_EFUSE_STATUS_EIO		get failed
*/
int tls_get_tx_lo(u8 *txlo);

/**
* @brief 	This function is used to set tx lod
*
* @param[in]	txlo		tx lod
*
* @retval	 	TLS_EFUSE_STATUS_OK			set success
* @retval		TLS_EFUSE_STATUS_EIO		set failed
*/

int tls_set_tx_lo(u8 *txlo);

/**
* @brief 	This function is used to get tx iq gain
*
* @param[in]	txGain
*
* @retval	 	TLS_EFUSE_STATUS_OK			get success
* @retval		TLS_EFUSE_STATUS_EIO		get failed
*/
int tls_get_tx_iq_gain(u8 *txGain);

/**
* @brief 	This function is used to set tx iq gain
*
* @param[in]	txGain
*
* @retval	 	TLS_EFUSE_STATUS_OK			set success
* @retval		TLS_EFUSE_STATUS_EIO		set failed
*/
int tls_set_tx_iq_gain(u8 *txGain);

/**
* @brief 	This function is used to get rx iq gain
*
* @param[in]	rxGain
*
* @retval	 	TLS_EFUSE_STATUS_OK			get success
* @retval		TLS_EFUSE_STATUS_EIO		get failed
*/
int tls_get_rx_iq_gain(u8 *rxGain);

/**
* @brief 	This function is used to get rx iq gain
*
* @param[in]	rxGain
*
* @retval	 	TLS_EFUSE_STATUS_OK			set success
* @retval		TLS_EFUSE_STATUS_EIO		set failed
*/
int tls_set_rx_iq_gain(u8 *rxGain);

/**
* @brief 	This function is used to get tx iq phase
*
* @param[in]	txPhase
*
* @retval	 	TLS_EFUSE_STATUS_OK			get success
* @retval		TLS_EFUSE_STATUS_EIO		get failed
*/
int tls_get_tx_iq_phase(u8 *txPhase);

/**
* @brief 	This function is used to set tx iq phase
*
* @param[in]	txPhase
*
* @retval	 	TLS_EFUSE_STATUS_OK			set success
* @retval		TLS_EFUSE_STATUS_EIO		set failed
*/
int tls_set_tx_iq_phase(u8 *txPhase);

/**
* @brief 	This function is used to get rx iq phase
*
* @param[in]	rxPhase
*
* @retval	 	TLS_EFUSE_STATUS_OK			get success
* @retval		TLS_EFUSE_STATUS_EIO		get failed
*/
int tls_get_rx_iq_phase(u8 *rxPhase);

/**
* @brief 	This function is used to set rx iq phase
*
* @param[in]	rxPhase
*
* @retval	 	TLS_EFUSE_STATUS_OK			set success
* @retval		TLS_EFUSE_STATUS_EIO		set failed
*/
int tls_set_rx_iq_phase(u8 *rxPhase);

/**
* @brief 	This function is used to set/get freq err
*
* @param[in]	freqerr	(Unit:Hz),relative to base frequency(chan 1,2,3,4,5......13,14)
* @param[in]    flag  1-set  0-get
* @retval	 	TLS_EFUSE_STATUS_OK			set/get success
* @retval		TLS_EFUSE_STATUS_EIO		set/get failed
*/
int tls_freq_err_op(u8 *freqerr, u8 flag);

/**
* @brief 	This function is used to set/get cal finish flag
*
* @param[in]	calflag 1- finish calibration, non-1-do not calibration
* @param[in]    flag  1-set  0-get
*
* @retval	 	TLS_EFUSE_STATUS_OK		set/get success
* @retval		TLS_EFUSE_STATUS_EIO		set/get failed
*/
int tls_rf_cal_finish_op(u8 *calflag, u8 flag);

/**
 * @}
 */

/**
 * @}
 */

#endif /* WM_EFUSE_H */

