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

#ifndef WM_AT_RI_H
#define WM_AT_RI_H

/**
 * @defgroup APP_APIs APP APIs
 * @brief APP APIs
 */

/**
 * @addtogroup APP_APIs
 * @{
 */

/**
 * @defgroup AT_RI_APIs AT_RI APIs
 * @brief AT_RI command APIs
 */

/**
 * @addtogroup AT_RI_APIs
 * @{
 */

/**
 * @brief          This function is used to initialize hostif task
 				   used by AT&RI Command
 *
 * @param          None
 *
 * @retval         0     success
 * @retval         other failed
 *
 * @note           Usually the system will call this api at power on.
 */
int tls_hostif_init(void);

/**
 * @}
 */

/**
 * @}
 */

/**
 * @brief          This function is used to initialize high speed SPI
 *
 * @param          None
 *
 * @retval         0     success
 * @retval         other failed
 *
 * @note           Users can decide to call this api or not according to his application.
 */
int tls_hspi_init(void);

/**
 * @brief          This function is used to initialize UART
 *
 * @param          None
 *
 * @return         None
 *
 * @note           Usually the system will call this api at power on.
 */
void tls_uart_init(void);

#endif /* WM_AT_RI_H */

