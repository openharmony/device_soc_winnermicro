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
 * @file    wm_watchdog.h
 *
 * @brief   watchdog Driver Module
 *
 * @author  dave
 *
 * Copyright (c) 2014 Winner Microelectronics Co., Ltd.
 */
#ifndef WM_WATCHDOG_H
#define WM_WATCHDOG_H

/**
 * @defgroup Driver_APIs Driver APIs
 * @brief Driver APIs
 */

/**
 * @addtogroup Driver_APIs
 * @{
 */

/**
 * @defgroup WDG_Driver_APIs WDG Driver APIs
 * @brief WDG driver APIs
 */

/**
 * @addtogroup WDG_Driver_APIs
 * @{
 */

/**
 * @brief          This function is used to feed the dog.
 *
 * @param          None
 *
 * @return         None
 *
 * @note           None
 */
void tls_watchdog_clr(void);

/**
 * @brief          This function is used to init and start the watchdog.
 *
 * @param[in]      usec    microseconds
 *
 * @return         None
 *
 * @note           None
 */
void tls_watchdog_init(u32 usec);

/**
 * @brief          This function is used to deinit watchdog
 *
 * @param[in]     None
 *
 * @return         None
 *
 * @note           None
 */
void tls_watchdog_deinit(void);

/**
 * @brief          This function is used to reset the system.
 *
 * @param          None
 *
 * @return         None
 *
 * @note           None
 */
void tls_sys_reset(void);

/**
 * @}
 */

/**
 * @}
 */

#endif /* WM_WATCHDOG_H */

