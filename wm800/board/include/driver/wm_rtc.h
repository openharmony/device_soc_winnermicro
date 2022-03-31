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
 * @file    wm_rtc.h
 *
 * @brief   rtc Driver Module
 *
 * @author  dave
 *
 * Copyright (c) 2014 Winner Microelectronics Co., Ltd.
 */
#ifndef WM_RTC_H
#define WM_RTC_H

#include <time.h>
#include "wm_type_def.h"

/** rtc interrupt callback */
typedef void (*tls_rtc_irq_callback)(void *arg);

/**
 * @defgroup Driver_APIs Driver APIs
 * @brief Driver APIs
 */

/**
 * @addtogroup Driver_APIs
 * @{
 */

/**
 * @defgroup RTC_Driver_APIs RTC Driver APIs
 * @brief RTC driver APIs
 */

/**
 * @addtogroup RTC_Driver_APIs
 * @{
 */

/**
 * @brief          This function is used to set pmu rtc time
 *
 * @param[in]      tblock    time value
 *
 * @return         None
 *
 * @note           None
 */
void tls_set_rtc(struct tm *tblock);

/**
 * @brief          This function is used to get pmu rtc time
 *
 * @param[out]     tblock    time value
 *
 * @return         None
 *
 * @note           None
 */
void tls_get_rtc(struct tm *tblock);

/**
 * @brief          This function is used to register pmu rtc interrupt
 *
 * @param[in]      callback    the rtc interrupt call back function
 * @param[in]      arg         parameter of call back function
 *
 * @return         None
 *
 * @note
 * User does not need to clear the interrupt flag.
 * Rtc callback function is called in interrupt,
 * so do not operate the critical data in the callback fuuction.
 * Sending messages to other tasks to handle is recommended.
 */
void tls_rtc_isr_register(tls_rtc_irq_callback callback, void *arg);

/**
 * @brief          This function is used to start pmu rtc timer
 *
 * @param[in]      tblock    timer value
 *
 * @return         None
 *
 * @note           None
 */
void tls_rtc_timer_start(struct tm *tblock);

/**
 * @brief          This function is used to stop pmu rtc timer
 *
 * @param          None
 *
 * @return         None
 *
 * @note           This function also is used to clear rtc timer interrupt
 */
void tls_rtc_timer_stop(void);


/**
 * @}
 */

/**
 * @}
 */

#endif

