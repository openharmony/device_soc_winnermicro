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
 * @file    wm_timer.h
 *
 * @brief   Timer Driver Module
 *
 * @author  dave
 *
 * Copyright (c) 2014 Winner Microelectronics Co., Ltd.
 */
#ifndef WM_TIMER_H
#define WM_TIMER_H

#include "wm_type_def.h"
/** invalid timer id */
#define WM_TIMER_ID_INVALID              0xFF

/** timer interrupt callback */
typedef void (*tls_timer_irq_callback)(void *arg);

/** timer unit */
enum tls_timer_unit {
    TLS_TIMER_UNIT_US = 0,    /**< microsecond level(us) */
    TLS_TIMER_UNIT_MS         /**< millisecond level(ms) */
};

/** timer configuration */
struct tls_timer_cfg {
    enum tls_timer_unit unit;           /**< timer accuracy */
    u32  timeout;                       /**< timeout period */
    bool is_repeat;                     /**< cycle timer */
    tls_timer_irq_callback callback;    /**< timeout callback function */
    void *arg;                          /**< parameter fot the timeout callback function */
};

/**
 * @defgroup Driver_APIs Driver APIs
 * @brief Driver APIs
 */

/**
 * @addtogroup Driver_APIs
 * @{
 */

/**
 * @defgroup TIMER_Driver_APIs TIMER Driver APIs
 * @brief TIMER driver APIs
 */

/**
 * @addtogroup TIMER_Driver_APIs
 * @{
 */

/**
 * @brief          This function is used to create a timer
 *
 * @param[in]      cfg     timer configuration
 *
 * @retval         WM_TIMER_ID_INVALID     failed
 * @retval         other                   timer id
 *
 * @note
 * User does not need to clear the interrupt flag.
 * Rtc callback function is called in interrupt,
 * so do not operate the critical data in the callback fuuction.
 * Sending messages to other tasks to handle is recommended.
 */
u8 tls_timer_create(struct tls_timer_cfg *cfg);

/**
 * @brief          This function is used to start a timer
 *
 * @param[in]      timer_id    timer id
 *
 * @return         None
 *
 * @note           None
 */
void tls_timer_start(u8 timer_id);

/**
 * @brief          This function is used to stop a timer
 *
 * @param[in]      timer_id    timer id
 *
 * @return         None
 *
 * @note           None
 */
void tls_timer_stop(u8 timer_id);

/**
 * @brief           This function is used to change a timer wait time
 *
 * @param[in]      	timer_id    timer id[0~5]
 *
 * @param[in]      	newtime     new wait time
 *
 * @retval         	None
 *
 * @note            If the timer does not start, this function will start the timer
 */
void tls_timer_change(u8 timer_id, u32 newtime);

/**
 * @brief           This function is used to read a timer's current value
 *
 * @param[in]      	timer_id    timer id[0~5]
 *
 * @retval          timer's	current  value
 *
 * @note            none
 */
u32 tls_timer_read(u8 timer_id);

/**
 * @brief          This function is used to delete a timer
 *
 * @param[in]      timer_id    timer id
 *
 * @return         None
 *
 * @note           None
 */
void tls_timer_destroy(u8 timer_id);

/**
 * @}
 */

/**
 * @}
 */

#endif /* WM_TIMER_H */

