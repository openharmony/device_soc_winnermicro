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
 * @file    wm_watchdog.c
 *
 * @brief   watchdog Driver Module
 *
 * @author  kevin
 *
 * Copyright (c) 2014 Winner Microelectronics Co., Ltd.
 */
#include "wm_debug.h"
#include "wm_regs.h"
#include "wm_irq.h"
#include "wm_cpu.h"
#include "wm_watchdog.h"

#define WDG_LOAD_VALUE_MAX  (0xFFFFFFFF / 40)
#define WDG_LOAD_VALUE_DEF  (20 * 1000 * 1000)

static volatile u8 wdg_reset = 0;
static volatile u8 wdg_enable = 0;
static volatile u32 wdg_value_us = WDG_LOAD_VALUE_DEF;
static volatile u32 wdg_jumpclear_flag = 0; /* 0:donot jump clear, 1: jump clear, 2:close wdg */
ATTRIBUTE_ISR void WDG_IRQHandler(void)
{
    csi_kernel_intrpt_enter();
    if (wdg_reset) {
        csi_kernel_intrpt_exit();
        return;
    }
    csi_kernel_intrpt_exit();
}

/**
 * @brief          This function is used to clear watchdog irq in case watchdog reset
 *
 * @param          None
 *
 * @return         None
 *
 * @note           None
 */
void tls_watchdog_clr(void)
{
    if (wdg_jumpclear_flag == 0) {
        tls_reg_write32(HR_WDG_INT_CLR, 0x01);
    }
}

static void __tls_watchdog_init(u32 usec)
{
    tls_sys_clk sysclk;

    tls_sys_clk_get(&sysclk);
    tls_irq_enable(WDG_IRQn);

    tls_reg_write32(HR_WDG_LOAD_VALUE, sysclk.apbclk * usec);  /* 40M dominant frequency: 40 * 10^6 * (usec / 10^6) */
    tls_reg_write32(HR_WDG_CTRL, 0x3);             /* enable irq & reset */
}

static void __tls_watchdog_deinit(void)
{
    tls_irq_disable(WDG_IRQn);
    tls_reg_write32(HR_WDG_CTRL, 0);
    tls_reg_write32(HR_WDG_INT_CLR, 0x01);
}

/**
 * @brief          This function is used to init watchdog
 *
 * @param[in]      usec    microseconds
 *
 * @return         None
 *
 * @note           None
 */
void tls_watchdog_init(u32 usec)
{
    __tls_watchdog_init(usec);

    wdg_value_us = usec;
    wdg_enable = 1;
}

/**
 * @brief          This function is used to deinit watchdog
 *
 * @param[in]     None
 *
 * @return         None
 *
 * @note           None
 */
void tls_watchdog_deinit(void)
{
    __tls_watchdog_deinit();

    wdg_value_us = WDG_LOAD_VALUE_DEF;
    wdg_enable = 0;
}

/**
 * @brief          This function is used to start calculating elapsed time.
 *
 * @param[in]      None
 *
 * @return         elapsed time, unit:millisecond
 *
 * @note           None
 */
void tls_watchdog_start_cal_elapsed_time(void)
{
    if (wdg_enable) {
        wdg_jumpclear_flag = 1;

        __tls_watchdog_deinit();

        __tls_watchdog_init(WDG_LOAD_VALUE_MAX);
    } else {
        wdg_jumpclear_flag = 2;
        __tls_watchdog_init(WDG_LOAD_VALUE_MAX);
    }
}

/**
 * @brief          This function is used to stop calculating & return elapsed time.
 *
 * @param[in]     none
 *
 * @return         elapsed time, unit:millisecond
 *
 * @note           None
 */
u32 tls_watchdog_stop_cal_elapsed_time(void)
{
#define RT_TIME_BASE (40)
    u32 val = 0;

    switch (wdg_jumpclear_flag) {
        case 1:
            {
                val = (tls_reg_read32(HR_WDG_LOAD_VALUE) - tls_reg_read32(HR_WDG_CUR_VALUE))/RT_TIME_BASE;
                __tls_watchdog_deinit();
                __tls_watchdog_init(wdg_value_us);
                wdg_jumpclear_flag = 0;
            }
            break;

        case 2:
            {
                val = (tls_reg_read32(HR_WDG_LOAD_VALUE) - tls_reg_read32(HR_WDG_CUR_VALUE))/RT_TIME_BASE;
                __tls_watchdog_deinit();
                wdg_jumpclear_flag = 0;
            }
            break;

        default:
            wdg_jumpclear_flag = 0;
            break;
    }

    return val;
}
/**
 * @brief          This function is used to reset system
 *
 * @param          None
 *
 * @return         None
 *
 * @note           None
 */
void tls_sys_reset(void)
{
    tls_os_set_critical();
    wdg_reset = 1;
    __tls_watchdog_deinit();
    tls_reg_write32(HR_WDG_LOCK, 0x1ACCE551);
    tls_reg_write32(HR_WDG_LOAD_VALUE, 0x100);
    tls_reg_write32(HR_WDG_CTRL, 0x3);
    tls_reg_write32(HR_WDG_LOCK, 1);
    while (1) {
    }
}

