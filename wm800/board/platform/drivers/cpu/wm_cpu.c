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
 * @file    wm_cpu.c
 *
 * @brief   cpu driver module
 *
 * @author  kevin
 *
 * Copyright (c) 2014 Winner Microelectronics Co., Ltd.
 */
#include "wm_debug.h"
#include "wm_regs.h"
#include "wm_irq.h"
#include "wm_cpu.h"
#include "wm_pwm.h"

/**
 * @brief          This function is used to set cpu clock
 *
 * @param[in]      	clk    select cpu clock
 *                        	clk == CPU_CLK_80M	80M
 *				clk == CPU_CLK_40M	40M
 *
 * @return         None
 *
 * @note           None
 */
void tls_sys_clk_set(u32 clk)
{
#ifndef TLS_CONFIG_FPGA
	u32 RegValue;
	u8 wlanDiv, cpuDiv = clk;
	u8 bus2Fac;

	if ((clk < 2) || (clk > 240))
	{
		return;
	}

	RegValue = tls_reg_read32(HR_CLK_DIV_CTL);
	wlanDiv = (RegValue>>8)&0xFF;
	RegValue &= 0xFF000000;
	RegValue |= 0x80000000;
	if(cpuDiv > 12)
	{
		bus2Fac = 1;
		wlanDiv = cpuDiv/4;
	}
	else  /*wlan can run*/
	{
		wlanDiv=3;
		bus2Fac = (wlanDiv*4/cpuDiv)&0xFF;
	}
	RegValue |= (bus2Fac<<16) | (wlanDiv<<8) | cpuDiv;
	tls_reg_write32(HR_CLK_DIV_CTL, RegValue);
	SysTick_Config(W800_PLL_CLK_MHZ*UNIT_MHZ/cpuDiv/HZ);
#endif
	return;
}

/**
 * @brief          	This function is used to get cpu clock
 *
 * @param[out]     *sysclk	point to the addr for system clk output
 *
 * @return         	None
 *
 * @note           	None
 */
void tls_sys_clk_get(tls_sys_clk *sysclk)
{
#ifndef TLS_CONFIG_FPGA
	clk_div_reg clk_div;

	clk_div.w = tls_reg_read32(HR_CLK_DIV_CTL);
	sysclk->cpuclk = W800_PLL_CLK_MHZ/(clk_div.b.CPU);
	sysclk->wlanclk = W800_PLL_CLK_MHZ/(clk_div.b.WLAN);
	sysclk->apbclk = sysclk->cpuclk / clk_div.b.BUS2;
#else
	sysclk->apbclk =
	sysclk->cpuclk =
	sysclk->wlanclk = 40;
#endif
}



