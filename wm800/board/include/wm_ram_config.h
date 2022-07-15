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
 * @file    wm_ram_config.h
 *
 * @brief   WM ram model configure
 *
 * @author  winnermicro
 *
 * Copyright (c) 2015 Winner Microelectronics Co., Ltd.
 */
#ifndef __WM_RAM_CONFIG_H__
#define __WM_RAM_CONFIG_H__
#include "wm_config.h"

/*see gcc_csky.ld in directory ld/w800,__heap_end must be bigger than 0x20028000
if __heap_end is lower than 0x20028000,then SLAVE_HSPI_SDIO_ADDR must be changed to 0x20028000 or bigger.
*/
extern unsigned int __heap_end;
extern unsigned int __heap_start;

/*High speed SPI or SDIO buffer to exchange data*/
#define SLAVE_HSPI_SDIO_ADDR        ((unsigned int)(&__heap_end))

#if TLS_CONFIG_HS_SPI
#define SLAVE_HSPI_MAX_SIZE         (0x2000)
#else
#define SLAVE_HSPI_MAX_SIZE         (0x0)
#endif

/*Wi-Fi use buffer to exchange data*/
#define WIFI_MEM_START_ADDR        (SLAVE_HSPI_SDIO_ADDR + SLAVE_HSPI_MAX_SIZE)

#endif /*__WM_RAM_CONFIG_H__*/

