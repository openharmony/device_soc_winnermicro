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
 * @file    wm_os_config.h
 *
 * @brief   WM OS select freertos or ucos
 *
 * @author  winnermicro
 *
 * Copyright (c) 2015 Winner Microelectronics Co., Ltd.
 */
 
#ifndef __WM_OS_CONFIG_H__
#define __WM_OS_CONFIG_H__
#define OS_CFG_ON  1
#define OS_CFG_OFF 0

#undef TLS_OS_FREERTOS
#define TLS_OS_FREERTOS                     OS_CFG_OFF   /*FreeRTOS need to modify wm_config.inc*/
#define TLS_OS_LITEOS                       OS_CFG_ON
#endif
