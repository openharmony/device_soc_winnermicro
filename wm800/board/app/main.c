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

/***************************************************************************** 
* 
* File Name : main.c
* 
* Description: main 
* 
* Copyright (c) 2014 Winner Micro Electronic Design Co., Ltd. 
* All rights reserved. 
* 
* Author : dave
* 
* Date : 2014-6-14
*****************************************************************************/ 

#include "devmgr_service_start.h"

void UserMain(void)
{
    printf("\n user task \n");

#if DEMO_CONSOLE
    CreateDemoTask();
#endif

#if defined(LOSCFG_KERNEL_TEST_FULL) || defined(LOSCFG_KERNEL_TEST)
	LosAppInit(); 
#else
    if (DeviceManagerStart()) {
        printf("[%s] No drivers need load by hdf manager!",__func__);
    }
#endif	
	
}

