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
	//用户自己的task
	if (DeviceManagerStart()) {
        printf("[%s] No drivers need load by hdf manager!",__func__);
    }
}

