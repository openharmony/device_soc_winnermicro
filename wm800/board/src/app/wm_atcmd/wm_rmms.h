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

#ifndef __RMMS_H__
#define __RMMS_H__

#if TLS_CONFIG_RMMS
#if (GCC_COMPILE==1)
#include "wm_cmdp_hostif_gcc.h"
#else
#include "wm_cmdp_hostif.h"
#endif
#define RMMS_LISTERN_PORT   988

#define RMMS_ERR_SUCCESS         0
#define RMMS_ERR_LINKDOWN       -1
#define RMMS_ERR_PARAM          -2
#define RMMS_ERR_MEM            -3
#define RMMS_ERR_NOT_BIND       -4
#define RMMS_ERR_NOT_FOUND      -5
#define RMMS_ERR_INACTIVE       -6


s8 RMMS_Init(const struct netif *Netif);
void RMMS_Fini(void);
void RMMS_SendHedAtRsp(struct rmms_msg *Msg);
#endif

#endif

