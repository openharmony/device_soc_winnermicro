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

#ifndef __PING_H__
#define __PING_H__

#define TLS_CONFIG_WIFI_PING_TEST   (CFG_ON && TLS_CONFIG_HOSTIF)

#if TLS_CONFIG_WIFI_PING_TEST
struct ping_param{
    char host[64];
    u32 interval;/* ms */
    u32 cnt;/* -t */
    u32 src;
};

void ping_test_create_task(void);
void ping_test_start(struct ping_param *para);
void ping_test_stop(void);

int ping_test_sync(struct ping_param *para);
#endif

#endif /* __PING_H__ */

