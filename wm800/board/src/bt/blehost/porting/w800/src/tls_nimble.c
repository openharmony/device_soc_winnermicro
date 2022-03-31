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


#include <assert.h>
#include "syscfg/syscfg.h"
#include "nimble/nimble_port.h"
#include "wm_mem.h"
#include "wm_osal.h"
#if TLS_OS_FREERTOS
static void *tls_host_task_stack_ptr = NULL;
#endif
static tls_os_task_t host_task_ptr = NULL;
static void nimble_host_task(void *arg)
{
    nimble_port_run();
}

void tls_nimble_start(void)
{
#if TLS_OS_LITEOS
    tls_os_task_create(&host_task_ptr, "bth",
                       nimble_host_task,
                       (void *)0,
                       (void *)NULL,
                       MYNEWT_VAL(OS_HS_STACK_SIZE)*sizeof(uint32_t),
                       MYNEWT_VAL(OS_HS_TASK_PRIO),
                       0);
#else
    tls_host_task_stack_ptr = (void *)tls_mem_alloc(MYNEWT_VAL(OS_HS_STACK_SIZE) * sizeof(uint32_t));
    assert(tls_host_task_stack_ptr != NULL);
    tls_os_task_create(&host_task_ptr, "bth",
                       nimble_host_task,
                       (void *)0,
                       (void *)tls_host_task_stack_ptr,
                       MYNEWT_VAL(OS_HS_STACK_SIZE)*sizeof(uint32_t),
                       MYNEWT_VAL(OS_HS_TASK_PRIO),
                       0);
#endif
}

static void free_host_task_stack()
{
#if TLS_OS_LITEOS
#else

    if(tls_host_task_stack_ptr) {
        tls_mem_free(tls_host_task_stack_ptr);
        tls_host_task_stack_ptr = NULL;
    }

#endif
}
void tls_nimble_stop(void)
{
    if(host_task_ptr) {
        tls_os_task_del_by_task_handle(host_task_ptr, free_host_task_stack);
    }
}