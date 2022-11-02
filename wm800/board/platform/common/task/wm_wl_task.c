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
 
#include <string.h>
#include "wm_mem.h"
#include "wm_wl_timers.h"
#include "wm_wl_task.h"

static tls_mbox_t task_mbox[TLS_MBOX_ALL_COUNT];
struct task_msg wl_msg[TLS_MSG_ALL_COUONT];

static void task_thread(void *arg)
{
    struct task_msg *msg;
    start_routine fun;
    void *argu;
    struct task_parameter *task_param = (struct task_parameter *)arg;

  /* MAIN Loop */
    while (1) {
        /* wait for a message, timeouts are processed while waiting */
        tls_timeouts_mbox_fetch_p(task_param->timeo_id, task_mbox[task_param->mbox_id], (void **)&msg);
        switch (msg->type) {
            case TASK_MSG_CALLBACK:
                msg->msg.cb.function(msg->msg.cb.ctx);
                tls_mem_free(msg);
                break;
            case TASK_MSG_CALLBACK_STATIC:
                fun = msg->msg.cbs.function;
                argu = msg->msg.cbs.ctx;
                msg->msg.cbs.cnt--;
                fun(argu);
                break;
            case TASK_MSG_TIMEOUT:
                tls_timeout_p(task_param->timeo_id, msg->msg.tmo.msecs, msg->msg.tmo.h, msg->msg.tmo.arg);
                tls_mem_free(msg);
                break;
            case TASK_MSG_UNTIMEOUT:
                tls_untimeout_p(task_param->timeo_id, msg->msg.tmo.h, msg->msg.tmo.arg);
                tls_mem_free(msg);
                break;
            default:
                break;
        }
    }
}

s8 tls_wl_task_run(struct task_parameter *task_param)
{
    if (tls_mbox_new(&task_mbox[task_param->mbox_id], task_param->mbox_size) != TLS_OS_SUCCESS) {
        return -1;
    }

    tls_os_task_create(NULL,
                       task_param->name,
                       task_thread,
                       (void *)task_param,
                       (void *)(task_param->stk_start),
                       task_param->stk_size * sizeof(u32),
                       TLS_TASK_START_PRIO+task_param->task_id,
                       0);
    return 0;
}

s8 tls_wl_task_callback_static(struct task_parameter *task_param,
                               start_routine function, void *ctx, u8 block, u8 msg_id)
{
    struct task_msg *msg = &wl_msg[msg_id];

    if (msg->msg.cbs.cnt > 0) {
        return TLS_OS_ERROR;
    }

    if (tls_mbox_valid(task_mbox[task_param->mbox_id])) {
        msg->type = TASK_MSG_CALLBACK_STATIC;
        msg->msg.cbs.function = function;
        msg->msg.cbs.ctx = ctx;
        if (block) {
            tls_mbox_post(task_mbox[task_param->mbox_id], (void *)msg);
        } else {
            if (tls_mbox_trypost(task_mbox[task_param->mbox_id], (void *)msg) != TLS_OS_SUCCESS)
                return TLS_OS_ERROR;
        }
        msg->msg.cbs.cnt++;
        return TLS_OS_SUCCESS;
    }
    return TLS_OS_ERROR;
}

s8 tls_wl_task_callback(struct task_parameter *task_param, start_routine function, void *ctx, u8 block)
{
    struct task_msg *msg;

    if (tls_mbox_valid(task_mbox[task_param->mbox_id])) {
        msg = (struct task_msg *)tls_mem_alloc(sizeof(struct task_msg));
        if (msg == NULL) {
        return TLS_OS_ERROR;
    }

    msg->type = TASK_MSG_CALLBACK;
    msg->msg.cb.function = function;
    msg->msg.cb.ctx = ctx;
    if (block) {
        tls_mbox_post(task_mbox[task_param->mbox_id], msg);
    } else {
        if (tls_mbox_trypost(task_mbox[task_param->mbox_id], msg) != TLS_OS_SUCCESS) {
            tls_mem_free(msg);
            return TLS_OS_ERROR;
        }
    }
    return TLS_OS_SUCCESS;
    }
    return TLS_OS_ERROR;
}

s8 tls_wl_task_add_timeout(struct task_parameter *task_param, u32 msecs, tls_timeout_handler h, void *arg)
{
    struct task_msg *msg;

    if (tls_mbox_valid(task_mbox[task_param->mbox_id])) {
        msg = (struct task_msg *)tls_mem_alloc(sizeof(struct task_msg));
        if (msg == NULL) {
        return TLS_OS_ERROR;
    }

    msg->type = TASK_MSG_TIMEOUT;
    msg->msg.tmo.msecs = msecs;
    msg->msg.tmo.h = h;
    msg->msg.tmo.arg = arg;
    tls_mbox_post(task_mbox[task_param->mbox_id], msg);
    return TLS_OS_SUCCESS;
    }
    return TLS_OS_ERROR;
}

s8 tls_wl_task_untimeout(struct task_parameter *task_param, tls_timeout_handler h, void *arg)
{
    struct task_msg *msg;

    if (tls_mbox_valid(task_mbox[task_param->mbox_id])) {
        msg = (struct task_msg *)tls_mem_alloc(sizeof(struct task_msg));
        if (msg == NULL) {
          return TLS_OS_ERROR;
        }

        msg->type = TASK_MSG_UNTIMEOUT;
        msg->msg.tmo.h = h;
        msg->msg.tmo.arg = arg;
        tls_mbox_post(task_mbox[task_param->mbox_id], msg);
        return TLS_OS_SUCCESS;
    }
  return TLS_OS_ERROR;
}

s8 tls_wl_task_init(void)
{
    memset(wl_msg, 0, sizeof(struct task_msg));
    return 0;
}

