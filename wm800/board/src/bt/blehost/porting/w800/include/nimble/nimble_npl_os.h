/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#ifndef _NIMBLE_NPL_OS_H_
#define _NIMBLE_NPL_OS_H_

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "wm_osal.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BLE_NPL_OS_ALIGNMENT    4

#define BLE_NPL_TIME_FOREVER    0xffffffffUL

/* This should be compatible with TickType_t */
typedef uint32_t ble_npl_time_t;
typedef int32_t ble_npl_stime_t;

struct ble_npl_event {
    bool queued;
    ble_npl_event_fn *fn;
    void *arg;
};

struct ble_npl_eventq {
    tls_os_queue_t *q;
};

struct ble_npl_callout {
    tls_os_timer_t *handle;
    struct ble_npl_eventq *evq;
    struct ble_npl_event ev;
};

struct ble_npl_mutex {
    tls_os_mutex_t *handle;
};

struct ble_npl_sem {
    tls_os_sem_t *handle;
};

/*
 * Simple APIs are just defined as static inline below, but some are a bit more
 * complex or require some global state variables and thus are defined in .c
 * file instead and static inline wrapper just calls proper implementation.
 * We need declarations of these functions and they are defined in header below.
 */
#include "os/npl_freertos.h"

static inline bool ble_npl_os_started(void)
{
    return tls_os_task_schedule_state() != 0;
}

static inline void *ble_npl_get_current_task_id(void)
{
    return (void *)tls_os_task_id();
}

static inline void ble_npl_eventq_init(struct ble_npl_eventq *evq)
{
    tls_os_queue_create(&evq->q, 32); // 32:queue size

    if (evq->q == NULL) {
        assert(0);
    }
}

static inline void ble_npl_eventq_deinit(struct ble_npl_eventq *evq)
{
    if (evq && evq->q) {
        tls_os_queue_delete(evq->q);
    }
}

static inline struct ble_npl_event *ble_npl_eventq_get(struct ble_npl_eventq *evq, ble_npl_time_t tmo)
{
    return npl_freertos_eventq_get(evq, tmo);
}

static inline void ble_npl_eventq_put(struct ble_npl_eventq *evq, struct ble_npl_event *ev)
{
    npl_freertos_eventq_put(evq, ev);
}

static inline void ble_npl_eventq_remove(struct ble_npl_eventq *evq, struct ble_npl_event *ev)
{
    npl_freertos_eventq_remove(evq, ev);
}

static inline void ble_npl_event_run(struct ble_npl_event *ev)
{
    ev->fn(ev);
}

static inline bool ble_npl_eventq_is_empty(struct ble_npl_eventq *evq)
{
    return tls_os_queue_is_empty(evq->q);
}

static inline void ble_npl_event_init(struct ble_npl_event *ev, ble_npl_event_fn *fn, void *arg)
{
    memset_s(ev, sizeof(*ev), 0, sizeof(*ev));
    ev->fn = fn;
    ev->arg = arg;
}

static inline bool ble_npl_event_is_queued(struct ble_npl_event *ev)
{
    return ev->queued;
}

static inline void *ble_npl_event_get_arg(struct ble_npl_event *ev)
{
    return ev->arg;
}

static inline void ble_npl_event_set_arg(struct ble_npl_event *ev, void *arg)
{
    ev->arg = arg;
}

static inline ble_npl_error_t ble_npl_mutex_init(struct ble_npl_mutex *mu)
{
    return npl_freertos_mutex_init(mu);
}

static inline ble_npl_error_t ble_npl_mutex_deinit(struct ble_npl_mutex *mu)
{
    return npl_freertos_mutex_deinit(mu);
}

static inline ble_npl_error_t ble_npl_mutex_pend(struct ble_npl_mutex *mu, ble_npl_time_t timeout)
{
    return npl_freertos_mutex_pend(mu, timeout);
}

static inline ble_npl_error_t ble_npl_mutex_release(struct ble_npl_mutex *mu)
{
    return npl_freertos_mutex_release(mu);
}

static inline ble_npl_error_t ble_npl_sem_init(struct ble_npl_sem *sem, uint16_t tokens)
{
    return npl_freertos_sem_init(sem, tokens);
}
static inline ble_npl_error_t ble_npl_sem_deinit(struct ble_npl_sem *sem)
{
    return npl_freertos_sem_deinit(sem);
}

static inline ble_npl_error_t ble_npl_sem_pend(struct ble_npl_sem *sem, ble_npl_time_t timeout)
{
    return npl_freertos_sem_pend(sem, timeout);
}

static inline ble_npl_error_t ble_npl_sem_release(struct ble_npl_sem *sem)
{
    return npl_freertos_sem_release(sem);
}

static inline uint16_t ble_npl_sem_get_count(struct ble_npl_sem *sem)
{
    return npl_freertos_get_sem_count(sem);
}

static inline void ble_npl_callout_init(struct ble_npl_callout *co, struct ble_npl_eventq *evq,
                                        ble_npl_event_fn *ev_cb, void *ev_arg)
{
    npl_freertos_callout_init(co, evq, ev_cb, ev_arg);
}

static inline void ble_npl_callout_deinit(struct ble_npl_callout *co)
{
    if (co && co->handle) {
        tls_os_timer_delete(co->handle);
    }
}

static inline ble_npl_error_t ble_npl_callout_reset(struct ble_npl_callout *co, ble_npl_time_t ticks)
{
    return npl_freertos_callout_reset(co, ticks);
}

static inline void ble_npl_callout_stop(struct ble_npl_callout *co)
{
    tls_os_timer_stop(co->handle);
}

static inline bool ble_npl_callout_is_active(struct ble_npl_callout *co)
{
    return tls_os_timer_active(co->handle) == 1;
}

static inline ble_npl_time_t ble_npl_callout_get_ticks(struct ble_npl_callout *co)
{
    return tls_os_timer_expirytime(co->handle);
}

static inline uint32_t ble_npl_callout_remaining_ticks(struct ble_npl_callout *co, ble_npl_time_t time)
{
    return npl_freertos_callout_remaining_ticks(co, time);
}

static inline void ble_npl_callout_set_arg(struct ble_npl_callout *co, void *arg)
{
    co->ev.arg = arg;
}

static inline uint32_t ble_npl_time_get(void)
{
    return tls_os_get_time();
}

static inline ble_npl_error_t ble_npl_time_ms_to_ticks(uint32_t ms, ble_npl_time_t *out_ticks)
{
    return npl_freertos_time_ms_to_ticks(ms, out_ticks);
}

static inline ble_npl_error_t ble_npl_time_ticks_to_ms(ble_npl_time_t ticks, uint32_t *out_ms)
{
    return ble_npl_time_ticks_to_ms(ticks, out_ms);
}

static inline ble_npl_time_t ble_npl_time_ms_to_ticks32(uint32_t ms)
{
    return ms * HZ / 1000; // 1000; BYTE ALIGNMENT
}

static inline uint32_t ble_npl_time_ticks_to_ms32(ble_npl_time_t ticks)
{
    return ticks * 1000 / HZ; // 1000; BYTE ALIGNMENT
}

static inline void ble_npl_time_delay(ble_npl_time_t ticks)
{
    tls_os_time_delay(ticks);
}

#if NIMBLE_CFG_CONTROLLER
static inline void ble_npl_hw_set_isr(int irqn, void (*addr)(void))
{
    npl_freertos_hw_set_isr(irqn, addr);
}
#endif

static inline uint32_t ble_npl_hw_enter_critical(void)
{
    vPortEnterCritical();
    return 0;
}

static inline void ble_npl_hw_exit_critical(uint32_t ctx)
{
    vPortExitCritical();
}

#ifdef __cplusplus
}
#endif

#endif  /* _NPL_H_ */