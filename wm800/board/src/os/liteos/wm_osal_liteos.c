/*
 * Copyright (c) 2020, HiHope Community.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef WM_OS_LITEOS_H
#define WM_OS_LITEOS_H

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "securec.h"
#include "wm_config.h"
#include "los_config.h"
#include "los_task.h"
#include "los_mux.h"
#include "los_queue.h"
#include "los_swtmr.h"
#include "los_sem.h"
#include "los_swtmr.h"
#include "wm_type_def.h"
#include "wm_osal.h"
#include "wm_mem.h"
#include "portliteos.h"

#define TLS_USER_PRORITY_MIN    25
const unsigned int HZ = LOSCFG_BASE_CORE_TICK_PER_SECOND;

#include "securec.h"

typedef struct {
    u32 handle;
} tls_os_handle_t;

u16 tls_os_priority_translate(u16 nPriority)
{
    u16 priority;
    if (nPriority < OS_TASK_PRIORITY_LOWEST) {
        return nPriority;
    } else {
        priority = TLS_USER_PRORITY_MIN +
                           (nPriority - OS_TASK_PRIORITY_LOWEST)
                           / (OS_TASK_PRIORITY_LOWEST - TLS_USER_PRORITY_MIN);
        if (priority >= OS_TASK_PRIORITY_LOWEST) {
            priority = OS_TASK_PRIORITY_LOWEST - 1;
        }
    }

    return priority;
}
/*
*********************************************************************************************************
*                                     CREATE A TASK (Extended Version)
*
* Description: This function is used to have uC/OS-II manage the execution of a task.  Tasks can either
*              be created prior to the start of multitasking or by a running task.  A task cannot be
*              created by an ISR.
*
* Arguments  : task      is a pointer to the task'
*
*            name     is the task's name
*
*            entry    is the task's entry function
*
*              param     is a pointer to an optional data area which can be used to pass parameters to
*                        the task when the task first executes.  Where the task is concerned it thinks
*                        it was invoked and passed the argument 'param' as follows:
*
*                            void Task (void *param)
*                            {
*                                for (;;) {
*                                    Task code;
*                                }
*                            }
*
*              stk_start      is a pointer to the task's bottom of stack.
*
*              stk_size  is the size of the stack in number of elements.  If OS_STK is set to u8,
*                        'stk_size' corresponds to the number of bytes available.  If OS_STK is set to
*                        INT16U, 'stk_size' contains the number of 16-bit entries available.  Finally, if
*                        OS_STK is set to INT32U, 'stk_size' contains the number of 32-bit entries
*                        available on the stack.
*
*              prio      is the task's priority.  A unique priority MUST be assigned to each task and the
*                        lower the number, the higher the priority.
*
*              flag       contains additional information about the behavior of the task.
*
* Returns    : TLS_OS_SUCCESS             if the function was successful.
*              TLS_OS_ERROR
*********************************************************************************************************
*/
tls_os_status_t tls_os_task_create(tls_os_task_t *task,
    const char* name,
    void (*entry)(void* param),
    void* param,
    u8 *stk_start,
    u32 stk_size,
    u32 prio,
    u32 flag)
{
    u32 error;
    char *tmp_name;
    tls_os_status_t os_status;
    TSK_INIT_PARAM_S stInitParam = {0};
    u32 TskID;
    tls_os_handle_t *pHandle = NULL;

    if (stk_start != NULL) {
        printf(" --- task name %s\n", name);
        assert(stk_start == NULL);
    }
    pHandle = tls_mem_alloc(sizeof(tls_os_handle_t));
    if (!pHandle) {
        if (task) {
            *task = NULL;
        }
        printf("%s: malloc error\n", __FUNCTION__);
        return TLS_OS_ERROR;
    }
    stInitParam.pfnTaskEntry = entry;
    stInitParam.usTaskPrio = tls_os_priority_translate(prio);
    stInitParam.uwArg = param;
    stInitParam.uwStackSize = stk_size;

    if (name == NULL) {
        tmp_name = tls_mem_alloc(20); // 20:alloc size
        if (tmp_name == NULL) {
            printf("mallo c error\n");
        }
        sprintf_s(tmp_name, sizeof(*tmp_name), "task%d", prio);
        stInitParam.pcName = tmp_name;
    } else {
        stInitParam.pcName = name;
    }
    error = LOS_TaskCreate(&TskID, &stInitParam);
    if (error == LOS_OK) {
        if (task) {
            pHandle->handle = TskID;
            *task = (tls_os_task_t)pHandle;
        }
        os_status = TLS_OS_SUCCESS;
        printf("%s: TskID %d, task name %s\n", __FUNCTION__, TskID, stInitParam.pcName);
    } else {
        printf("configMAX_PRIORITIES - prio:%d name:%s size:0x%x entry:0x%x error:%d\n",
            prio, stInitParam.pcName, stk_size, (u32)entry, error);
        if (task) {
            *task = NULL;
        }
        tls_mem_free(pHandle);
        os_status = TLS_OS_ERROR;
    }

    return os_status;
}

/*
*********************************************************************************************************
*                                            DELETE A TASK
*
* Description: This function allows you to delete a task.  The calling task can delete itself by
*              its own priority number.  The deleted task is returned to the dormant state and can be
*              re-activated by creating the deleted task again.
*
* Arguments  : prio: the task priority
*                    freefun: function to free resource
*
* Returns    : TLS_OS_SUCCESS             if the call is successful
*                  TLS_OS_ERROR
*********************************************************************************************************
*/
tls_os_status_t tls_os_task_del(u8 prio, void (*freefun)(void))
{
    printf("modify compile tls_os_task_del is null fun . \n");
    assert(0);
    return TLS_OS_ERROR;
}

/**
 * @brief          This function allows you to delete a task.  The calling
                   task can delete itself by its handle.
                   The deleted task is returned to the dormant state
                   and can be re-activated by creating the deleted task
                   again.
 *
 * @param[in]      handle                task handle to delete
 * @param[in]      (*freefun)(void)    function to free resource,default using null
 *
 * @retval         TLS_OS_SUCCESS     the call is successful
 * @retval         TLS_OS_ERROR       failed
 *
 * @note           Generally, you do not need to call this function in your application.
 */
tls_os_status_t tls_os_task_del_by_task_handle(tls_os_task_t task, void (*freefun)(void))
{
    tls_os_status_t os_status;
    tls_os_handle_t *pHandle = (tls_os_handle_t *)task;
    int ret = LOS_TaskDelete(pHandle->handle);
    if (ret == LOS_OK) {
        os_status = TLS_OS_SUCCESS;
        tls_mem_free(pHandle);
    } else {
        os_status = TLS_OS_ERROR;
    }
    printf("%s: handle %d, ret %d\n", __FUNCTION__, (u32)task, ret);
    return os_status;
}

/*
*********************************************************************************************************
*                                  CREATE A MUTUAL EXCLUSION SEMAPHORE
*
* Description: This function creates a mutual exclusion semaphore.
*
* Arguments  : prio          is the priority to use when accessing the mutual exclusion semaphore.  In
*                            other words, when the semaphore is acquired and a higher priority task
*                            attempts to obtain the semaphore then the priority of the task owning the
*                            semaphore is raised to this priority.  It is assumed that you will specify
*                            a priority that is LOWER in value than ANY of the tasks competing for the
*                            mutex.
*
*              mutex          is a pointer to the event control clock (OS_EVENT) associated with the
*                            created mutex.
*
*
* Returns    :TLS_OS_SUCCESS         if the call was successful.
*                 TLS_OS_ERROR
*
* Note(s)    : 1) The LEAST significant 8 bits of '.OSEventCnt' are used to hold the priority number
*                 of the task owning the mutex or 0xFF if no task owns the mutex.
*
*              2) The MOST  significant 8 bits of '.OSEventCnt' are used to hold the priority number
*                 to use to reduce priority inversion.
*********************************************************************************************************
*/
tls_os_status_t tls_os_mutex_create(u8 prio, tls_os_mutex_t **mutex)
{
    u32 error;
    UINT32 mutexID = 0 ;
    tls_os_status_t os_status;
    tls_os_handle_t *pHandle = tls_mem_alloc(sizeof(tls_os_handle_t));
    if (!pHandle) {
        printf("%s: malloc error\n", __FUNCTION__);
        return TLS_OS_ERROR;
    }

    error = LOS_MuxCreate(&mutexID);
    if (error == LOS_OK) {
        pHandle->handle = mutexID;
        *mutex = (tls_os_mutex_t *)pHandle;
        os_status = TLS_OS_SUCCESS;
    } else {
        *mutex = NULL;
        os_status = TLS_OS_ERROR;
        tls_mem_free(pHandle);
    }
    return os_status;
}

/*
*********************************************************************************************************
*                                          DELETE A MUTEX
*
* Description: This function deletes a mutual exclusion semaphore and readies all tasks pending on the it.
*
* Arguments  : mutex        is a pointer to the event control block associated with the desired mutex.
*
* Returns    : TLS_OS_SUCCESS             The call was successful and the mutex was deleted
*                            TLS_OS_ERROR        error
*
* Note(s)    : 1) This function must be used with care.  Tasks that would normally expect the presence of
*                 the mutex MUST check the return code of OSMutexPend().
*
*              2) This call can potentially disable interrupts for a long time.  The interrupt disable
*                 time is directly proportional to the number of tasks waiting on the mutex.
*
*              3) Because ALL tasks pending on the mutex will be readied, you MUST be careful because the
*                 resource(s) will no longer be guarded by the mutex.
*
*              4) IMPORTANT: In the 'OS_DEL_ALWAYS' case, we assume that the owner of the Mutex (if there
*                            is one) is ready-to-run and is thus NOT pending on another kernel object or
*                            has delayed itself.  In other words, if a task owns the mutex being deleted,
*                            that task will be made ready-to-run at its original priority.
*********************************************************************************************************
*/
tls_os_status_t tls_os_mutex_delete(tls_os_mutex_t *mutex)
{
    u32 error;
    tls_os_status_t os_status;
    tls_os_handle_t *pHandle = (tls_os_handle_t *)mutex;

    error = LOS_MuxDelete(pHandle->handle);
    if (error == LOS_OK) {
        os_status = TLS_OS_SUCCESS;
        tls_mem_free(pHandle);
    } else {
        os_status = TLS_OS_ERROR;
    }
    return os_status;
}

/*
*********************************************************************************************************
*                                  PEND ON MUTUAL EXCLUSION SEMAPHORE
*
* Description: This function waits for a mutual exclusion semaphore.
*
* Arguments  : mutex        is a pointer to the event control block associated with the desired
*                            mutex.
*
*              wait_time       is an optional timeout period (in clock ticks).  If non-zero, your task will
*                            wait for the resource up to the amount of time specified by this argument.
*                            If you specify 0, however, your task will wait forever at the specified
*                            mutex or, until the resource becomes available.
*
*
*
* Returns    : TLS_OS_SUCCESS        The call was successful and your task owns the mutex
*                  TLS_OS_ERROR
*
* Note(s)    : 1) The task that owns the Mutex MUST NOT pend on any other event while it owns the mutex.
*
*              2) You MUST NOT change the priority of the task that owns the mutex
*********************************************************************************************************
*/
tls_os_status_t tls_os_mutex_acquire(tls_os_mutex_t *mutex, u32 wait_time)
{
    u8 error;
    tls_os_status_t os_status;
    unsigned int time;
    tls_os_handle_t *pHandle = (tls_os_handle_t *)mutex;

    if (wait_time == 0)
        time = LOS_WAIT_FOREVER;
    else
        time = wait_time;
    error = LOS_MuxPend(pHandle->handle, time);
    if (error == LOS_OK)
        os_status = TLS_OS_SUCCESS;
    else
        os_status = TLS_OS_ERROR;

    return os_status;
}

/*
*********************************************************************************************************
*                                  POST TO A MUTUAL EXCLUSION SEMAPHORE
*
* Description: This function signals a mutual exclusion semaphore
*
* Arguments  : mutex              is a pointer to the event control block associated with the desired
*                                  mutex.
*
* Returns    : TLS_OS_SUCCESS             The call was successful and the mutex was signaled.
*                  TLS_OS_ERROR
*********************************************************************************************************
*/
tls_os_status_t tls_os_mutex_release(tls_os_mutex_t *mutex)
{
    u32 error;
    tls_os_status_t os_status;
    tls_os_handle_t *pHandle = (tls_os_handle_t *)mutex;

    error = LOS_MuxPost(pHandle->handle);
    if (error == LOS_OK)
        os_status = TLS_OS_SUCCESS;
    else
        os_status = TLS_OS_ERROR;

    return os_status;
}

/*
*********************************************************************************************************
*                                           CREATE A SEMAPHORE
*
* Description: This function creates a semaphore.
*
* Arguments  :sem         is a pointer to the event control block (OS_EVENT) associated with the
*                            created semaphore
*            cnt           is the initial value for the semaphore.  If the value is 0, no resource is
*                            available (or no event has occurred).  You initialize the semaphore to a
*                            non-zero value to specify how many resources are available (e.g. if you have
*                            10 resources, you would initialize the semaphore to 10).
*
* Returns    : TLS_OS_SUCCESS    The call was successful
*            TLS_OS_ERROR
*********************************************************************************************************
*/
tls_os_status_t tls_os_sem_create(tls_os_sem_t **sem, u32 cnt)
{
    u32 error;

    tls_os_status_t os_status;
    tls_os_handle_t *pHandle = tls_mem_alloc(sizeof(tls_os_handle_t));
    if (!pHandle) {
        printf("%s: malloc error\n", __FUNCTION__);
        return TLS_OS_ERROR;
    }

    error = LOS_SemCreate(cnt, &pHandle->handle);
    if (error == LOS_OK) {
        *sem = (tls_os_sem_t *)pHandle;
        os_status = TLS_OS_SUCCESS;
    } else {
        *sem = NULL;
        os_status = TLS_OS_ERROR;
        tls_mem_free(pHandle);
    }

    return os_status;
}

/*
*********************************************************************************************************
*                                         DELETE A SEMAPHORE
*
* Description: This function deletes a semaphore and readies all tasks pending on the semaphore.
*
* Arguments  : sem        is a pointer to the event control block associated with the desired
*                            semaphore.
*
* Returns    : TLS_OS_SUCCESS             The call was successful and the semaphore was deleted
*                            TLS_OS_ERROR
*
*********************************************************************************************************
*/
tls_os_status_t tls_os_sem_delete(tls_os_sem_t *sem)
{
    u32 error;
    tls_os_status_t os_status;
    tls_os_handle_t *pHandle = (tls_os_handle_t *)sem;

    error = LOS_SemDelete(pHandle->handle);
    if (error == LOS_OK) {
        os_status = TLS_OS_SUCCESS;
        tls_mem_free(pHandle);
    } else
        os_status = TLS_OS_ERROR;

    return os_status;
}

/*
*********************************************************************************************************
*                                           PEND ON SEMAPHORE
*
* Description: This function waits for a semaphore.
*
* Arguments  : sem        is a pointer to the event control block associated with the desired
*                            semaphore.
*
*              wait_time       is an optional timeout period (in clock ticks).  If non-zero, your task will
*                            wait for the resource up to the amount of time specified by this argument.
*                            If you specify 0, however, your task will wait forever at the specified
*                            semaphore or, until the resource becomes available (or the event occurs).
*
* Returns    : TLS_OS_SUCCESS
*            TLS_OS_ERROR
*********************************************************************************************************
*/
tls_os_status_t tls_os_sem_acquire(tls_os_sem_t *sem, u32 wait_time)
{
    u8 error;
    tls_os_status_t os_status;
    unsigned int time;
    tls_os_handle_t *pHandle = (tls_os_handle_t *)sem;

    if (wait_time == 0)
        time = LOS_WAIT_FOREVER;
    else
        time = wait_time;
    error = LOS_SemPend(pHandle->handle, time);
    if (error == LOS_OK)
        os_status = TLS_OS_SUCCESS;
    else
        os_status = TLS_OS_ERROR;

    return os_status;
}

/*
*********************************************************************************************************
*                                         POST TO A SEMAPHORE
*
* Description: This function signals a semaphore
*
* Arguments  : sem        is a pointer to the event control block associated with the desired
*                            semaphore.
*
* Returns    : TLS_OS_SUCCESS
*            TLS_OS_ERROR
*********************************************************************************************************
*/
tls_os_status_t tls_os_sem_release(tls_os_sem_t *sem)
{
    u8 error;
    tls_os_status_t os_status;
    tls_os_handle_t *pHandle = (tls_os_handle_t *)sem;
    
    error = LOS_SemPost(pHandle->handle);
    if (error == LOS_OK)
        os_status = TLS_OS_SUCCESS;
    else
        os_status = TLS_OS_ERROR;

    return os_status;
}

UINT32 LOS_SemCount(UINT32 semHandle)
{
    UINT32 intRet = 0;
    UINT32 intSave;
    LosSemCB *semPosted = GET_SEM(semHandle);
    LosTaskCB *resumedTask = NULL;

    if (semHandle >= LOSCFG_BASE_IPC_SEM_LIMIT) {
        return intRet;
    }

    intSave = LOS_IntLock();

    if (semPosted->semStat == OS_SEM_UNUSED) {
        (void)LOS_IntRestore(intSave);
        return intRet;
    }

    if (semPosted->maxSemCount == semPosted->semCount) {
        (void)LOS_IntRestore(intSave);
        return intRet;
    }
    intRet = semPosted->semCount;
    (void)LOS_IntRestore(intSave);
    return intRet;
}

/*
*********************************************************************************************************
*                                         GET THE SEMPHORE COUNT
*
* Description: This function get the count of  a semaphore
*
* Arguments  : sem        is a pointer to the event control block associated with the desired
*                            semaphore.
*
* Returns    : the count number
*********************************************************************************************************
*/
u16 tls_os_sem_get_count(tls_os_sem_t *sem)
{
    tls_os_handle_t *pHandle = (tls_os_handle_t *)sem;
    
    return (u16)LOS_SemCount(pHandle->handle);
}

/*
*********************************************************************************************************
*                                        CREATE A MESSAGE QUEUE
*
* Description: This function creates a message queue if free event control blocks are available.
*
* Arguments  : queue    is a pointer to the event control clock (OS_EVENT) associated with the
*                                created queue
*
*            queue_start         is a pointer to the base address of the message queue storage area.  The
*                            storage area MUST be declared as an array of pointers to 'void' as follows
*
*                            void *MessageStorage[size]
*
*                  queue_size          is the number of elements in the storage area
*
*            msg_size
*
* Returns    : TLS_OS_SUCCESS
*            TLS_OS_ERROR
*********************************************************************************************************
*/
tls_os_status_t tls_os_queue_create(tls_os_queue_t **queue, u32 queue_size)
{
    tls_os_status_t os_status;
    u32 ret;
    UINT32 uwQueueID;
    tls_os_handle_t *pHandle = tls_mem_alloc(sizeof(tls_os_handle_t));
    if (!pHandle) {
        printf("%s: malloc error\n", __FUNCTION__);
        return TLS_OS_ERROR;
    }

    ret = LOS_QueueCreate(NULL, queue_size, &uwQueueID, 0, 4); // 4:queue size
    if (ret == LOS_OK) {
        pHandle->handle = uwQueueID;
        *queue = (tls_os_queue_t *)pHandle;
        os_status = TLS_OS_SUCCESS;
    } else {
        *queue = NULL;
        os_status = TLS_OS_ERROR;
        tls_mem_free(pHandle);
    }
        printf("%s: %d\n", __FUNCTION__, ret);
    return os_status;
}

/*
*********************************************************************************************************
*                                        DELETE A MESSAGE QUEUE
*
* Description: This function deletes a message queue and readies all tasks pending on the queue.
*
* Arguments  : queue        is a pointer to the event control block associated with the desired
*                            queue.
*
*
* Returns    : TLS_OS_SUCCESS
*            TLS_OS_ERROR
*********************************************************************************************************
*/
tls_os_status_t tls_os_queue_delete(tls_os_queue_t *queue)
{
    tls_os_status_t os_status;
    u32 ret;
    tls_os_handle_t *pHandle = (tls_os_handle_t *)queue;

    ret = LOS_QueueDelete(pHandle->handle);
    if (ret == LOS_OK) {
        os_status = TLS_OS_SUCCESS;
        tls_mem_free(pHandle);
    } else {
        os_status = TLS_OS_ERROR;
    }
        printf("%s: %d\n", __FUNCTION__, ret);

    return os_status;
}

/*
*********************************************************************************************************
*                                        POST MESSAGE TO A QUEUE
*
* Description: This function sends a message to a queue
*
* Arguments  : queue        is a pointer to the event control block associated with the desired queue
*
*                  msg          is a pointer to the message to send.
*
*            msg_size
* Returns    : TLS_OS_SUCCESS
*            TLS_OS_ERROR
*********************************************************************************************************
*/
tls_os_status_t tls_os_queue_send(tls_os_queue_t *queue, void *msg, u32 msg_size)
{
    u32 ret;
    tls_os_status_t os_status;
    tls_os_handle_t *pHandle = (tls_os_handle_t *)queue;

    if (msg_size == 0) {
        msg_size = sizeof(void *);
    }
    
    ret = LOS_QueueWriteCopy(pHandle->handle, &msg, msg_size, 0);
    if (ret == LOS_OK)
        os_status = TLS_OS_SUCCESS;
    else {
        os_status = TLS_OS_ERROR;
        printf("tls_os_queue_send ret %d\n", ret);
    }
    return os_status;
}

/*
*********************************************************************************************************
*                                     PEND ON A QUEUE FOR A MESSAGE
*
* Description: This function waits for a message to be sent to a queue
*
* Arguments  : queue        is a pointer to the event control block associated with the desired queue
*
*            msg        is a pointer to the message received
*
*            msg_size
*
*              wait_time       is an optional timeout period (in clock ticks).  If non-zero, your task will
*                            wait for a message to arrive at the queue up to the amount of time
*                            specified by this argument.  If you specify 0, however, your task will wait
*                            forever at the specified queue or, until a message arrives.
*
* Returns    : TLS_OS_SUCCESS
*            TLS_OS_ERROR
*********************************************************************************************************
*/
tls_os_status_t tls_os_queue_receive(tls_os_queue_t *queue, void **msg, u32 msg_size, u32 wait_time)
{
    u32 ret;
    tls_os_status_t os_status;
    tls_os_handle_t *pHandle = (tls_os_handle_t *)queue;
    
    if (wait_time == 0)
        wait_time = LOS_WAIT_FOREVER;

    if (msg_size == 0) {
            msg_size = sizeof(void *);
    }
    ret = LOS_QueueReadCopy(pHandle->handle, msg, msg_size, wait_time);
    if (ret == LOS_OK) {
        os_status = TLS_OS_SUCCESS;
    } else {
        os_status = TLS_OS_ERROR;
        if (ret != LOS_ERRNO_QUEUE_TIMEOUT)
            printf("%s: %d\n", __FUNCTION__, ret);
    }

    return os_status;
}

/*
*********************************************************************************************************
*                                             FLUSH QUEUE
*
* Description : This function is used to flush the contents of the message queue.
*
* Arguments   : none
*
* Returns    : TLS_OS_SUCCESS
*             TLS_OS_ERROR
* At present, no use for freeRTOS
*********************************************************************************************************
*/
tls_os_status_t tls_os_queue_flush(tls_os_queue_t *queue)
{
    return TLS_OS_SUCCESS;
}

/*
*********************************************************************************************************
*                                         GET CURRENT SYSTEM TIME
*
* Description: This function is used by your application to obtain the current value of the 32-bit
*              counter which keeps track of the number of clock ticks.
*
* Arguments  : none
*
* Returns    : The current value of OSTime
*********************************************************************************************************
*/
u32 tls_os_get_time(void)
{
    UINT64 cycle = LOS_SysCycleGet();
    UINT64 nowNsec = (cycle / OS_SYS_CLOCK) * OS_SYS_NS_PER_SECOND +
                     (cycle % OS_SYS_CLOCK) * OS_SYS_NS_PER_SECOND / OS_SYS_CLOCK;

    UINT32 tv_sec = nowNsec * HZ / OS_SYS_NS_PER_SECOND;
    return tv_sec;
}

/**********************************************************************************************************
* Description: Disable interrupts by preserving the state of interrupts.
*
* Arguments  : none
*
* Returns    : cpu_sr
***********************************************************************************************************/
u32 tls_os_set_critical(void)
{
    return LOS_IntLock();
}

/**********************************************************************************************************
* Description: Enable interrupts by preserving the state of interrupts.
*
* Arguments  : cpu_sr
*
* Returns    : none
***********************************************************************************************************/
void tls_os_release_critical(u32 cpu_sr)
{
    (void)LOS_IntRestore(cpu_sr);
    return;
}

typedef struct {
    void *arg;
    TLS_OS_TIMER_CALLBACK callback_fn;
    u32 swtmrId;
}tls_swtmr_cb_t;

static void tls_swtmr_common_callback(u32 para)
{
    tls_swtmr_cb_t *tmr_cb = (tls_swtmr_cb_t *)para;
    if (tmr_cb == NULL || tmr_cb->callback_fn == NULL) {
        return;
    }

    tmr_cb->callback_fn(tmr_cb, tmr_cb->arg);
}

/*
************************************************************************************************************************
*                                                   CREATE A TIMER
*
* Description: This function is called by your application code to create a timer.
*
* Arguments  : timer    A pointer to an OS_TMR data structure.This is the 'handle' that your application
*                        will use to reference the timer created.
*
*                callback      Is a pointer to a callback function that will be called when the timer expires.  The
*                               callback function must be declared as follows:
*
*                               void MyCallback (OS_TMR *ptmr, void *p_arg);
*
*                  callback_arg  Is an argument (a pointer) that is passed to the callback function when it is called.
*
*                      period        The 'period' being repeated for the timer.
*                               If you specified 'OS_TMR_OPT_PERIODIC' as an option, when the timer expires, it will
*                               automatically restart with the same period.
*
*            repeat    if repeat
*
*                 pname         Is a pointer to an ASCII string that is used to name the timer.  Names are useful for
*                               debugging.
*
* Returns    : TLS_OS_SUCCESS
*            TLS_OS_ERROR
************************************************************************************************************************
*/
tls_os_status_t tls_os_timer_create(tls_os_timer_t **timer,
    TLS_OS_TIMER_CALLBACK callback,
    void *callback_arg,
    u32 period,
    bool repeat,
    u8 *name)
{
    u32 ret;
    u32 uwTimerID;
    tls_os_status_t os_status;
    UINT8 ucMode;

    if (period == 0)
        period = 1;

    if (repeat)
        ucMode = LOS_SWTMR_MODE_PERIOD;
    else
        ucMode = LOS_SWTMR_MODE_NO_SELFDELETE;

    tls_swtmr_cb_t *swtmr_cb = tls_mem_alloc(sizeof(tls_swtmr_cb_t));
    if (!swtmr_cb) {
        printf("%s: malloc error\n", __FUNCTION__);
        return TLS_OS_ERROR;
    }
    swtmr_cb->callback_fn = callback;
    swtmr_cb->arg = callback_arg;
    
#if (LOSCFG_BASE_CORE_SWTMR_ALIGN == 1)
    ret = LOS_SwtmrCreate(period, ucMode, tls_swtmr_common_callback, &uwTimerID,
        swtmr_cb, OS_SWTMR_ROUSES_IGNORE, OS_SWTMR_ALIGN_SENSITIVE);
#else
    ret = LOS_SwtmrCreate(period, ucMode, tls_swtmr_common_callback, &uwTimerID, swtmr_cb);
#endif
    if (ret  == LOS_OK) {
        *timer = (tls_os_timer_t *)swtmr_cb;
        swtmr_cb->swtmrId = uwTimerID;
        os_status = TLS_OS_SUCCESS;
    } else {
        tls_mem_free(swtmr_cb);
        os_status = TLS_OS_ERROR;
        printf("%s: %d\n", __FUNCTION__, ret);
    }
    return os_status;
}

/*
************************************************************************************************************************
*                                                   START A TIMER
*
* Description: This function is called by your application code to start a timer.
*
* Arguments  : timer          Is a pointer to an OS_TMR
*
************************************************************************************************************************
*/
tls_os_status_t tls_os_timer_start(tls_os_timer_t *timer)
{
    u32 ret;
    u32 uwTimerID;
    tls_swtmr_cb_t *swtmr_cb = (tls_swtmr_cb_t *)timer;
    if (swtmr_cb == NULL) {
        return;
    }
    uwTimerID = swtmr_cb->swtmrId;
    ret = LOS_SwtmrStart(uwTimerID);
    if (ret  == LOS_OK) {
        return TLS_OS_SUCCESS;
    } else {
        return TLS_OS_ERROR;
    }
}

/*
************************************************************************************************************************
*                                                   CHANGE A TIMER WAIT TIME
*
* Description: This function is called by your application code to change a timer wait time.
*
* Arguments  : timer          Is a pointer to an OS_TMR
*
*            ticks            is the wait time
************************************************************************************************************************
*/
extern LITE_OS_SEC_BSS SWTMR_CTRL_S     *g_swtmrCBArray;

#define SET_PERIOD(usSwTmrID, uvIntSave, pstSwtmr, ticks) { \
    do { \
        uvIntSave = LOS_IntLock(); \
        (pstSwtmr) = g_swtmrCBArray + (usSwTmrID) % LOSCFG_BASE_CORE_SWTMR_LIMIT; \
        if ((pstSwtmr)->usTimerID % LOSCFG_BASE_CORE_SWTMR_LIMIT != (usSwTmrID) % LOSCFG_BASE_CORE_SWTMR_LIMIT)  \
        {                                     \
            (void)LOS_IntRestore((uvIntSave));        \
            printf("0x%x-%d-%d", (u32)(pstSwtmr), (pstSwtmr)->usTimerID, (usSwTmrID) ); \
            assert(0); \
        }                                     \
        (pstSwtmr)->uwInterval = (ticks); \
        (void)LOS_IntRestore(uvIntSave); \
    } while (0); \
}

tls_os_status_t tls_os_timer_change(tls_os_timer_t *timer, u32 ticks)
{
//  must need
    tls_swtmr_cb_t *swtmr_cb = (tls_swtmr_cb_t *)timer;
    if (swtmr_cb == NULL) {
        return;
    }
    
    UINT16 usSwTmrID = swtmr_cb->swtmrId;
    UINTPTR uvIntSave;
    SWTMR_CTRL_S *pstSwtmr;
    UINT32 err = 0;
    tls_os_status_t os_status;
    if (ticks == 0)
        ticks = 1;
    err = LOS_SwtmrStop(usSwTmrID);
    SET_PERIOD(usSwTmrID, uvIntSave, pstSwtmr, ticks);
    err = LOS_SwtmrStart(usSwTmrID);
    if (err  == LOS_OK)
        os_status = TLS_OS_SUCCESS;
    else
        os_status = TLS_OS_ERROR;

    return os_status;
}

// /< return 1 active while 0 not active
int LOS_SwtmrIsActive(UINT32 swtmrId)
{
    SWTMR_CTRL_S *swtmr = NULL;
    UINTPTR intSave;
    UINT16 swtmrCbId;
    int ret = 0;

    if (swtmrId >= 0xFFFFFFFF) {
        return ret;
    }
    intSave = LOS_IntLock();
    swtmrCbId = swtmrId % LOSCFG_BASE_CORE_SWTMR_LIMIT;
    swtmr = g_swtmrCBArray + swtmrCbId;
    if (swtmr->usTimerID != swtmrId) {
        (void)LOS_IntRestore(intSave);
        return ret;
    }
    if (swtmr->ucState == OS_SWTMR_STATUS_TICKING) {
        ret = 1;
    }
    (void)LOS_IntRestore(intSave);
    return ret;
}

/*
************************************************************************************************************************
*                                                   STOP A TIMER
*
* Description: This function is called by your application code to stop a timer.
*
* Arguments  : timer          Is a pointer to the timer to stop.
*
************************************************************************************************************************
*/
tls_os_status_t tls_os_timer_stop(tls_os_timer_t *timer)
{
    u32 ret;
    u32 uwTimerID;
    tls_swtmr_cb_t *swtmr_cb = (tls_swtmr_cb_t *)timer;
    if (swtmr_cb == NULL) {
        return;
    }
    tls_os_status_t os_status;
    uwTimerID = swtmr_cb->swtmrId;
    ret = LOS_SwtmrStop(uwTimerID);
    if (ret  == LOS_OK) {
        os_status = TLS_OS_SUCCESS;
    } else {
        os_status = TLS_OS_ERROR;
    }

    return os_status;
}

/*
************************************************************************************************************************
*                                                   Delete A TIMER
*
* Description: This function is called by your application code to delete a timer.
*
* Arguments  : timer          Is a pointer to the timer to delete.
*
************************************************************************************************************************
*/
tls_os_status_t tls_os_timer_delete(tls_os_timer_t *timer)
{
    u32 ret = 0;
    u32 uwTimerID;
    tls_swtmr_cb_t *swtmr_cb = (tls_swtmr_cb_t *)timer;
    if (swtmr_cb == NULL) {
        return TLS_OS_ERROR;
    }
    uwTimerID = swtmr_cb->swtmrId;
    tls_os_status_t os_status;
    (void)LOS_SwtmrStop(uwTimerID);
    ret = LOS_SwtmrDelete(uwTimerID);
    if (ret  == LOS_OK) {
        os_status = TLS_OS_SUCCESS;
        tls_mem_free(swtmr_cb);
    } else {
        os_status = TLS_OS_ERROR;
    }
    return os_status;
}

/*
************************************************************************************************************************
*                                                   Query the timer status:active or not
*
* Description: This function is called by your application code to query the timer status
*
* Arguments  : timer          Is a pointer to the timer to query
*
************************************************************************************************************************
*/

u8 tls_os_timer_active(tls_os_timer_t *timer)
{
    u32 uwTimerID;
    tls_swtmr_cb_t *swtmr_cb = (tls_swtmr_cb_t *)timer;
    if (swtmr_cb == NULL) {
        return 0;
    }
    uwTimerID = swtmr_cb->swtmrId;
    return (u8)LOS_SwtmrIsActive(uwTimerID);
}

u32 tls_os_timer_expirytime(tls_os_timer_t *timer)
{
    u32 ret = 0;
    u32 uwTimerID;
    tls_swtmr_cb_t *swtmr_cb = (tls_swtmr_cb_t *)timer;
    if (swtmr_cb == NULL) {
        return 0;
    }
    uwTimerID = swtmr_cb->swtmrId;
    if (LOS_OK == LOS_SwtmrTimeGet(uwTimerID, &ret)) {
        ret += tls_os_get_time();
    }
    return ret;
}

/*
*********************************************************************************************************
*                                       DELAY TASK 'n' TICKS
*
* Description: This function is called to delay execution of the currently running task until the
*              specified number of system ticks expires.  This, of course, directly equates to delaying
*              the current task for some time to expire.  No delay will result If the specified delay is
*              0.  If the specified delay is greater than 0 then, a context switch will result.
*
* Arguments  : ticks     is the time delay that the task will be suspended in number of clock 'ticks'.
*                        Note that by specifying 0, the task will not be delayed.
*
* Returns    : none
*********************************************************************************************************
*/
void tls_os_time_delay(u32 ticks)
{
    (void)LOS_TaskDelay(ticks);
}

/*
*********************************************************************************************************
*                                       task stat info
*
* Description: This function is used to display stat info
*
* Returns    : none
*********************************************************************************************************
*/
void tls_os_disp_task_stat_info(void)
{
    (void)LOS_TaskInfoMonitor();
}

/*
*********************************************************************************************************
*                                     OS INIT function
*
* Description: This function is used to init os common resource
*
* Arguments  : None;
*
* Returns    : None
*********************************************************************************************************
*/
void tls_os_init(void *arg)
{
    (void)LOS_KernelInit();
}

/*
*********************************************************************************************************
*                                     OS scheduler start function
*
* Description: This function is used to start task schedule
*
* Arguments  : None;
*
* Returns    : None
*********************************************************************************************************
*/
void tls_os_start_scheduler(void)
{
    (void)LOS_Start();
}

/*
*********************************************************************************************************
*                                     Get OS TYPE
*
* Description: This function is used to get OS type
*
* Arguments  : None;
*
* Returns    : TLS_OS_TYPE
*                     OS_UCOSII = 0,
*                 OS_FREERTOS = 1,
*********************************************************************************************************
*/
int tls_os_get_type(void)
{
    return (int)OS_LITEOS;
}

/*
*********************************************************************************************************
*                                     OS tick handler
*
* Description: This function is  tick handler.
*
* Arguments  : None;
*
* Returns    : None
*********************************************************************************************************
*/
void tls_os_time_tick(void *p) {
}

static uint32_t CK_IN_INTRP(void)
{
    uint32_t vec = 0;
    asm volatile(
        "mfcr    %0, psr \n"
        "lsri    %0, 16\n"
        "sextb   %0\n"
        :"=r"(vec):);

    if (vec >= 32 || (vec == 10)) { // 32:Analyzing conditions, 10:value of vec
        return 1;
    } else {
        return 0;
    }
}

/**
 * @brief              get isr count
 *
 * @param[in]          None
 *
 * @retval             count
 *
 * @note               None
 */

u8 tls_get_isr_count(void)
{
    return (u8)CK_IN_INTRP();
}

long PortSaveLocalPSR(void)
{
    return SaveLocalPSR();
}

void PortRestoreLocalPSR(long ulDummy)
{
    RestoreLocalPSR(ulDummy);
}

void PortEnableInterrupt(void)
{
    portEnableInterrupt();
}

void PorDisableInterrupt(void)
{
    portDisableInterrupt();
}

static  int ulCriticalNesting = 0;
void vPortEnterCritical(void)
{
    portDisableInterrupt();
    ulCriticalNesting ++;
}

void vPortExitCritical(void)
{
    if (ulCriticalNesting == 0) {
        while (1) {};
    }

    ulCriticalNesting --;
    if (ulCriticalNesting == 0) {
        portEnableInterrupt();
    }
}

extern BOOL g_taskScheduled;
u8 tls_os_task_schedule_state()
{
    return (u8)g_taskScheduled;
}

tls_os_task_t tls_os_task_id()
{
    return (tls_os_task_t)LOS_CurTaskIDGet();
}

void HalHwiHandleReInit(UINT32 hwiFormAddr)
{
    HWI_PROC_FUNC *p_hwiForm = (HWI_PROC_FUNC *)hwiFormAddr;

    p_hwiForm[0] = (HWI_PROC_FUNC)Reset_Handler;
    p_hwiForm[PendSV_IRQn] = (HWI_PROC_FUNC)tspend_handler;
}

#endif /* end of WM_OS_LITEOS_H */