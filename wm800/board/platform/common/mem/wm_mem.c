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
* File Name : wm_mem.c
*
* Description: memory manager Module
*
* Copyright (c) 2014 Winner Micro Electronic Design Co., Ltd.
* All rights reserved.
*
* Author : dave
*
* Date : 2014-6-12
*****************************************************************************/

#include "wm_osal.h"
#include "wm_mem.h"
#include "list.h"
#include <string.h>
#if TLS_OS_LITEOS
#include "los_memory.h"
#endif
extern u8 tls_get_isr_count(void);
/**
 * This variable is set if the memory mananger has been initialized.
 * This is available only for debug version of the driver
 */
bool         memory_manager_initialized = false;
/**
 * This mutex is used to synchronize the list of allocated
 * memory blocks. This is a debug version only feature
 */
tls_os_sem_t    *mem_sem;
#if WM_MEM_DEBUG

struct dl_list memory_used_list;
struct dl_list memory_free_list;
#define MEM_BLOCK_SIZE           800
MEMORY_BLOCK mem_blocks[MEM_BLOCK_SIZE];

u32 alloc_heap_mem_bytes = 0;
u32 alloc_heap_mem_blk_cnt = 0;
u32 alloc_heap_mem_max_size = 0;

#define PRE_OVERSIZE        0
#define OVERSIZE        0

/**
 * This is a debug only function that performs memory management operations for us.
 * Memory allocated using this function is tracked, flagged when leaked, and caught for
 * overflows and underflows.
 *
 * \param size            The size in bytes of memory to
 *        allocate
 *
 * \param file            The full path of file where this
 *        function is invoked from
 * \param line            The line number in the file where this
 *        method was called from
 * \return Pointer to the allocated memory or NULL in case of a failure
 */
void *mem_alloc_debug(u32 size, char* file, int line)
{
    void *buf = NULL;
    u32 pad_len;
    u32  cpu_sr;
    //
    // If the memory manager has not been initialized, do so now
    //
    cpu_sr = tls_os_set_critical();
    if (!memory_manager_initialized) {
        tls_os_status_t os_status;
        memory_manager_initialized = true;
        //
        // NOTE: If two thread allocate the very first allocation simultaneously
        // it could cause double initialization of the memory manager. This is a
        // highly unlikely scenario and will occur in debug versions only.
        //
        os_status = tls_os_sem_create(&mem_sem, 1);
        if (os_status != TLS_OS_SUCCESS)
            printf("mem_alloc_debug: tls_os_sem_create mem_sem error\r\n");
        dl_list_init(&memory_used_list);
        dl_list_init(&memory_free_list);
        for (int i = 0; i < MEM_BLOCK_SIZE; i++) {
            dl_list_add_tail(&memory_free_list, &mem_blocks[i].list);
        }
    }
    tls_os_release_critical(cpu_sr);

    tls_os_sem_acquire(mem_sem, 0);
    cpu_sr = tls_os_set_critical();
    //
    // Allocate the required memory chunk plus header and trailer bytes
    //
    pad_len = sizeof(u32) - (size & 0x3);
    buf = malloc(sizeof(MEMORY_PATTERN) + PRE_OVERSIZE + size + pad_len + OVERSIZE + sizeof(MEMORY_PATTERN));
    if (buf) {
        //
        // Memory allocation succeeded. Add information about the allocated
        // block in the list that tracks all allocations.
        //
        PMEMORY_PATTERN  mem_ptn_hd;
        PMEMORY_PATTERN  mem_ptn_tl;
        PMEMORY_BLOCK  mem_blk_hd1;

        if (dl_list_empty(&memory_free_list)) {
            printf("Memory blocks empty!\r\n");
                free(buf);
                tls_os_release_critical(cpu_sr);
                tls_os_sem_release(mem_sem);
            tls_mem_alloc_info();
                return NULL;
        }
        mem_blk_hd1 = dl_list_first(&memory_free_list, MEMORY_BLOCK, list);
        dl_list_del(&mem_blk_hd1->list);
        dl_list_add_tail(&memory_used_list, &mem_blk_hd1->list);
            alloc_heap_mem_bytes += size+sizeof(MEMORY_PATTERN) + sizeof(MEMORY_PATTERN) + pad_len +\
                PRE_OVERSIZE + OVERSIZE;
            alloc_heap_mem_blk_cnt++;
            if (alloc_heap_mem_bytes > alloc_heap_mem_max_size) {
                alloc_heap_mem_max_size = alloc_heap_mem_bytes;
            }

            mem_blk_hd1->pad = pad_len;
            mem_blk_hd1->file = file;
            mem_blk_hd1->line = line;
            mem_blk_hd1->length = size;
            mem_blk_hd1->header_pattern = (u32)buf;

            // Fill in the memory header and trailer
            mem_ptn_hd = (PMEMORY_PATTERN)buf;
            mem_ptn_hd->pattern0= MEM_HEADER_PATTERN;

            mem_ptn_tl = (PMEMORY_PATTERN)(((u8 *)(buf))+size + sizeof(MEMORY_PATTERN)+pad_len + \
                PRE_OVERSIZE + OVERSIZE);
            mem_ptn_tl->pattern0= MEM_TAILER_PATTERN;

            // Jump ahead by memory header so pointer returned to caller points at the right place
            buf = ((u8 *)buf) + sizeof (MEMORY_PATTERN) + PRE_OVERSIZE;
    } else {
        printf("==>Memory was allocated from %s at line %d with length %d, allocated size %d, count %d\r\n",
               file,
               line,
               size, alloc_heap_mem_bytes, alloc_heap_mem_blk_cnt);
        tls_os_release_critical(cpu_sr);
    tls_os_sem_release(mem_sem);
    tls_mem_alloc_info();
    return buf;
    }
    tls_os_release_critical(cpu_sr);
    tls_os_sem_release(mem_sem);
    return buf;
}

void *mem_calloc_debug(u32 n, u32 size, char* file, int line)
{
    void *buf = NULL;
    u32 pad_len;
    u32  cpu_sr;
    //
    // If the memory manager has not been initialized, do so now
    //
    cpu_sr = tls_os_set_critical();
    if (!memory_manager_initialized) {
        tls_os_status_t os_status;
        memory_manager_initialized = true;
        //
        // NOTE: If two thread allocate the very first allocation simultaneously
        // it could cause double initialization of the memory manager. This is a
        // highly unlikely scenario and will occur in debug versions only.
        //
        os_status = tls_os_sem_create(&mem_sem, 1);
        if (os_status != TLS_OS_SUCCESS)
            printf("mem_alloc_debug: tls_os_sem_create mem_sem error\r\n");
        dl_list_init(&memory_used_list);
        dl_list_init(&memory_free_list);
        for (int i = 0; i < MEM_BLOCK_SIZE; i++) {
            dl_list_add_tail(&memory_free_list, &mem_blocks[i].list);
        }
    }
    tls_os_release_critical(cpu_sr);

    tls_os_sem_acquire(mem_sem, 0);
    cpu_sr = tls_os_set_critical();
    //
    // Allocate the required memory chunk plus header and trailer bytes
    //
    pad_len = sizeof(u32) - ((n*size) & 0x3);
    buf = malloc(sizeof(MEMORY_PATTERN) + PRE_OVERSIZE + n*size + pad_len + OVERSIZE + sizeof(MEMORY_PATTERN));
    if (buf) {
        //
        // Memory allocation succeeded. Add information about the allocated
        // block in the list that tracks all allocations.
        //
        PMEMORY_PATTERN  mem_ptn_hd;
        PMEMORY_PATTERN  mem_ptn_tl;
        PMEMORY_BLOCK  mem_blk_hd1;

    if (dl_list_empty(&memory_free_list)) {
    printf("Memory blocks empty!\r\n");
    free(buf);
    tls_os_release_critical(cpu_sr);
    tls_os_sem_release(mem_sem);
    tls_mem_alloc_info();
    return NULL;
    }
        mem_blk_hd1 = dl_list_first(&memory_free_list, MEMORY_BLOCK, list);
        dl_list_del(&mem_blk_hd1->list);
        dl_list_add_tail(&memory_used_list, &mem_blk_hd1->list);
        alloc_heap_mem_bytes += n*size+sizeof(MEMORY_PATTERN)+sizeof(MEMORY_PATTERN)+pad_len + PRE_OVERSIZE + OVERSIZE;
        alloc_heap_mem_blk_cnt++;
        if (alloc_heap_mem_bytes > alloc_heap_mem_max_size) {
            alloc_heap_mem_max_size = alloc_heap_mem_bytes;
        }

        mem_blk_hd1->pad = pad_len;
        mem_blk_hd1->file = file;
        mem_blk_hd1->line = line;
        mem_blk_hd1->length = n*size;
        mem_blk_hd1->header_pattern = (u32)buf;

        // Fill in the memory header and trailer
        mem_ptn_hd = (PMEMORY_PATTERN)buf;
        mem_ptn_hd->pattern0= MEM_HEADER_PATTERN;

        mem_ptn_tl = (PMEMORY_PATTERN)(((u8 *)(buf))+n*size + sizeof(MEMORY_PATTERN)+pad_len + PRE_OVERSIZE + OVERSIZE);
        mem_ptn_tl->pattern0= MEM_TAILER_PATTERN;

        // Jump ahead by memory header so pointer returned to caller points at the right place
        buf = ((u8 *)buf) + sizeof (MEMORY_PATTERN) + PRE_OVERSIZE;
    } else {
        printf("==>Memory was allocated from %s at line %d with length %d, allocated size %d, count %d\r\n",
               file,
               line,
               n*size, alloc_heap_mem_bytes, alloc_heap_mem_blk_cnt);

    tls_os_release_critical(cpu_sr);
    tls_os_sem_release(mem_sem);
    tls_mem_alloc_info();
    return buf;
    }
    tls_os_release_critical(cpu_sr);
    tls_os_sem_release(mem_sem);
    return buf;
}
/**
 * This routine is called to free memory which was previously allocated using MpAllocateMemory function.
 * Before freeing the memory, this function checks and makes sure that no overflow or underflows have
 * happened and will also try to detect multiple frees of the same memory chunk.
 *
 * \param p    Pointer to allocated memory
 */
void mem_free_debug(void *p,  char* file, int line)
{
    PMEMORY_PATTERN  mem_ptn_hd;
    PMEMORY_PATTERN  mem_ptn_tl;
    PMEMORY_BLOCK  mem_blk_hd1;
    u8              needfree = 0;
    u8  haserr = 0;
    u32  cpu_sr;

    // Jump back by memory header size so we can get to the header
    mem_ptn_hd = (PMEMORY_PATTERN) (((u8 *)p) - sizeof(MEMORY_PATTERN)  - PRE_OVERSIZE);
    tls_os_sem_acquire(mem_sem, 0);
    cpu_sr = tls_os_set_critical();
    dl_list_for_each(mem_blk_hd1, &memory_used_list, MEMORY_BLOCK, list) {
        if (mem_blk_hd1->header_pattern == (u32)mem_ptn_hd) {
            needfree = 1;
            break;
        }
    }
    if (needfree) {
        dl_list_del(&mem_blk_hd1->list);
        dl_list_add_tail(&memory_free_list, &mem_blk_hd1->list);
        alloc_heap_mem_bytes -= mem_blk_hd1->length + sizeof(MEMORY_PATTERN) + sizeof(MEMORY_PATTERN) +
            PRE_OVERSIZE + OVERSIZE + mem_blk_hd1->pad;
        alloc_heap_mem_blk_cnt--;
    }
    if (needfree == 0) {
    printf("Memory Block %p was deallocated from %s at line %d \r\n", mem_ptn_hd, file, line);
    printf("Memory %p has been deallocated!\r\n", p);
    dl_list_for_each_reverse(mem_blk_hd1, &memory_free_list, MEMORY_BLOCK, list) {
        if (mem_blk_hd1->header_pattern == (u32)mem_ptn_hd) {
            printf("Memory Block %p has been put free list!\r\n", mem_ptn_hd);
            break;
        }
    }
    tls_os_release_critical(cpu_sr);
    tls_os_sem_release(mem_sem);
    tls_mem_alloc_info();
    return;
    }
    mem_ptn_tl = (PMEMORY_PATTERN) ((u8 *)p + mem_blk_hd1->length + mem_blk_hd1->pad + OVERSIZE);
    //
    // Check that header was not corrupted
    //
    if (mem_ptn_hd->pattern0 != MEM_HEADER_PATTERN) {
        printf("Memory %p was deallocated from %s at line %d \r\n", p, file, line);
        printf("Memory header corruption due to underflow detected at memory block %p\r\n",
            mem_ptn_hd);
        printf("Header pattern 0(0x%x)\r\n", mem_ptn_hd->pattern0);
        printf("Memory was allocated from %s at line %d with length %d\r\n",
               mem_blk_hd1->file,
               mem_blk_hd1->line,
               mem_blk_hd1->length);
        haserr = 1;
    }

    //
    // Check that trailer was not corrupted
    //
    if (mem_ptn_tl->pattern0 != MEM_TAILER_PATTERN) {
        printf("Memory %p was deallocated from %s at line %d \r\n", p, file, line);
        printf("Memory tailer corruption due to overflow detected at %p\r\n", mem_ptn_hd);
        printf("Tailer pattern 0(0x%x)\r\n", mem_ptn_tl->pattern0);
        printf("Memory was allocated from %s at line %d with length %d\r\n",
            mem_blk_hd1->file, mem_blk_hd1->line, mem_blk_hd1->length);
        haserr = 1;
    }
    if (needfree) {
        free(mem_ptn_hd);
    }

    tls_os_release_critical(cpu_sr);
    tls_os_sem_release(mem_sem);

    if (haserr)
        tls_mem_alloc_info();
}

void *mem_realloc_debug(void *mem_address, u32 size, char* file, int line)
{
    void *mem_re_addr;
    u32 cpu_sr;

    if ((mem_re_addr = mem_alloc_debug(size,  file, line)) == NULL) {
        printf("mem_realloc_debug failed(size=%d).\r\n", size);
        return NULL;
    }
    if (mem_address != NULL) {
        cpu_sr = tls_os_set_critical();
        memcpy(mem_re_addr, mem_address, size);
        tls_os_release_critical(cpu_sr);
        mem_free_debug(mem_address, file, line);
    }
    return mem_re_addr;
}

void tls_mem_alloc_info(void)
{
    int i;
    MEMORY_BLOCK *pos;
    u32 cpu_sr;

    tls_os_sem_acquire(mem_sem, 0);
    cpu_sr = tls_os_set_critical();
    printf("==>Memory was allocated size %d, count %d\r\n",
        alloc_heap_mem_bytes, alloc_heap_mem_blk_cnt);
    i = 1;
    dl_list_for_each(pos, &memory_used_list, MEMORY_BLOCK, list) {
        printf("Block(%2d): addr<%p>, file<%s>, line<%d>, length<%d>\r\n",
               i, pos->header_pattern, pos->file, pos->line, pos->length);
        i++;
    }
    tls_os_release_critical(cpu_sr);
    tls_os_sem_release(mem_sem);
}

int is_safe_addr_debug(void* p, u32 len, char* file, int line)
{
    int i;
    MEMORY_BLOCK *pos;
    u32 cpu_sr;

    if (((u32)p) >= (u32)0x64ae8 || ((u32)p) < (u32)0x54ae8) {
        return 1;
    }
    tls_os_sem_acquire(mem_sem, 0);
    cpu_sr = tls_os_set_critical();
    i = 1;
    dl_list_for_each(pos, &memory_used_list, MEMORY_BLOCK, list) {
        if ((pos->header_pattern + sizeof (MEMORY_PATTERN)  + PRE_OVERSIZE) <= ((u32)p) && ((u32)p) <= \
            ((u32)(pos->header_pattern + sizeof(MEMORY_PATTERN) + PRE_OVERSIZE + pos->length))) {
            if (((u32)p) + len > ((u32)(pos->header_pattern + sizeof(MEMORY_PATTERN) + PRE_OVERSIZE + pos->length))) {
                printf("==>Memory oversize. Block(%2d): addr<%p>, file<%s>, line<%d>, length<%d>\r\n",
                    i, pos->header_pattern, pos->file, pos->line, pos->length);
                break;
            } else {
                tls_os_release_critical(cpu_sr);
                tls_os_sem_release(mem_sem);
                return 1;
            }
        }
        i++;
    }
    tls_os_release_critical(cpu_sr);
    tls_os_sem_release(mem_sem);
    printf("==>Memory is not safe addr<%p>, file<%s>, line<%d>.\r\n", p, file, line);
    return 0;
}

#else /* WM_MEM_DEBUG */
void *mem_alloc_debug(u32 size)
{
    u32 *buffer = (u32 *)LOS_MemAlloc(OS_SYS_MEM_ADDR, size);

    if (buffer == NULL)
        printf("malloc error \n");

    return buffer;
}

void mem_free_debug(void *p)
{
    int ret = LOS_MemFree(OS_SYS_MEM_ADDR, p);
    if (ret) {
        printf("mem free error\n");
    }
}

void *mem_realloc_debug(void *mem_address, u32 size)
{
    u32 *mem_re_addr = (u32 *)LOS_MemRealloc(OS_SYS_MEM_ADDR, mem_address, size);

    return mem_re_addr;
}

void *mem_calloc_debug(u32 n, u32 size)
{
    u32 *buffer = (u32 *)LOS_MemAlloc(OS_SYS_MEM_ADDR, n*size);
    if (buffer) {
        memset(buffer, 0, n*size);
    }

    return buffer;
}
#endif /* WM_MEM_DEBUG */

u32 tls_mem_get_avail_heapsize(void)
{
    LOS_MEM_POOL_STATUS status = {0};
    if (LOS_MemInfoGet(OS_SYS_MEM_ADDR, &status) == LOS_NOK) {
        return 0;
    }
    return status.totalFreeSize;
}