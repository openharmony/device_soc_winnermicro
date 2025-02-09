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

#include "wm_littlefs.h"
#include "wm_internal_flash.h"

int32_t littlefs_block_read(const struct lfs_config *c, lfs_block_t block,
                            lfs_off_t off, void *dst, lfs_size_t size)
{
    uint32_t addr = INSIDE_FLS_BASE_ADDR + c->block_size * ((lfs_off_t)c->context + block) + off;
    return tls_fls_read(addr, dst, size);
}

int32_t littlefs_block_write(const struct lfs_config *c, lfs_block_t block,
                             lfs_off_t off, const void *dst, lfs_size_t size)
{
    uint32_t addr = INSIDE_FLS_BASE_ADDR + c->block_size * ((lfs_off_t)c->context + block) + off;
    return tls_fls_write(addr, dst, size);
}

int32_t littlefs_block_erase(const struct lfs_config *c, lfs_block_t block)
{
    uint32_t addr = INSIDE_FLS_BASE_ADDR + c->block_size * ((lfs_off_t)c->context + block);
    return tls_fls_erase(addr/INSIDE_FLS_SECTOR_SIZE);
}

int32_t littlefs_block_sync(const struct lfs_config *c)
{
    return 0;
}
