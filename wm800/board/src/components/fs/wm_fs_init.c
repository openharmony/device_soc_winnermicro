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

#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "wm_littlefs.h"
#include "wm_internal_flash.h"
#include "los_config.h"
#include "los_fs.h"
#include "hdf_log.h"
#include "hdf_device_desc.h"
#include "device_resource_if.h"
#include "lfs_adapter.h"


#define LFS_CFG_READ_SIZE       1
#define LFS_CFG_AHEAD_SIZE      16
#define LFS_CFG_PROG_SIZE       256
#define LFS_CFG_BLOCK_SIZE      256
#define LFS_CFG_CACHE_SIZE      1024
#define LFS_CFG_BLOCK_CYCLES    500

struct fs_cfg {
    char *mount_point;
    struct PartitionCfg lfs_cfg;
};

static struct fs_cfg fs[LOSCFG_LFS_MAX_MOUNT_SIZE] = {0};

static int lfs_flash_block_read(int partition, UINT32 * offset, void *buffer, UINT32 size)
{
    tls_fls_read(*offset, buffer, size);
    return 0;
}

static int lfs_flash_block_prog(int partition, UINT32 * offset, void *buffer, UINT32 size)
{
    tls_fls_write(*offset, (void *)buffer, size);
    return 0;
}

static int lfs_flash_block_erase(int partition, UINT32 offset,UINT32 size)
{
    tls_fls_erase(offset / INSIDE_FLS_SECTOR_SIZE);
    return 0;
}

static uint32_t FsGetResource(struct fs_cfg *fs, const struct DeviceResourceNode *resourceNode)
{
    struct DeviceResourceIface *resource = DeviceResourceGetIfaceInstance(HDF_CONFIG_SOURCE);
    if (resource == NULL) {
        HDF_LOGE("Invalid DeviceResourceIface");
        return HDF_FAILURE;
    }
    int32_t num = resource->GetElemNum(resourceNode, "mount_points");
    if (num < 0 || num > LOSCFG_LFS_MAX_MOUNT_SIZE) {
        HDF_LOGE("%s: invalid mount_points num %d", __func__, num);
        return HDF_FAILURE;
    }
    for (int32_t i = 0; i < num; i++) {
        if (resource->GetStringArrayElem(resourceNode, "mount_points", i,
            &fs[i].mount_point, NULL) != HDF_SUCCESS) {
            HDF_LOGE("%s: failed to get mount_points", __func__);
            return HDF_FAILURE;
        }
        if (resource->GetUint32ArrayElem(resourceNode, "block_start_positions", i,
            (uint32_t *)&fs[i].lfs_cfg.partNo, 0) != HDF_SUCCESS) {
            HDF_LOGE("%s: failed to get partitions", __func__);
            return HDF_FAILURE;
        }
        if (resource->GetUint32ArrayElem(resourceNode, "block_size", i,
            &fs[i].lfs_cfg.blockSize, 0) != HDF_SUCCESS) {
            HDF_LOGE("%s: failed to get block_size", __func__);
            return HDF_FAILURE;
        }
        if (resource->GetUint32ArrayElem(resourceNode, "block_count", i,
            &fs[i].lfs_cfg.blockCount, 0) != HDF_SUCCESS) {
            HDF_LOGE("%s: failed to get block_count", __func__);
            return HDF_FAILURE;
        }
        HDF_LOGD("%s: fs[%d] mount_point=%s, partition=%u, block_size=%u, block_count=%u", __func__, i,
                 fs[i].mount_point, (uint32_t)fs[i].lfs_cfg.partNo,
                 fs[i].lfs_cfg.blockSize, fs[i].lfs_cfg.blockCount);
    }
    return HDF_SUCCESS;
}

static int32_t FsDriverInit(struct HdfDeviceObject *object)
{
    int ret = HDF_FAILURE;
    int lfs_space[1] = {0};
    int lfs_addr[1] = {0};
    if (object == NULL) {
        return HDF_FAILURE;
    }
    if (object->property) {
        if (FsGetResource(fs, object->property) != HDF_SUCCESS) {
            HDF_LOGE("%s: FsGetResource failed", __func__);
            return HDF_FAILURE;
        }
    }

    for (int i = 0; i < sizeof(fs) / sizeof(fs[0]); i++) {
        if (fs[i].mount_point == NULL)
            continue;

        fs[i].lfs_cfg.readFunc  = lfs_flash_block_read;
        fs[i].lfs_cfg.writeFunc  = lfs_flash_block_prog;
        fs[i].lfs_cfg.eraseFunc = lfs_flash_block_erase;

        fs[i].lfs_cfg.readSize = LFS_CFG_READ_SIZE;
        fs[i].lfs_cfg.writeSize = LFS_CFG_PROG_SIZE;
        fs[i].lfs_cfg.cacheSize = LFS_CFG_CACHE_SIZE;
        fs[i].lfs_cfg.lookaheadSize = LFS_CFG_AHEAD_SIZE;
        fs[i].lfs_cfg.blockCycles = LFS_CFG_BLOCK_CYCLES;

        lfs_space[0] = fs[i].lfs_cfg.blockSize * fs[i].lfs_cfg.blockCount;
        lfs_addr[0] = fs[i].lfs_cfg.partNo * fs[i].lfs_cfg.blockSize + INSIDE_FLS_BASE_ADDR;
        fs[i].lfs_cfg.partNo = 0;
        ret = LOS_DiskPartition("lfs_dev0", "littlefs", &lfs_space, &lfs_addr, 1);
        HDF_LOGI("%s: DiskPartition %s\n", __func__, (ret == 0) ? "succeed" : "failed");
        if (ret != 0) {
            return -1;
        }

        ret = mount(NULL, fs[i].mount_point, "littlefs", 0, &fs[i].lfs_cfg);
        HDF_LOGI("FsDriverInit mount ret %d\n", ret);
        if (!ret) {
            ret = mkdir(fs[i].mount_point, S_IRUSR | S_IWUSR | S_IXUSR);
            HDF_LOGI("%s: mkdir %s %s\n", __func__, fs[i].mount_point, (ret == 0) ? "succeed" : "failed");
        }
        if (ret) {
            break;
        }
    }
    HDF_LOGI("%s: mount littlefs %s\n", __func__, (ret == 0) ? "succeed" : "failed");
    return (ret == 0) ? HDF_SUCCESS : HDF_FAILURE;
}

static int32_t FsDriverBind(struct HdfDeviceObject *device)
{
    (void)device;
    return HDF_SUCCESS;
}

static void FsDriverRelease(struct HdfDeviceObject *device)
{
    (void)device;
}

static struct HdfDriverEntry g_fsDriverEntry = {
    .moduleVersion = 1,
    .moduleName = "W800_FS_LITTLEFS",
    .Bind = FsDriverBind,
    .Init = FsDriverInit,
    .Release = FsDriverRelease,
};

HDF_INIT(g_fsDriverEntry);