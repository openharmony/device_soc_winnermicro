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

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "hal_file.h"
#include "utils_file.h"
#include "wm_type_def.h"

#define FLASH_FILE_NAME_LEN      32
#define FLASH_FILE_MAX_NUM       64

#define MAX_NUM_OF_OPENED_FILES 32
static int g_openFileNum = 0;

static int _mode_convert(int flags)
{
    int mode, res = 0;

    mode = flags & O_ACCMODE;
    if (mode == O_RDONLY_FS) {
        res |= O_RDONLY;
    } else if (mode == O_WRONLY_FS) {
        res |= O_WRONLY;
    } else if (mode == O_RDWR_FS) {
        res |= O_RDWR;
    }
    // printf("%s: 1 res 0x%x mode 0x%x, flags 0x%x\n", __func__, res,  mode, flags);
    if (flags & O_CREAT_FS) {
        res |= O_CREAT;
    }
    if (flags & O_EXCL_FS) {
        res |= O_EXCL;
    }
    if (flags & O_TRUNC_FS) {
        res |= O_TRUNC;
    }
    if (flags & O_APPEND_FS) {
        res |= O_CREAT | O_APPEND;
    }
    // printf("%s: 2 res 0x%x, O_CREAT 0x%x, O_CREAT_FS 0x%x\n", __func__, res, O_CREAT, O_CREAT_FS);
    return res;
}

/* Relative path convert */
static char *_path_convert(const char *path)
{
    int len;
    char *target_path;

    len = strlen(path) + 8;
    target_path = (char *)malloc(len);
    if (target_path == NULL) {
        return NULL;
    }
    memset_s(target_path, len, 0, len);
    int i, j = 0;
    // target_path[j++] = '/';
    memcpy(target_path, "/data/", 6);
    j += 6;
    for (i = 0; i < strlen(path); i++) {
        if (path[i] != '/') {
            target_path[j++] = path[i];
        }
    }
    target_path[j] = '\0';

    return target_path;
}

int HalFileOpen(const char* path, int oflag, int mode)
{
    // printf("%s: path %s enter\n", __func__, path);
    if ((path == NULL) || (strlen(path) >= FLASH_FILE_NAME_LEN)) {
        return -1;
    }
    if (g_openFileNum >= MAX_NUM_OF_OPENED_FILES) {
        printf("\r\n_file_open: the number of open files reached max (%d)", MAX_NUM_OF_OPENED_FILES);
        return -1;
    }

    char *target_path = _path_convert(path);
    if (target_path == NULL) {
        printf("\r\n_file_open: target_path is null");
        return -1;
    }
    int newMode = _mode_convert(oflag);
    int fd = open(target_path, newMode);
    // printf("%s: target_path %s fd %d\n", __func__, target_path, fd);
    free(target_path);
    target_path = NULL;
    if (fd < 0) {
        return -1;
    }
    g_openFileNum ++;
    return fd+1;
}

int HalFileClose(int fd)
{
    int ret = 0;
    // printf("%s: enter\n", __func__);
    if (fd < 0) {
        return -1;
    }
    ret = close(fd-1);
    if (ret) {
        return -1;
    }
    g_openFileNum --;
    return ret;
}

int HalFileRead(int fd, char* buf, unsigned int len)
{
    int ret = 0;
    // printf("%s: enter\n", __func__);
    if (fd < 0 || (buf == NULL) || (len == 0)) {
        return -1;
    }
    ret = read(fd-1, buf, len);
    return ret;
}

int HalFileWrite(int fd, const char* buf, unsigned int len)
{
    int ret = 0;
    // printf("%s: enter\n", __func__);
    if (fd < 0 || (buf == NULL) || (len == 0)) {
        return -1;
    }
    ret = write(fd-1, buf, len);
    return ret;
}

int HalFileDelete(const char* path)
{
    int ret = 0;
    // printf("%s: path %s enter\n", __func__, path);
    if ((path == NULL) || (strlen(path) >= FLASH_FILE_NAME_LEN)) {
        printf("\r\nHalFileDelete: input invalid parameter");
        return -1;
    }

    char *target_path = _path_convert(path);
    if (target_path == NULL) {
        printf("\r\n_file_open: target_path is null");
        return -1;
    }
    ret = unlink(target_path);
    free(target_path);
    return ret;
}

int HalFileStat(const char* path, unsigned int* fileSize)
{
    // printf("%s: path %s enter\n", __func__, path);
    if ((path == NULL) || (strlen(path) >= FLASH_FILE_NAME_LEN)) {
        return -1;
    }

    char *target_path = _path_convert(path);
    if (target_path == NULL) {
        printf("\r\n_file_open: target_path is null");
        return -1;
    }
    struct stat info = {0};
    if (stat(target_path, &info) != F_OK) {
        free(target_path);
        return -1;
    }
    free(target_path);
    *fileSize = info.st_size;
    return 0;
}

int HalFileSeek(int fd, int offset, unsigned int whence)
{
    int ret = 0;
    // printf("%s: enter\n", __func__);
    if (fd < 0) {
        return -1;
    }
    ret = lseek(fd-1, offset, whence);
    if (ret < 0) {
        return -1;
    }
    struct stat info = {0};
    if (fstat(fd-1, &info) != F_OK) {
        return -1;
    }
    if (ret > info.st_size) {
        return -1;
    }
    return ret;
}
#if 0
int WM_KvRead(const char* path, char* buf, unsigned int len)
{
    int fd = HalFileOpen(path, O_RDWR_FS | O_CREAT_FS, 0);
    if (fd < 0) {
        printf("\r\nWM_KvRead: open fail");
        return -1;
    }
    int ret = HalFileRead(fd, buf, len);
    if (ret < 0) {
        printf("\r\nWM_KvRead: read fail");
    }
    HalFileClose(fd);
    return ret;
}

int WM_KvWrite(const char* path, char* buf, unsigned int len)
{
    int fd = HalFileOpen(path, O_RDWR_FS | O_CREAT_FS, 0);
    if (fd < 0) {
        printf("\r\nWM_KvWrite: open fail");
        return -1;
    }
    int ret = HalFileWrite(fd, buf, len);
    if (ret < 0) {
        printf("\r\nWM_KvWrite: write fail");
    }
    HalFileClose(fd);
    return ret;
}

int WM_KvGetLen(const char* path, unsigned int* fileSize)
{
    return HalFileStat(path, fileSize);
}

int WM_KvDelete(const char* path)
{
    return HalFileDelete(path);
}
#endif
