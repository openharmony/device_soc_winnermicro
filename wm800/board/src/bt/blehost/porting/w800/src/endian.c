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

#include "os/endian.h"

void put_le16(void *buf, uint16_t x)
{
    uint8_t *u8ptr;
    u8ptr = buf;
    u8ptr[0] = (uint8_t)x;
    u8ptr[1] = (uint8_t)(x >> 8); // 8:byte alignment
}

void put_le24(void *buf, uint32_t x)
{
    uint8_t *u8ptr;
    u8ptr = buf;
    u8ptr[0] = (uint8_t)x;
    u8ptr[1] = (uint8_t)(x >> 8); // 8:byte alignment
    u8ptr[2] = (uint8_t)(x >> 16); // 2:array element, 8:byte alignment
}

void put_le32(void *buf, uint32_t x)
{
    uint8_t *u8ptr;
    u8ptr = buf;
    u8ptr[0] = (uint8_t)x;
    u8ptr[1] = (uint8_t)(x >> 8); // 8:byte alignment
    u8ptr[2] = (uint8_t)(x >> 16); // 2:array element, 16:byte alignment
    u8ptr[3] = (uint8_t)(x >> 24); // 3:array element, 24:byte alignment
}

void put_le64(void *buf, uint64_t x)
{
    uint8_t *u8ptr;
    u8ptr = buf;
    u8ptr[0] = (uint8_t)x;
    u8ptr[1] = (uint8_t)(x >> 8); // 8:byte alignment
    u8ptr[2] = (uint8_t)(x >> 16); // 2:array element, 8:byte alignment
    u8ptr[3] = (uint8_t)(x >> 24); // 2:array element, 8:byte alignment
    u8ptr[4] = (uint8_t)(x >> 32); // 2:array element, 8:byte alignment
    u8ptr[5] = (uint8_t)(x >> 40); // 2:array element, 8:byte alignment
    u8ptr[6] = (uint8_t)(x >> 48); // 2:array element, 8:byte alignment
    u8ptr[7] = (uint8_t)(x >> 56); // 2:array element, 8:byte alignment
}

uint16_t get_le16(const void *buf)
{
    const uint8_t *u8ptr;
    uint16_t x;
    u8ptr = buf;
    x = u8ptr[0];
    x |= (uint16_t)u8ptr[1] << 8; // 8:byte alignment
    return x;
}

uint32_t get_le24(const void *buf)
{
    const uint8_t *u8ptr;
    uint32_t x;
    u8ptr = buf;
    x = u8ptr[0];
    x |= (uint32_t)u8ptr[1] << 8; // 8:byte alignment
    x |= (uint32_t)u8ptr[2] << 16;
    return x;
}

uint32_t get_le32(const void *buf)
{
    const uint8_t *u8ptr;
    uint32_t x;
    u8ptr = buf;
    x = u8ptr[0];
    x |= (uint32_t)u8ptr[1] << 8; // 8:byte alignment
    x |= (uint32_t)u8ptr[2] << 16; // 2:array element, 16:byte alignment
    x |= (uint32_t)u8ptr[3] << 24; // 3:array element, 24:byte alignment
    return x;
}

uint64_t get_le64(const void *buf)
{
    const uint8_t *u8ptr;
    uint64_t x;
    u8ptr = buf;
    x = u8ptr[0];
    x |= (uint64_t)u8ptr[1] << 8; // 8:byte alignment
    x |= (uint64_t)u8ptr[2] << 16; // 2:array element, 8:byte alignment
    x |= (uint64_t)u8ptr[3] << 24; // 3:array element, 24:byte alignment
    x |= (uint64_t)u8ptr[4] << 32; // 4:array element, 32:byte alignment
    x |= (uint64_t)u8ptr[5] << 40; // 5:array element, 40:byte alignment
    x |= (uint64_t)u8ptr[6] << 48; // 6:array element, 48:byte alignment
    x |= (uint64_t)u8ptr[7] << 56; // 7:array element, 56:byte alignment
    return x;
}

void put_be16(void *buf, uint16_t x)
{
    uint8_t *u8ptr;
    u8ptr = buf;
    u8ptr[0] = (uint8_t)(x >> 8); // 8:byte alignment
    u8ptr[1] = (uint8_t)x;
}

void put_be24(void *buf, uint32_t x)
{
    uint8_t *u8ptr;
    u8ptr = buf;
    u8ptr[0] = (uint8_t)(x >> 24); // 24:byte alignment
    u8ptr[1] = (uint8_t)(x >> 16); // 16:byte alignment
    u8ptr[2] = (uint8_t)(x >> 8); // 2:array element, 8:byte alignment
}

void put_be32(void *buf, uint32_t x)
{
    uint8_t *u8ptr;
    u8ptr = buf;
    u8ptr[0] = (uint8_t)(x >> 24); // 24:byte alignment
    u8ptr[1] = (uint8_t)(x >> 16); // 16:byte alignment
    u8ptr[2] = (uint8_t)(x >> 8); // 2:array element, 8:byte alignment
    u8ptr[3] = (uint8_t)x; // 3:array element
}

void put_be64(void *buf, uint64_t x)
{
    uint8_t *u8ptr;
    u8ptr = buf;
    u8ptr[0] = (uint8_t)(x >> 56); // 56:byte alignment
    u8ptr[1] = (uint8_t)(x >> 48); // 48:byte alignment
    u8ptr[2] = (uint8_t)(x >> 40); // 2:array element, 40:byte alignment
    u8ptr[3] = (uint8_t)(x >> 32); // 3:array element, 32:byte alignment
    u8ptr[4] = (uint8_t)(x >> 24); // 4:array element, 24:byte alignment
    u8ptr[5] = (uint8_t)(x >> 16); // 5:array element, 16:byte alignment
    u8ptr[6] = (uint8_t)(x >> 8); // 6:array element, 8:byte alignment
    u8ptr[7] = (uint8_t)x; // 7:array element
}

uint16_t get_be16(const void *buf)
{
    const uint8_t *u8ptr;
    uint16_t x;
    u8ptr = buf;
    x = (uint16_t)u8ptr[0] << 8; // 8:byte alignment
    x |= u8ptr[1];
    return x;
}

uint32_t get_be24(const void *buf)
{
    const uint8_t *u8ptr;
    uint32_t x;
    u8ptr = buf;
    x = (uint32_t)u8ptr[0] << 24; // 24:byte alignment
    x |= (uint32_t)u8ptr[1] << 16; // 16:byte alignment
    x |= (uint32_t)u8ptr[2] << 8; // 2:array element, 8:byte alignment
    return x;
}

uint32_t get_be32(const void *buf)
{
    const uint8_t *u8ptr;
    uint32_t x;
    u8ptr = buf;
    x = (uint32_t)u8ptr[0] << 24; // 24:byte alignment
    x |= (uint32_t)u8ptr[1] << 16; // 16:byte alignment
    x |= (uint32_t)u8ptr[2] << 8; // 2:array element, 8:byte alignment
    x |= u8ptr[3]; // 3:array element
    return x;
}

uint64_t get_be64(const void *buf)
{
    const uint8_t *u8ptr;
    uint64_t x;
    u8ptr = buf;
    x = (uint64_t)u8ptr[0] << 56; // 56:byte alignment
    x |= (uint64_t)u8ptr[1] << 48; // 48:byte alignment
    x |= (uint64_t)u8ptr[2] << 40; // 2:array element, 40:byte alignment
    x |= (uint64_t)u8ptr[3] << 32; // 3:array element, 32:byte alignment
    x |= (uint64_t)u8ptr[4] << 24; // 4:array element, 24:byte alignment
    x |= (uint64_t)u8ptr[5] << 16; // 5:array element, 16:byte alignment
    x |= (uint64_t)u8ptr[6] << 8; // 6:array element, 8:byte alignment
    x |= u8ptr[7]; // 7:array element
    return x;
}
void swap_in_place(void *buf, int len)
{
    uint8_t *u8ptr;
    int i;
    int j;
    u8ptr = buf;

    for (i = 0, j = len - 1; i < j; i++, j--) {
        uint8_t tmp;
        tmp = u8ptr[i];
        u8ptr[i] = u8ptr[j];
        u8ptr[j] = tmp;
    }
}

/* swap octets */
void swap_buf(uint8_t *dst, const uint8_t *src, int len)
{
    int i;

    for (i = 0; i < len; i++) {
        dst[len - 1 - i] = src[i];
    }
}