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

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include "securec.h"
#include "os/os_mbuf.h"
#include "nimble/ble.h"
#include "ble_hs_priv.h"
#include "host/ble_uuid.h"

static uint8_t ble_uuid_base[16] = {
    0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80,
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

#if MYNEWT_VAL(BLE_HS_DEBUG)
#define VERIFY_UUID(uuid)                       \
    assert((uuid->type == BLE_UUID_TYPE_16) ||  \
           (uuid->type == BLE_UUID_TYPE_32) ||  \
           (uuid->type == BLE_UUID_TYPE_128))
#else
#define VERIFY_UUID(uuid)
#endif

int ble_uuid_init_from_buf(ble_uuid_any_t *uuid, const void *buf, size_t len)
{
    switch (len) {
        case 2: // 2:case value
            uuid->u.type = BLE_UUID_TYPE_16;
            uuid->u16.value = get_le16(buf);
            return 0;

        case 4: // 4:case value
            uuid->u.type = BLE_UUID_TYPE_32;
            uuid->u32.value = get_le32(buf);
            return 0;

        case 16: // 16:case value
            uuid->u.type = BLE_UUID_TYPE_128;
            memcpy_s(uuid->u128.value, sizeof(uuid->u128.value), buf, 16); // 16:size
            return 0;
        default:
            break;
    }

    return BLE_HS_EINVAL;
}

int ble_uuid_cmp(const ble_uuid_t *uuid1, const ble_uuid_t *uuid2)
{
    VERIFY_UUID(uuid1);
    VERIFY_UUID(uuid2);

    if (uuid1->type != uuid2->type) {
        return uuid1->type - uuid2->type;
    }

    switch (uuid1->type) {
        case BLE_UUID_TYPE_16:
            return (int) BLE_UUID16(uuid1)->value - (int) BLE_UUID16(uuid2)->value;

        case BLE_UUID_TYPE_32:
            return (int) BLE_UUID32(uuid1)->value - (int) BLE_UUID32(uuid2)->value;

        case BLE_UUID_TYPE_128:
            return memcmp(BLE_UUID128(uuid1)->value, BLE_UUID128(uuid2)->value, 16); // 16:size
        
        default:
            break;
    }

    BLE_HS_DBG_ASSERT(0);
    return -1;
}

void ble_uuid_copy(ble_uuid_any_t *dst, const ble_uuid_t *src)
{
    VERIFY_UUID(src);

    switch (src->type) {
        case BLE_UUID_TYPE_16:
            dst->u16 = *(const ble_uuid16_t *)src;
            break;

        case BLE_UUID_TYPE_32:
            dst->u32 = *(const ble_uuid32_t *)src;
            break;

        case BLE_UUID_TYPE_128:
            dst->u128 = *(const ble_uuid128_t *)src;
            break;

        default:
            BLE_HS_DBG_ASSERT(0);
            break;
    }
}

char *ble_uuid_to_str(const ble_uuid_t *uuid, char *dst)
{
    const uint8_t *u8p;

    switch (uuid->type) {
        case BLE_UUID_TYPE_16:
            sprintf_s(dst, sizeof(*dst), "0x%04x", BLE_UUID16(uuid)->value);
            break;

        case BLE_UUID_TYPE_32:
            sprintf_s(dst, sizeof(*dst), "0x%08x", BLE_UUID32(uuid)->value);
            break;

        case BLE_UUID_TYPE_128:
            u8p = BLE_UUID128(uuid)->value;
            sprintf_s(dst, sizeof(*dst), "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
                    "%02x%02x%02x%02x%02x%02x",
                    u8p[15], u8p[14], // 15:array element, 14:array element
                    u8p[13], u8p[12], // 13:array element, 12:array element
                    u8p[11], u8p[10], // 11:array element, 10:array element
                    u8p[9],  u8p[8], // 9:array element, 9:array element
                    u8p[7],  u8p[6], // 7:array element, 6:array element
                    u8p[5],  u8p[4], // 5:array element, 4:array element
                    u8p[3],  u8p[2], // 3:array element, 2:array element
                    u8p[1],  u8p[0]);
            break;

        default:
            dst[0] = '\0';
            break;
    }

    return dst;
}

uint16_t ble_uuid_u16(const ble_uuid_t *uuid)
{
    VERIFY_UUID(uuid);
    return uuid->type == BLE_UUID_TYPE_16 ? BLE_UUID16(uuid)->value : 0;
}

/* APIs below are private (ble_uuid_priv.h) */

int ble_uuid_init_from_att_mbuf(ble_uuid_any_t *uuid, struct os_mbuf *om, int off, int len)
{
    uint8_t val[16];
    int rc;
    rc = os_mbuf_copydata(om, off, len, val);
    if (rc != 0) {
        return rc;
    }

    rc = ble_uuid_init_from_att_buf(uuid, val, len);
    return rc;
}

int ble_uuid_init_from_att_buf(ble_uuid_any_t *uuid, const void *buf, size_t len)
{
    int rc = 0;

    if (len == 2) { // 2:Analyzing conditions
        uuid->u.type = BLE_UUID_TYPE_16;
        uuid->u16.value = get_le16(buf);
    } else if (len == 16) { // 16:Analyzing conditions
        uuid->u.type = BLE_UUID_TYPE_128;
        memcpy_s(uuid->u128.value, sizeof(uuid->u128.value), buf, 16); // 16:size
    } else {
        rc = BLE_HS_EINVAL;
    }

    return rc;
}

int ble_uuid_to_any(const ble_uuid_t *uuid, ble_uuid_any_t *uuid_any)
{
    VERIFY_UUID(uuid);
    uuid_any->u.type = uuid->type;

    switch (uuid->type) {
        case BLE_UUID_TYPE_16:
            uuid_any->u16.value = BLE_UUID16(uuid)->value;
            break;

        case BLE_UUID_TYPE_32:
            uuid_any->u32.value = BLE_UUID32(uuid)->value;
            break;

        case BLE_UUID_TYPE_128:
            memcpy_s(uuid_any->u128.value, sizeof(uuid_any->u128.value), BLE_UUID128(uuid)->value, 16); // 16:size
            break;

        default:
            break;
    }

    return 0;
}

int ble_uuid_to_mbuf(const ble_uuid_t *uuid, struct os_mbuf *om)
{
    int len;
    void *buf;
    VERIFY_UUID(uuid);
    len = ble_uuid_length(uuid);
    buf = os_mbuf_extend(om, len);
    if (buf == NULL) {
        return BLE_HS_ENOMEM;
    }

    ble_uuid_flat(uuid, buf);
    return 0;
}

int ble_uuid_flat(const ble_uuid_t *uuid, void *dst)
{
    VERIFY_UUID(uuid);

    switch (uuid->type) {
        case BLE_UUID_TYPE_16:
            put_le16(dst, BLE_UUID16(uuid)->value);
            break;

        case BLE_UUID_TYPE_32:
            memcpy_s(dst, sizeof(*dst), ble_uuid_base, 16); // 16:size
            put_le32((uint8_t *)dst + 12, BLE_UUID32(uuid)->value); // 12:byte alignment
            break;

        case BLE_UUID_TYPE_128:
            memcpy_s(dst, sizeof(*dst), BLE_UUID128(uuid)->value, 16); // 16:size
            break;

        default:
            return BLE_HS_EINVAL;
    }

    return 0;
}

int ble_uuid_length(const ble_uuid_t *uuid)
{
    VERIFY_UUID(uuid);
    return uuid->type >> 3; // 3:byte alignment
}