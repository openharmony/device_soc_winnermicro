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

#include <stddef.h>
#include <string.h>
#include "securec.h"
#include "host/ble_uuid.h"
#include "nimble/ble.h"
#include "ble_hs_priv.h"

static const ble_uuid_t *uuid_ccc =
                BLE_UUID16_DECLARE(BLE_GATT_DSC_CLT_CFG_UUID16);

static const char *const ble_gatt_chr_f_names[] = {
    "BROADCAST",
    "READ",
    "WRITE_NO_RSP",
    "WRITE",
    "NOTIFY",
    "INDICATE",
    "AUTH_SIGN_WRITE",
    "RELIABLE_WRITE",
    "AUX_WRITE",
    "READ_ENC",
    "READ_AUTHEN",
    "READ_AUTHOR",
    "WRITE_ENC",
    "WRITE_AUTHEN",
    "WRITE_AUTHOR",
    NULL
};

static const char *const ble_gatt_dsc_f_names[] = {
    "READ",
    "WRITE",
    "READ_ENC",
    "READ_AUTHEN",
    "READ_AUTHOR",
    "WRITE_ENC",
    "WRITE_AUTHEN",
    "WRITE_AUTHOR",
    NULL
};

#define BLE_CHR_FLAGS_STR_LEN 180

static char *ble_gatts_flags_to_str(uint16_t flags, char *buf, const char *const *names)
{
    int bit;
    bool non_empty = false;
    size_t length = 0;
    buf[0] = '\0';
    strcpy_s(buf, sizeof(buf), "[");
    length += 1;

    for (bit = 0; names[bit]; ++bit) {
        if (flags & (1 << bit)) {
            length += strlen(names[bit]);
            if (length + 1 >= BLE_CHR_FLAGS_STR_LEN) {
                return buf;
            }

            if (non_empty) {
                strcat_s(buf, sizeof(buf), "|");
                length += 1;
            }

            strcat_s(buf,  sizeof(buf), names[bit]);
            non_empty = true;
        }
    }

    strcat_s(buf, sizeof(buf), "]");
    return buf;
}

#define STRINGIFY(X) #X
#define FIELD_NAME_LEN STRINGIFY(12)
#define FIELD_INDENT STRINGIFY(2)

static void ble_gatt_show_local_chr(const struct ble_gatt_svc_def *svc,
                                    uint16_t handle, char *uuid_buf, char *flags_buf)
{
    const struct ble_gatt_chr_def *chr;
    const struct ble_gatt_dsc_def *dsc;

    for (chr = svc->characteristics; chr && chr->uuid; ++chr) {
        printf("characteristic\n");
        printf("%" FIELD_INDENT "s %" FIELD_NAME_LEN "s "
               "%s\n", " ", "uuid",
               ble_uuid_to_str(chr->uuid, uuid_buf));
        printf("%" FIELD_INDENT "s %" FIELD_NAME_LEN "s "
               "%d\n", " ", "def_handle", handle);
        printf("%" FIELD_INDENT "s %" FIELD_NAME_LEN "s "
               "%d\n", " ", "val_handle", handle + 1);
        printf("%" FIELD_INDENT "s %" FIELD_NAME_LEN "s "
               "%d\n", " ", "min_key_size", chr->min_key_size);
        printf("%" FIELD_INDENT "s %" FIELD_NAME_LEN "s "
               "%s\n", " ", "flags",
               ble_gatts_flags_to_str(chr->flags,
                                      flags_buf, ble_gatt_chr_f_names));
        handle += 2;

        if ((chr->flags & BLE_GATT_CHR_F_NOTIFY) ||
                (chr->flags & BLE_GATT_CHR_F_INDICATE)) {
            printf("ccc descriptor\n");
            printf("%" FIELD_INDENT "s %" FIELD_NAME_LEN "s "
                   "%s\n", " ", "uuid",
                   ble_uuid_to_str(uuid_ccc, uuid_buf));
            printf("%" FIELD_INDENT "s %" FIELD_NAME_LEN "s "
                   "%d\n", " ", "handle", handle);
            printf("%" FIELD_INDENT "s %" FIELD_NAME_LEN "s "
                   "%d\n", " ", "min_key_size", 0);
            printf("%" FIELD_INDENT "s %" FIELD_NAME_LEN "s "
                   "%s\n", " ", "flags",
                   ble_gatts_flags_to_str(BLE_ATT_F_READ | BLE_ATT_F_WRITE,
                                          flags_buf, ble_gatt_dsc_f_names));
            handle++;
        }

        for (dsc = chr->descriptors; dsc && dsc->uuid; ++dsc) {
            printf("descriptor\n");
            printf("%" FIELD_INDENT "s %" FIELD_NAME_LEN "s "
                   "%s\n", " ", "uuid",
                   ble_uuid_to_str(dsc->uuid, uuid_buf));
            printf("%" FIELD_INDENT "s %" FIELD_NAME_LEN "s "
                   "%d\n", " ", "handle", handle);
            printf("%" FIELD_INDENT "s %" FIELD_NAME_LEN "s "
                   "%d\n", " ", "min_key_size", dsc->min_key_size);
            printf("%" FIELD_INDENT "s %" FIELD_NAME_LEN "s "
                   "%s\n", " ", "flags",
                   ble_gatts_flags_to_str(dsc->att_flags,
                                          flags_buf, ble_gatt_dsc_f_names));
            handle++;
        }
    }
}

static int ble_gatt_show_local_inc_svc(const struct ble_gatt_svc_def *svc,
                                       uint16_t handle, char *uuid_buf)
{
    const struct ble_gatt_svc_def **includes;
    int num = 0;

    for (includes = &svc->includes[0]; *includes != NULL; ++includes) {
        printf("included service\n");
        printf("%" FIELD_INDENT "s %" FIELD_NAME_LEN "s "
               "%s\n", " ", "uuid",
               ble_uuid_to_str((*includes)->uuid, uuid_buf));
        printf("%" FIELD_INDENT "s %" FIELD_NAME_LEN "s "
               "%d\n", " ", "attr handle", handle);
        ++num;
    }

    return num;
}

static void ble_gatt_show_local_svc(const struct ble_gatt_svc_def *svc,
                                    uint16_t handle, uint16_t end_group_handle,
                                    void *arg)
{
    uint16_t handle_tmp = handle;
    char uuid_buf[BLE_UUID_STR_LEN];
    char flags_buf[BLE_CHR_FLAGS_STR_LEN];
    printf("%s service\n",
           svc->type == BLE_GATT_SVC_TYPE_PRIMARY ?
           "primary" : "secondary");
    printf("%" FIELD_INDENT "s %" FIELD_NAME_LEN "s "
           "%s\n", " ", "uuid",
           ble_uuid_to_str(svc->uuid, uuid_buf));
    printf("%" FIELD_INDENT "s %" FIELD_NAME_LEN "s "
           "%d\n", " ", "handle",
           handle_tmp);
    printf("%" FIELD_INDENT "s %" FIELD_NAME_LEN "s "
           "%d\n", " ", "end_handle",
           end_group_handle);
    handle_tmp++;

    if (svc->includes) {
        handle_tmp += ble_gatt_show_local_inc_svc(svc, handle_tmp, uuid_buf);
    }

    ble_gatt_show_local_chr(svc, handle_tmp,
                            uuid_buf, flags_buf);
}

void ble_gatts_show_local(void)
{
    ble_gatts_lcl_svc_foreach(ble_gatt_show_local_svc, NULL);
}