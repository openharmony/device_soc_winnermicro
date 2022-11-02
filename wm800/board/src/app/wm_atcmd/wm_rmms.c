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
#include <stdio.h>
#include <string.h>

#include "wm_mem.h"
#if (GCC_COMPILE==1)
#include "wm_cmdp_hostif_gcc.h"
#else
#include "wm_cmdp_hostif.h"
#endif
#include "wm_wl_task.h"
#include "wm_rmms.h"

#if TLS_CONFIG_RMMS

#ifdef  RMMS_DEBUG
#define RMMS_PRINT printf
#else
#define RMMS_PRINT(s, ...)
#endif

static const u8 SysSuperPass[] = "^$#^%&";  /* Shift <643657> */
static struct udp_pcb *rmms_pcb = NULL;

extern struct task_parameter wl_task_param_hostif;
static void tls_proc_rmms(struct rmms_msg *msg)
{
    int err;
    struct tls_hostif *hif = tls_get_hostif();

    if (0 == hif->rmms_status) {
        hif->rmms_status = 1;
        err = tls_hostif_cmd_handler(HOSTIF_RMMS_AT_CMD, (char *)msg,
                                     6 + strlen((char *)(msg->CmdStr)));
        if (0 != err) {
            tls_mem_free(msg);
            hif->rmms_status = 0;
        }
    }

    return;
}

static void rmms_recv(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16 port)
{
    u8 head[8];
    struct rmms_msg *at;
    int i = 0;
    int offset = 0;
    int length = p->tot_len;
    bool bPermit = FALSE;

    if (length < 2) {
        goto exit;
    }

    pbuf_copy_partial(p, head, 2, 0);

    if (strncmp((char *)head, (char *)SysSuperPass, 2) == 0) {
        if (length >= 8) {
            pbuf_copy_partial(p, &head[2], 6, 2);
            if (strncmp((char *)head, (char *)SysSuperPass, 6) == 0) {
                offset = 6;
                bPermit = TRUE;
                RMMS_PRINT("Administrator come in\n\r");
            }
        }
    } else {
        RMMS_PRINT("Function is disabled, dropped\n\r");
    }

#ifdef RMMS_DEBUG
    if (((head[0] == 'A')||(head[0] == 'a'))&&((head[1] == 'T')||(head[1] == 't'))) {
        offset = 0;
        bPermit = TRUE;
        RMMS_PRINT("Debug mode come in\n\r");
    }
#endif

    if (bPermit) {
        RMMS_PRINT("At cmd from %s\n\r", ip_ntoa(addr));

        at = tls_mem_alloc(sizeof(struct rmms_msg));
        if (at == NULL) {
            RMMS_PRINT("Not enough memory, dropped\n\r");
            goto exit;
        }
        memset(at, 0, sizeof(struct rmms_msg));

        at->SrcAddr[0] = (addr->addr) & 0xff;
        at->SrcAddr[1] = ((addr->addr)>>8) & 0xff;
        at->SrcAddr[2] = ((addr->addr)>>16) & 0xff;
        at->SrcAddr[3] = ((addr->addr)>>24) & 0xff;
        at->SrcAddr[4] = (port) & 0xff;
        at->SrcAddr[5] = ((port)>>8) & 0xff;

        length -= offset; 

        if (length > 512) {
            length = 512;
        }

        pbuf_copy_partial(p, &at->CmdStr[0], length, offset);

         /* at指令只认\n结尾 */
        for (i = 2; i < length; i++) {
            if ((at->CmdStr[i] == 0x0d)) {
                at->CmdStr[i] = 0x0a;
                at->CmdStr[i + 1] = 0;
                break;
            }
        }

        if(tls_wl_task_callback(&wl_task_param_hostif, (start_routine)tls_proc_rmms, at, 0)) {
            tls_mem_free(at);
        }
    }

exit:
    pbuf_free(p);

    return;
}

void RMMS_SendHedAtRsp(struct rmms_msg *Msg)
{
    int DataLen = 0;
    struct pbuf *p;
    ip_addr_t addr;
    u16 port;

    addr.addr = Msg->SrcAddr[0] + (Msg->SrcAddr[1]<<8) + (Msg->SrcAddr[2]<<16) + (Msg->SrcAddr[3]<<24);
    port = Msg->SrcAddr[4] + (Msg->SrcAddr[5]<<8);

    DataLen = strlen((char *)(Msg->CmdStr)) + 1;
    p = pbuf_alloc(PBUF_TRANSPORT, DataLen, PBUF_RAM);
    if (NULL != p) {
        pbuf_take(p, Msg->CmdStr, DataLen);
        udp_sendto(rmms_pcb, p, &addr, port);
        pbuf_free(p);
    }

    tls_mem_free(Msg);

    RMMS_PRINT("At response is sent to %s:%hu, %s\n\r", ip_ntoa(&addr), port, Msg->CmdStr);

    return;
}

s8 RMMS_Init(const struct netif *Netif)
{
    return RMMS_ERR_SUCCESS;
}

void RMMS_Fini(void)
{
    if (NULL != rmms_pcb) {
        udp_remove(rmms_pcb);
        rmms_pcb = NULL;
    }

    return;
}
#endif

