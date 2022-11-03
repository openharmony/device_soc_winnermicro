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
#include "wm_mem.h"
#if (GCC_COMPILE == 1)
#include "wm_cmdp_hostif_gcc.h"
#else
#include "wm_cmdp_hostif.h"
#endif
#include "wm_wl_task.h"
#include "wm_rmms.h"

#define TWO 2
#define THREE 3
#define FOUR 4
#define FIVE 5
#define SIX 6
#define EIGHT 8
#define SIXTEEN 16
#define TWENTY_FOUR 24
#define FIVE_HUNDRED_AND_TWELVE 512

#if TLS_CONFIG_RMMS

#ifdef  RMMS_DEBUG
#define RMMS_PRINT printf
#else
#define RMMS_PRINT(s, ...)
#endif

static const u8 SysSuperPass[] = "^$#^%&";  /* Shift <643657> */
static struct udp_pcb *rmms_pcb = NULL;

static void tls_proc_rmms(struct rmms_msg *msg)
{
    int err;
    struct tls_hostif *hif = tls_get_hostif();

    if (hif->rmms_status == 0) {
        hif->rmms_status = 1;
        err = tls_hostif_cmd_handler(HOSTIF_RMMS_AT_CMD, (char *)msg,
                                     SIX + strlen((char *)(msg->CmdStr)));
        if (err != 0) {
            tls_mem_free(msg);
            hif->rmms_status = 0;
        }
    }

    return;
}

static void rmms_recv(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16 port)
{
    return;
}

void RMMS_SendHedAtRsp(struct rmms_msg *Msg)
{
    int DataLen = 0;
    struct pbuf *p;
    ip_addr_t addr;
    u16 port;

    addr.addr = Msg->SrcAddr[0] + (Msg->SrcAddr[1] << EIGHT) + (Msg->SrcAddr[TWO] << SIXTEEN) + (Msg->SrcAddr[THREE] << TWENTY_FOUR);
    port = Msg->SrcAddr[FOUR] + (Msg->SrcAddr[FIVE] << EIGHT);

    DataLen = strlen((char *)(Msg->CmdStr)) + 1;
    p = pbuf_alloc(PBUF_TRANSPORT, DataLen, PBUF_RAM);
    if (p != NULL) {
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
    if (rmms_pcb != NULL) {
        udp_remove(rmms_pcb);
        rmms_pcb = NULL;
    }

    return;
}
#endif

