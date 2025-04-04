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

#ifndef TLS_NETCONN_H
#define TLS_NETCONN_H

#include "tls_common.h"
#include "list.h"
#include "wm_socket.h"
#include "arch/sys_arch.h"
#include "wm_netif.h"

#define TLS_NETCONN_TCP       0
#define TLS_NETCONN_UDP       1

#define RAW_SOCKET_USE_CUSTOM_PBUF  LWIP_SUPPORT_CUSTOM_PBUF

#define CONN_SEM_NOT_FREE       1

 /* A netconn descriptor */
struct tls_netconn {
    struct dl_list list;
    struct tls_socket_desc *skd;
    u8        skt_num;
    bool      used;

 /* client or server mode */
    bool      client;
    ip_addr_t addr;
    u16       port;
    u16       localport;
    u16       proto;
 /* the lwIP internal protocol control block */
    union {
        struct ip_pcb  *ip;
        struct tcp_pcb *tcp;
        struct udp_pcb *udp;
        struct raw_pcb *raw;
    } pcb;
    bool   write_state;
    u16    write_offset;
    struct tls_net_msg *current_msg;
    u8     tcp_connect_cnt;
    u8     state;
    err_t  last_err;
#if !CONN_SEM_NOT_FREE
    sys_sem_t op_completed;
#endif
    u32 idle_time;
};

struct tls_net_msg {
    struct dl_list list;
    void *dataptr;
    struct pbuf *p;
    ip_addr_t addr;
    u16       port;
    u32   len;
    u32   write_offset;
    err_t err;
    int skt_no;
};

#if (RAW_SOCKET_USE_CUSTOM_PBUF)
struct raw_sk_pbuf_custom {
    /** 'base class' */
    struct pbuf_custom pc;
    /** pointer to the original pbuf that is referenced */
    struct pbuf *original;
    /* custom pbuf free function used */
    void *conn;
    void *pcb;
};
#endif

int tls_net_init(void);
struct tls_netconn *tls_net_get_socket(u8 socket);

#endif /* end of TLS_NETCONN_H */

