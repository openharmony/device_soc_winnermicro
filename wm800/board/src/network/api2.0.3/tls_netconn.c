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
#include "wm_config.h"

#if TLS_CONFIG_SOCKET_RAW

#include "tls_netconn.h"
#include "wm_debug.h"
#include <string.h>
#include "ip_addr.h"
#include "wm_mem.h"

#define FOUR 4

#define TCP_WRITE_FLAG_COPY 0x01
#define TCP_WRITE_FLAG_MORE 0x02

struct tls_netconn *p_net_conn[TLS_MAX_NETCONN_NUM];
#if CONN_SEM_NOT_FREE
sys_sem_t conn_op_completed[TLS_MAX_NETCONN_NUM] = {NULL};
#endif

static void net_tcp_err_cb(void *arg, err_t err);
static err_t net_tcp_poll_cb(void *arg, struct tcp_pcb *pcb);
static void net_free_socket(int socketno);

u32 current_src_ip = 0;
void tls_net_set_sourceip(u32 ipvalue)
{
    current_src_ip = ipvalue;
}

u32 tls_net_get_sourceip(void)
{
    return current_src_ip;
}

struct tls_netconn *get_server_conn(struct tls_netconn *conn)
{
    struct tls_netconn *server_conn = NULL;

    do {
        server_conn = dl_list_first(&conn->list, struct tls_netconn, list);
        conn = server_conn;
    } while ((server_conn != NULL) && server_conn->client);

    return server_conn;
}

static struct tls_netconn *net_alloc_socket(struct tls_netconn *conn)
{
    int sock = -1, i = 0, j = 0;
    u32 cpu_sr;
    struct tls_netconn *conn_t = NULL;

    for (i = 0; i < TLS_MAX_NETCONN_NUM; i++) {
        if (p_net_conn[i] == NULL) {
            sock = i;
            break;
        }
    }

    if (i == TLS_MAX_NETCONN_NUM) {
        TLS_DBGPRT_ERR("\nnet_alloc_socket error\n");
        return NULL;
    }

    if (conn != NULL) {
        j = dl_list_len(&conn->list);
        if (j >= FOUR) {
            TLS_DBGPRT_ERR("list len > 4\n");
            sock = -1;
        }
    }

    if (sock < 0) {
        TLS_DBGPRT_ERR("sock < 0\n");
        return NULL;
    }
    cpu_sr = tls_os_set_critical();
    conn_t = tls_mem_alloc(sizeof(struct tls_netconn));
    tls_os_release_critical(cpu_sr);
    if (conn_t != NULL) {
        p_net_conn[sock] = conn_t;
        memset(conn_t, 0, sizeof(struct tls_netconn));
        conn_t->used = true;
        conn_t->state = NETCONN_STATE_NONE;
        conn_t->skt_num = sock + 1;  /* TLS_MAX_NETCONN_NUM + */
        dl_list_init(&conn_t->list);
#if CONN_SEM_NOT_FREE
        TLS_DBGPRT_INFO("conn_op_completed[%d]=%x\n", sock, (u32)conn_op_completed[sock]);
        if (conn_op_completed[sock] == NULL) {
            if (sys_sem_new(&conn_op_completed[sock], 0) != ERR_OK) {
                net_free_socket(conn_t->skt_num);
            }
        }
#else
        if (sys_sem_new(&conn_t->op_completed, 0) != ERR_OK) {
            net_free_socket(conn_t->skt_num);
        }
#endif
    }
    TLS_DBGPRT_INFO("net_alloc_socket conn ptr = 0x%x\n", (u32)conn_t);
    return conn_t;
}

static void net_free_socket(int socketno)
{
    int index;
    u32 cpu_sr;
    struct tls_netconn *conn = NULL;

    conn = tls_net_get_socket(socketno);
    if (conn == NULL || TRUE != conn->used) {
        TLS_DBGPRT_ERR("\nconn=%x,used=%d\n", (u32)conn, conn->used);
        return;
    }
    TLS_DBGPRT_INFO("conn ptr = 0x%x\n", (u32)conn);
#if !CONN_SEM_NOT_FREE
    if (conn->op_completed != NULL) {
        sys_sem_free(&conn->op_completed);
    }
#endif
    conn->used = false;
    if (conn->client && conn->list.prev != NULL && conn->list.prev != &conn->list) {
        TLS_DBGPRT_INFO("del from list.\n");
        cpu_sr = tls_os_set_critical();
        dl_list_del(&conn->list);
        tls_os_release_critical(cpu_sr);
    }
    index = conn->skt_num - 1;    /* TLS_MAX_NETCONN_NUM */
    if (conn->pcb.tcp) {
        tcp_close(conn->pcb.tcp);
        conn->pcb.tcp = NULL;
    }
    tls_mem_free(conn);
    cpu_sr = tls_os_set_critical();
    conn = NULL;
    p_net_conn[index] = NULL;
    tls_os_release_critical(cpu_sr);
}

static void net_send_event_to_hostif (struct tls_netconn *conn, int event)
{
    struct tls_socket_desc *skt_desc = conn->skd;
    TLS_DBGPRT_INFO("skt_desc->state_changed: 0x%x, event=%d\n", (u32)skt_desc->state_changed, event);
    if (skt_desc->state_changed) {
        skt_desc->state_changed(conn->skt_num, event, conn->state);
    }
}

static void net_tcp_close_connect(int socketno)
{
}

static err_t net_tcp_poll_cb(void *arg, struct tcp_pcb *pcb)
{
    return ERR_OK;
}

static void net_tcp_err_cb(void *arg, err_t err)
{
    struct tls_netconn *conn = NULL;
    struct tcp_pcb *pcb = NULL;
    int socketno = (int)arg;
    u8 event = NET_EVENT_TCP_CONNECT_FAILED;

    conn = tls_net_get_socket(socketno);
    if (conn == NULL || TRUE != conn->used) {
        TLS_DBGPRT_ERR("\nconn=%x,used=%d\n", (u32)conn, conn->used);
        return;
    }
    pcb = conn->pcb.tcp;
    TLS_DBGPRT_INFO("tcp err = %d, pcb==%x, conn==%x, skt==%x\n", err, (u32)pcb, (u32)conn, (u32)conn->skd);

    if (pcb) {
        tcp_arg(pcb, NULL);
        tcp_sent(pcb, NULL);
        tcp_recv(pcb, NULL);
        tcp_err(pcb, NULL);
        if (!conn->client) {
            tcp_accept(pcb, NULL);
        }
        if (err == ERR_OK) {
            tcp_close(pcb);
        }
        if (conn->state != NETCONN_STATE_NONE) {
            conn->state = NETCONN_STATE_NONE;
            event = NET_EVENT_TCP_DISCONNECT;
        }

        net_send_event_to_hostif (conn, event);
        if (conn->skd->errf != NULL) {
            conn->skd->errf(conn->skt_num, err);
        }
        conn->pcb.tcp = NULL;
        net_free_socket(socketno);
    }
}

#if (RAW_SOCKET_USE_CUSTOM_PBUF)
static struct raw_sk_pbuf_custom *raw_sk_alloc_pbuf_custom(void)
{
    return (struct raw_sk_pbuf_custom*)mem_malloc(sizeof(struct raw_sk_pbuf_custom));
}

static void raw_sk_free_pbuf_custom(struct raw_sk_pbuf_custom* p)
{
    if (p != NULL) {
        mem_free(p);
        p = NULL;
    }
}

static void raw_sk_free_pbuf_custom_fn(struct pbuf *p)
{
    struct raw_sk_pbuf_custom *pcr = (struct raw_sk_pbuf_custom *)p;

    if (p != NULL) {
        if (TRUE == ((struct tls_netconn *)pcr->conn)->used &&
            pcr->pcb == ((struct tls_netconn *)pcr->conn)->pcb.tcp) {
            tcp_recved((struct tcp_pcb *)pcr->pcb, p->tot_len);
        }

        if (pcr->original != NULL) {
            pbuf_free(pcr->original);
        }
        raw_sk_free_pbuf_custom(pcr);
    }
}
#endif

/**
 * Receive callback function for TCP connect.
 */
static err_t net_tcp_recv_cb(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    return;
}

/**
 * tcp connnect callback
 */
static err_t net_tcp_connect_cb(void *arg, struct tcp_pcb *pcb, err_t err)
{
    struct tls_netconn *conn;
    err_t  err_ret = ERR_OK;
    int socketno = -1;

    socketno = (int)arg;
    conn = tls_net_get_socket(socketno);
    if (conn == NULL || conn->used != TRUE) {
        TLS_DBGPRT_ERR("\nconn=%x,used=%d\n", (u32)conn, conn->used);
        tcp_abort(pcb);
        return ERR_ABRT;
    }

    if ((conn->proto == TLS_NETCONN_TCP) && (err == ERR_OK)) {
        TLS_DBGPRT_INFO("net_tcp_connect_cb =====> state : %d\n", pcb->state);
        conn->state = NETCONN_STATE_CONNECTED;
        net_send_event_to_hostif(conn, NET_EVENT_TCP_CONNECTED);
    } else {
        TLS_DBGPRT_INFO("the err is =%d\n", err);
    }

    if (conn->skd != NULL && conn->skd->connf != NULL) {
        err_ret = conn->skd->connf(conn->skt_num, err);
        if (err_ret == ERR_ABRT) {
            tcp_abort(pcb);
        }
        return err_ret;
    }

    return err;
}

/**
 * Accept callback function for TCP netconns.
 */
static err_t net_tcp_accept_cb(void *arg, struct tcp_pcb *newpcb, err_t err)
{
    return;
}

/**
 * Start create TCP connection
 */
static err_t net_tcp_start(struct tls_netconn *conn)
{
    return;
}

/**
 * Start create UDP connection
 */
static err_t net_udp_start(struct tls_netconn *conn)
{
    return ERR_OK;
}

static err_t net_skt_tcp_send(struct tls_net_msg *net_msg)
{
    struct tcp_pcb *pcb = NULL;
    struct tls_netconn *conn;
    err_t err;

    conn = tls_net_get_socket(net_msg->skt_no);
    if (conn == NULL || TRUE != conn->used) {
        TLS_DBGPRT_ERR("conn =%x,used=%d\n", (u32)conn, conn->used);
        return ERR_ARG;
    }
    pcb = conn->pcb.tcp;
    /*
        When tcp error occured, lwip will delete the pcb and sometimes GSKT.
        This function maybe registered by GSKT_TimerSend, so we must check if GSKT has been delted!!!
    */
    err = tcp_write(pcb, net_msg->dataptr, net_msg->len, TCP_WRITE_FLAG_COPY);
    if (err == ERR_OK) {
        tcp_output(pcb);
    } else {
    }
    return err;
}

/**
 * Send data on a UDP pcb
 */
static void net_do_send(void *ctx)
{
    struct tls_net_msg *msg = (struct tls_net_msg *)ctx;
    struct tls_netconn *conn = NULL;
    struct pbuf *p;
    int socketno = msg->skt_no;

    p = msg->p;
    conn = tls_net_get_socket(socketno);
    if (conn == NULL || TRUE != conn->used) {
        TLS_DBGPRT_ERR("conn =%x,used=%d\n", (u32)conn, conn->used);
        if (p) {
            pbuf_free(p);
        }
#if CONN_SEM_NOT_FREE
        sys_sem_signal(&conn_op_completed[socketno - 1]);
#endif
        return;
    }
#if LWIP_CHECKSUM_ON_COPY
    if (ip_addr_isany(&msg->addr)) {
        msg->err = udp_send_chksum(conn->pcb.udp, p, 0, 0);
    } else {
        msg->err = udp_sendto_chksum(conn->pcb.udp, p, &msg->addr, msg->port, 0, 0);
    }
#else /* LWIP_CHECKSUM_ON_COPY */
    if (ip_addr_isany(&msg->addr)) {
        msg->err = udp_send(conn->pcb.udp, p);
    } else {
        msg->err = udp_sendto(conn->pcb.udp, p, &msg->addr, msg->port);
    }
#endif /* LWIP_CHECKSUM_ON_COPY */

    pbuf_free(p);
#if CONN_SEM_NOT_FREE
    sys_sem_signal(&conn_op_completed[socketno - 1]);
#else
    conn = tls_net_get_socket(socketno);
    if (conn && TRUE == conn->used) {
        sys_sem_signal(&conn->op_completed);
    }
#endif
}

static void do_create_connect(void *ctx)
{
    struct tls_net_msg *net_msg = (struct tls_net_msg *)ctx;
    struct tls_netconn *conn;
    err_t  err;
    int socketno = -1;
    socketno = net_msg->skt_no;
    conn = tls_net_get_socket(socketno);
    if (conn == NULL || TRUE != conn->used) {
        tls_mem_free(net_msg);
        TLS_DBGPRT_ERR("\nconn=%x,usde=%d\n", (u32)conn, conn->used);
        return;
    }
    TLS_DBGPRT_INFO("conn ptr = 0x%x, conn->skt_num=%d, conn->client=%d\n", (u32)conn, conn->skt_num, conn->client);

    switch (conn->proto) {
        case TLS_NETCONN_UDP:
            err = net_udp_start(conn);
            if (err != ERR_OK) {
                conn->state = NETCONN_STATE_NONE;
                net_send_event_to_hostif (conn, NET_EVENT_UDP_START_FAILED);
                net_free_socket(socketno);
            } else {
                conn->state = NETCONN_STATE_CONNECTED;
                net_send_event_to_hostif (conn, NET_EVENT_UDP_START);
            }
            break;
        case TLS_NETCONN_TCP:
            err = net_tcp_start(conn);
            if (err != ERR_OK) {
                conn->state = NETCONN_STATE_NONE;
                net_send_event_to_hostif (conn, NET_EVENT_TCP_CONNECT_FAILED);
                net_free_socket(socketno);
            } else {
                if (!conn->client) {
                    net_send_event_to_hostif (conn, NET_EVENT_TCP_CONNECTED);
                }
            }
            break;
        default:
            /* Unsupported netconn type, e.g. protocol disabled */
            break;
    }
    tls_mem_free(net_msg);
    return;
}

static void do_close_connect(void *ctx)
{
    struct tls_net_msg *net_msg = (struct tls_net_msg *)ctx;
    struct tls_netconn *conn = NULL;
    struct tls_netconn *client_conn;
    int socketno = net_msg->skt_no;
    int i;
    int sktNums[TLS_MAX_SOCKET_NUM] = {-1}; /* 2*TLS_MAX_NETCONN_NUM */

    conn = tls_net_get_socket(socketno);
    if (conn == NULL || TRUE != conn->used) {
        TLS_DBGPRT_ERR("conn==%x,used=%d\n", (u32)conn, conn->used);
        tls_mem_free(net_msg);
        return;
    }

    switch (conn->proto) {
        case TLS_NETCONN_UDP:
            if (conn->pcb.udp != NULL) {
                udp_remove(conn->pcb.udp);
                conn->pcb.udp = NULL;
            }
            conn->state = NETCONN_STATE_CLOSED;
            break;
        case TLS_NETCONN_TCP:
            if (!conn->client) {
                /* it's a server, close connected client */
                i = 0;
                dl_list_for_each(client_conn, &conn->list, struct tls_netconn, list) {
                    if (client_conn->used) {
                        client_conn->state = NETCONN_STATE_CLOSED;
                        sktNums[i++] = client_conn->skt_num;
                    }
                }

                while(i-- > 0) {
                    net_tcp_close_connect(sktNums[i]);
                }
            }

            conn->state = NETCONN_STATE_CLOSED;
            net_tcp_close_connect(socketno);
            break;
        default:
            break;
    }
    net_free_socket(socketno);
    tls_mem_free(net_msg);
}

int tls_socket_create(struct tls_socket_desc *skd)
{
    return;
}

int tls_socket_get_status(u8 socket, u8 *buf, u32 bufsize)
{
    return;
}

struct tls_netconn *tls_net_get_socket(u8 socket)
{
    struct tls_netconn *conn = NULL;

    if (socket < 1 || socket > TLS_MAX_NETCONN_NUM) {
        TLS_DBGPRT_ERR("skt num=%d\n", socket);
        return NULL;
    }

    conn = p_net_conn[socket - 1];
    return conn;
}

int tls_socket_close(u8 socket)
{
    struct tls_net_msg *net_msg;
    struct tls_netconn *conn;
    err_t err;

    if (socket < 1 || socket > TLS_MAX_NETCONN_NUM) {
        TLS_DBGPRT_ERR("skt num=%d\n", socket);
        return -1;
    }

    conn = tls_net_get_socket(socket);

    if (conn == NULL || TRUE != conn->used) {
        TLS_DBGPRT_ERR("conn==%x,used=%d\n", (u32)conn, conn->used);
        return -1;
    }
    net_msg = tls_mem_alloc(sizeof(*net_msg));
    if (net_msg == NULL) {
        TLS_DBGPRT_ERR("\nmem err\n");
        return -1;
    }
    memset(net_msg, 0, sizeof(*net_msg));
    net_msg->skt_no = socket;

    return err;
}

int tls_socket_udp_sendto(u16 localport, u8  *ip_addr, u16 port, void *pdata, u16 len)
{
    return;
}

int tls_socket_send(u8 skt_num, void *pdata, u16 len)
{
    return;
}

int tls_net_init()
{
    memset(p_net_conn, 0, sizeof(struct tls_netconn *) *TLS_MAX_NETCONN_NUM);
    return 0;
}

#endif /* TLS_CONFIG_SOCKET_RAW */

