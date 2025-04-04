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

#include "wm_debug.h"
#include "wm_regs.h"
#include "wm_params.h"
#include "wm_fwup.h"
#include "wm_uart_task.h"
#if (GCC_COMPILE==1)
#include "wm_cmdp_hostif_gcc.h"
#else
#endif
#include "wm_irq.h"
#include "utils.h"
#include "wm_config.h"
#include "wm_socket.h"
#include "wm_mem.h"
#include "wm_wl_task.h"
#include "wm_io.h"

#define ONE 1
#define TWO 2
#define THREE 3
#define FOUR 4
#define FIVE 5
#define EIGHT 8
#define TEN 10
#define TWELVE 12
#define SIXTEEN 16
#define FIFTY 50
#define ONE_HUNDRED 100
#define FIVE_HUNDRED_AND_TWELVE 512
#define ONE_THOUSAND 1000
#define ONE_MILLION 1000000

#if (TLS_CONFIG_HOSTIF && TLS_CONFIG_UART)

extern struct tls_uart_port uart_port[TWO];
struct tls_uart uart_st[TWO];
#if TLS_CONFIG_SOCKET_RAW || TLS_CONFIG_SOCKET_STD
static u32 uart1_delaytime = 0;
#endif

#define UART_NET_SEND_DATA_SIZE      256  // 512

struct uart_tx_msg {
    struct tls_uart *uart;
    struct tls_hostif_tx_msg *tx_msg;
};

extern void tls_uart_set_fc_status(int uart_no,
    TLS_UART_FLOW_CTRL_MODE_T status);
extern void tls_uart_free_tx_sent_data(struct tls_uart_port *port);
extern void tls_uart_tx_callback_register(u16 uart_no,
    s16(*tx_callback) (struct tls_uart_port *port));

void uart_rx_timeout_handler(void *arg);
void uart_rx(struct tls_uart *uart);
void uart_tx(struct uart_tx_msg *tx_data);
static void uart_tx_event_finish_callback(void *arg)
{
    if (arg)
        tls_mem_free(arg);
}

#if TLS_CONFIG_SOCKET_RAW || TLS_CONFIG_SOCKET_STD
static void uart_tx_socket_finish_callback(void *arg)
{
    if (arg) {
        struct pbuf *p = (struct pbuf *) arg;
        pbuf_free(p);
    }
}
#endif

extern struct task_parameter wl_task_param_hostif;
static void uart_send_tx_msg(u8 hostif_mode, struct tls_hostif_tx_msg *tx_msg,
    bool is_event)
{
    struct uart_tx_msg *tx_data = NULL;
    if (tx_msg == NULL)
        return;
    switch (hostif_mode) {
        case HOSTIF_MODE_UART0:
            if (uart_st[0].uart_port == NULL) {
                free_tx_msg_buffer(tx_msg);
                tls_mem_free(tx_msg);
                return;
            }
            tx_data = tls_mem_alloc(sizeof(struct uart_tx_msg));
            if (tx_data == NULL) {
                free_tx_msg_buffer(tx_msg);
                tls_mem_free(tx_msg);
                return;
            }
            tx_data->tx_msg = tx_msg;
            tx_data->uart = &uart_st[0];
            if (tls_wl_task_callback(&wl_task_param_hostif, (start_routine) uart_tx, tx_data, 0)) {
                TLS_DBGPRT_INFO("send tx msg error.\n");
                free_tx_msg_buffer(tx_msg);
                tls_mem_free(tx_msg);
                tls_mem_free(tx_data);
                return;
            }
            break;
        case HOSTIF_MODE_UART1_LS:
        case HOSTIF_MODE_UART1_HS:
            if (uart_st[1].uart_port == NULL) {
                free_tx_msg_buffer(tx_msg);
                tls_mem_free(tx_msg);
                return;
            }
            if (is_event && (hostif_mode != HOSTIF_MODE_UART1_HS || uart_st[1].cmd_mode != UART_RICMD_MODE)) {
                free_tx_msg_buffer(tx_msg);
                tls_mem_free(tx_msg);
                return;
            }
            tx_data = tls_mem_alloc(sizeof(struct uart_tx_msg));
            if (tx_data == NULL) {
                free_tx_msg_buffer(tx_msg);
                tls_mem_free(tx_msg);
                return;
            }
            tx_data->tx_msg = tx_msg;
            tx_data->uart = &uart_st[1];
            if (tls_wl_task_callback(&wl_task_param_hostif, (start_routine) uart_tx, tx_data, 0)) {
                TLS_DBGPRT_INFO("send tx msg error.\n");
                free_tx_msg_buffer(tx_msg);
                tls_mem_free(tx_msg);
                tls_mem_free(tx_data);
                return;
            }
            break;
        default:
            break;
    }
}

static void uart_get_uart1_port(struct tls_uart_port **uart1_port)
{
    *uart1_port = uart_st[1].uart_port;
}

static void uart_set_uart1_mode(u32 cmd_mode)
{
    uart_st[1].cmd_mode = cmd_mode;
    if (UART_TRANS_MODE == cmd_mode) {
        tls_uart_set_fc_status(uart_st[1].uart_port->uart_no,
                               TLS_UART_FLOW_CTRL_HARDWARE);
    } else {
        tls_uart_set_fc_status(uart_st[1].uart_port->uart_no,
                               TLS_UART_FLOW_CTRL_NONE);
    }
}

static void uart_set_uart0_mode(u32 cmd_mode)
{
    uart_st[0].cmd_mode = cmd_mode;
    if (UART_TRANS_MODE == cmd_mode) {
        tls_uart_set_fc_status(uart_st[0].uart_port->uart_no,
                               TLS_UART_FLOW_CTRL_HARDWARE);
    } else {
        tls_uart_set_fc_status(uart_st[0].uart_port->uart_no,
                               TLS_UART_FLOW_CTRL_NONE);
    }
}

static void uart_set_uart1_sock_param(u16 sksnd_cnt, bool rx_idle)
{
    uart_st[1].sksnd_cnt = sksnd_cnt;
}

s16 uart_tx_sent_callback(struct tls_uart_port *port)
{
    return tls_wl_task_callback_static(&wl_task_param_hostif,
                                       (start_routine)
                                       tls_uart_free_tx_sent_data, port, 0,
                                       TLS_MSG_ID_UART_SENT_FREE);
}

void tls_uart_init(void)
{
    struct tls_uart_options uart_opts;
    struct tls_uart *uart;
    struct tls_hostif *hif = tls_get_hostif();
    struct tls_param_uart uart_cfg;

    memset(uart_st, 0, TWO * sizeof(struct tls_uart));

    /* init socket config */
    tls_cmd_init_socket_cfg();
    tls_cmd_register_set_uart0_mode(uart_set_uart0_mode);

    /* setting uart0 */
    if (WM_SUCCESS != tls_uart_port_init(TLS_UART_0, NULL, 0))
        return;
    tls_uart_tx_callback_register(TLS_UART_0, uart_tx_sent_callback);
    uart = tls_uart_open(TLS_UART_0, TLS_UART_MODE_INT);
    if (uart == NULL)
        return;

    uart->cmd_mode = UART_ATCMD_MODE;
    hif->uart_send_tx_msg_callback = uart_send_tx_msg;
    tls_param_get(TLS_PARAM_ID_UART, (void *) &uart_cfg, 0);
#if TLS_CONFIG_SOCKET_RAW || TLS_CONFIG_SOCKET_STD
    if (uart_cfg.baudrate) {
        uart1_delaytime =
            (UART_NET_SEND_DATA_SIZE * (TEN * ONE_MILLION / uart_cfg.baudrate) /
             ONE_THOUSAND + FIVE);
    } else {
        uart1_delaytime = ONE_HUNDRED;
    }
#endif
    tls_cmd_register_get_uart1_port(uart_get_uart1_port);
    tls_cmd_register_set_uart1_mode(uart_set_uart1_mode);
    tls_cmd_register_set_uart1_sock_param(uart_set_uart1_sock_param);
    if (hif->hostif_mode == HOSTIF_MODE_UART1_HS) {
        /* 根据flash读取的参数配置串口寄存器 */
        uart_opts.baudrate = uart_cfg.baudrate;
        uart_opts.charlength = TLS_UART_CHSIZE_8BIT;
        uart_opts.flow_ctrl = (enum TLS_UART_FLOW_CTRL_MODE) uart_cfg.flow;
        uart_opts.paritytype = (enum TLS_UART_PMODE) uart_cfg.parity;
        uart_opts.stopbits = (enum TLS_UART_STOPBITS) uart_cfg.stop_bits;

        if (WM_SUCCESS != tls_uart_port_init(TLS_UART_1, &uart_opts, 0))
            return;
        tls_uart_tx_callback_register(TLS_UART_1, uart_tx_sent_callback);
        uart = tls_uart_open(TLS_UART_1, TLS_UART_MODE_INT);
        if (uart == NULL)
            return;

        uart->cmd_mode = UART_RICMD_MODE;
    } else if (hif->hostif_mode == HOSTIF_MODE_UART1_LS) {
        uart_opts.baudrate = uart_cfg.baudrate;
        if (uart_cfg.charsize == 0) {
            uart_opts.charlength = TLS_UART_CHSIZE_8BIT;
        } else {
            uart_opts.charlength = (TLS_UART_CHSIZE_T) uart_cfg.charsize;
        }
        uart_opts.flow_ctrl = (enum TLS_UART_FLOW_CTRL_MODE) uart_cfg.flow;
        uart_opts.paritytype = (enum TLS_UART_PMODE) uart_cfg.parity;
        uart_opts.stopbits = (enum TLS_UART_STOPBITS) uart_cfg.stop_bits;
        if (WM_SUCCESS != tls_uart_port_init(TLS_UART_1, &uart_opts, 0))
            return;
        tls_uart_tx_callback_register(TLS_UART_1, uart_tx_sent_callback);
        uart = tls_uart_open(TLS_UART_1, TLS_UART_MODE_INT);
        if (uart == NULL)
            return;
#if TLS_CONFIG_SOCKET_RAW || TLS_CONFIG_SOCKET_STD
        if (tls_cmd_get_auto_mode()) {
            uart->cmd_mode = UART_TRANS_MODE;
            tls_uart_set_fc_status(uart->uart_port->uart_no,
                                   TLS_UART_FLOW_CTRL_HARDWARE);
        } else
#endif /* TLS_CONFIG_SOCKET_RAW */
        {
            uart->cmd_mode = UART_ATCMD_MODE;   // 指令模式关闭流控
            tls_uart_set_fc_status(uart->uart_port->uart_no,
                                   TLS_UART_FLOW_CTRL_NONE);
        }
    } else {
        ;
    }

#if TLS_CONFIG_SOCKET_RAW || TLS_CONFIG_SOCKET_STD
    tls_hostif_set_net_status_callback();
#endif
}

static s16 tls_uart0_task_rx_cb(u16 len, void *p)
{
    struct tls_uart *uart = &uart_st[0];

    if ((UART_TRANS_MODE == uart->cmd_mode)
        && (uart->uart_port->plus_char_cnt == THREE)) {
        uart->cmd_mode = UART_ATCMD_MODE;
        tls_uart_set_fc_status(uart->uart_port->uart_no,
                               TLS_UART_FLOW_CTRL_NONE);
    }

    if (tls_wl_task_callback_static(&wl_task_param_hostif,
                                    (start_routine) uart_rx,
                                    uart,
                                    0,
                                    TLS_MSG_ID_UART0_RX)) {
        return WM_FAILED;
    }
    return WM_SUCCESS;
}

s16 tls_uart1_task_rx_cb(u16 len, void *p)
{
    struct tls_uart *uart = &uart_st[1];

    if ((UART_TRANS_MODE == uart->cmd_mode)
        && (uart->uart_port->plus_char_cnt == THREE)) {
        uart->cmd_mode = UART_ATCMD_MODE;
        tls_uart_set_fc_status(uart->uart_port->uart_no,
                               TLS_UART_FLOW_CTRL_NONE);
    }

    if (tls_wl_task_callback_static(&wl_task_param_hostif, (start_routine) uart_rx,
                                    uart, 0, TLS_MSG_ID_UART1_RX)) {
        return WM_FAILED;
    }
    return WM_SUCCESS;
}

struct tls_uart *tls_uart_open(u32 uart_no, TLS_UART_MODE_T uart_mode)
{
    struct tls_uart *uart;
    if (uart_no == TLS_UART_0) {
        uart = &uart_st[0];
        memset(uart, 0, sizeof(struct tls_uart));
        uart->uart_port = &uart_port[0];
        tls_uart_rx_callback_register(uart_no, tls_uart0_task_rx_cb, NULL);
    } else if (uart_no == TLS_UART_1) {
        uart = &uart_st[1];
        memset(uart, 0, sizeof(struct tls_uart));
        uart->uart_port = &uart_port[1];
        tls_uart_rx_callback_register(uart_no, tls_uart1_task_rx_cb, NULL);
    } else
        return NULL;

    uart->uart_port->uart_mode = uart_mode;
    return uart;
}

int tls_uart_close(struct tls_uart *uart)
{
    return WM_FAILED;
}

static u8 *find_atcmd_eol(u8 * src, u32 len)
{
    u8 *p = NULL;
    u8 *q = NULL;
    p = memchr(src, '\r', len);
    q = memchr(src, '\n', len);
    if (p && q) {
        if ((p - q) > 1) {
            return q;
        }
        if ((q - p) > 1) {
            return p;
        }
        if ((p - q) == 1) {
            return p;
        }
        if ((q - p) == 1) {
            return q;
        }
        return NULL;
    }
    if (p) {
        return p;
    }
    if (q) {
        return q;
    }
    return NULL;
}

static void modify_atcmd_tail(struct tls_uart_circ_buf *recv, u8 ** p)
{
    u32 cmd_len;

    if (*p >= &recv->buf[recv->tail]) {
        cmd_len = *p - &recv->buf[recv->tail];
    } else {
        cmd_len = *p + TLS_UART_RX_BUF_SIZE  - &recv->buf[recv->tail];
    }

    if (cmd_len > FIVE_HUNDRED_AND_TWELVE) {
        recv->tail = recv->head;
        *p = NULL;
        TLS_DBGPRT_INFO("EOF char find > 512 \r\n");
    } else {
        recv->tail = (recv->tail + cmd_len) & (TLS_UART_RX_BUF_SIZE - 1);
    }
}

static u8 *parse_atcmd_eol(struct tls_uart *uart)
{
    struct tls_uart_circ_buf *recv = &uart->uart_port->recv;
    u8 *p = NULL;

    /* jump to end of line */
    if (recv->head > recv->tail) {
        p = find_atcmd_eol((u8 *)&recv->buf[recv->tail], (u32)(recv->head - recv->tail));
        if (p) {
            modify_atcmd_tail(recv, &p);
        }
    } else {
        p = find_atcmd_eol((u8 *)&recv->buf[recv->tail],
                           TLS_UART_RX_BUF_SIZE - recv->tail);
        if (!p) {
            p = find_atcmd_eol((u8 *)&recv->buf[0], recv->head);
            if (p) {
                modify_atcmd_tail(recv, &p);
            }
        } else {
            modify_atcmd_tail(recv, &p);
        }
    }

    /* jump over EOF char */
    if ((recv->buf[recv->tail] == '\r') || (recv->buf[recv->tail] == '\n')) {
        recv->tail = (recv->tail + 1) & (TLS_UART_RX_BUF_SIZE - 1);
    }
    return p;
}

static void parse_atcmd_line(struct tls_uart *uart)
{
    struct tls_uart_circ_buf *recv = &uart->uart_port->recv;
    u8 *ptr_eol;
    u32 cmd_len, tail_len = 0;
    u8 *atcmd_start = NULL;
    char *buf;
    u8 hostif_uart_type;

    while ((CIRC_CNT(recv->head, recv->tail, TLS_UART_RX_BUF_SIZE) >= FOUR)
           && (atcmd_start == NULL)) {  /* check "at+" char */
        if (((recv->buf[recv->tail] == 'A') || (recv->buf[recv->tail] == 'a'))
            &&
            ((recv->buf[(recv->tail + 1) & (TLS_UART_RX_BUF_SIZE - 1)] == 'T')
             || (recv->buf[(recv->tail + 1) & (TLS_UART_RX_BUF_SIZE - 1)] ==
                 't'))
            && (recv->buf[(recv->tail + TWO) & (TLS_UART_RX_BUF_SIZE - 1)] ==
                '+')) {
            atcmd_start = (u8 *)&recv->buf[recv->tail];
            recv->tail = (recv->tail + THREE) & (TLS_UART_RX_BUF_SIZE - 1);
            ptr_eol = parse_atcmd_eol(uart);
            if (!ptr_eol) {  /* no terminator, may receive only half a command */
                if (CIRC_CNT(recv->head, recv->tail, TLS_UART_RX_BUF_SIZE) > FIVE_HUNDRED_AND_TWELVE) {
                    recv->tail = recv->head;
                } else {
                    recv->tail = (recv->tail - THREE) & (TLS_UART_RX_BUF_SIZE - 1);
                }
                break;
            }

            if (ptr_eol >= atcmd_start) {         /* Getting the command length */
                cmd_len = ptr_eol - atcmd_start;
            } else {
                tail_len = (u32) (&recv->buf[TLS_UART_RX_BUF_SIZE - 1] - atcmd_start + 1);
                cmd_len = tail_len + (ptr_eol - &recv->buf[0]);
            }

            buf = tls_mem_alloc(cmd_len + TWO);
            if (!buf) {
                return;
            }

            if (ptr_eol >= atcmd_start) {
                MEMCPY(buf, atcmd_start, cmd_len);
            } else {
                MEMCPY(buf, atcmd_start, tail_len);
                MEMCPY(buf + tail_len, (void *)&recv->buf[0], ptr_eol - (u8 *)&recv->buf[0]);
            }

            if (buf[cmd_len - TWO] == '\r' || buf[cmd_len - TWO] == '\n') {
                buf[cmd_len - TWO] = '\n';
                buf[cmd_len - 1] = '\0';
                cmd_len = cmd_len - 1;
            } else if (buf[cmd_len - 1] == '\r' || buf[cmd_len - 1] == '\n') {
                buf[cmd_len - 1] = '\n';
                buf[cmd_len] = '\0';
                cmd_len = cmd_len;
            } else {
                buf[cmd_len] = '\n';
                buf[cmd_len + 1] = '\0';
                cmd_len = cmd_len + 1;
            }

            if (uart->uart_port->uart_no == TLS_UART_0) {
                hostif_uart_type = HOSTIF_UART0_AT_CMD;
            } else {
                hostif_uart_type = HOSTIF_UART1_AT_CMD;
            }
            tls_hostif_cmd_handler(hostif_uart_type, buf, cmd_len);
            tls_mem_free(buf);
            atcmd_start = NULL;
            if (CIRC_CNT(recv->head, recv->tail, TLS_UART_RX_BUF_SIZE) > 0) {
                if (uart->uart_port->uart_no == TLS_UART_0) {
                    tls_uart0_task_rx_cb(CIRC_CNT(recv->head, recv->tail, TLS_UART_RX_BUF_SIZE),
                                         NULL);
                } else {
                    tls_uart1_task_rx_cb(CIRC_CNT(recv->head, recv->tail, TLS_UART_RX_BUF_SIZE),
                                         NULL);
                }
                break;
            }
        } else {
            recv->tail = (recv->tail + 1)%TLS_UART_RX_BUF_SIZE;
        }
    }
}

static int cache_tcp_recv(struct tls_hostif_tx_msg *tx_msg)
{
    struct tls_uart_circ_buf *precvmit =
        tls_hostif_get_recvmit(tx_msg->u.msg_tcp.sock);
    struct pbuf *p;
    u16 buflen;
    u16 copylen;
    u32 tail = 0;
    bool overflow = 0;

    p = (struct pbuf *) tx_msg->u.msg_tcp.p;
    if (p->tot_len >= TLS_SOCKET_RECV_BUF_SIZE) {
        tx_msg->offset = p->tot_len - TLS_SOCKET_RECV_BUF_SIZE + 1;
    }
    TLS_DBGPRT_INFO("p->tot_len=%d\n", p->tot_len);
    TLS_DBGPRT_INFO("precvmit->head=%d, precvmit->tail=%d\n", precvmit->head,
                    precvmit->tail);
    buflen = p->tot_len - tx_msg->offset;
    tail = precvmit->tail;
    while (1) {
        copylen = CIRC_SPACE_TO_END_FULL(precvmit->head,
                                         tail, TLS_SOCKET_RECV_BUF_SIZE);
        if (copylen == 0) {
            tail = 0;
            overflow = 1;
            continue;
        }
        if (buflen < copylen)
            copylen = buflen;
        pbuf_copy_partial(p,
                          (u8 *)precvmit->buf + precvmit->head,
                          copylen, tx_msg->offset);
        precvmit->head =
            (precvmit->head + copylen) & (TLS_SOCKET_RECV_BUF_SIZE - 1);
        TLS_DBGPRT_INFO("precvmit->head=%d, precvmit->tail=%d\n",
                        precvmit->head, precvmit->tail);
        tx_msg->offset += copylen;
        buflen -= copylen;
        if (tx_msg->offset >= p->tot_len)
            break;
    };
    if (overflow)
        precvmit->tail = precvmit->head + 1;

     /* Check whether the pbuf data is copied to the uart cache */
    if (tx_msg->offset >= p->tot_len) {
        pbuf_free(p);
    }

    return copylen;
}

 /*
 * 处理流程说明：
 * 首先判断上次的同步帧是否已经处理完成，如果已经处理结束，
 *          则检查缓存head指向的字节，判断是否是0xAA(SYN_FLAG)，
 *          如果是，则检查缓存的长度是否大于等于8，如果不是
 *          则返回，如果是，则提取字节标记和长度信息，校验信息，
 *          计算校验和，检查校验值是否匹配，
 */
static int ricmd_handle_sync(struct tls_uart *uart, struct tls_uart_circ_buf *recv)
{
    return 0;
}

static int data_loop(struct tls_uart *uart,
                     int numbytes, struct tls_uart_circ_buf *recv)
{
    return 0;
}

#define MAX_RICMD_LENGTH      200
u8 ricmd_buffer[MAX_RICMD_LENGTH + EIGHT];

static int cmd_loop(struct tls_uart *uart,
                    int numbytes, struct tls_uart_circ_buf *recv)
{
    unsigned cbytes = uart->ricmd_info.cbytes;
    unsigned procbytes = 0;
    unsigned char c;

    while (procbytes < numbytes) {
        c = recv->head;
        procbytes++;

        /* append to line buffer if possible */
        if (cbytes < MAX_RICMD_LENGTH)
            ricmd_buffer[EIGHT + cbytes] = c;
        uart->ricmd_info.cbytes++;

        if (uart->ricmd_info.cbytes == uart->ricmd_info.length) {
            tls_hostif_cmd_handler(HOSTIF_UART1_RI_CMD,
                                   (char *) ricmd_buffer,
                                   uart->ricmd_info.length + EIGHT);
            uart->ricmd_info.cbytes = 0;
            uart->inputstate = 0;
            break;
        }
    }
    return procbytes;
}

void parse_ricmd_line(struct tls_uart *uart)
{
    struct tls_uart_circ_buf *recv = &uart->uart_port->recv;
    int skip_count;
    int numbytes;
    int procbytes;

    while (!uart_circ_empty(recv)) {
        /* check for frame header */
        skip_count = ricmd_handle_sync(uart, recv);
        if ((skip_count == 0) && !(uart->inputstate & INS_SYNC_CHAR))
            break;

        if (uart->inputstate & INS_SYNC_CHAR) {
            /* process a contiguous block of bytes */
            numbytes = CIRC_CNT(recv->head, recv->tail, TLS_UART_RX_BUF_SIZE);

            if (uart->inputstate & INS_RICMD)
                procbytes = cmd_loop(uart, numbytes, recv);
            else if (uart->inputstate & INS_DATA)
                procbytes = data_loop(uart, numbytes, recv);
            else
                procbytes = numbytes;
        } else {
            /* 没有需要处理的数据(第一个字符不是SYNC_FLAG)，而且以前的包已经处理完成 */
            procbytes = skip_count;
        }
        recv->head = (recv->head + procbytes) & (TLS_UART_RX_BUF_SIZE - 1);
    }

    return;
}

#define UART_UPFW_DATA_SIZE sizeof(struct tls_fwup_block)

static int uart_fwup_rsp(u8 portno, int status)
{
    char *cmd_rsp = NULL;
    u32 len;
    u8 hostif_type;

    cmd_rsp = tls_mem_alloc(SIXTEEN);
    if (cmd_rsp == NULL) {
        return -1;
    }
    if (status) {
        len = sprintf(cmd_rsp, "+OK=%d\r\n\r\n", status);
    } else {
        len = sprintf(cmd_rsp, "+ERR=%d\r\n\r\n", status);
    }

    if (TLS_UART_0 == portno) {
        hostif_type = HOSTIF_MODE_UART0;
    } else {
        hostif_type = HOSTIF_MODE_UART1_LS;
    }

    if (tls_hostif_process_cmdrsp(hostif_type, cmd_rsp, len)) {
        tls_mem_free(cmd_rsp);
    }
    return 0;
}

void uart_fwup_send(struct tls_uart *uart)
{
    struct tls_uart_circ_buf *recv = &uart->uart_port->recv;
    u32 data_cnt = CIRC_CNT(recv->head, recv->tail, TLS_UART_RX_BUF_SIZE);
    struct tls_fwup_block *pfwup = NULL;
    u8 *p;
    u32 i, session_id, status;

    if (data_cnt >= UART_UPFW_DATA_SIZE) {
        uart->cmd_mode = UART_ATCMD_MODE;
        pfwup = (struct tls_fwup_block *) tls_mem_alloc(UART_UPFW_DATA_SIZE);
        if (!pfwup) {
            recv->tail = (recv->tail + UART_UPFW_DATA_SIZE) & (TLS_UART_RX_BUF_SIZE - 1);
            return;
        }
        p = (u8 *) pfwup;
        for (i = 0; i < UART_UPFW_DATA_SIZE; i++) {
            *p++ = recv->buf[recv->tail++];
            recv->tail &= TLS_UART_RX_BUF_SIZE - 1;
        }
        session_id = tls_fwup_get_current_session_id();
        if (session_id) {
            if (get_crc32((u8 *) pfwup, UART_UPFW_DATA_SIZE - TWELVE) == pfwup->crc32) {
                if (tls_fwup_set_update_numer(pfwup->number) == TLS_FWUP_STATUS_OK) {
                    struct tls_fwup_block *blk;
                    u8 *buffer;
                    blk = (struct tls_fwup_block *)pfwup;
                    buffer = blk->data;
                    status = 1;
                    uart_fwup_rsp(uart->uart_port->uart_no, status);
                    tls_fwup_request_sync(session_id, buffer, TLS_FWUP_BLK_SIZE);
                } else {
                    TLS_DBGPRT_INFO("tls_fwup_set_update_numer err!!!\r\n");
                    status = 0;
                    uart_fwup_rsp(uart->uart_port->uart_no, status);
                }
            } else {
                TLS_DBGPRT_INFO("err crc32 !!!\r\n");
                status = 0;
                uart_fwup_rsp(uart->uart_port->uart_no, status);
            }
        }
        tls_mem_free(pfwup);
    }
}

#if TLS_CONFIG_SOCKET_RAW || TLS_CONFIG_SOCKET_STD
void uart_rx_timeout_handler(void * arg)
{
    int data_cnt;
    struct tls_uart *uart = (struct tls_uart *)arg;
    struct tls_uart_circ_buf *recv = &uart->uart_port->recv;

    if (uart->cmd_mode == UART_TRANS_MODE) {
        data_cnt = CIRC_CNT(recv->head, recv->tail, TLS_UART_RX_BUF_SIZE);
        if (data_cnt) {
            uart_net_send(uart, recv->head, recv->tail, data_cnt);
        }
    }
}
#endif

void uart_rx(struct tls_uart *uart)
{
#if TLS_CONFIG_SOCKET_RAW || TLS_CONFIG_SOCKET_STD
    struct tls_uart_circ_buf *recv = &uart->uart_port->recv;
    int data_cnt;
    u8 send_data = 0;
#endif
    int err = 0;
    u8 len = 0;
    char *cmd_rsp = NULL;

    if (uart->cmd_mode == UART_ATCMD_MODE) {
        if (uart->uart_port->plus_char_cnt == THREE) {
            cmd_rsp = tls_mem_alloc(strlen("+OK!!\r\n\r\n") + 1);
            if (!cmd_rsp) {
                return;
            }
            len = sprintf(cmd_rsp, "+OK!!\r\n\r\n");
            uart->uart_port->plus_char_cnt = 0;
            err = tls_hostif_process_cmdrsp(HOSTIF_MODE_UART1_LS, cmd_rsp, len);
            if (err) {
                tls_mem_free(cmd_rsp);
            }
        }
        parse_atcmd_line(uart);
    } else if (uart->cmd_mode == UART_ATDATA_MODE) {
        uart_fwup_send(uart);
    } else if (uart->cmd_mode == UART_RICMD_MODE) {
        parse_ricmd_line(uart);
    } else {
    }
}

void uart_tx(struct uart_tx_msg *tx_data)
{
    struct tls_uart *uart = tx_data->uart;
    struct tls_hostif *hif = tls_get_hostif();
    struct tls_hostif_tx_msg *tx_msg = tx_data->tx_msg;
    u32 cpu_sr;
    tls_uart_tx_msg_t *uart_tx_msg;
    struct pbuf *p;

    switch (tx_msg->type) {
        case HOSTIF_TX_MSG_TYPE_EVENT:
        case HOSTIF_TX_MSG_TYPE_CMDRSP:
            tls_uart_fill_buf(uart->uart_port, tx_msg->u.msg_event.buf,
                              tx_msg->u.msg_event.buflen);
            uart_tx_event_finish_callback(tx_msg->u.msg_event.buf);
            tls_uart_tx_chars_start(uart->uart_port);
            break;
#if TLS_CONFIG_SOCKET_RAW || TLS_CONFIG_SOCKET_STD
        /* Tcp and Udp both use the below case. */
        case HOSTIF_TX_MSG_TYPE_UDP:
        case HOSTIF_TX_MSG_TYPE_TCP:
            if (uart->cmd_mode == UART_TRANS_MODE || hif->rptmode) {
                p = (struct pbuf *) tx_msg->u.msg_tcp.p;
                uart_tx_msg = tls_mem_alloc(sizeof(tls_uart_tx_msg_t));
                if (uart_tx_msg == NULL) {
                    uart_tx_socket_finish_callback(p);
                    goto out;
                }
                dl_list_init(&uart_tx_msg->list);
                uart_tx_msg->buf = p->payload;
                uart_tx_msg->buflen = p->tot_len;
                uart_tx_msg->offset = 0;
                uart_tx_msg->finish_callback = uart_tx_socket_finish_callback;
                uart_tx_msg->callback_arg = p;

                cpu_sr = tls_os_set_critical();
                dl_list_add_tail(&uart->uart_port->tx_msg_pending_list,
                                 &uart_tx_msg->list);
                tls_os_release_critical(cpu_sr);
                tls_uart_tx_chars_start(uart->uart_port);
            } else {
                cache_tcp_recv(tx_msg);
            }
            break;
#endif
        default:
            break;
    }
  out:
    if (tx_msg)
        tls_mem_free(tx_msg);
    if (tx_data)
        tls_mem_free(tx_data);
}
#endif /* CONFIG_UART */
