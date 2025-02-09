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

#include <string.h>
#include "wm_irq.h"
#include "wm_i2s.h"

#define FPGA_800_I2S     0
#define I2S_CLK          160000000
#define TEST_WITH_F401   0
#define APPEND_NUM       4

wm_i2s_buf_t  wm_i2s_buf[1] = { 0 };
static uint8_t tx_channel = 0, rx_channel = 0;
static wm_dma_desc g_dma_desc_tx[2];
static wm_dma_desc g_dma_desc_rx[2];

// master or slave
static void wm_i2s_set_mode(bool bl)
{
    tls_bitband_write(HR_I2S_CTRL, 28, bl);
}

// master or slave
static uint32_t wm_i2s_get_mode(void)
{
    uint32_t reg;

    reg = tls_reg_read32(HR_I2S_CTRL);
    reg = reg>>28;

    return (reg & 0x1);
}

// i2s_stardard
static void wm_i2s_set_format(uint32_t format)
{
    uint32_t reg;
    reg = tls_reg_read32(HR_I2S_CTRL);
    reg &= ~(0x3<<24);
    reg |= format;
    tls_reg_write32(HR_I2S_CTRL, reg);
}

static void wm_i2s_left_channel_sel(bool bl)
{
    tls_bitband_write(HR_I2S_CTRL, 23, bl);
}

static void wm_i2s_mono_select(bool bl)
{
    tls_bitband_write(HR_I2S_CTRL, 22, bl);
}

static void wm_i2s_rx_dma_enable(bool bl)
{
    tls_bitband_write(HR_I2S_CTRL, 21, bl);
}

static void wm_i2s_tx_dma_enable(bool bl)
{
    tls_bitband_write(HR_I2S_CTRL, 20, bl);
}

static void wm_i2s_rx_fifo_clear(void)
{
    tls_bitband_write(HR_I2S_CTRL, 19, 1);
}

static void wm_i2s_tx_fifo_clear(void)
{
    tls_bitband_write(HR_I2S_CTRL, 18, 1);
}

static void wm_i2s_set_rxth(uint8_t th)
{
    uint32_t reg;

    if (th > 7) {
        th = 7;
    }
    reg = tls_reg_read32(HR_I2S_CTRL);
    reg &= ~(0x7<<12);
    reg |= (th << 12);
    tls_reg_write32(HR_I2S_CTRL, reg);
}

static void wm_i2s_set_txth(uint8_t th)
{
    uint32_t reg;

    if (th > 7) {
        th = 7;
    }
    reg = tls_reg_read32(HR_I2S_CTRL);
    reg &= ~(0x7<<9);
    reg |= (th << 9);
    tls_reg_write32(HR_I2S_CTRL, reg);
}

static void wm_i2s_set_word_len(uint8_t len)
{
    uint32_t reg;

    reg = tls_reg_read32(HR_I2S_CTRL);
    reg &= ~(0x3<<4);
    len = (len>>3) - 1;
    reg |= (len<<4);
    tls_reg_write32(HR_I2S_CTRL, reg);
}

void wm_i2s_rx_enable(bool bl)
{
    tls_bitband_write(HR_I2S_CTRL, 2, bl);
}

void wm_i2s_tx_enable(bool bl)
{
    tls_bitband_write(HR_I2S_CTRL, 1, bl);
}

static void wm_i2s_enable(bool bl)
{
    tls_bitband_write(HR_I2S_CTRL, 0, bl);
}

static void wm_i2s_txth_int_mask(bool bl)
{
    tls_bitband_write(HR_I2S_INT_MASK, 6, bl);
}

static void wm_i2s_rxth_int_mask(bool bl)
{
    tls_bitband_write(HR_I2S_INT_MASK, 2, bl);
}

static void wm_i2s_set_freq(uint32_t lr_freq, uint32_t mclk)
{
    uint32_t div, mclk_div;
    uint32_t temp;
    uint8_t wdwidth, stereo;

    temp = I2S->CTRL;
    wdwidth = (((temp>>4)&0x03)+1)<<3;
    stereo = tls_bitband_read(HR_I2S_CTRL, 22) ? 1:2;
    stereo = 2;
    div = (I2S_CLK + lr_freq * wdwidth * stereo)/(lr_freq * wdwidth * stereo) - 1;

#if FPGA_800_I2S
    div = div/2;
#endif
    if (mclk == 0) {
    }
    mclk_div = I2S_CLK / mclk;

    if (mclk_div > 0x3F) {
        mclk_div = 0x3F;
    }

    *(volatile uint32_t *)HR_CLK_I2S_CTL &= ~0x3FFFF;
    // set bclk div ,mclk div, inter clk be used, mclk enabled.
    *(volatile uint32_t *)HR_CLK_I2S_CTL |= (uint32_t)((div<<8) | (mclk_div<<2) | 2);
}

static void wm_i2s_int_clear_all(void)
{
    tls_reg_write32(HR_I2S_INT_SRC, 0x3FF);
}

static void wm_i2s_int_mask_all(void)
{
    tls_reg_write32(HR_I2S_INT_MASK, 0x3FF);
}

static void wm_i2s_dma_start(uint8_t ch)
{
    DMA_CHNLCTRL_REG(ch) = DMA_CHNL_CTRL_CHNL_ON;
}

static void wm_i2s_module_reset(void)
{
    tls_bitband_write(HR_CLK_RST_CTL, 24, 0);
    tls_bitband_write(HR_CLK_RST_CTL, 24, 1);
}

static void wm_i2s_dma_tx_init(uint8_t ch, uint32_t count, int16_t *buf)
{
    DMA_INTMASK_REG &= ~(0x02<<(ch*2));
    DMA_SRCADDR_REG(ch) = (uint32_t)buf;
    DMA_DESTADDR_REG(ch) = HR_I2S_TX;

    DMA_CTRL_REG(ch) = DMA_CTRL_SRC_ADDR_INC | DMA_CTRL_DATA_SIZE_WORD | DMA_CTRL_BURST_SIZE1;
    DMA_MODE_REG(ch) = DMA_MODE_SEL_I2S_TX | DMA_MODE_HARD_MODE;
    DMA_CTRL_REG(ch) &= ~0xFFFF00;
    DMA_CTRL_REG(ch) |= (count<<8);
}

static void wm_i2s_dma_rx_init(uint8_t ch, uint32_t count, int16_t * buf)
{
    DMA_INTMASK_REG &=~(0x02<<(ch*2));
    DMA_SRCADDR_REG(ch) = HR_I2S_RX;
    DMA_DESTADDR_REG(ch) = (uint32_t)buf;

    DMA_CTRL_REG(ch) = DMA_CTRL_DEST_ADDR_INC | DMA_CTRL_DATA_SIZE_WORD | DMA_CTRL_BURST_SIZE1;
    DMA_MODE_REG(ch) = DMA_MODE_SEL_I2S_RX | DMA_MODE_HARD_MODE;
    DMA_CTRL_REG(ch) &= ~0xFFFF00;
    DMA_CTRL_REG(ch) |= (count<<8);
}

ATTRIBUTE_ISR void i2s_I2S_IRQHandler(void)
{
    volatile uint32_t temp;
    csi_kernel_intrpt_enter();
    /* TxTH */
    if ((M32(HR_I2S_INT_SRC) >> 6) & 0x1) { // 6:byte alignment
        if (wm_i2s_buf->txtail < wm_i2s_buf->txlen) {
            volatile uint8_t fifo_level;
            for (fifo_level = ((I2S->INT_STATUS >> 4) & 0x0F), // 4:byte alignment
                temp = 0; temp < 8 - fifo_level; temp++) { // 8:byte alignment
                tls_reg_write32(HR_I2S_TX, wm_i2s_buf->txbuf[wm_i2s_buf->txtail++]);
                if (wm_i2s_buf->txtail >= wm_i2s_buf->txlen) {
                    wm_i2s_buf->txtail = 0;
                    wm_i2s_buf->txdata_done = 1;
                    tls_bitband_write(HR_I2S_INT_MASK, 6, 1); // 6:value of bit
                    break;
                }
            }
        }
        tls_reg_write32(HR_I2S_INT_SRC, 0x40);
    }
    /* LZC */
    if (tls_bitband_read(HR_I2S_INT_SRC, 9)) { // 9:value of bit
        tls_reg_write32(HR_I2S_INT_SRC, 0x200);
    }
    /* RZC */
    if (tls_bitband_read(HR_I2S_INT_SRC, 8)) { // 8:value of bit
        tls_reg_write32(HR_I2S_INT_SRC, 0x100);
    }
    /* Tx Done */
    if (tls_bitband_read(HR_I2S_INT_SRC, 7)) { // 7:value of bit
        tls_reg_write32(HR_I2S_INT_SRC, 0x80);
    }
    /* TXOV */
    if (tls_bitband_read(HR_I2S_INT_SRC, 5)) { // 5:value of bit
        tls_reg_write32(HR_I2S_INT_SRC, 0x20);
    }
    /* TXUD */
    if (tls_bitband_read(HR_I2S_INT_SRC, 4)) { // 4:value of bit
        tls_reg_write32(HR_I2S_INT_SRC, 0x10);
    }
    /* Rx Done */
    if (tls_bitband_read(HR_I2S_INT_SRC, 3)) { // 3:value of bit
        tls_reg_write32(HR_I2S_INT_SRC, 0x08);
    }
    /* RxTH */
    if (tls_bitband_read(HR_I2S_INT_SRC, 2)) { // 2:value of bit
        volatile uint8_t cnt;
        for (cnt = (I2S->INT_STATUS & 0x0F), temp = 0; temp < cnt; temp++) {
            if (wm_i2s_buf->rxhead < wm_i2s_buf->rxlen) {
                wm_i2s_buf->rxbuf[wm_i2s_buf->rxhead++] = I2S->RX;
                if (wm_i2s_buf->rxhead >= wm_i2s_buf->rxlen) {
                    wm_i2s_buf->rxhead = 0;
                    wm_i2s_buf->rxdata_ready = 1;
                    tls_bitband_write(HR_I2S_INT_MASK, 2, 1); // 2:value of bit
                    break;
                }
            }
        }
        tls_reg_write32(HR_I2S_INT_SRC, 0x04);
    }
    /* RXOV */
    if (tls_bitband_read(HR_I2S_INT_SRC, 1)) {
        tls_reg_write32(HR_I2S_INT_SRC, 0x02);
    }
    /* RXUD */
    if (tls_bitband_read(HR_I2S_INT_SRC, 0)) {
        tls_reg_write32(HR_I2S_INT_SRC, 0x01);
    }
    csi_kernel_intrpt_exit();
}

void i2s_DMA_TX_Channel_IRQHandler(void *p)
{
    wm_dma_handler_type *hdma = (wm_dma_handler_type *)p;
    wm_dma_desc *dma_desc = &g_dma_desc_tx[0];
    if (p) {
        if (wm_i2s_buf->txdata_done) {
            wm_i2s_buf->txdata_done = 0;
            dma_desc[1].valid |= (1 << 31);
            if (hdma->XferCpltCallback) {
                hdma->XferCpltCallback(hdma);
            }
        } else {
            wm_i2s_buf->txdata_done = 1;
            dma_desc[0].valid |= (1 << 31);
            if (hdma->XferHalfCpltCallback) {
                hdma->XferHalfCpltCallback(hdma);
            }
        }
    } else {
        wm_i2s_buf->txdata_done = 1;
    }
}

void i2s_DMA_RX_Channel_IRQHandler(void *p)
{
    wm_dma_handler_type *hdma = (wm_dma_handler_type *)p;
    wm_dma_desc *dma_desc = &g_dma_desc_rx[0];
    if (p) {
        if (wm_i2s_buf->rxdata_ready) {
            wm_i2s_buf->rxdata_ready = 0;
            dma_desc[1].valid |= (1 << 31);
            if (hdma->XferCpltCallback) {
                hdma->XferCpltCallback(hdma);
            }
        } else {
            wm_i2s_buf->rxdata_ready = 1;
            dma_desc[0].valid |= (1 << 31);
            if (hdma->XferHalfCpltCallback) {
                hdma->XferHalfCpltCallback(hdma);
            }
        }
    } else {
        wm_i2s_buf->rxdata_ready = 1;
    }
}

void wm_i2s_register_callback(tls_i2s_callback callback)
{
    wm_i2s_buf->tx_callback = callback;
}

int wm_i2s_port_init(I2S_InitDef *opts)
{
    I2S_InitDef opt = { I2S_MODE_MASTER, I2S_CTRL_STEREO, I2S_RIGHT_CHANNEL, I2S_Standard, \
                        I2S_DataFormat_16, 8000, 5000000 };

    if (opts != NULL) {
        memcpy_s(&opt, sizeof(opt), opts, sizeof(I2S_InitDef));
    }

    wm_i2s_module_reset();

    tls_reg_write32(HR_I2S_CTRL, 0);
    wm_i2s_set_mode(opt.I2S_Mode_MS);
    wm_i2s_int_clear_all();
    wm_i2s_int_mask_all();

    wm_i2s_mono_select(opt.I2S_Mode_SS);
    wm_i2s_left_channel_sel(opt.I2S_Mode_LR);
    wm_i2s_set_format(opt.I2S_Trans_STD);
    wm_i2s_set_word_len(opt.I2S_DataFormat);
    wm_i2s_set_freq(opt.I2S_AudioFreq, opt.I2S_MclkFreq);
    wm_i2s_set_txth(4);
    wm_i2s_set_rxth(4);

    return WM_SUCCESS;
}

void wm_i2s_tx_rx_stop(void)
{
    wm_i2s_tx_enable(0);
    wm_i2s_rx_enable(0);

    tls_dma_free(tx_channel);
    tls_dma_free(rx_channel);

    wm_i2s_enable(0);
}

int wm_i2s_tx_int(int16_t *data, uint16_t len, int16_t *next_data)
{
    volatile uint32_t temp;
    volatile uint8_t fifo_level;

    if ((data == NULL) || (len == 0)) {
        return  WM_FAILED;
    }
    wm_i2s_buf->txlen = (uint32_t)len;
    wm_i2s_buf->txtail = 0;
    wm_i2s_buf->txbuf = (uint32_t *)data;
    wm_i2s_buf->txdata_done = 0;

    wm_i2s_set_mode(I2S_MODE_MASTER);
    wm_i2s_txth_int_mask(0);
    wm_i2s_tx_fifo_clear();
    tls_irq_enable(I2S_IRQn);
    wm_i2s_tx_enable(1);

    for (fifo_level = ((I2S->INT_STATUS >> 4) & 0x0F), // 4:byte alignment
        temp = 0; temp < 8 - fifo_level; temp++) { // 8:byte alignment
        tls_reg_write32(HR_I2S_TX, wm_i2s_buf->txbuf[wm_i2s_buf->txtail++]);
    }
    wm_i2s_enable(1);

    if ((wm_i2s_buf->tx_callback != NULL) && (next_data != NULL)) {
        wm_i2s_buf->tx_callback((uint32_t *)next_data, &len);
    }
    while (wm_i2s_buf->txdata_done == 0);
    while (tls_reg_read32(HR_I2S_STATUS)&0xF0);

    return WM_SUCCESS;
}

int wm_i2s_tx_dma(int16_t *data, uint16_t len, int16_t *next_data)
{
    if ((data == NULL) || (len == 0)) {
            return  WM_FAILED;
    }
    wm_i2s_buf->txdata_done = 0;

    wm_i2s_set_mode(I2S_MODE_MASTER);
    wm_i2s_dma_tx_init(tx_channel, len*4, data);
    wm_i2s_dma_start(tx_channel);
    wm_i2s_tx_dma_enable(1);
    wm_i2s_tx_enable(1);
    wm_i2s_enable(1);

    if ((wm_i2s_buf->tx_callback != NULL) && (next_data != NULL)) {
        wm_i2s_buf->tx_callback((uint32_t *)next_data, &len);
    }
    while (wm_i2s_buf->txdata_done == 0);
    while (tls_reg_read32(HR_I2S_STATUS)&0xF0);

    return WM_SUCCESS;
}

int wm_i2s_tx_dma_link(int16_t *data, uint16_t len, int16_t *next_data)
{
    if ((data == NULL) || (next_data == NULL) || (len == 0)) {
            return  WM_FAILED;
    }
    uint32_t dma_ctrl;
    wm_dma_desc dma_desc[2];

    wm_i2s_buf->txdata_done = 0;
    wm_i2s_set_mode(I2S_MODE_MASTER);

    dma_ctrl = DMA_CTRL_SRC_ADDR_INC | DMA_CTRL_DATA_SIZE_WORD | DMA_CTRL_BURST_SIZE1;
    dma_ctrl &= ~ 0xFFFF00;
    dma_ctrl |= ((len*2)<<8);

    dma_desc[0].next = &dma_desc[1];
    dma_desc[0].dest_addr = HR_I2S_TX;
    dma_desc[0].src_addr = (unsigned int)data;
    dma_desc[0].dma_ctrl = dma_ctrl>>1;
    dma_desc[0].valid = 0x80000000;

    dma_desc[1].next = &dma_desc[0];
    dma_desc[1].dest_addr = HR_I2S_TX;
    dma_desc[1].src_addr = (unsigned int)next_data;
    dma_desc[1].dma_ctrl = dma_ctrl>>1;
    dma_desc[1].valid = 0x80000000;

    DMA_INTMASK_REG &= ~(0x02<<(tx_channel*2));
    DMA_MODE_REG(tx_channel) = DMA_MODE_SEL_I2S_TX | DMA_MODE_CHAIN_MODE | DMA_MODE_HARD_MODE | (1<<6);
    tls_reg_write32(HR_DMA_CHNL0_LINK_DEST_ADDR + 0x30*tx_channel, (uint32_t)dma_desc);

    wm_i2s_dma_start(tx_channel);
    wm_i2s_tx_dma_enable(1);
    wm_i2s_tx_enable(1);
    wm_i2s_enable(1);

    while (1) {
        if (dma_desc[0].valid == 0) {
            dma_desc[0].valid = 0x80000000;
            if (wm_i2s_buf->tx_callback != NULL) {
                wm_i2s_buf->tx_callback((uint32_t *)data, &len);
            }
        }
        if (dma_desc[1].valid == 0) {
            dma_desc[1].valid = 0x80000000;
            if (wm_i2s_buf->tx_callback != NULL) {
                wm_i2s_buf->tx_callback((uint32_t *)next_data, &len);
            }
        }
        /* todo: a way to break this rountine */
        if (len == 0xFFFF) {
            break;
        }
    }

    return WM_SUCCESS;
}

int wm_i2s_rx_int(int16_t *data, uint16_t len)
{
    if ((data == NULL) || (len == 0)) {
            return  WM_FAILED;
    }
    wm_i2s_buf->rxbuf = (uint32_t *)data;
    wm_i2s_buf->rxlen = (uint32_t)len;
    wm_i2s_buf->rxhead = 0;
    wm_i2s_buf->rxdata_ready = 0;

    wm_i2s_set_mode(I2S_MODE_SLAVE);
    wm_i2s_rxth_int_mask(0);
    wm_i2s_rx_fifo_clear();
    tls_irq_enable(I2S_IRQn);
    wm_i2s_rx_enable(1);
    wm_i2s_enable(1);

    while (wm_i2s_buf->rxdata_ready == 0);

    return WM_SUCCESS;
}

int wm_i2s_rx_dma(int16_t *data, uint16_t len)
{
    if ((data == NULL) || (len == 0)) {
            return  WM_FAILED;
    }
    wm_i2s_buf->rxdata_ready = 0;

    wm_i2s_set_mode(I2S_MODE_SLAVE);
    wm_i2s_dma_rx_init(rx_channel, len*4, data);
    wm_i2s_dma_start(rx_channel);
    wm_i2s_rx_dma_enable(1);
    wm_i2s_rx_enable(1);
    wm_i2s_enable(1);

    while (wm_i2s_buf->rxdata_ready == 0);

    return WM_SUCCESS;
}

int wm_i2s_tx_rx_int(I2S_InitDef *opts, int16_t *data_tx, int16_t *data_rx, uint16_t len)
{
    if ((data_tx == NULL) || (data_rx == NULL) || (len == 0)) {
        return  WM_FAILED;
    }
    wm_i2s_buf->txbuf = (uint32_t *)data_tx;
    wm_i2s_buf->txlen = (uint32_t)len;
    wm_i2s_buf->txtail = 0;
    wm_i2s_buf->txdata_done = 0;

    wm_i2s_buf->rxbuf = (uint32_t *)data_rx;
    wm_i2s_buf->rxlen = (uint32_t)len;
    wm_i2s_buf->rxhead = 0;
    wm_i2s_buf->rxdata_ready = 0;

    wm_i2s_set_mode(opts->I2S_Mode_MS);
#if TEST_WITH_F401
    (opts->I2S_Trans_STD==I2S_Standard || opts->I2S_Trans_STD==I2S_Standard_MSB)? \
        (wm_i2s_clk_inverse(0)):(wm_i2s_clk_inverse(1));
#endif
    wm_i2s_txth_int_mask(0);
    wm_i2s_rxth_int_mask(0);
    tls_irq_enable(I2S_IRQn);
    wm_i2s_tx_enable(1);
    wm_i2s_rx_enable(1);
    wm_i2s_enable(1);

    while (wm_i2s_buf->txdata_done == 0 || wm_i2s_buf->rxdata_ready == 0);
    while (tls_reg_read32(HR_I2S_STATUS)&0xF0);

    return WM_SUCCESS;
}

int wm_i2s_tx_rx_dma(I2S_InitDef *opts, int16_t *data_tx, int16_t *data_rx, uint16_t len)
{
    if ((data_tx == NULL) || (data_rx == NULL) || (len == 0)) {
            return  WM_FAILED;
    }
    wm_i2s_buf->txdata_done = 0;
    wm_i2s_buf->rxdata_ready = 0;

    wm_i2s_set_mode(opts->I2S_Mode_MS);
#if TEST_WITH_F401
    (opts->I2S_Trans_STD==I2S_Standard || \
     opts->I2S_Trans_STD==I2S_Standard_MSB)?(wm_i2s_clk_inverse(0)):(wm_i2s_clk_inverse(1));
#endif
    wm_i2s_tx_dma_enable(1);
    wm_i2s_rx_dma_enable(1);
    wm_i2s_tx_enable(1);
    wm_i2s_rx_enable(1);
    wm_i2s_dma_tx_init(tx_channel, len*4, data_tx);
    wm_i2s_dma_rx_init(rx_channel, len*4, data_rx);
    wm_i2s_dma_start(tx_channel);
    wm_i2s_dma_start(rx_channel);
    wm_i2s_enable(1);

    while (wm_i2s_buf->txdata_done == 0 || wm_i2s_buf->rxdata_ready == 0);
    while (tls_reg_read32(HR_I2S_STATUS)&0xF0);

    return WM_SUCCESS;
}
int wm_i2s_receive_dma(wm_dma_handler_type *hdma, uint16_t *data, uint16_t len)
{
    uint32_t dma_ctrl;
    wm_dma_desc *dma_desc = &g_dma_desc_rx[0];
    uint16_t *next_data = &data[(len/2)];
    if ((data == NULL) || (len == 0)) {
        return  WM_FAILED;
    }

    wm_i2s_buf->rxdata_ready = 0;

    if (rx_channel) {
        tls_dma_free(rx_channel);
    }

    rx_channel = tls_dma_request(WM_I2S_RX_DMA_CHANNEL, TLS_DMA_FLAGS_CHANNEL_SEL(TLS_DMA_SEL_I2S_RX) |
                                 TLS_DMA_FLAGS_HARD_MODE);
    if (rx_channel == 0xFF) {
        return WM_FAILED;
    }
    hdma->channel = rx_channel;
    if (tls_dma_stop(rx_channel)) {
        return WM_FAILED;
    }

    tls_dma_irq_register(rx_channel, i2s_DMA_RX_Channel_IRQHandler, hdma, TLS_DMA_IRQ_TRANSFER_DONE);

    dma_ctrl = DMA_CTRL_DEST_ADDR_INC | DMA_CTRL_DATA_SIZE_WORD | DMA_CTRL_BURST_SIZE1;
    dma_ctrl &= ~ 0xFFFF00;
    dma_ctrl |= ((len)<<8); // half length of data

    dma_desc[0].next = &dma_desc[1];
    dma_desc[0].dest_addr = (unsigned int)data;
    dma_desc[0].src_addr = HR_I2S_RX;
    dma_desc[0].dma_ctrl = dma_ctrl>>1;
    dma_desc[0].valid = 0x80000000;

    dma_desc[1].next = &dma_desc[0];
    dma_desc[1].dest_addr = (unsigned int)next_data;
    dma_desc[1].src_addr = HR_I2S_RX;
    dma_desc[1].dma_ctrl = dma_ctrl>>1;
    dma_desc[1].valid = 0x80000000;

    DMA_INTMASK_REG &= ~(0x02<<(rx_channel*2));
    DMA_MODE_REG(rx_channel) = DMA_MODE_SEL_I2S_RX | DMA_MODE_CHAIN_MODE | DMA_MODE_HARD_MODE | DMA_MODE_CHAIN_LINK_EN;
    tls_reg_write32(HR_DMA_CHNL0_LINK_DEST_ADDR + 0x30*rx_channel, (uint32_t)dma_desc);

    wm_i2s_dma_start(rx_channel);
    wm_i2s_rx_dma_enable(1);
    wm_i2s_rx_enable(1);
    wm_i2s_enable(1);
    return WM_SUCCESS;
}
int wm_i2s_transmit_dma(wm_dma_handler_type *hdma, uint16_t *data, uint16_t len)
{
    uint32_t dma_ctrl;
    wm_dma_desc *dma_desc = &g_dma_desc_tx[0];
    uint16_t *next_data = &data[(len/2)];
    if ((data == NULL) || (len == 0)) {
        return  WM_FAILED;
    }

    wm_i2s_buf->txdata_done = 0;

    if (tx_channel) {
        tls_dma_free(tx_channel);
    }

    tx_channel = tls_dma_request(WM_I2S_TX_DMA_CHANNEL, TLS_DMA_FLAGS_CHANNEL_SEL(TLS_DMA_SEL_I2S_TX) |
                                 TLS_DMA_FLAGS_HARD_MODE);
    if (tx_channel == 0xFF) {
        return WM_FAILED;
    }
    hdma->channel = tx_channel;
    if (tls_dma_stop(tx_channel)) {
        return WM_FAILED;
    }

    tls_dma_irq_register(tx_channel, i2s_DMA_TX_Channel_IRQHandler, hdma, TLS_DMA_IRQ_TRANSFER_DONE);

    dma_ctrl = DMA_CTRL_SRC_ADDR_INC | DMA_CTRL_DATA_SIZE_WORD | DMA_CTRL_BURST_SIZE1;
    dma_ctrl &= ~ 0xFFFF00;
    dma_ctrl |= ((len)<<8); // half length of data

    dma_desc[0].next = &dma_desc[1];
    dma_desc[0].dest_addr = HR_I2S_TX;
    dma_desc[0].src_addr = (unsigned int)data;
    dma_desc[0].dma_ctrl = dma_ctrl>>1;
    dma_desc[0].valid = 0x80000000;

    dma_desc[1].next = &dma_desc[0];
    dma_desc[1].dest_addr = HR_I2S_TX;
    dma_desc[1].src_addr = (unsigned int)next_data;
    dma_desc[1].dma_ctrl = dma_ctrl>>1;
    dma_desc[1].valid = 0x80000000;

    DMA_INTMASK_REG &= ~(0x02<<(tx_channel*2));
    DMA_MODE_REG(tx_channel) = DMA_MODE_SEL_I2S_TX | DMA_MODE_CHAIN_MODE | DMA_MODE_HARD_MODE | DMA_MODE_CHAIN_LINK_EN;
    tls_reg_write32(HR_DMA_CHNL0_LINK_DEST_ADDR + 0x30*tx_channel, (uint32_t)dma_desc);

    wm_i2s_dma_start(tx_channel);
    wm_i2s_tx_dma_enable(1);
    wm_i2s_tx_enable(1);
    wm_i2s_enable(1);
    return WM_SUCCESS;
}

int wm_i2s_tranceive_dma(uint32_t i2s_mode, wm_dma_handler_type *hdma_tx, wm_dma_handler_type *hdma_rx,
                         uint16_t *data_tx, uint16_t *data_rx, uint16_t len)
{
    uint32_t dma_ctrl;
    wm_dma_desc *dma_desc_tx = &g_dma_desc_tx[0];
    wm_dma_desc *dma_desc_rx = &g_dma_desc_rx[0];
    uint16_t *next_data_tx = &data_tx[(len/2)];
    uint16_t *next_data_rx = &data_rx[(len/2)];
    if ((data_tx == NULL) || (data_rx == NULL) || (len == 0)) {
        return  WM_FAILED;
    }

    wm_i2s_buf->txdata_done = 0;
    wm_i2s_buf->rxdata_ready = 0;
    wm_i2s_set_mode(i2s_mode);

    if (tx_channel) {
        tls_dma_free(tx_channel);
    }

    tx_channel = tls_dma_request(WM_I2S_TX_DMA_CHANNEL, TLS_DMA_FLAGS_CHANNEL_SEL(TLS_DMA_SEL_I2S_TX) |
                                 TLS_DMA_FLAGS_HARD_MODE);
    if (tx_channel == 0xFF) {
        return WM_FAILED;
    }
    hdma_tx->channel = tx_channel;
    if (tls_dma_stop(tx_channel)) {
        return WM_FAILED;
    }

    tls_dma_irq_register(tx_channel, i2s_DMA_TX_Channel_IRQHandler, hdma_tx, TLS_DMA_IRQ_TRANSFER_DONE);

    dma_ctrl = DMA_CTRL_SRC_ADDR_INC | DMA_CTRL_DATA_SIZE_WORD | DMA_CTRL_BURST_SIZE1;
    dma_ctrl &= ~ 0xFFFF00;
    dma_ctrl |= ((len)<<8); // half length of data

    dma_desc_tx[0].next = &dma_desc_tx[1];
    dma_desc_tx[0].dest_addr = HR_I2S_TX;
    dma_desc_tx[0].src_addr = (unsigned int)data_tx;
    dma_desc_tx[0].dma_ctrl = dma_ctrl>>1;
    dma_desc_tx[0].valid = 0x80000000;

    dma_desc_tx[1].next = &dma_desc_tx[0];
    dma_desc_tx[1].dest_addr = HR_I2S_TX;
    dma_desc_tx[1].src_addr = (unsigned int)next_data_tx;
    dma_desc_tx[1].dma_ctrl = dma_ctrl>>1;
    dma_desc_tx[1].valid = 0x80000000;
    DMA_MODE_REG(tx_channel) = DMA_MODE_SEL_I2S_TX | DMA_MODE_CHAIN_MODE | DMA_MODE_HARD_MODE | DMA_MODE_CHAIN_LINK_EN;
    tls_reg_write32(HR_DMA_CHNL0_LINK_DEST_ADDR + 0x30*tx_channel, (uint32_t)dma_desc_tx);

    if (rx_channel) {
        tls_dma_free(rx_channel);
    }

    rx_channel = tls_dma_request(WM_I2S_RX_DMA_CHANNEL,
        TLS_DMA_FLAGS_CHANNEL_SEL(TLS_DMA_SEL_I2S_RX) | TLS_DMA_FLAGS_HARD_MODE);
    if (rx_channel == 0xFF) {
        return WM_FAILED;
    }
    hdma_rx->channel = rx_channel;
    if (tls_dma_stop(rx_channel)) {
        return WM_FAILED;
    }

    tls_dma_irq_register(rx_channel, i2s_DMA_RX_Channel_IRQHandler, hdma_rx, TLS_DMA_IRQ_TRANSFER_DONE);

    dma_ctrl = DMA_CTRL_DEST_ADDR_INC | DMA_CTRL_DATA_SIZE_WORD | DMA_CTRL_BURST_SIZE1;
    dma_ctrl &= ~ 0xFFFF00;
    dma_ctrl |= ((len)<<8); // half length of data

    dma_desc_rx[0].next = &dma_desc_rx[1];
    dma_desc_rx[0].dest_addr = (unsigned int)data_rx;
    dma_desc_rx[0].src_addr = HR_I2S_RX;
    dma_desc_rx[0].dma_ctrl = dma_ctrl>>1;
    dma_desc_rx[0].valid = 0x80000000;

    dma_desc_rx[1].next = &dma_desc_rx[0];
    dma_desc_rx[1].dest_addr = (unsigned int)next_data_rx;
    dma_desc_rx[1].src_addr = HR_I2S_RX;
    dma_desc_rx[1].dma_ctrl = dma_ctrl>>1;
    dma_desc_rx[1].valid = 0x80000000;
    DMA_MODE_REG(rx_channel) = DMA_MODE_SEL_I2S_RX | DMA_MODE_CHAIN_MODE | DMA_MODE_HARD_MODE | DMA_MODE_CHAIN_LINK_EN;
    tls_reg_write32(HR_DMA_CHNL0_LINK_DEST_ADDR + 0x30*rx_channel, (uint32_t)dma_desc_rx);

    wm_i2s_dma_start(rx_channel);
    wm_i2s_rx_dma_enable(1);
    wm_i2s_rx_enable(1);

    wm_i2s_dma_start(tx_channel);
    wm_i2s_tx_dma_enable(1);
    wm_i2s_tx_enable(1);
    wm_i2s_enable(1);
    return WM_SUCCESS;
}