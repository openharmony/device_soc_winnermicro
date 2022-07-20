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

/**
 * @file    wm_irq.c
 *
 * @brief   interupt driver module
 *
 * @author  dave
 *
 * Copyright (c) 2015 Winner Microelectronics Co., Ltd.
 */

#include "core_804.h"
#include "wm_regs.h"
#include "wm_irq.h"
#include "wm_config.h"
#include "wm_mem.h"

/* irq functions declare */
extern ATTRIBUTE_ISR void i2s_I2S_IRQHandler(void);
extern ATTRIBUTE_ISR void GPIOA_IRQHandler(void);
extern ATTRIBUTE_ISR void GPIOB_IRQHandler(void);
extern ATTRIBUTE_ISR void i2c_I2C_IRQHandler(void);
extern ATTRIBUTE_ISR void UART0_IRQHandler(void);
extern ATTRIBUTE_ISR void UART1_IRQHandler(void);
extern ATTRIBUTE_ISR void UART2_IRQHandler(void);
extern ATTRIBUTE_ISR void UART2_4_IRQHandler(void);
extern ATTRIBUTE_ISR void PWM_IRQHandler(void);
extern ATTRIBUTE_ISR void SPI_LS_IRQHandler(void);
extern ATTRIBUTE_ISR void HSPI_IRQHandler(void);
extern ATTRIBUTE_ISR void SDIOA_IRQHandler(void);
extern ATTRIBUTE_ISR void DMA_Channel0_IRQHandler(void);
extern ATTRIBUTE_ISR void DMA_Channel1_IRQHandler(void);
extern ATTRIBUTE_ISR void DMA_Channel2_IRQHandler(void);
extern ATTRIBUTE_ISR void DMA_Channel3_IRQHandler(void);
extern ATTRIBUTE_ISR void DMA_Channel4_7_IRQHandler(void);
extern ATTRIBUTE_ISR void ADC_IRQHandler(void);
extern ATTRIBUTE_ISR void GPSEC_IRQ_Handler(void);
extern ATTRIBUTE_ISR void RSA_IRQ_Handler(void);
extern ATTRIBUTE_ISR void TIM0_5_IRQ_Handler(void);
extern ATTRIBUTE_ISR void SPI_HS_IRQ_Handler(void);
extern ATTRIBUTE_ISR void MAC_IRQ_Handler(void);
extern ATTRIBUTE_ISR void SEC_IRQ_Handler(void);
extern ATTRIBUTE_ISR void PMU_IRQ_Handler(void);
extern ATTRIBUTE_ISR void WDG_IRQHandler(void);

static u32 irqen_status = 0;

/**
 * @brief              This function is used to initial system interrupt.
 *
 * @param[in]          None
 *
 * @return             None
 *
 * @note               None
 */
void tls_irq_init(void)
{
    /* clear bt mask */
    tls_reg_write32(0x40002A10,0xFFFFFFFF);
    NVIC_ClearPendingIRQ(BT_IRQn);
    
    csi_vic_set_vector(I2S_IRQn, (uint32_t)i2s_I2S_IRQHandler);
    csi_vic_set_vector(I2C_IRQn, (uint32_t)i2c_I2C_IRQHandler);
    csi_vic_set_vector(GPIOA_IRQn, (uint32_t)GPIOA_IRQHandler);
    csi_vic_set_vector(GPIOB_IRQn, (uint32_t)GPIOB_IRQHandler);
    csi_vic_set_vector(UART0_IRQn, (uint32_t)UART0_IRQHandler);
    csi_vic_set_vector(UART1_IRQn, (uint32_t)UART1_IRQHandler);
    csi_vic_set_vector(UART24_IRQn, (uint32_t)UART2_4_IRQHandler);
    csi_vic_set_vector(PWM_IRQn, (uint32_t)PWM_IRQHandler);
    csi_vic_set_vector(SPI_LS_IRQn, (uint32_t)SPI_LS_IRQHandler);
#if TLS_CONFIG_HS_SPI
    csi_vic_set_vector(SPI_HS_IRQn, (uint32_t)HSPI_IRQHandler);
    csi_vic_set_vector(SDIO_IRQn, (uint32_t)SDIOA_IRQHandler);
#endif
    csi_vic_set_vector(ADC_IRQn, (uint32_t)ADC_IRQHandler);
    csi_vic_set_vector(DMA_Channel0_IRQn, (uint32_t)DMA_Channel0_IRQHandler);
    csi_vic_set_vector(DMA_Channel1_IRQn, (uint32_t)DMA_Channel1_IRQHandler);
    csi_vic_set_vector(DMA_Channel2_IRQn, (uint32_t)DMA_Channel2_IRQHandler);
    csi_vic_set_vector(DMA_Channel3_IRQn, (uint32_t)DMA_Channel3_IRQHandler);
    csi_vic_set_vector(DMA_Channel4_7_IRQn, (uint32_t)DMA_Channel4_7_IRQHandler);
    csi_vic_set_vector(RSA_IRQn, (uint32_t)RSA_IRQ_Handler);
    csi_vic_set_vector(CRYPTION_IRQn, (uint32_t)GPSEC_IRQ_Handler);
    csi_vic_set_vector(TIMER_IRQn, (uint32_t)TIM0_5_IRQ_Handler);
    csi_vic_set_vector(SPI_HS_IRQn, (uint32_t)SPI_HS_IRQ_Handler);
    csi_vic_set_vector(MAC_IRQn, (uint32_t)MAC_IRQ_Handler);
    csi_vic_set_vector(SEC_IRQn, (uint32_t)SEC_IRQ_Handler);
    csi_vic_set_vector(PMU_IRQn, (uint32_t)PMU_IRQ_Handler);
}

/**
 * @brief              This function is used to register interrupt.
 *
 * @param[in]          vec_no           interrupt no
 * @param[in]          handler
 * @param[in]          *data
 *
 * @return             None
 *
 * @note               None
 */
void tls_irq_register_handler(u8 vec_no, intr_handler_func handler, void *data)
{
}

/**
 * @brief              This function is used to enable interrupt.
 *
 * @param[in]          vec_no       interrupt no
 *
 * @return             None
 *
 * @note               None
 */
void tls_irq_enable(u8 vec_no)
{
    if ((irqen_status & (1<<vec_no)) == 0)
    {
        irqen_status |= 1<<vec_no;
        NVIC_ClearPendingIRQ((IRQn_Type)vec_no);
        NVIC_EnableIRQ((IRQn_Type)vec_no);
    }
}

/**
 * @brief              This function is used to disable interrupt.
 *
 * @param[in]          vec_no       interrupt no
 *
 * @return             None
 *
 * @note               None
 */
void tls_irq_disable(u8 vec_no)
{
    if (irqen_status & (1<<vec_no))
    {
        irqen_status &= ~(1<<vec_no);
        NVIC_DisableIRQ((IRQn_Type)vec_no);
    }
}

void tls_irq_priority(u8 vec_no, u32 prio)
{
    NVIC_SetPriority((IRQn_Type)vec_no, prio);
}