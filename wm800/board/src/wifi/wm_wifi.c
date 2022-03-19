/*****************************************************************************
*
* File Name : wm_wifi.c
*
* Description: wm wifi
*
* Copyright (c) 2014 Winner Micro Electronic Design Co., Ltd.
* All rights reserved.
*
* Author :
*
* Date : 2022-3-10
*****************************************************************************/

#include <string.h>
#include "wm_params.h"
#include "wm_mem.h"
#include "wm_wifi.h"
#include "wm_ram_config.h"
#include "wm_debug.h"

static struct tls_wifi_netif_status_event wifi_netif_status_event;
static u8 wifi_inited_ok = 0;
static void wifi_status_changed(u8 status)
{
    struct tls_wifi_netif_status_event *status_event;

    dl_list_for_each(status_event, &wifi_netif_status_event.list, struct tls_wifi_netif_status_event, list)
    {
        if(status_event->status_callback != NULL)
        {
            switch(status)
            {
                case WIFI_JOIN_SUCCESS:             
                    status_event->status_callback(NETIF_WIFI_JOIN_SUCCESS);
                    break;
                case WIFI_JOIN_FAILED:
                    status_event->status_callback(NETIF_WIFI_JOIN_FAILED);
                    break;
                case WIFI_DISCONNECTED:
                    status_event->status_callback(NETIF_WIFI_DISCONNECTED);
                    break;
#if TLS_CONFIG_AP
                case WIFI_SOFTAP_SUCCESS:
                    status_event->status_callback(NETIF_WIFI_SOFTAP_SUCCESS);
                    break;
                case WIFI_SOFTAP_FAILED:
                    status_event->status_callback(NETIF_WIFI_SOFTAP_FAILED);
                    break;
                case WIFI_SOFTAP_CLOSED:
                    status_event->status_callback(NETIF_WIFI_SOFTAP_CLOSED);
                    break;
#endif
                default:
                    break;
            }
        }
    }
}

/**
 * @brief          This function is used to initialize wifi
 *
 * @param[in]      None
 *
 * @return         0-success
 *
 * @note           None
 */
int tls_wifi_init(void)
{
	extern u8 tx_gain_group[];
    u8 mac_addr[6] = {0x00, 0x25, 0x08, 0x09, 0x01, 0x0F};
	if (wifi_inited_ok == 1)
	{
		return 0;
	}

    tls_get_tx_gain(&tx_gain_group[0]);
    if (tls_wifi_mem_cfg(WIFI_MEM_START_ADDR, 5, 3)) /*wifi tx&rx mem customized interface*/
    {
        TLS_DBGPRT_INFO("wl mem initial failured\n");
		return -1;
    }

    tls_get_mac_addr(&mac_addr[0]);
	TLS_DBGPRT_INFO("%02x%02x%02x%02x%02x%02x\n", mac_addr[0], mac_addr[1], mac_addr[2], 
		mac_addr[3], mac_addr[4], mac_addr[5]);
    if(tls_wl_init(NULL, &mac_addr[0], NULL) == NULL)
    {
        TLS_DBGPRT_INFO("wl driver initial failured\n");
		return -1;
    }
    if (wpa_supplicant_init(mac_addr))
    {
        TLS_DBGPRT_INFO("supplicant initial failured\n");
		return -1;
    }
    tls_wifi_status_change_cb_register(wifi_status_changed);
	wifi_inited_ok = 1;
	return 0;	
}

/**
 * @brief		   This function is used to initialize wifi netif event list
 *
 * @param[in]	   None
 *
 * @return		   0-success
 *
 * @note		   None
 */
void tls_wifi_netif_event_init(void)
{
    dl_list_init(&wifi_netif_status_event.list);
}


/**
 * @brief          This function is used to add wifi event function
 *
 * @param[in]      None
 *
 * @return         0-success
 *
 * @note           None
 */
int tls_wifi_netif_add_status_event(tls_wifi_netif_status_event_fn event_fn)
{
    u32 cpu_sr;
    struct tls_wifi_netif_status_event *evt;
    //if exist, remove from event list first.
    tls_wifi_netif_remove_status_event(event_fn);
    evt = tls_mem_alloc(sizeof(struct tls_wifi_netif_status_event));
    if(evt==NULL)
        return -1;
    memset(evt, 0, sizeof(struct tls_wifi_netif_status_event));
    evt->status_callback = event_fn;
    cpu_sr = tls_os_set_critical();
    dl_list_add_tail(&wifi_netif_status_event.list, &evt->list);
    tls_os_release_critical(cpu_sr);

	return 0;
}

/**
 * @brief          This function is used to remove wifi event function
 *
 * @param[in]      None
 *
 * @return         0-success
 *
 * @note           None
 */
int tls_wifi_netif_remove_status_event(tls_wifi_netif_status_event_fn event_fn)
{
    struct tls_wifi_netif_status_event *status_event;
    bool is_exist = FALSE;
    u32 cpu_sr;
    if(dl_list_empty(&wifi_netif_status_event.list))
        return 0;
    dl_list_for_each(status_event, &wifi_netif_status_event.list, struct tls_wifi_netif_status_event, list)
    {
        if(status_event->status_callback == event_fn)
        {
            is_exist = TRUE;
            break;
        }
    }
    if(is_exist)
    {
        cpu_sr = tls_os_set_critical();
        dl_list_del(&status_event->list);
        tls_os_release_critical(cpu_sr);
        tls_mem_free(status_event);
    }
    return 0;
}

