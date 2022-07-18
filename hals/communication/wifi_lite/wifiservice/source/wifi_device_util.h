/*
 * Copyright (c) 2020 HiHope Community.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef WIFI_DEVICE_UTIL_H
#define WIFI_DEVICE_UTIL_H

#include "wifi_device.h"
#include "wifi_device_config.h"
#include "wifi_error_code.h"

#include  "wm_wifi_api.h"

/**
 * @brief lock wifi global lock
 *
 * @return WifiErrorCode.
 */
WifiErrorCode LockWifiGlobalLock(void);

/**
 * @brief unlock wifi global lock
 *
 * @return WifiErrorCode.
 */
WifiErrorCode UnlockWifiGlobalLock(void);

/**
 * @brief lock wifi event lock
 *
 * @return WifiErrorCode.
 */
WifiErrorCode LockWifiEventLock(void);

/**
 * @brief unlock wifi event lock
 *
 * @return WifiErrorCode.
 */
WifiErrorCode UnlockWifiEventLock(void);

/**
 * @brief convert Harmony OS security type to WinnerMicro security type
 *
 * @param type [in] Harmony OS security type.
 *
 * @return WinnerMicro security type.
 */
int HoSec2WmSec(WifiSecurityType type);

/**
 * @brief convert WinnerMicro security type to Harmony OS security type
 *
 * @param type [in] WinnerMicro security type.
 *
 * @return Harmony OS security type.
 */
WifiSecurityType WmSec2HoSec(int mode);

/**
 * @brief convert WinnerMicro enum tls_wifi_auth_mode to Harmony OS WifiSecurityType
 *
 * @param mode in WinnerMicro enum tls_wifi_auth_mode type.
 *
 * @return Harmony OS WifiSecurityType
 */
WifiSecurityType WmAuth2HoSec(int mode);

#endif  // WIFI_DEVICE_UTIL_H
