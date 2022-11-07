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
 * @file
 * IP address API (common IPv4 and IPv6)
 */

/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Adam Dunkels <adam@sics.se>
 *
 */
#ifndef LWIP_HDR_IP_ADDR_H
#define LWIP_HDR_IP_ADDR_H

#ifdef __cplusplus
extern "C" {
#endif

#if LWIP_IPV4

extern const ip_addr_t ip_addr_any;
extern const ip_addr_t ip_addr_broadcast;

 /**
 * @ingroup ip4addr
 * Can be used as a fixed/const ip_addr_t
 * for the IP wildcard.
 * Defined to @ref IP4_ADDR_ANY when IPv4 is enabled.
 * Defined to @ref IP6_ADDR_ANY in IPv6 only systems.
 * Use this if you can handle IPv4 _AND_ IPv6 addresses.
 * Use @ref IP4_ADDR_ANY or @ref IP6_ADDR_ANY when the IP
 * type matters.
 */
#define IP_ADDR_ANY         IP4_ADDR_ANY
/**
 * @ingroup ip4addr
 * Can be used as a fixed/const ip_addr_t
 * for the IPv4 wildcard and the broadcast address
 */
#define IP4_ADDR_ANY        (&ip_addr_any)
/**
 * @ingroup ip4addr
 * Can be used as a fixed/const ip4_addr_t
 * for the wildcard and the broadcast address
 */
#define IP4_ADDR_ANY4       (ip_2_ip4(&ip_addr_any))

/** @ingroup ip4addr */
#define IP_ADDR_BROADCAST   (&ip_addr_broadcast)
/** @ingroup ip4addr */
#define IP4_ADDR_BROADCAST  (ip_2_ip4(&ip_addr_broadcast))

#endif /* LWIP_IPV4 */

#if LWIP_IPV6

extern const ip_addr_t ip6_addr_any;

 /**
 * @ingroup ip6addr
 * IP6_ADDR_ANY can be used as a fixed ip_addr_t
 * for the IPv6 wildcard address
 */
#define IP6_ADDR_ANY   (&ip6_addr_any)
 /**
 * @ingroup ip6addr
 * IP6_ADDR_ANY6 can be used as a fixed ip6_addr_t
 * for the IPv6 wildcard address
 */
#define IP6_ADDR_ANY6  (ip_2_ip6(&ip6_addr_any))

#if !LWIP_IPV4
 /** IPv6-only configurations */
#define IP_ADDR_ANY IP6_ADDR_ANY
#endif /* !LWIP_IPV4 */

#endif

#if LWIP_IPV4 && LWIP_IPV6
/** @ingroup ipaddr */
#define IP_ANY_TYPE    (&ip_addr_any_type)
#else
#define IP_ANY_TYPE    IP_ADDR_ANY
#endif

#ifdef __cplusplus
}
#endif

#endif /* LWIP_HDR_IP_ADDR_H */
