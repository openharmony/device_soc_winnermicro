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

/**************************************************************************
 * File Name                   : utils.h
 * Author                      :
 * Version                     : 1.0
 * Date                        :
 * Description                 :
 *
 * Copyright (c) 2014 Winner Microelectronics Co., Ltd.
 * All rights reserved.
 *
 ***************************************************************************/
#ifndef UTILS_H
#define UTILS_H

int chk_crc8(u8 *ptr, u32 len);
u8 get_crc8(u8 *ptr, u32 len);
u8 calculate_crc8(u8 crc8, u8 *ptr, u32 len);
u32 get_crc32(u8 *data, u32 data_size);
u32 checksum(u32 *data, u32 length, u32 init);
int atodec(char ch);
int strtodec(int *dec, char *str);
int atohex(char ch);
int strtohex(u32 *hex, char *str);
int strtohexarray(u8 array[], int cnt, char *str);
int strtoip(u32 *ipadr, char *str);
void iptostr(u32 ip, char *str);
void mactostr(u8 mac[], char *str);

int hex_to_digit(int c);
int digit_to_hex(int c);
int hexstr_to_unit(char *buf, u32 *d);
int string_to_uint(char *buf, u32 *d);
int string_to_ipaddr(const char *buf, u8 *addr);
char *strdup(const char *s);
char *strndup(const char *s, size_t len);

int sendchar(int ch);

#endif /* UTILS_H */
