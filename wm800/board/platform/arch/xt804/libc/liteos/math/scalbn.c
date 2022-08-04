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

#include <math.h>
#include <stdint.h>

double scalbn(long double x, int n)
{
    union {double f; uint64_t i;} u;
    double_t y = x;
    int z = n;

    if (z > 1023) { // 1023:byte alignment
        y *= 0x1p1023;
        z -= 1023; // 1023:byte alignment
        if (z > 1023) { // 1023:byte alignment
            y *= 0x1p1023;
            z -= 1023; // 1023:byte alignment
            if (z > 1023) { // 1023:byte alignment
                z = 1023; // 1023:byte alignment
            }
        }
    } else if (z < -1022) { // -1022:byte alignment
        /* make sure final z < -53 to avoid double
           rounding in the subnormal range */
        y *= 0x1p-1022 * 0x1p53;
        z += 1022 - 53; // 1022:byte alignment, 53:byte alignment
        if (z < -1022) { // -1022:byte alignment
            y *= 0x1p-1022 * 0x1p53;
            z += 1022 - 53; // 1022:byte alignment, 53:byte alignment
            if (z < -1022) { // -1022:byte alignment
                z = -1022; // -1022:byte alignment
            }
        }
    }
    u.i = (uint64_t)(0x3ff + z) << 52;
    x = y * u.f;
    return x;
}