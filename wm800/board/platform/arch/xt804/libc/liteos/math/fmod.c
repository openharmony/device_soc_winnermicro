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

double fmod(double x, double y)
{
    union {double f; uint64_t i;} ux = {x}, uy = {y};
    int ex = (ux.i>>52) & 0x7ff;
    int ey = (uy.i>>52) & 0x7ff;
    int sx = ux.i>>63;
    uint64_t i;

    /* in the followings uxi should be ux.i, but then gcc wrongly adds */
    /* float load/store to inner loops ruining performance and code size */
    uint64_t uxi = ux.i;

    if ((uy.i<<1) == 0 || isnan(y) || ex == 0x7ff) {
        return (x*y*1.0)/(x*y);
    }
    if ((uxi<<1) <= (uy.i<<1)) {
        if ((uxi<<1) == (uy.i<<1)) {
            return 0*x;
        }
        return x;
    }

    /* normalize x and y */
    if (!ex) {
        for (i = (uxi << 12); (i >> 63) == 0; ex--, i <<= 1) { // 12:byte alignment, 63:byte alignment
        }
        uxi <<= -ex + 1;
    } else {
        uxi &= -1ULL >> 12;
        uxi |= 1ULL << 52;
    }
    if (!ey) {
        for (i = (uy.i<<12); (i>>63) == 0; ey--, i <<= 1) {
        }
        uy.i <<= -ey + 1;
    } else {
        uy.i &= -1ULL >> 12;
        uy.i |= 1ULL << 52;
    }

    /* x mod y */
    for (; ex > ey; ex--) {
        i = uxi - uy.i;
        if ((i >> 63) == 0) {
            if (i == 0) {
                return 0*x;
            }
            uxi = i;
        }
        uxi <<= 1;
    }
    i = uxi - uy.i;
    if ((i >> 63) == 0) {
        if (i == 0) {
            return 0*x;
        }
        uxi = i;
    }
    for (; (uxi>>52) == 0; uxi <<= 1, ex--) {   // 右移52位
    }

    /* scale result */
    if (ex > 0) {
        uxi -= 1ULL << 52;
        uxi |= (uint64_t)ex << 52;
    } else {
        uxi >>= -ex + 1;
    }
    uxi |= (uint64_t)sx << 63;
    ux.i = uxi;
    return ux.f;
}
