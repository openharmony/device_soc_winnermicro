/*
 * Copyright (C) 2022 HiHope Open Source Organization .
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "wm_include.h"

#if !(defined(LOSCFG_BASE_CORE_HILOG))

#include "stdarg.h"
#include "stdio.h"

int hal_trace_printf(int attr, const char *fmt, ...)
{
    int ret = 0;
    va_list ap;

    va_start(ap, fmt);	
	vprintf(fmt, ap);
    va_end(ap);
	
    return ret;
}

#endif

int HdfSysEventSend(unsigned long eventClass, unsigned int event, const char *content, bool sync)
{
    int ret = 0;
	
    return ret;	
}
