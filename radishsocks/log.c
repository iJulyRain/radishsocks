/*
 * =====================================================================================
 *
 *       Filename:  log.c
 *
 *    Description:  log
 *
 *        Version:  1.0
 *        Created:  10/27/2016 03:59:39 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  lizhixian (group3), lizhixian@integritytech.com.cn
 *   Organization:  
 *
 * =====================================================================================
 */

#include "log.h"

void log(int level, const char *format, ...)
{
    va_list ap; 

    if (level > loglevel)
        return ;

    va_start(ap, format);
    vprintf(format, ap);
    va_end(ap);
}
