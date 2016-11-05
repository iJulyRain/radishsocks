/*
 * =====================================================================================
 *
 *       Filename:  log.h
 *
 *    Description:  log header
 *
 *        Version:  1.0
 *        Created:  10/27/2016 04:08:59 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  lizhixian (group3), lizhixian@integritytech.com.cn
 *   Organization:  
 *
 * =====================================================================================
 */
#ifndef __LOG_H__
#define __LOG_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

enum{
    ERROR=0,
    DEBUG,
    INFO
};

int loglevel;

void vlog(int level, const char *format, ...);
void vlog_array(int level, unsigned char arr[], int arr_size);

#endif
