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
	
static const char *header[] = {"ERROR", "DEBUG", "INFO"};

void vlog(int level, const char *format, ...)
{
    va_list ap; 

    if (level > loglevel)
        return ;

	printf("[%s] ", header[level]);

    va_start(ap, format);
    vprintf(format, ap);
    va_end(ap);
}

void vlog_array(int level, char arr[], int arr_size)
{
	int i;

    if (level > loglevel)
        return ;

	printf("[%s] ", header[level]);

	for (i = 0; i < arr_size; i++)
		printf("%#02X ", arr[i]);
	
	printf("\n");
}

