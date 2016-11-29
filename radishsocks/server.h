/*
 * =====================================================================================
 *
 *       Filename:  server.h
 *
 *    Description:  server header
 *
 *        Version:  1.0
 *        Created:  2016年11月19日 23时06分52秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  julyrain (T3), lzx1442@163.com
 *   Organization:  
 *
 * =====================================================================================
 */
#ifndef __RS_SERVER_H__
#define __RS_SERVER_H__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>

#include <getopt.h>

#include <assert.h>

#include <event2/dns.h>
#include <event2/dns_struct.h>

#include "log.h"
#include "cipher.h"
#include "base.h"

#include "common.h"

void register_rs_object_server(void);

#endif
