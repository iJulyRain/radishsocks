/*
 * =====================================================================================
 *
 *       Filename:  client.h
 *
 *    Description:  client header
 *
 *        Version:  1.0
 *        Created:  11/16/2016 03:59:22 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  lizhixian (group3), lizhixian@integritytech.com.cn
 *   Organization:  
 *
 * =====================================================================================
 */
#ifndef __RS_CLIENT_H__
#define __RS_CLIENT_H__

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <signal.h>

#include <getopt.h>

#include <assert.h>

#include "log.h"
#include "cipher.h"
#include "base.h"

#include "common.h"

#define STAGE_INIT    0x00
#define STAGE_VERSION 0x01
#define STAGE_AUTH    0x02
#define STAGE_ADDR    0x03
#define STAGE_STREAM  0x04
#define STAGE_UDP     0x05

#define SERVER_INFO_MAX 16  //max server
#define LOCAL_INFO_MAX  64  //max listener

void register_rs_object_client(void);

#endif
