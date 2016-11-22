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

#define NAME "rs-client"

#define STAGE_INIT    0x00
#define STAGE_VERSION 0x01
#define STAGE_AUTH    0x02
#define STAGE_ADDR    0x03
#define STAGE_STREAM  0x04
#define STAGE_UDP     0x05

#define SERVER_INFO_MAX 16  //max server
#define LOCAL_INFO_MAX  64  //max listener

struct server_info{ //server
    char server_ip[IP_ADDRESS_MAX];
    char server_pwd[PASSWORD_MAX];
    int  server_port;
};

struct local_info{ //local
    char local_ip[IP_ADDRESS_MAX];
    int  local_port;
    struct evconnlistener *listener;
};

struct manager_info{ //manager
    char server_ip[IP_ADDRESS_MAX];
    char server_pwd[PASSWORD_MAX];
    int  server_port;

    struct event_base *base;
};

struct config_info{
	int server_info_count;
    struct server_info server_info[SERVER_INFO_MAX]; //muti server

	int local_info_count;
    struct local_info local_info[LOCAL_INFO_MAX]; //muti local

    struct manager_info manager_info; //single manager
};

struct ev_container{
	struct bufferevent *bev_local;
    struct bufferevent *bev_remote;
    struct bufferevent *bev_udp; //udp proxy 

    struct object_container udp_server_table; //udp server table 

    struct event *timeout_ev;
    struct sockaddr sa; //local

	int stage;

	struct server_info *server_info; //event server info
};

void register_rs_object_client(void);

#endif
