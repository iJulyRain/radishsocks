/*
 * =====================================================================================
 *
 *       Filename:  base.h
 *
 *    Description:  base of radishsocks
 *
 *        Version:  1.0
 *        Created:  11/14/2016 01:53:35 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  lizhixian (group3), lizhixian@integritytech.com.cn
 *   Organization:  
 *
 * =====================================================================================
 */

#ifndef __RS_BASE_H__
#define __RS_BASE_H__

#include "object.h"
#include "log.h"

#include <string.h>

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/event.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/**
* @brief radish socket object base
*/
struct rs_object_base
{
    struct object parent;

    struct event_base *base;
    
    int (*init)(int argc, char **argv, void *self);
    void (*run)(void *self);
    void (*destroy)(void *self);

    void *user_data;
};

struct rs_object_base *new_rs_object(const char *name, int type);
void delete_rs_object(struct rs_object_base *rs_object_base);

#endif
