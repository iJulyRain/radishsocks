/*
 * =====================================================================================
 *
 *       Filename:  common.h
 *
 *    Description:  common header
 *
 *        Version:  1.0
 *        Created:  11/18/2016 07:02:25 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  lizhixian (group3), lizhixian@integritytech.com.cn
 *   Organization:  
 *
 * =====================================================================================
 */
#ifndef __RS_COMMON_H__
#define __RS_COMMON_H__

#include "base.h"

#define ADDRESS_MAX 256 

enum{
    type_ip = 0,
    type_domain
};

struct domain_info{
    int type; //0 ip/ 1 domain
    char address[ADDRESS_MAX];
    int port;
};

void reset_timer(struct event *timeout_ev, int timeout);
int parse_header(const unsigned char *data, const int datalen, struct domain_info *domain_info);

#endif
