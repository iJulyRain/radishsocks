/*
 * =====================================================================================
 *
 *       Filename:  common.c
 *
 *    Description:  common
 *
 *        Version:  1.0
 *        Created:  11/18/2016 07:08:48 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  lizhixian (group3), lizhixian@integritytech.com.cn
 *   Organization:  
 *
 * =====================================================================================
 */

#include "common.h"

void reset_timer(struct event *timeout_ev, int timeout)
{
	struct timeval tv;

    evtimer_del(timeout_ev);

	evutil_timerclear(&tv);
	tv.tv_sec = timeout;
	evtimer_add(timeout_ev, &tv);
}

int parse_header(const unsigned char *data, const int datalen, struct domain_info *domain_info)
{
    if (data[3] == 0x03){ //<domain
        char domain[256];
        size_t domain_size;

        domain_size = data[4];
        if (datalen < (7 + domain_size)){
            vlog(ERROR, "bad package\n");
            return -1;
        }
            
        memset(domain, 0, sizeof(domain));
        memcpy(domain, data + 5, domain_size);

        domain_info->type = type_domain; 
        strncpy(domain_info->address, domain, strlen(domain));
        domain_info->port = data[5 + domain_size + 0] << 8 | data[5 + domain_size + 1] << 0;
    } else if (data[3] == 0x01) { //<ip
        struct sockaddr_in sa_remote;

        if (datalen < 10){
            vlog(ERROR, "bad package\n");
            return -1;
        }

        memset(&sa_remote, 0, sizeof(struct sockaddr_in));

        domain_info->type = type_ip;
        memcpy(&sa_remote.sin_addr.s_addr, data + 4, 4);
        strcpy(domain_info->address, inet_ntoa(sa_remote.sin_addr));
        domain_info->port = data[8] << 8 | data[9] << 0;
    }

    return 0;
}
