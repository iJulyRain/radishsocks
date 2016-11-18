/*
 * =====================================================================================
 *
 *       Filename:  server.c
 *
 *    Description:  server for radishsocks
 *
 *        Version:  1.0
 *        Created:  10/27/2016 01:07:56 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  lizhixian (group3), lizhixian@integritytech.com.cn
 *   Organization:  
 *
 * =====================================================================================
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <getopt.h>

#include <assert.h>

#include "log.h"
#include "cipher.h"
#include "base.h"

#define NAME "rs-server"

static struct event_base *base;
static struct evdns_base *evdns_base;

static char server_pwd[128] = "";

#define BEV_TIMEOUT   30 //s

struct ev_container{
	struct bufferevent *bev_local, *bev_remote;
    struct event *timeout_ev;
    struct sockaddr sa, sa_remote;
    struct evdns_getaddrinfo_request *dns_req;
	char domain[256];
};

static void
free_ev_container(struct ev_container *evc)
{
	if (evc->bev_local){
		bufferevent_free(evc->bev_local);
		evc->bev_local = NULL;
	}
	
	if (evc->bev_remote){
    	bufferevent_free(evc->bev_remote);
		evc->bev_remote = NULL;
	}
	
	if (evc->timeout_ev){
		evtimer_del(evc->timeout_ev);
		event_free(evc->timeout_ev);
		evc->timeout_ev = NULL;
	}

    if (evc->dns_req){
        evdns_getaddrinfo_cancel(evc->dns_req);
        evc->dns_req = NULL;
    }

	free(evc);
}

static void 
reset_timer(struct event *timeout_ev)
{
	struct timeval tv;

	if (!timeout_ev)
		return;

    evtimer_del(timeout_ev);

	evutil_timerclear(&tv);
	tv.tv_sec = BEV_TIMEOUT;
	evtimer_add(timeout_ev, &tv);
}

static void
timeout_cb(evutil_socket_t fd, short event, void *user_data)
{
	struct ev_container *evc = user_data;

	free_ev_container(evc);
}

static void
conn_writecb(struct bufferevent *bev, void *user_data)
{
	struct evbuffer *output = bufferevent_get_output(bev);

	if (evbuffer_get_length(output) == 0) {
	    bufferevent_disable(bev, EV_WRITE);
	}
}

static void
conn_eventcb(struct bufferevent *bev, short events, void *user_data)
{
	struct ev_container *evc = user_data;

	if (events & BEV_EVENT_EOF) {
		vlog(DEBUG, "(%s) Connection closed.\n", evc->domain);
	} else if (events & BEV_EVENT_ERROR) {
		vlog(ERROR, "(%s) Got an error on the connection: %s\n",
            evc->domain,
		    strerror(errno));/*XXX win32*/
	} else if (events & BEV_EVENT_CONNECTED) {
        return;
	}

	/* None of the other events can happen here, since we haven't enabled
	 * timeouts */
	free_ev_container(evc);
}

//client read callback
static void
remote_readcb(struct bufferevent *bev, void *user_data)
{
	struct evbuffer *input = bufferevent_get_input(bev);
	struct ev_container *evc = user_data;
    struct bufferevent *partner = evc->bev_local;
	ev_ssize_t datalen = 0;
	unsigned char *data = NULL, *outdata = NULL;

	datalen = evbuffer_get_length(input); 
	data = (unsigned char *)calloc(datalen, sizeof(unsigned char));
	assert(data);

	datalen = evbuffer_remove(input, data, datalen);
	vlog(INFO, "REMOTE RECV(%d)\n", datalen);

	vlog_array(INFO, data, datalen);

    reset_timer(evc->timeout_ev);

    //TODO encrypt
    outdata = (unsigned char *)calloc(datalen, sizeof(unsigned char));
    rs_encrypt(data, outdata, datalen, server_pwd);
    //memcpy(outdata, data, datalen);

    bufferevent_write(partner, outdata, datalen);
    bufferevent_enable(partner, EV_WRITE);

	free(data);
    free(outdata);
}

static void
dns_cb(int errcode, struct evutil_addrinfo *addr, void *ptr)
{
    int rc = 0;
	struct ev_container *evc = ptr;
    struct evutil_addrinfo *ai;
	uint32_t address = 0;

    evc->dns_req = NULL;

    if (errcode){
        vlog(ERROR, "-> %s\n", evutil_gai_strerror(errcode));
        //free_ev_container(evc);
        return;
    }

    for (ai = addr; ai; ai = ai->ai_next){
        if (ai->ai_family == AF_INET){
            address = ((struct sockaddr_in *)ai->ai_addr)->sin_addr.s_addr;
            break;
        }
    }

    if (address == 0){
        vlog(ERROR, "(%s) -> not answer\n", evc->domain);
        free_ev_container(evc);
        return;
    }

	((struct sockaddr_in *)&evc->sa_remote)->sin_addr.s_addr = address;
    vlog(INFO, "dns resolve -> %s(%s)\n", evc->domain, inet_ntoa(((struct sockaddr_in *)&evc->sa_remote)->sin_addr));

	rc = bufferevent_socket_connect(
		evc->bev_remote,
		&evc->sa_remote,
		sizeof(struct sockaddr)
	);
	if (rc < 0) {
		vlog(ERROR, "bufferevent socket connect\n");

		free_ev_container(evc);
		return;
	}

	bufferevent_setcb(evc->bev_remote, remote_readcb, conn_writecb, conn_eventcb, (void *)evc);
	bufferevent_enable(evc->bev_remote, EV_READ);

    //pong
    char output[1] = {0x01};
    bufferevent_write(evc->bev_local, output, 1);
    bufferevent_enable(evc->bev_local, EV_WRITE);
}

//local server read callback
static void
local_readcb(struct bufferevent *bev, void *user_data)
{
    int rc = 0;
	struct evbuffer *input = bufferevent_get_input(bev);
	struct ev_container *evc = user_data;
    struct bufferevent *partner = evc->bev_remote;
	ev_ssize_t datalen = 0;
    uint16_t port = 0;
	unsigned char *data = NULL, *outdata = NULL;
   
	datalen = evbuffer_get_length(input); 

	data = (unsigned char *)calloc(datalen, sizeof(unsigned char));
	assert(data);

	datalen = evbuffer_remove(input, data, datalen);
    reset_timer(evc->timeout_ev);

	//<TODO decrypt
    outdata = (unsigned char *)calloc(datalen, sizeof(unsigned char));
    rs_decrypt(data, outdata, datalen, server_pwd);
    //memcpy(outdata, data, datalen);

	vlog(INFO, "LOCAL RECV(%d)\n", datalen);
	vlog_array(INFO, outdata, datalen);

    ((struct sockaddr_in *)&evc->sa_remote)->sin_family = AF_INET;

	do{
		if ((unsigned char)outdata[0] == 0xFF) { //<addr
			if (outdata[3] == 0x03){ //<domain
				char domain[256];
				size_t domain_size;
                struct evutil_addrinfo hints;
                struct evdns_getaddrinfo_request *dns_req;

				domain_size = outdata[4];
				if (datalen < (7 + domain_size)){
					free_ev_container(evc);
					break;
				}
					
				memset(domain, 0, sizeof(domain));
				memcpy(domain, outdata + 5, domain_size);

				port = outdata[5 + domain_size + 0] << 8 | outdata[5 + domain_size + 1] << 0;

				vlog(DEBUG, "connection %s:%d from %s:%d\n",
					domain,
					port,
					inet_ntoa(((struct sockaddr_in *)&evc->sa)->sin_addr),
					ntohs(((struct sockaddr_in *)&evc->sa)->sin_port)
				);
				strncpy(evc->domain, domain, strlen(domain));
				((struct sockaddr_in *)&evc->sa_remote)->sin_port = htons(port);

                memset(&hints, 0, sizeof(hints));
                hints.ai_family = AF_UNSPEC;
                hints.ai_flags = EVUTIL_AI_CANONNAME;
                dns_req = evdns_getaddrinfo(evdns_base, domain, NULL, &hints, dns_cb, (void *)evc);

                evc->dns_req = dns_req;
				//evdns_base_resolve_ipv4(evdns_base, domain, 0, dns_cb, (void *)evc);
			} else if (outdata[3] == 0x01) { //<ip
				if (datalen < 10){
					free_ev_container(evc);
					break;
				}

				port = outdata[8] << 8 | outdata[9] << 0;
				((struct sockaddr_in *)&evc->sa_remote)->sin_port = htons(port);
				memcpy(&((struct sockaddr_in *)&evc->sa_remote)->sin_addr.s_addr, outdata + 4, 4);

                char remote_ip[32] = "", local_ip[32] = "";
                strcpy(remote_ip, inet_ntoa(((struct sockaddr_in *)&evc->sa_remote)->sin_addr));
                strcpy(local_ip, inet_ntoa(((struct sockaddr_in *)&evc->sa)->sin_addr));
				vlog(DEBUG, "connection %s:%d from %s:%d\n",
                    remote_ip,
					port,
                    local_ip,
					ntohs(((struct sockaddr_in *)&evc->sa)->sin_port)
				);

				rc = bufferevent_socket_connect(
					partner,
					&evc->sa_remote,
					sizeof(struct sockaddr)
				);
				if (rc < 0) {
					vlog(ERROR, "bufferevent socket connect\n");

					free_ev_container(evc);
					break;
				}
				bufferevent_setcb(partner, remote_readcb, conn_writecb, conn_eventcb, (void *)evc);
				bufferevent_enable(partner, EV_READ);

                //pong
                bufferevent_write(bev, outdata, datalen);
                bufferevent_enable(bev, EV_WRITE);
			}
		} else { //<stream
			bufferevent_write(partner, outdata, datalen);
            if (bufferevent_getfd(partner) != -1)
			    bufferevent_enable(partner, EV_WRITE);
		}
	}while(0);

	free(data);
    free(outdata);
}

static void
listener_cb(struct evconnlistener *listener, evutil_socket_t fd,
    struct sockaddr *sa, int socklen, void *user_data)
{
	struct event *timeout;
	struct timeval tv;
	struct bufferevent *bev_in  = NULL;
	struct bufferevent *bev_out = NULL;
	struct ev_container *evc = NULL;

	vlog(DEBUG, "new client from %s:%d\n", 
		inet_ntoa(((struct sockaddr_in *)sa)->sin_addr), ntohs(((struct sockaddr_in *)sa)->sin_port));

	bev_in = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
	if (!bev_in) {
		vlog(ERROR, "Error constructing bufferevent (input)!");
		event_base_loopbreak(base);
		return;
	}

	bev_out = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
	if (!bev_out) {
		vlog(ERROR, "Error constructing bufferevent (input)!");
		event_base_loopbreak(base);
		return;
	}

    //< ev container
	evc = (struct ev_container *)calloc(1, sizeof(struct ev_container));
	assert(evc);

	evc->bev_local = bev_in;
	evc->bev_remote = bev_out;
    evc->sa = *sa;

	///<local
	bufferevent_setcb(bev_in, local_readcb, conn_writecb, conn_eventcb, (void *)evc);
	bufferevent_enable(bev_in, EV_READ);

	///timeout
	timeout = evtimer_new(base, timeout_cb, (void *)evc);
    evc->timeout_ev = timeout;
	evutil_timerclear(&tv);
	tv.tv_sec = BEV_TIMEOUT;
	evtimer_add(timeout, &tv);
}

static void 
usage()
{
    vlog(ERROR, 
        "Usage: \n"
        "\t-v <verbose>: 0 DEFAULT/1 DEBUG/2 INFO\n"
        "\t-b <localAddress>: local bind address\n"
        "\t-l <localPort>: local bind port\n"
        "\t-k <password>: password\n"
    );
}

static int 
server_init(int argc, char **argv)
{
    int rc;
	struct evconnlistener *listener;
	struct sockaddr_in saddr;
    int option;
    char bind_ip[16] = "";
    int bind_port = 0;

    loglevel = ERROR;

    //TODO options
    while ((option = getopt(argc, argv, "v:b:l:k:")) > 0){
        switch (option) {
        case 'v':
	        loglevel = atoi(optarg);
            break;
        case 'b':
            memset(bind_ip, 0, sizeof(bind_ip));
            strncpy(bind_ip, optarg, sizeof(bind_ip) - 1);
            break;
        case 'l':
            bind_port = atoi(optarg);
            break;
        case 'k':
            memset(server_pwd, 0, sizeof(server_pwd));
            strncpy(server_pwd, optarg, sizeof(server_pwd) - 1);
            break;
        default:
            break;
        }
    }

    if (server_pwd[0] == '\0'){
        usage();
        return -1; 
    }

    if (bind_port == 0)
        bind_port = 8575;
    if (bind_ip[0] == '\0')
        strcpy(bind_ip, "127.0.0.1");

    vlog(DEBUG, "listen %s:%d\n", bind_ip, bind_port);

    base = event_base_new();
    assert(base);

    evdns_base = evdns_base_new(base, 0);
    assert(evdns_base);

    rc = evdns_base_nameserver_ip_add(evdns_base, "8.8.4.4");
	//rc = evdns_base_resolv_conf_parse(evdns_base, DNS_OPTION_NAMESERVERS, "/etc/resolv.conf");
    if (rc < 0){
        vlog(ERROR, "Couldn't configure nameserver");
        return -2;
    }

    memset(&saddr, 0, sizeof(struct sockaddr_in));
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(bind_port);
    saddr.sin_addr.s_addr = inet_addr(bind_ip);

    listener = evconnlistener_new_bind(
        base,
        listener_cb,
        (void *)0,
	    LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE, 
        -1,
	    (struct sockaddr*)&saddr,
	    sizeof(saddr));
    assert(listener);

    return 0;
}

static void 
server_destroy(void *self)
{

}

static struct rs_object_base rs_obj = {
    .init    = server_init,
    .destroy = server_destroy
}; 

void register_rs_object_server(void)
{
	object_addend(&rs_obj.parent, NAME, rs_obj_type_server);
}
