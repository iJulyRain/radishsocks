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
#include <signal.h>

#include <getopt.h>

#include <assert.h>

#include <event2/dns.h>
#include <event2/dns_struct.h>

#include "log.h"
#include "cipher.h"
#include "base.h"

#include "common.h"

#define NAME "rs-server"

struct local_info{ //local
    char local_ip[IP_ADDRESS_MAX];
    char local_pwd[PASSWORD_MAX];
    int  local_port;

    struct evconnlistener *listener;
};

struct server_info{ //server
    char server_ip[IP_ADDRESS_MAX];
    char server_pwd[PASSWORD_MAX];
    int  server_port;
};

struct config_info{
    struct local_info local_info;
	struct evdns_base *evdns_base;

    struct server_info manager_info;
};

struct ev_container{
	struct bufferevent *bev_local, *bev_remote;
    struct event *timeout_ev;
    struct sockaddr sa, sa_remote;
    struct evdns_getaddrinfo_request *dns_req;
	struct domain_info domain_info;

	struct local_info *local_info;
	struct evdns_base *evdns_base;
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
signal_cb(evutil_socket_t fd, short event, void *user_data)
{
    struct rs_object_base *rs_obj; 

    vlog(ERROR, "==>got signal SIGPIPE!\n");
	
	rs_obj = (struct rs_object_base *)user_data;
    rs_obj->destroy(rs_obj);
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
		vlog(DEBUG, "(%s) Connection closed.\n", evc->domain_info.address);
	} else if (events & BEV_EVENT_ERROR) {
		vlog(ERROR, "(%s) Got an error on the connection: %s\n",
            evc->domain_info.address,
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
    reset_timer(evc->timeout_ev, BEV_TIMEOUT);

    //TODO encrypt
    outdata = (unsigned char *)calloc(datalen, sizeof(unsigned char));
    rs_encrypt(data, outdata, datalen, evc->local_info->local_pwd);
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
        return;
    }

    for (ai = addr; ai; ai = ai->ai_next){
        if (ai->ai_family == AF_INET){
            address = ((struct sockaddr_in *)ai->ai_addr)->sin_addr.s_addr;
            break;
        }
    }

    if (address == 0){
        vlog(ERROR, "(%s) -> not answer\n", evc->domain_info.address);
        free_ev_container(evc);
        return;
    }

	((struct sockaddr_in *)&evc->sa_remote)->sin_addr.s_addr = address;
    vlog(INFO, "dns resolve -> %s(%s)\n", evc->domain_info.address, inet_ntoa(((struct sockaddr_in *)&evc->sa_remote)->sin_addr));

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
	unsigned char *data = NULL, *outdata = NULL;
   
	datalen = evbuffer_get_length(input); 

	data = (unsigned char *)calloc(datalen, sizeof(unsigned char));
	assert(data);

	datalen = evbuffer_remove(input, data, datalen);
    reset_timer(evc->timeout_ev, BEV_TIMEOUT);

	//<TODO decrypt
    outdata = (unsigned char *)calloc(datalen, sizeof(unsigned char));
    rs_decrypt(data, outdata, datalen, evc->local_info->local_pwd);

	vlog(INFO, "LOCAL RECV(%d)\n", datalen);
	vlog_array(INFO, outdata, datalen);

	do{
		if ((unsigned char)outdata[0] == 0xFF) { //<addr
			rc = parse_header(outdata, datalen, &evc->domain_info);
			if (rc != 0){
				vlog(ERROR, "bad package!\n");
				free_ev_container(evc);
				break;
			}

			vlog(DEBUG, "==> <%s:%d> connect to <%s:%d>\n", 
				inet_ntoa(((struct sockaddr_in *)&evc->sa)->sin_addr),
				ntohs(((struct sockaddr_in *)&evc->sa)->sin_port),
				evc->domain_info.address,
				evc->domain_info.port
			);

    		((struct sockaddr_in *)&evc->sa_remote)->sin_family = AF_INET;
			((struct sockaddr_in *)&evc->sa_remote)->sin_port = htons(evc->domain_info.port);

			if (evc->domain_info.type == type_ip){
				((struct sockaddr_in *)&evc->sa_remote)->sin_addr.s_addr = inet_addr(evc->domain_info.address);

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
				char output[1] = {0x01};
                bufferevent_write(bev, output, 1);
                bufferevent_enable(bev, EV_WRITE);
			}else if(evc->domain_info.type == type_domain){
				struct evutil_addrinfo hints;

				memset(&hints, 0, sizeof(hints));
				hints.ai_family = AF_UNSPEC;
				hints.ai_flags = EVUTIL_AI_CANONNAME;
				evc->dns_req = evdns_getaddrinfo(evc->evdns_base, evc->domain_info.address, NULL, &hints, dns_cb, (void *)evc);
			}
		} else { //<stream
			bufferevent_write(partner, outdata, datalen);
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
	struct event *timeout = NULL;
	struct timeval tv;
	struct bufferevent *bev_in  = NULL;
	struct bufferevent *bev_out = NULL;
	struct ev_container *evc = NULL;
    struct rs_object_base *rs_obj = NULL; 
	struct config_info *config_info = NULL;
	struct event_base *base = NULL;

	rs_obj = (struct rs_object_base *)user_data;
	config_info = (struct config_info *)rs_obj->user_data;

	base = rs_obj->base;

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

    evc->sa = *sa;
	evc->bev_local = bev_in;
	evc->bev_remote = bev_out;
	evc->local_info = &config_info->local_info;
	evc->evdns_base = config_info->evdns_base;

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
server_init(int argc, char **argv, void *self)
{
    int rc;
    int option;
    struct rs_object_base *rs_obj; 
	struct config_info *config_info;
    struct event *signal_event;

	rs_obj = (struct rs_object_base *)self;

	config_info = (struct config_info *)calloc(1, sizeof(struct config_info));
	assert(config_info);

    loglevel = ERROR;

    //TODO options
    while ((option = getopt(argc, argv, "v:b:l:k:")) > 0){
        switch (option) {
        case 'v':
	        loglevel = atoi(optarg);
            if (loglevel > INFO){
                usage();
                return -1;
            }
            break;
        case 'b':
            strncpy(config_info->local_info.local_ip, optarg, IP_ADDRESS_MAX - 1);
            break;
        case 'l':
			config_info->local_info.local_port = atoi(optarg);
            break;
        case 'k':
            strncpy(config_info->local_info.local_pwd, optarg, PASSWORD_MAX - 1);
            break;
        default:
        	usage();
			return -1;
        }
    }

    if (config_info->local_info.local_pwd[0] == '\0'){
        usage();
        return -1; 
    }

    if (config_info->local_info.local_port == 0)
        config_info->local_info.local_port = 9600;
    if (config_info->local_info.local_ip[0] == '\0')
        strcpy(config_info->local_info.local_ip, "127.0.0.1");
	
	//new event base
    rs_obj->base = event_base_new();
    assert(rs_obj->base);

	//new event dns base
    config_info->evdns_base = evdns_base_new(rs_obj->base, 0);
    assert(config_info->evdns_base);

	rs_obj->user_data = config_info;

    //rc = evdns_base_nameserver_ip_add(evdns_base, "8.8.4.4");
	rc = evdns_base_resolv_conf_parse(config_info->evdns_base, DNS_OPTION_NAMESERVERS, "/etc/resolv.conf");
    if (rc < 0){
        vlog(ERROR, "Couldn't configure nameserver");
        return -2;
    }

	config_info->local_info.listener = create_listener(
			config_info->local_info.local_ip,
			config_info->local_info.local_port,
			listener_cb,
			self
		);
	assert(config_info->local_info.listener);

    //signal event
    signal_event = evsignal_new(rs_obj->base, SIGPIPE, signal_cb, self);
    assert(signal_event);
    evsignal_add(signal_event, NULL);

    return 0;
}

static void 
server_destroy(void *self)
{
    struct rs_object_base *rs_obj; 
	struct config_info *config_info;

	rs_obj = (struct rs_object_base *)self;
	config_info = (struct config_info *)rs_obj->user_data;

	event_base_dispatch(rs_obj->base);
	evconnlistener_free(config_info->local_info.listener);

	evdns_base_free(config_info->evdns_base, 0);

    event_base_free(rs_obj->base);
}

static struct rs_object_base rs_obj = {
    .init    = server_init,
    .destroy = server_destroy
}; 

void register_rs_object_server(void)
{
	object_addend(&rs_obj.parent, NAME, rs_obj_type_server);
}
