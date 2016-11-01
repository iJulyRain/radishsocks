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
#include <signal.h>
#include <errno.h>

#include <getopt.h>
#include <libgen.h>

#include <assert.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/event.h>
#include <event2/dns.h>
#include <event2/dns_struct.h>

#include "log.h"

static struct event_base *base;
static struct evdns_base *evdns_base;

static char server_pwd[64] = "";

#define BEV_TIMEOUT   10 //s

struct ev_container{
	struct bufferevent *bev_local, *bev_remote;
    struct event *timeout_ev;
    struct sockaddr sa, sa_remote;
};

static void 
reset_timeout(struct event *timeout_ev)
{
	struct timeval tv;

    evtimer_del(timeout_ev);

	evutil_timerclear(&tv);
	tv.tv_sec = BEV_TIMEOUT;
	evtimer_add(timeout_ev, &tv);
}

static void
timeout_cb(evutil_socket_t fd, short event, void *user_data)
{
	struct ev_container *evc = user_data;

	bufferevent_free(evc->bev_local);
    bufferevent_free(evc->bev_remote);
    event_free(evc->timeout_ev);
}

static void
conn_writecb(struct bufferevent *bev, void *user_data)
{
	struct evbuffer *output = bufferevent_get_output(bev);

	if (evbuffer_get_length(output) == 0) {
		vlog(INFO, "flushed answer\n");
	    bufferevent_disable(bev, EV_WRITE);
	}
}

static void
conn_eventcb(struct bufferevent *bev, short events, void *user_data)
{
	struct ev_container *evc = user_data;

	if (events & BEV_EVENT_EOF) {
		vlog(ERROR, "Connection closed.\n");
	} else if (events & BEV_EVENT_ERROR) {
		vlog(ERROR, "Got an error on the connection: %s\n",
		    strerror(errno));/*XXX win32*/
	} else if (events & BEV_EVENT_CONNECTED) {
        return;
	}

	/* None of the other events can happen here, since we haven't enabled
	 * timeouts */
	bufferevent_free(evc->bev_local);
    bufferevent_free(evc->bev_remote);

    evtimer_del(evc->timeout_ev);
    event_free(evc->timeout_ev);
}

static void
dns_cb(int result, char type, int count, int ttl, void *addrs, void *orig)
{

}

//client read callback
static void
remote_readcb(struct bufferevent *bev, void *user_data)
{
	struct evbuffer *input = bufferevent_get_input(bev);
	struct ev_container *evc = user_data;
    struct bufferevent *partner = evc->bev_local;
	ev_ssize_t datalen = 0;

	datalen = evbuffer_get_length(input); 

	char data[datalen + 1];
	datalen = evbuffer_remove(input, data, datalen);

	vlog_array(INFO, data, datalen);

    reset_timeout(evc->timeout_ev);

    //TODO encrypt
    bufferevent_write(partner, data, datalen);
    bufferevent_enable(partner, EV_WRITE);
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
    unsigned short port = 0;
    evutil_socket_t fd;
    struct sockaddr_in sa;
    socklen_t addrlen;
    char output[16];
   
	datalen = evbuffer_get_length(input); 
	char data[datalen + 1];

	datalen = evbuffer_remove(input, data, datalen);
	//vlog(INFO, "(%d)%s\n", datalen, data);

	vlog_array(INFO, data, datalen);

    reset_timeout(evc->timeout_ev);

    ((struct sockaddr_in *)&evc->sa_remote)->sin_family = AF_INET;

    //<TODO decrypt
    if (data[0] == 0xFF) { //<addr
        if (data[3] == 0x03){ //<domain
            char domain[256];
            size_t domain_size;

            domain_size = data[4];
            memset(domain, 0, sizeof(domain));
            memcpy(domain, data + 5, domain_size);

            vlog(DEBUG, "connection %s:%d from %s:%d\n",
                domain,
                port,
                inet_ntoa(((struct sockaddr_in *)&evc->sa)->sin_addr),
                ntohs(((struct sockaddr_in *)&evc->sa)->sin_port)
            );
            evdns_base_resolve_ipv4(evdns_base, domain, 0, dns_cb, (void *)evc);
            port = data[5 + domain_size + 0] << 8 | data[5 + domain_size + 1] << 0;
            ((struct sockaddr_in *)&evc->sa_remote)->sin_port = htons(port);
        } else if (data[3] == 0x01) { //<ip
            port = data[8] << 8 | data[9] << 0;
            ((struct sockaddr_in *)&evc->sa_remote)->sin_port = htons(port);
            memcpy(&((struct sockaddr_in *)&evc->sa_remote)->sin_addr.s_addr, data + 4, 4);

            vlog(DEBUG, "connection %s:%d from %s:%d\n",
                inet_ntoa(((struct sockaddr_in *)&evc->sa_remote)->sin_addr),
                port,
                inet_ntoa(((struct sockaddr_in *)&evc->sa)->sin_addr),
                ntohs(((struct sockaddr_in *)&evc->sa)->sin_port)
            );

            rc = bufferevent_socket_connect(
                partner,
                &evc->sa_remote,
                sizeof(struct sockaddr)
            );
            if (rc < 0) {
                vlog(ERROR, "bufferevent socket connect\n");

                bufferevent_free(bev);
                bufferevent_free(partner);

                evtimer_del(evc->timeout_ev);
                event_free(evc->timeout_ev);

                return;
            }

            fd = bufferevent_getfd(partner);
            addrlen = sizeof(sa);
            getsockname(fd, (struct sockaddr *)&sa, &addrlen);

            memset(output, 0, sizeof(output));
            output[0] = 0x05;
            output[1] = 0x00;
            output[2] = 0x00;
            output[3] = 0x01;
            output[4] = 0x00;
            output[5] = 0x00;
            output[6] = 0x00;
            output[7] = 0x00;
            output[8] = 0x00;
            output[9] = 0x00;

            bufferevent_write(bev, output, 10);
            bufferevent_enable(bev, EV_WRITE);
        }
    } else { //<stream
        //<TODO decrypt
        bufferevent_write(partner, data, datalen);
        bufferevent_enable(partner, EV_WRITE);
    }
}

static void
listener_cb(struct evconnlistener *listener, evutil_socket_t fd,
    struct sockaddr *sa, int socklen, void *user_data)
{
	struct event *timeout;
	struct timeval tv;
	struct bufferevent *bev_in  = NULL;
	struct bufferevent *bev_out = NULL;
	struct ev_container *evc;

	vlog(DEBUG, "new client from %s:%d\n", 
		inet_ntoa(((struct sockaddr_in *)sa)->sin_addr), ntohs(((struct sockaddr_in *)sa)->sin_port));

	bev_in = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	if (!bev_in) {
		vlog(ERROR, "Error constructing bufferevent (input)!");
		event_base_loopbreak(base);
		return;
	}

	bev_out = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
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

	//==========================================================
	//<remote
    bufferevent_setcb(bev_out, remote_readcb, conn_writecb, conn_eventcb, (void *)evc);
	bufferevent_enable(bev_out, EV_READ);

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
init(int argc, char **argv)
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
	        loglevel++;
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
        strcpy(bind_ip, "0.0.0.0");

    vlog(DEBUG, "listen %s:%d\n", bind_ip, bind_port);

    base = event_base_new();
    assert(base);

    evdns_base = evdns_base_new(base, 0);
    assert(evdns_base);
    rc = evdns_base_nameserver_ip_add(evdns_base, "114.114.114.114");
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

void 
run(void)
{
    event_base_dispatch(base);
}

int 
main(int argc, char **argv)
{
    int rc;

    rc = init(argc, argv);
    if (rc != 0) {
        vlog(ERROR, "initial error!\n");
        return -1;
    }

    run();
    //won't be here

    return 0;
}
