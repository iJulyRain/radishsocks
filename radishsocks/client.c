/*
 * =====================================================================================
 *
 *       Filename:  client.c
 *
 *    Description:  client for radishsocks
 *
 *        Version:  1.0
 *        Created:  10/27/2016 01:08:51 AM
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

#include "log.h"

struct ev_container
{
    struct event_base *evbase;
    char srv_ip[16];
    int  srv_port;
    char srv_pwd[64];
};

static void
listener_cb(struct evconnlistener *listener, evutil_socket_t fd,
    struct sockaddr *sa, int socklen, void *user_data)
{
    struct ev_container *evc = (struct ev_container *)user_data;

	bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
	if (!bev) {
		log(ERROR, "Error constructing bufferevent!");
		event_base_loopbreak(base);
		return;
	}
	bufferevent_setcb(bev, conn_readcb, conn_writecb, conn_eventcb, NULL);
	bufferevent_enable(bev, EV_WRITE);
	bufferevent_enable(bev, EV_READ);
}

static void
conn_readcb(struct bufferevent *bev, void *user_data)
{
	struct evbuffer *output = bufferevent_get_output(bev);
	if (evbuffer_get_length(output) == 0) {
		printf("flushed answer\n");
		bufferevent_free(bev);
	}
}

static void
conn_writecb(struct bufferevent *bev, void *user_data)
{
	struct evbuffer *output = bufferevent_get_output(bev);
	if (evbuffer_get_length(output) == 0) {
		printf("flushed answer\n");
		bufferevent_free(bev);
	}
}

static void
conn_eventcb(struct bufferevent *bev, short events, void *user_data)
{
	if (events & BEV_EVENT_EOF) {
		printf("Connection closed.\n");
	} else if (events & BEV_EVENT_ERROR) {
		printf("Got an error on the connection: %s\n",
		    strerror(errno));/*XXX win32*/
	}
	/* None of the other events can happen here, since we haven't enabled
	 * timeouts */
	bufferevent_free(bev);
}


static int 
init(struct event_base **evbase, int argc, char **argv)
{
    struct event_base *base;
	struct evconnlistener *listener;
	struct event *signal_event;

	struct sockaddr_in saddr;
    struct ev_container evc;

    if (argc < 6)
    {
        log(ERROR, "usage: ./%s server_ip server_port local_ip local_port password", basename(argv[0]));
        return -1;
    }

    base = event_base_new();
    assert(base);
    *evbase = base;

    evc.evbase = base; 
    strncpy(evc.srv_ip, argv[1], 15);
    strncpy(evc.srv_pwd, argv[5], 63);
    evc.srv_port = atoi(argv[2]);

    memset(&saddr, 0, sizeof(struct sockaddr_in));
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(atoi(argv[4]));
    saddr.sin_addr.s_addr = inet_addr(argv[3]);

    listener = evconnlistener_new_bind(
        base,
        listener_cb,
        (void *)evc,
	    LEV_OPT_REUSEABLE|LEV_OPT_CLOSE_ON_FREE, 
        -1,
	    (struct sockaddr*)&saddr,
	    sizeof(saddr));
    assert(listener);
    
    return 0;
}

int 
main(int argc, char **argv)
{	
    int rc;
    struct event_base *base;

    rc = init(&base, argc, argv);
    if (rc != 0)
    {
        log(ERROR, "initial fatal!\n");
        return -1;
    }

    event_base_dispatch(base);

    //won't be here

    return 0;
}
