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

#include "log.h"

static struct event_base *base;
static char server_ip[16];
static char server_pwd[64];
static int  server_port;

#define STAGE_VERSION 0x01
#define STATE_ADDR    0x02
#define STATE_STREAM  0x03

struct ev_container{
	struct bufferevent *bev;

	int stage;
};

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
    struct bufferevent *partner = user_data;

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
	bufferevent_free(bev);
    bufferevent_free(partner);
}

//client read callback
static void
cli_readcb(struct bufferevent *bev, void *user_data)
{
	struct evbuffer *input = bufferevent_get_input(bev);
    struct bufferevent *partner = user_data;
	char *data = NULL;
	ev_ssize_t datalen = 0;

    //TODO using memory pool
	datalen = evbuffer_get_length(input); 
	data = (char *)calloc(1, datalen + 1);
	datalen = evbuffer_remove(input, data, datalen);
	//vlog(INFO, "(%d)%s\n", datalen, data);
    
    bufferevent_write(partner, data, datalen);
    bufferevent_enable(partner, EV_WRITE);

	free(data);
}

//local server read callback
static void
conn_readcb(struct bufferevent *bev, void *user_data)
{
	struct evbuffer *input = bufferevent_get_input(bev);
    struct bufferevent *partner = user_data;
	ev_ssize_t datalen = 0;
   
	datalen = evbuffer_get_length(input); 

	char data[datalen + 1];
	
	datalen = evbuffer_remove(input, data, datalen);
	//vlog(INFO, "(%d)%s\n", datalen, data);

    bufferevent_write(partner, data, datalen);
    bufferevent_enable(partner, EV_WRITE);
}

static void
listener_cb(struct evconnlistener *listener, evutil_socket_t fd,
    struct sockaddr *sa, int socklen, void *user_data)
{
    int rc;
	struct bufferevent *bev_in  = NULL;
	struct bufferevent *bev_out = NULL;
    struct sockaddr_in saddr;

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

	bufferevent_setcb(bev_in, conn_readcb, conn_writecb, conn_eventcb, bev_out);
	bufferevent_enable(bev_in, EV_READ);

	//<connect to server
    memset(&saddr, 0, sizeof(struct sockaddr_in));
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(server_port);
    saddr.sin_addr.s_addr = inet_addr(server_ip);

	rc = bufferevent_socket_connect(
		bev_out,
		(struct sockaddr *)&saddr,
		sizeof(saddr)
	);
	if (rc < 0) {
		vlog(ERROR, "bufferevent socket connect\n");

		bufferevent_free(bev_in);
		bufferevent_free(bev_out);

		return;
	}

    bufferevent_setcb(bev_out, cli_readcb, conn_writecb, conn_eventcb, bev_in);
	bufferevent_enable(bev_out, EV_READ);
}

static int 
init(int argc, char **argv)
{
	struct evconnlistener *listener;
	struct sockaddr_in saddr;

    //TODO options
    if (argc < 6){
        vlog(ERROR, "usage: ./%s server_ip server_port local_ip local_port password\n", basename(argv[0]));
        return -1;
    }

	loglevel = INFO;

    base = event_base_new();
    assert(base);

    strncpy(server_ip, argv[1], 15);
    strncpy(server_pwd, argv[5], 63);
    server_port = atoi(argv[2]);

    memset(&saddr, 0, sizeof(struct sockaddr_in));
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(atoi(argv[4]));
    saddr.sin_addr.s_addr = inet_addr(argv[3]);

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
        vlog(ERROR, "initial fatal!\n");
        return -1;
    }

    run();
    //won't be here

    return 0;
}
