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
static char server_ip[16] = "";
static char server_pwd[64] = "";
static int  server_port = 0;

#define STAGE_INIT    0x00
#define STAGE_VERSION 0x01
#define STAGE_ADDR    0x02
#define STAGE_STREAM  0x03

#define BEV_TIMEOUT   10 //s

struct ev_container{
	struct bufferevent *bev_local, *bev_remote;
    struct event *timeout_ev;

	int stage;
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

	switch (evc->stage)
	{
		case STAGE_ADDR:
		{
			//TODO decrypt
			bufferevent_write(partner, data, datalen);
			bufferevent_enable(partner, EV_WRITE);

			evc->stage = STAGE_STREAM;
		}
			break;
		case STAGE_STREAM:
		{
			//TODO decrypt
			bufferevent_write(partner, data, datalen);
			bufferevent_enable(partner, EV_WRITE);
		}
			break;
	}
}

//local server read callback
static void
local_readcb(struct bufferevent *bev, void *user_data)
{
	struct evbuffer *input = bufferevent_get_input(bev);
	struct ev_container *evc = user_data;
    struct bufferevent *partner = evc->bev_remote;
	ev_ssize_t datalen = 0;
   
	datalen = evbuffer_get_length(input); 

	char data[datalen + 1];
	datalen = evbuffer_remove(input, data, datalen);
	//vlog(INFO, "(%d)%s\n", datalen, data);

	vlog_array(INFO, data, datalen);

    reset_timeout(evc->timeout_ev);

	switch (evc->stage)
	{
		case STAGE_INIT:
		{
			int i, method, nmethods = 0;
			int noauth = 0, pwdauth = 0;
			char output[4];

			if (datalen < 3){
				vlog(ERROR, "Socks5 method header too short\n");
				bufferevent_free(bev);
				bufferevent_free(partner);

                break;
			}

			if (data[0] != 0x05){
				vlog(ERROR, "Only Supported Socks5\n");
				bufferevent_free(bev);
				bufferevent_free(partner);

                break;
			}

			nmethods = data[1];

			if (nmethods < 1 || datalen != (nmethods + 2)){
				vlog(ERROR, "Socks5 NMETHODs and METHODS not match\n");
				bufferevent_free(bev);
				bufferevent_free(partner);

                break;
			}
			
			for (i = 0; i < nmethods; i++){
				method = data[2 + i];	
				if (method == 0x00)
					noauth = 1;
				else if (method == 0x02)
					pwdauth = 1;
			}

			output[0] = 0x05;
			if (noauth)
				output[1] = 0x00;
			else if (pwdauth)
				output[1] = 0x02;
            else{
				vlog(ERROR, "Socks5 METHODS need 0,2\n");
				bufferevent_free(bev);
				bufferevent_free(partner);
            }

			bufferevent_write(bev, output, 2);
			bufferevent_enable(bev, EV_WRITE);

			evc->stage = STAGE_VERSION;
		}
			break;
		case STAGE_VERSION:
		{
			if (data[0] != 0x05){
				vlog(ERROR, "Only Supported Socks5\n");
				bufferevent_free(bev);
				bufferevent_free(partner);

                break;
			}

            if (data[1] != 0x01){
				vlog(ERROR, "Only Supported TCP relay\n");
				bufferevent_free(bev);
				bufferevent_free(partner);

                break;
            }

			//TODO encrypt
            data[0] = 0xFF;
			bufferevent_write(partner, data, datalen);
			bufferevent_enable(partner, EV_WRITE);

			evc->stage = STAGE_ADDR;
		}
			break;
		case STAGE_STREAM:
		{
			//TODO encrypt
			bufferevent_write(partner, data, datalen);
			bufferevent_enable(partner, EV_WRITE);
		}
			break;
	}
}

static void
listener_cb(struct evconnlistener *listener, evutil_socket_t fd,
    struct sockaddr *sa, int socklen, void *user_data)
{
    int rc;
	struct event *timeout;
	struct timeval tv;
	struct bufferevent *bev_in  = NULL;
	struct bufferevent *bev_out = NULL;
    struct sockaddr_in saddr;
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

	///<local
	evc = (struct ev_container *)calloc(1, sizeof(struct ev_container));
	assert(evc);

	evc->bev_local = bev_in;
	evc->bev_remote = bev_out;
	evc->stage = STAGE_INIT;

	bufferevent_setcb(bev_in, local_readcb, conn_writecb, conn_eventcb, (void *)evc);
	bufferevent_enable(bev_in, EV_READ);

	//==========================================================
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
        "\t-s <serverIP>: rsserver address\n"
        "\t-p <serverPort>: rsserver listen port\n"
        "\t-b <localAddress>: local bind address\n"
        "\t-l <localPort>: local bind port\n"
        "\t-k <password>: password\n"
    );
}

static int 
init(int argc, char **argv)
{
	struct evconnlistener *listener;
	struct sockaddr_in saddr;
    int option;
    char bind_ip[16] = "";
    int bind_port = 0;

    loglevel = ERROR;

    //TODO options
    while ((option = getopt(argc, argv, "v:s:p:b:l:k:")) > 0){
        switch (option) {
        case 'v':
	        loglevel++;
            break;
        case 's':
            memset(server_ip, 0, sizeof(server_ip));
            strncpy(server_ip, optarg, sizeof(server_ip) - 1);
            break;
        case 'p':
            server_port = atoi(optarg);
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

    if (server_ip[0] == '\0' || server_pwd[0] == '\0'){
        usage();
        return -1; 
    }
    if (server_port == 0)
        server_port = 8575;
    if (bind_port == 0)
        bind_port = 1080;
    if (bind_ip[0] == '\0')
        strcpy(bind_ip, "0.0.0.0");

    vlog(DEBUG, "listen %s:%d\n", bind_ip, bind_port);

    base = event_base_new();
    assert(base);

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
