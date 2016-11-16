/*
 * =====================================================================================
 *
 *       Filename:  client.c
 *
 *    Description:  client
 *
 *        Version:  1.0
 *        Created:  11/16/2016 03:56:49 PM
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

#define NAME "client"

#define STAGE_INIT    0x00
#define STAGE_VERSION 0x01
#define STAGE_ADDR    0x02
#define STAGE_STREAM  0x03

#define BEV_TIMEOUT   30 //s

#define IP_ADDRESS_MAX   32
#define SERVER_PWD_MAX  32 

#define SERVER_INFO_MAX 16
#define LOCAL_INFO_MAX  64  //max listener

struct server_info{ //server
    char server_ip[IP_ADDRESS_MAX];
    char server_pwd[SERVER_PWD_MAX];
    int  server_port;
};

struct local_info{
    char local_ip[IP_ADDRESS_MAX];
    int  local_port;
    struct evconnlistener *listener;
};

struct config_info{
    struct server_info server_info[SERVER_INFO_MAX];
    struct local_info local_info[LOCAL_INFO_MAX];

    struct server_info manager_info;
};

struct ev_container{
	struct bufferevent *bev_local, *bev_remote;
    struct event *timeout_ev;

	int stage;

    struct rs_object_base *rs_obj;
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

	free(evc);
}

static void 
reset_timer(struct event *timeout_ev)
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
		vlog(DEBUG, "Connection closed.\n");
	} else if (events & BEV_EVENT_ERROR) {
		vlog(ERROR, "Got an error on the connection: %s\n",
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
    unsigned char output[16];

	datalen = evbuffer_get_length(input); 
    data = (unsigned char *)calloc(datalen, sizeof(unsigned char));
	datalen = evbuffer_remove(input, data, datalen);

    //TODO decrypt
    outdata = (unsigned char *)calloc(datalen, sizeof(unsigned char));
    rs_encrypt(data, outdata, datalen, server_pwd);
    //memcpy(outdata, data, datalen);

	vlog(INFO, "REMOTE RECV(%d)\n", datalen);
    vlog_array(INFO, outdata, datalen);

    reset_timer(evc->timeout_ev);

    switch (evc->stage)
    {
        case STAGE_ADDR:
        {
            //pong
			memset(output, 0, sizeof(output));
			output[0] = 0x05;
			output[1] = 0x00;
			output[2] = 0x00;
			output[3] = 0x01;
			output[4] = 0x00;
			output[5] = 0x00;
			output[6] = 0x00;
			output[7] = 0x00;
			output[8] = 0x10;
			output[9] = 0x10;

			bufferevent_write(partner, output, 10);
			bufferevent_enable(partner, EV_WRITE);

            evc->stage = STAGE_STREAM;
        }
            break;

        case STAGE_STREAM:
        {
            bufferevent_write(partner, outdata, datalen);
            bufferevent_enable(partner, EV_WRITE);
            
        }
            break;
    }

    free(data);
    free(outdata);
}

//local server read callback
static void
local_readcb(struct bufferevent *bev, void *user_data)
{
	struct evbuffer *input = bufferevent_get_input(bev);
	struct ev_container *evc = user_data;
    struct bufferevent *partner = evc->bev_remote;
	ev_ssize_t datalen = 0;
	unsigned char *data = NULL, *outdata = NULL;
    unsigned char output[16];
   
	datalen = evbuffer_get_length(input); 
	data = (unsigned char *)calloc(datalen, sizeof(unsigned char));
	datalen = evbuffer_remove(input, data, datalen);

	vlog(INFO, "LOCAL RECV(%d)\n", datalen);
	vlog_array(INFO, data, datalen);

    reset_timer(evc->timeout_ev);

	switch (evc->stage)
	{
		case STAGE_INIT:
		{
			int i, method, nmethods = 0;
			int noauth = 0, pwdauth = 0;

			if (datalen < 3){
				vlog(ERROR, "Socks5 method header too short\n");
				free_ev_container(evc);
                break;
			}

			if (data[0] != 0x05){
				vlog(ERROR, "Only Supported Socks5\n");
				free_ev_container(evc);
                break;
			}

			nmethods = data[1];

			if (nmethods < 1 || datalen != (nmethods + 2)){
				vlog(ERROR, "Socks5 NMETHODs and METHODS not match\n");
				free_ev_container(evc);
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
				free_ev_container(evc);
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
				free_ev_container(evc);

                break;
			}

            if (data[1] != 0x01){
				vlog(ERROR, "Only Supported TCP relay\n");
				free_ev_container(evc);

                break;
            }

			//TODO encrypt
            data[0] = 0xFF;
            outdata = (unsigned char *)calloc(datalen, sizeof(unsigned char));
            rs_encrypt(data, outdata, datalen, server_pwd);
            //memcpy(outdata, data, datalen);

			bufferevent_write(partner, outdata, datalen);
			bufferevent_enable(partner, EV_WRITE);

            free(outdata);

			evc->stage = STAGE_ADDR;
		}
			break;
		case STAGE_STREAM:
		{
			//TODO encrypt
            outdata = (unsigned char *)calloc(datalen, sizeof(unsigned char));
            rs_encrypt(data, outdata, datalen, server_pwd);
            //memcpy(outdata, data, datalen);

			bufferevent_write(partner, outdata, datalen);
			bufferevent_enable(partner, EV_WRITE);

            free(outdata);
		}
			break;
	}

	free(data);
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
		free_ev_container(evc);
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
        "Usage: rssocks -t 0 [-v 0/1/2] -s x.x.x.x [-p 8575] [-b 127.0.0.1] [-l 1080] [-m xx.xx.xx.xx] -k password\n"
        "\t-v <verbose>: 0 DEFAULT/1 DEBUG/2 INFO\n"
        "\t-s <serverIP>: rsserver address\n"
        "\t-p <serverPort>: rsserver listen port\n"
        "\t-b <localAddress>: local bind address\n"
        "\t-l <localPort>: local bind port\n"
        "\t-m <manager>: manager address\n"
        "\t-k <password>: password\n"
    );
}

static struct evconnlistener *
create_listener(const char *ip, const int port, void *self)
{
	struct evconnlistener *listener;
	struct sockaddr_in saddr;
    struct rs_object_base *rs_obj = (struct rs_object_base *)self;

    memset(&saddr, 0, sizeof(struct sockaddr_in));
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(port);
    saddr.sin_addr.s_addr = inet_addr(ip);

    listener = evconnlistener_new_bind(
        rs_obj->base,
        listener_cb,
        self,
	    LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE, 
        -1,
	    (struct sockaddr*)&saddr,
	    sizeof(saddr));
    assert(listener);

    return listener;
}

static int 
init(int argc, char **argv, void *self)
{
    int option;

    loglevel = ERROR;

    while ((option = getopt(argc, argv, "v:s:p:b:l:k:")) > 0){
        switch (option) {
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

    if (server_pwd[0] == '\0'){
        usage();
        return -1; 
    }

    if (server_ip[0] == '\0')
        strcpy(server_ip, "127.0.0.1");

    if (server_port == 0)
        server_port = 8575;

    if (bind_port == 0)
        bind_port = 1080;

    if (bind_ip[0] == '\0')
        strcpy(bind_ip, "0.0.0.0");

    vlog(DEBUG, "listen %s:%d\n", bind_ip, bind_port);

    base = event_base_new();
    assert(base);

    return 0;
}

static void client_destroy(void *self)
{
    struct rs_object_base *rs_obj = (struct rs_object_base *)self;

    event_base_free(rs_obj->base);
}

static struct rs_object_base rs_obj = {
    .init    = client_init,
    .destroy = client_destroy
}; 

void register_rs_object_client(void)
{
	object_addend(&rs_obj.parent, NAME, rs_obj_type_client);
}
