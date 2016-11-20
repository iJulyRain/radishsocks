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
#include <time.h>
#include <signal.h>

#include <getopt.h>

#include <assert.h>

#include "log.h"
#include "cipher.h"
#include "base.h"

#include "common.h"

#define NAME "rs-client"

#define STAGE_INIT    0x00
#define STAGE_VERSION 0x01
#define STAGE_AUTH    0x02
#define STAGE_ADDR    0x03
#define STAGE_STREAM  0x04

#define SERVER_INFO_MAX 16  //max server
#define LOCAL_INFO_MAX  64  //max listener

struct server_info{ //server
    char server_ip[IP_ADDRESS_MAX];
    char server_pwd[PASSWORD_MAX];
    int  server_port;
};

struct local_info{ //local
    char local_ip[IP_ADDRESS_MAX];
    int  local_port;
    struct evconnlistener *listener;
};

struct config_info{
	int server_info_count;
    struct server_info server_info[SERVER_INFO_MAX]; //muti server

	int local_info_count;
    struct local_info local_info[LOCAL_INFO_MAX]; //muti local

    struct server_info manager_info; //single manager
};

struct ev_container{
	struct bufferevent *bev_local, *bev_remote;
    struct event *timeout_ev;
    struct sockaddr sa;

	int stage;

	struct server_info *server_info; //event server info
};

static int
verify_auth(const char *username, const char *password)
{
    vlog(INFO, "username: %s, password: %s\n", username, password);

    return 0;
}

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

	FREE(evc);
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
		vlog(INFO, "Connection closed.\n");
	} else if (events & BEV_EVENT_ERROR) {
		vlog(INFO, "Got an error on the connection: %s\n",
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
    data = (unsigned char *)CALLOC(datalen, sizeof(unsigned char));
	datalen = evbuffer_remove(input, data, datalen);

    //TODO decrypt
    outdata = (unsigned char *)CALLOC(datalen, sizeof(unsigned char));
    rs_decrypt(data, outdata, datalen, evc->server_info->server_pwd);

	vlog(INFO, "REMOTE RECV(%d)\n", datalen);
    vlog_array(INFO, outdata, datalen);

    reset_timer(evc->timeout_ev, BEV_TIMEOUT);

    switch (evc->stage)
    {
        case STAGE_ADDR:
        {
            //pong
			memset(output, 0, sizeof(output));
			output[0] = 0x05; output[1] = 0x00; output[2] = 0x00; output[3] = 0x01;
			output[4] = 0x00; output[5] = 0x00; output[6] = 0x00; output[7] = 0x00;
			output[8] = 0x10; output[9] = 0x10;

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

    FREE(data);
    FREE(outdata);
}

//local server read callback
static void
local_readcb(struct bufferevent *bev, void *user_data)
{
	struct evbuffer *input = bufferevent_get_input(bev);
	struct ev_container *evc = user_data;
    struct bufferevent *partner = evc->bev_remote;
    struct domain_info domain_info;
	ev_ssize_t datalen = 0;
	unsigned char *data = NULL, *outdata = NULL;
    unsigned char output[16];
   
	datalen = evbuffer_get_length(input); 
	data = (unsigned char *)CALLOC(datalen, sizeof(unsigned char));
	datalen = evbuffer_remove(input, data, datalen);

	vlog(INFO, "LOCAL RECV(%d)\n", datalen);
	vlog_array(INFO, data, datalen);

    reset_timer(evc->timeout_ev, BEV_TIMEOUT);

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
			if (pwdauth){
				output[1] = 0x02;
			    evc->stage = STAGE_AUTH;
            }else if (noauth){
				output[1] = 0x00;
			    evc->stage = STAGE_VERSION;
            }
            else{
				vlog(ERROR, "Socks5 METHODS need 0,2\n");
				free_ev_container(evc);
                break;
            }

			bufferevent_write(bev, output, 2);
			bufferevent_enable(bev, EV_WRITE);
		}
			break;
        case STAGE_AUTH:
        {
            int rc = 0;
            int username_size = 0, password_size = 0;
            char username[64] = "", password[64] = "";

            if (data[0] != 0x01){
                vlog(ERROR, "Bad header: %#02X\n", data[0]);
				free_ev_container(evc);
                break;
            }
            if (datalen < 5){
                vlog(ERROR, "Bad length: %d\n", datalen);
				free_ev_container(evc);
                break;
            }

            username_size = data[1];

            if (datalen < username_size + 4){
                vlog(ERROR, "Bad length: %d\n", datalen);
				free_ev_container(evc);
                break;
            }

            password_size = data[2 + username_size];

            if (datalen < username_size + password_size + 3){
                vlog(ERROR, "Bad length: %d\n", datalen);
				free_ev_container(evc);
                break;
            }

            memcpy(username, data + 2, username_size);
            memcpy(password, data + 2 + username_size + 1, password_size);

            //TODO verify auth
            rc = verify_auth(username, password);
            if (rc != 0){
                vlog(ERROR, "Bad auth: %s, %s\n", username, password);
				free_ev_container(evc);
                break;
            }

			memset(output, 0, sizeof(output));
			output[0] = 0x01; output[1] = 0x00; 

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

            memset(&domain_info, 0, sizeof(struct domain_info));

            parse_header(data, datalen, &domain_info);
            vlog(DEBUG, "==> <%s:%d> connect to <%s:%d>\n", 
                inet_ntoa(((struct sockaddr_in *)&evc->sa)->sin_addr),
                ntohs(((struct sockaddr_in *)&evc->sa)->sin_port),
                domain_info.address,
                domain_info.port
            );

			//TODO encrypt
            data[0] = 0xFF;
            outdata = (unsigned char *)CALLOC(datalen, sizeof(unsigned char));
            rs_encrypt(data, outdata, datalen, evc->server_info->server_pwd);

			bufferevent_write(partner, outdata, datalen);
			bufferevent_enable(partner, EV_WRITE);

            FREE(outdata);

			evc->stage = STAGE_ADDR;
		}
			break;
		case STAGE_STREAM:
		{
			//TODO encrypt
            outdata = (unsigned char *)CALLOC(datalen, sizeof(unsigned char));
            rs_encrypt(data, outdata, datalen, evc->server_info->server_pwd);

			bufferevent_write(partner, outdata, datalen);
			bufferevent_enable(partner, EV_WRITE);

            FREE(outdata);
		}
			break;
	}

	FREE(data);
}

static void
listener_cb(struct evconnlistener *listener, evutil_socket_t fd,
    struct sockaddr *sa, int socklen, void *user_data)
{
    int server_i, rc;
	struct event *timeout = NULL;
	struct timeval tv;
	struct bufferevent *bev_in  = NULL;
	struct bufferevent *bev_out = NULL;
    struct sockaddr_in saddr;
	struct ev_container *evc = NULL;
    struct rs_object_base *rs_obj = NULL;
	struct config_info *config_info = NULL;
	struct event_base *base = NULL;
	
	rs_obj = (struct rs_object_base *)user_data;
	config_info = (struct config_info *)rs_obj->user_data;

	base = rs_obj->base;

	server_i = rand() % config_info->server_info_count;

	vlog(DEBUG, "new client from %s:%d ==> using tunnel: %s:%d\n", 
		inet_ntoa(((struct sockaddr_in *)sa)->sin_addr), ntohs(((struct sockaddr_in *)sa)->sin_port),
		config_info->server_info[server_i].server_ip, config_info->server_info[server_i].server_port);

    //build bufferevent
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

	///<build ev container
	evc = (struct ev_container *)CALLOC(1, sizeof(struct ev_container));
	assert(evc);

    evc->sa = *sa;
	evc->bev_local = bev_in;
	evc->bev_remote = bev_out;
	evc->stage = STAGE_INIT;
	evc->server_info = config_info->server_info + server_i;

	bufferevent_setcb(bev_in, local_readcb, conn_writecb, conn_eventcb, (void *)evc);
	bufferevent_enable(bev_in, EV_READ);

	//==========================================================
	//<connect to server
    memset(&saddr, 0, sizeof(struct sockaddr_in));
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(config_info->server_info[server_i].server_port);
    saddr.sin_addr.s_addr = inet_addr(config_info->server_info[server_i].server_ip);

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
        "Usage: rssocks [-v 0/1/2] -s x.x.x.x [-p 9600] [-b 127.0.0.1 -l 1080] [-m xx.xx.xx.xx] -k password\n"
        "\t-v <verbose>: 0 default/ 1 debug/ 2 info\n"
        "\t-s <serverIP>: rsserver address\n"
        "\t-p <serverPort>: rsserver listen port\n"
        "\t-b <localAddress>: local bind address\n"
        "\t-l <localPort>: local bind port\n"
        "\t-m <manager>: manager address\n"
        "\t-k <password>: password\n"
    );
}

static int 
client_init(int argc, char **argv, void *self)
{
	int i;
    int option;
    struct rs_object_base *rs_obj; 
	struct config_info *config_info;
    struct event *signal_event;
	
	rs_obj = (struct rs_object_base *)self;

	config_info = (struct config_info *)CALLOC(1, sizeof(struct config_info));
	assert(config_info);

    loglevel = ERROR;

    while ((option = getopt(argc, argv, "v:s:p:b:l:k:m:")) > 0){
        switch (option) {
        case 'v':
            loglevel = atoi(optarg);
            if (loglevel > INFO){
                usage();
                return -1;
            }
            break;
        case 's':
			config_info->server_info_count++;
            strncpy(
                config_info->server_info[config_info->server_info_count - 1].server_ip, 
                optarg, 
                IP_ADDRESS_MAX - 1);
            config_info->server_info[config_info->server_info_count - 1].server_port = 9600; //default server port
            break;
        case 'p':
            config_info->server_info[config_info->server_info_count - 1].server_port = atoi(optarg);
            break;
        case 'b':
			config_info->local_info_count++;
            strncpy(
                config_info->local_info[config_info->local_info_count - 1].local_ip, 
                optarg, 
                IP_ADDRESS_MAX - 1);
            break;
        case 'l':
            config_info->local_info[config_info->local_info_count - 1].local_port = atoi(optarg);
            break;
        case 'k':
            strncpy(
                config_info->server_info[config_info->server_info_count - 1].server_pwd, 
                optarg, 
                PASSWORD_MAX - 1);
            break;
		case 'm':
            strncpy(
                config_info->manager_info.server_ip, 
                optarg, 
                IP_ADDRESS_MAX - 1);
			config_info->manager_info.server_port = 12800; //default manager port
            break;
        default:
			usage();
			return -1;
        }
    }

    //check config
    if (config_info->server_info_count == 0){
        usage();
        return -1;
    }

    for (i = 0; i < config_info->server_info_count; i++){
        if (config_info->server_info[i].server_pwd[0] == '\0'){
            usage();
            return -1;
        }
    }

    //default listen address 127.0.0.1:1080
    if (config_info->local_info_count == 0){
        config_info->local_info_count ++;

        strncpy(config_info->local_info[0].local_ip, "127.0.0.1", IP_ADDRESS_MAX - 1);
        config_info->local_info[0].local_port = 1080;
    }

    rs_obj->base = event_base_new();
    assert(rs_obj->base);

	rs_obj->user_data = config_info;

	//create listener 
	for (i = 0; i < config_info->local_info_count; i++)
	{
		config_info->local_info[i].listener = create_listener(
			config_info->local_info[i].local_ip,
			config_info->local_info[i].local_port,
			listener_cb,
			self
		);
        assert(config_info->local_info[i].listener);
	}

    //signal event
    signal_event = evsignal_new(rs_obj->base, SIGPIPE, signal_cb, self);
    assert(signal_event);
    evsignal_add(signal_event, NULL);

	srand(time(NULL));

    return 0;
}

static void 
client_destroy(void *self)
{
	int i;
    struct rs_object_base *rs_obj; 
	struct config_info *config_info;
	
	rs_obj = (struct rs_object_base *)self;
	config_info = (struct config_info *)rs_obj->user_data;

	event_base_dispatch(rs_obj->base);

	//free listener
	for (i = 0; i < LOCAL_INFO_MAX; i++)
	{
		if (!config_info->local_info[i].listener)
			continue;

		evconnlistener_free(config_info->local_info[i].listener);
	}

    event_base_free(rs_obj->base);

    FREE(config_info);
}

static struct rs_object_base rs_obj = {
    .init    = client_init,
    .destroy = client_destroy
}; 

void register_rs_object_client(void)
{
	object_addend(&rs_obj.parent, NAME, rs_obj_type_client);
}
