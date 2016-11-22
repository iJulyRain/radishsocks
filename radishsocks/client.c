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

#include "client.h"

static int
create_manager(struct event_base *base, struct manager_info *manager_info);

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

	if (evc->bev_udp){
    	bufferevent_free(evc->bev_udp);
		evc->bev_udp = NULL;
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
manager_reconnect(evutil_socket_t fd, short event, void *user_data)
{
    struct manager_info *manager_info = user_data;

    create_manager(manager_info->base, manager_info);
}

static void
manager_eventcb(struct bufferevent *bev, short events, void *user_data)
{
	struct timeval tv;
    struct event *timeout = NULL;
    struct manager_info *manager_info = user_data;

	if (events & BEV_EVENT_EOF) {
		vlog(INFO, "Connection closed.\n");
	} else if (events & BEV_EVENT_ERROR) {
		vlog(INFO, "Got an error on the connection: %s\n",
		    strerror(errno));/*XXX win32*/
	} else if (events & BEV_EVENT_CONNECTED) {
		vlog(INFO, "Connection ok.\n");
        return;
	}

    bufferevent_free(bev);

	timeout = evtimer_new(manager_info->base, manager_reconnect, (void *)manager_info);
	evutil_timerclear(&tv);
	tv.tv_sec = 5;
	evtimer_add(timeout, &tv);
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
    if (evc)
	    free_ev_container(evc);
}

static void
manager_readcb(struct bufferevent *bev, void *user_data)
{
	struct evbuffer *input = bufferevent_get_input(bev);
	ev_ssize_t datalen = 0;
    unsigned char *data = NULL;

	datalen = evbuffer_get_length(input); 
    data = (unsigned char *)CALLOC(datalen, sizeof(unsigned char));
	datalen = evbuffer_remove(input, data, datalen);

    vlog(INFO, "manager cmd: %s\n", data);
}

static void
udp_readcb(struct bufferevent *bev, void *user_data)
{
    int rc = 0;
	struct evbuffer *input = bufferevent_get_input(bev);
	struct ev_container *evc = user_data;
	ev_ssize_t datalen = 0;
    unsigned char *data = NULL;
    struct domain_info domain_info;
    object_t server_table_node;
    char buffer[256];
    uint32_t hash[4];

	datalen = evbuffer_get_length(input); 
    if (datalen < 11){
        vlog(ERROR, "UDP package too short\n");
        return;
    }

    do{
        data = (unsigned char *)CALLOC(datalen, sizeof(unsigned char));
        datalen = evbuffer_remove(input, data, datalen);

        if (data[0] != 0x00 || data[1] != 0x00){
            vlog(ERROR, "UDP bad package\n");
            break;
        }

        memset(&domain_info, 0, sizeof(domain_info));
        rc = parse_header(data, datalen, &domain_info);
        if (rc != 0){
            vlog(ERROR, "UDP bad header\n");
            break;
        }

        //insert server table
        server_table_node = (object_t)calloc(1, sizeof(struct object));
        assert(server_table_node);

        memset(buffer, 0, sizeof(buffer));
        snprintf(buffer, 255, "%s:%d", domain_info.address, domain_info.port);
        rs_md5((uint8_t*)buffer, strlen(buffer), hash);

        snprintf(server_table_node->name, OBJ_NAME_MAX - 1, "%08x%08x%08x%08x", hash[0], hash[1], hash[2], hash[3]);
        vlog(INFO, "%s:%d hash(%s)\n", domain_info.address, domain_info.port, server_table_node->name);

        if (!object_container_find(server_table_node->name, &evc->udp_server_table))
            object_container_addend(server_table_node, &evc->udp_server_table);
        
        //relay to server
        rs_encrypt(data, data, datalen, evc->server_info->server_pwd);
        bufferevent_write(evc->bev_remote, data, datalen);
        bufferevent_enable(evc->bev_remote, EV_WRITE);
    }while(0);

    FREE(data);
}

//client read callback
static void
remote_readcb(struct bufferevent *bev, void *user_data)
{
	struct evbuffer *input = bufferevent_get_input(bev);
	struct ev_container *evc = user_data;
    struct bufferevent *partner = evc->bev_local;
	ev_ssize_t datalen = 0;
    unsigned char *data = NULL;
    unsigned char output[16];

	datalen = evbuffer_get_length(input); 
    data = (unsigned char *)CALLOC(datalen, sizeof(unsigned char));
	datalen = evbuffer_remove(input, data, datalen);

    //TODO decrypt
    rs_decrypt(data, data, datalen, evc->server_info->server_pwd);

	vlog(INFO, "REMOTE RECV(%d)\n", datalen);
    vlog_array(INFO, data, datalen);

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
            bufferevent_write(partner, data, datalen);
            bufferevent_enable(partner, EV_WRITE);
        }
            break;

        case STAGE_UDP:
        {

        }
            break;
    }

    FREE(data);
}

//local server read callback
static void
local_readcb(struct bufferevent *bev, void *user_data)
{
	struct evbuffer *input = bufferevent_get_input(bev);
	struct ev_container *evc = user_data;
    struct bufferevent *partner = evc->bev_remote;
    struct event_base *base;
    struct domain_info domain_info;
	ev_ssize_t datalen = 0;
	unsigned char *data = NULL;
    unsigned char output[16];
   
	datalen = evbuffer_get_length(input); 
	data = (unsigned char *)CALLOC(datalen, sizeof(unsigned char));
	datalen = evbuffer_remove(input, data, datalen);

	vlog(INFO, "LOCAL RECV(%d)\n", datalen);
	vlog_array(INFO, data, datalen);

    reset_timer(evc->timeout_ev, BEV_TIMEOUT);

    base = bufferevent_get_base(bev);

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

            if (data[1] != 0x01 && data[1] != 0x03){
				vlog(ERROR, "Unknown relay type\n");
				free_ev_container(evc);

                break;
            }

            if (data[1] == 0x01){ //TCP Relay 
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
                rs_encrypt(data, data, datalen, evc->server_info->server_pwd);

                bufferevent_write(partner, data, datalen);
                bufferevent_enable(partner, EV_WRITE);

                evc->stage = STAGE_ADDR;
            } else if (data[1] == 0x03){ //UDP Relay
                struct sockaddr_in addr;
                socklen_t addrlen; 
                evutil_socket_t fd;
                char ip[IP_ADDRESS_MAX];
                int port;

                addrlen = sizeof(addr);

                //getsockname
                fd = bufferevent_getfd(bev);

                memset(&addr, 0, sizeof(addr));
                getsockname(fd, (struct sockaddr *)&addr, &addrlen);

                memset(ip, 0, IP_ADDRESS_MAX);
                strncpy(ip, inet_ntoa(addr.sin_addr), IP_ADDRESS_MAX - 1);

                //new udp socket
                fd = socket(AF_INET, SOCK_DGRAM, 0); 
                if (fd < 0){
                    vlog(ERROR, "Create socket error (UDP)\n");
                    free_ev_container(evc);
                    break;
                }

                memset(&addr, 0, sizeof(addr));
                addr.sin_family = AF_INET;
                addr.sin_port = htons(0); //os select
                addr.sin_addr.s_addr = inet_addr(ip);
                bind(fd, (struct sockaddr *)&addr, addrlen);

                //bufferevent
                evc->bev_udp = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
                if (!evc->bev_udp) {
                    vlog(ERROR, "Error constructing bufferevent (udp)!");
                    free_ev_container(evc);
                    break;
                }

                bufferevent_setcb(evc->bev_udp, udp_readcb, conn_writecb, conn_eventcb, (void *)evc);
                bufferevent_enable(evc->bev_udp, EV_READ);

                object_container_init(&evc->udp_server_table);

                //response
                memset(&addr, 0, sizeof(addr));
                getsockname(fd, (struct sockaddr *)&addr, &addrlen);
                port = ntohs(addr.sin_port);
                vlog(DEBUG, "UDP bind: %s:%d\n", ip, port);

                memset(output, 0, sizeof(output));
                output[0] = 0x05; output[1] = 0x00; output[2] = 0x00; output[3] = 0x01;
                memcpy(output + 4, &addr.sin_addr.s_addr, 4);
                memcpy(output + 8, &addr.sin_port, 2);
                
                vlog_array(INFO, output, 10);

                bufferevent_write(bev, output, 10);
                bufferevent_enable(bev, EV_WRITE);

                evc->stage = STAGE_UDP;
            }
		}
			break;
		case STAGE_STREAM:
		{
			//TODO encrypt
            rs_encrypt(data, data, datalen, evc->server_info->server_pwd);

			bufferevent_write(partner, data, datalen);
			bufferevent_enable(partner, EV_WRITE);
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
		vlog(ERROR, "Error constructing bufferevent (local)!");
		event_base_loopbreak(base);
		return;
	}

	bev_out = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	if (!bev_out) {
		vlog(ERROR, "Error constructing bufferevent (remote)!");
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
		vlog(ERROR, "bufferevent socket connect error (remote)\n");
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
        "Usage: %s [-v 0/1/2] -s x.x.x.x [-p 9600] [-b 127.0.0.1 -l 1080] [-m xx.xx.xx.xx -q password] -k password\n"
        "\t-v <verbose>: 0 default/ 1 debug/ 2 info\n"
        "\t-s <serverIP>: rsserver address\n"
        "\t-p <serverPort>: rsserver listen port\n"
        "\t-b <localAddress>: local bind address\n"
        "\t-l <localPort>: local bind port\n"
        "\t-m <manager>: manager address\n"
        "\t-q <password>: manager password\n",
        "\t-k <password>: password\n",
    NAME);
}

static int
create_manager(struct event_base *base, struct manager_info *manager_info)
{
    int rc = 0;
	struct bufferevent *bev_manager = NULL;
    struct sockaddr_in saddr;

    bev_manager = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
    if (!bev_manager) {
        vlog(ERROR, "Error constructing bufferevent (manager)!");
        return -1;
    }

    memset(&saddr, 0, sizeof(struct sockaddr_in));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = inet_addr(manager_info->server_ip);
    saddr.sin_port = htons(manager_info->server_port);

    rc = bufferevent_socket_connect(
        bev_manager,
        (struct sockaddr *)&saddr,
        sizeof(saddr)
    );
    if (rc < 0) {
        vlog(ERROR, "bufferevent socket connect error (manager)\n");
        return -1;
    }

    bufferevent_setcb(bev_manager, manager_readcb, conn_writecb, manager_eventcb, manager_info);
    bufferevent_enable(bev_manager, EV_READ);

    return 0;
}

static int 
client_init(int argc, char **argv, void *self)
{
	int i, rc = 0;
    int option;
    struct rs_object_base *rs_obj; 
	struct config_info *config_info;
    struct event *signal_event;
	
	rs_obj = (struct rs_object_base *)self;

	config_info = (struct config_info *)CALLOC(1, sizeof(struct config_info));
	assert(config_info);

    loglevel = ERROR;

    while ((option = getopt(argc, argv, "v:s:p:b:l:k:m:q:")) > 0){
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
        case 'q':
            strncpy(
                config_info->manager_info.server_pwd, 
                optarg,
                PASSWORD_MAX - 1);
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

    //create manager
    if (config_info->manager_info.server_ip[0] != '\0'
    &&  config_info->manager_info.server_pwd[0] != '\0'){
        config_info->manager_info.base = rs_obj->base;
        rc = create_manager(rs_obj->base, &config_info->manager_info);
        if (rc != 0)
            return -1;
    }

	//create listener 
	for (i = 0; i < config_info->local_info_count; i++){
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
	for (i = 0; i < LOCAL_INFO_MAX; i++){
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
