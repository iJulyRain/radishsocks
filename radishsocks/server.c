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

#include "server.h"

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
    struct event *ev_udp; //udp proxy 

    unsigned char *buffer_in;
    size_t buffer_in_size;

    struct event *timeout_ev;
    struct sockaddr sa, sa_remote;
    struct evdns_getaddrinfo_request *dns_req;
	struct domain_info domain_info;

	struct local_info *local_info;
	struct evdns_base *evdns_base; //point to config_info->dns_base
};

struct udp_write_block{
    struct event *event;
    unsigned char *buffer;
    size_t buffer_size;

    struct sockaddr sa;
    socklen_t sa_len;

	struct domain_info domain_info;
    struct evdns_getaddrinfo_request *dns_req;
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

	if (evc->ev_udp){
    	event_free(evc->ev_udp);
		evc->ev_udp = NULL;
	}

    if (evc->buffer_in){
        FREE(evc->buffer_in);
        evc->buffer_in = NULL;
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

static void udp_cb(evutil_socket_t fd, short which, void *user_data)
{
    int datalen = 0;
    struct sockaddr_in sa;
    socklen_t socklen;
	struct ev_container *evc;
    struct udp_write_block *uwb;

    unsigned char *data = NULL;

    if (which & EV_READ){
        evc = user_data;
        data = evc->buffer_in;

        socklen = sizeof(sa);
        memset(&sa, 0, sizeof(sa));
        memset(data, 0, BUFFER_MAX);

        datalen = recvfrom(fd, data + 10, BUFFER_MAX - 10, 0, (struct sockaddr *)&sa, &socklen);
        if (datalen < 0){
            vlog(ERROR, "UDP recvfrom error!\n");
            return;
        }

        vlog(INFO, "UDP RECV(%d)\n", datalen);
        vlog_array(INFO, data + 10, datalen);

        data[0] = 0x00; data[1] = 0x00; data[2] = 0x00; data[3] = 0x01;
        memcpy(data + 4, &sa.sin_addr.s_addr, 4);
        memcpy(data + 8, &sa.sin_port, 2);

        rs_encrypt(data, data, datalen + 10, evc->local_info->local_pwd);

        bufferevent_write(evc->bev_local, data, datalen + 10);
        bufferevent_enable(evc->bev_local, EV_WRITE);
    } else if (which & EV_WRITE) {
        uwb = user_data;

        data = uwb->buffer;
        datalen = uwb->buffer_size;
        sendto(fd, data, datalen, 0, &uwb->sa, uwb->sa_len);

        event_free(uwb->event);
        FREE(uwb->buffer);
        FREE(uwb);
    }
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

	datalen = evbuffer_get_length(input); 
	data = (unsigned char *)CALLOC(datalen, sizeof(unsigned char));
	assert(data);

	datalen = evbuffer_remove(input, data, datalen);
	vlog(INFO, "REMOTE RECV(%d)\n", datalen);

	vlog_array(INFO, data, datalen);
    reset_timer(evc->timeout_ev, BEV_TIMEOUT);

    //TODO encrypt
    rs_encrypt(data, data, datalen, evc->local_info->local_pwd);

    bufferevent_write(partner, data, datalen);
    bufferevent_enable(partner, EV_WRITE);

	FREE(data);
}

static void
udp_dns_cb(int errcode, struct evutil_addrinfo *addr, void *ptr)
{
    struct udp_write_block *uwb = ptr;
    struct evutil_addrinfo *ai;
	uint32_t address = 0;

    uwb->dns_req = NULL;

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
        vlog(ERROR, "(%s) -> not answer\n", uwb->domain_info.address);
        return;
    }

    ((struct sockaddr_in *)&uwb->sa)->sin_addr.s_addr = address;
    vlog(INFO, "dns resolve -> %s(%s)\n", uwb->domain_info.address, inet_ntoa(((struct sockaddr_in *)&uwb->sa)->sin_addr));

    event_add(uwb->event, NULL);
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

    vlog(INFO, "dns resolve -> %s(%s)\n", evc->domain_info.address, inet_ntoa(((struct sockaddr_in *)&evc->sa_remote)->sin_addr));

    ((struct sockaddr_in *)&evc->sa_remote)->sin_family = AF_INET;
    ((struct sockaddr_in *)&evc->sa_remote)->sin_port = htons(evc->domain_info.port);
    ((struct sockaddr_in *)&evc->sa_remote)->sin_addr.s_addr = address;

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
	unsigned char *data = NULL;
    struct event_base *base;
    evutil_socket_t ufd;
    struct event *ev_udp;
    struct udp_write_block *uwb;
   
	datalen = evbuffer_get_length(input); 

	data = (unsigned char *)CALLOC(datalen, sizeof(unsigned char));
	assert(data);

	datalen = evbuffer_remove(input, data, datalen);
    reset_timer(evc->timeout_ev, BEV_TIMEOUT);

	//<TODO decrypt
    rs_decrypt(data, data, datalen, evc->local_info->local_pwd);

	vlog(INFO, "LOCAL RECV(%d)\n", datalen);
	vlog_array(INFO, data, datalen);

	do{
		if ((unsigned char)data[0] == 0xFF) { //<addr
			rc = parse_header(data, datalen, &evc->domain_info);
			if (rc != 0){
				vlog(ERROR, "bad package!\n");
				free_ev_container(evc);
				break;
			}

			vlog(DEBUG, "==> (TCP) <%s:%d> connect to <%s:%d>\n", 
				inet_ntoa(((struct sockaddr_in *)&evc->sa)->sin_addr),
				ntohs(((struct sockaddr_in *)&evc->sa)->sin_port),
				evc->domain_info.address,
				evc->domain_info.port
			);

			if (evc->domain_info.type == type_ip){
                ((struct sockaddr_in *)&evc->sa_remote)->sin_family = AF_INET;
                ((struct sockaddr_in *)&evc->sa_remote)->sin_port = htons(evc->domain_info.port);
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
			} else if(evc->domain_info.type == type_domain) {
				struct evutil_addrinfo hints;

				memset(&hints, 0, sizeof(hints));
				hints.ai_family = AF_UNSPEC;
				hints.ai_flags = EVUTIL_AI_CANONNAME;
				evc->dns_req = evdns_getaddrinfo(evc->evdns_base, evc->domain_info.address, NULL, &hints, dns_cb, (void *)evc);
			}
        } else if (data[0] == 0x00 && data[1] == 0x00) { //udp relay
            if (!evc->ev_udp) {
                ufd = socket(AF_INET, SOCK_DGRAM, 0);
                if (ufd < 0){
                    vlog(ERROR, "New socket error\n");
				    free_ev_container(evc);
                    break;
                }
                base = bufferevent_get_base(bev);
                ev_udp = event_new(base, ufd, EV_READ | EV_PERSIST, udp_cb, (void *)evc); 
                event_add(ev_udp, NULL);

                evc->ev_udp = ev_udp;
            }

			rc = parse_header(data, datalen, &evc->domain_info);
			if (rc != 0){
				vlog(ERROR, "bad package!\n");
				free_ev_container(evc);
				break;
			}

			vlog(DEBUG, "==> (UDP) <%s:%d> connect to <%s:%d>\n", 
				inet_ntoa(((struct sockaddr_in *)&evc->sa)->sin_addr),
				ntohs(((struct sockaddr_in *)&evc->sa)->sin_port),
				evc->domain_info.address,
				evc->domain_info.port
			);

            ((struct sockaddr_in *)&evc->sa_remote)->sin_family = AF_INET;
            ((struct sockaddr_in *)&evc->sa_remote)->sin_port = htons(evc->domain_info.port);

            base = bufferevent_get_base(bev);
            ufd = event_get_fd(evc->ev_udp); 

            uwb = (struct udp_write_block *)CALLOC(1, sizeof(struct udp_write_block));
            uwb->event = event_new(base, ufd, EV_WRITE, udp_cb, (void *)uwb);
            uwb->buffer = (unsigned char *)CALLOC(BUFFER_MAX, sizeof(unsigned char));
            assert(uwb->buffer);

            memcpy(uwb->buffer, data + 10, datalen - 10);
            uwb->buffer_size = datalen - 10;
            uwb->domain_info = evc->domain_info;

			if (evc->domain_info.type == type_ip){
			    ((struct sockaddr_in *)&evc->sa_remote)->sin_addr.s_addr = inet_addr(evc->domain_info.address);

                uwb->sa = evc->sa_remote; 
                uwb->sa_len = sizeof(evc->sa_remote);

                event_add(uwb->event, NULL);
			} else if(evc->domain_info.type == type_domain) {
				struct evutil_addrinfo hints;

                uwb->sa = evc->sa_remote; 
                uwb->sa_len = sizeof(evc->sa_remote);

				memset(&hints, 0, sizeof(hints));
				hints.ai_family = AF_UNSPEC;
				hints.ai_flags = EVUTIL_AI_CANONNAME;
				uwb->dns_req = evdns_getaddrinfo(evc->evdns_base, evc->domain_info.address, NULL, &hints, udp_dns_cb, (void *)uwb);
            }
		} else { //<stream
			bufferevent_write(partner, data, datalen);
			bufferevent_enable(partner, EV_WRITE);
		}
	}while(0);

	FREE(data);
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
	evc = (struct ev_container *)CALLOC(1, sizeof(struct ev_container));
	assert(evc);

    evc->sa = *sa;
	evc->bev_local = bev_in;
	evc->bev_remote = bev_out;
	evc->local_info = &config_info->local_info;
	evc->evdns_base = config_info->evdns_base;

    evc->buffer_in = (unsigned char *)CALLOC(BUFFER_MAX, sizeof(unsigned char));
    assert(evc->buffer_in);

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
        "Usage: %s [-v 0/1/2] [-b 127.0.0.1] [-l 9600] -k password\n"
        "\t-v <verbose>: 0 DEFAULT/1 DEBUG/2 INFO\n"
        "\t-b <localAddress>: local bind address\n"
        "\t-l <localPort>: local bind port\n"
        "\t-k <password>: password\n",
    NAME);
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

	config_info = (struct config_info *)CALLOC(1, sizeof(struct config_info));
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
