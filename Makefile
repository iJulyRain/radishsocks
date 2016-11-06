all : rsclient rsserver

rsclient : radishsocks/client.c radishsocks/log.c radishsocks/cipher.c
	gcc -o $@ $^ -I ./libevent/include -L ./libevent/lib -levent -levent -static

rsserver : radishsocks/server.c radishsocks/log.c radishsocks/cipher.c
	gcc -o $@ $^ -I ./libevent/include -L ./libevent/lib -levent -levent -static

clean:
	rm -f rsclient rsserver
.PHONY:clean
