FROM alpine:3.4

MAINTAINER JulyRain <ijulyrain@gmail.com>

ADD repositories /etc/apk/repositories 
COPY ./ /build
COPY ./start.sh /app/

RUN apk add --update gcc g++ cmake make libevent libevent-dev \
&& cd build && cmake . && make \
&& cp output/* /app/ \
&& cd /app && ln -s rssocks rs-client && ln -s rssocks rs-server \
&& rm -rf build \
&& apk del gcc g++ cmake make libevent-dev \
&& rm -rf /var/cache/apk/* 

WORKDIR /app

ENTRYPOINT ["/bin/sh", "start.sh"]
