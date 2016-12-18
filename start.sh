#!/bin/sh

if [ $# -eq 0 ]; then
    echo "Usage. sudo docker run -it --rm --name rs-client --net=host julyrain/radishsocks rs-client -s xx.xx.xx.xx -p 9600 -b 0.0.0.0 -l 1080 -k xxxx"
fi

cmd="./$*"
eval $cmd
