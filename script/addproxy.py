#! /usr/bin/env python

import sys
import redis
import json

REDIS_HOST = "dev1.netlab.corp.qihoo.net"
REDIS_PORT = 6379

REDIS_KEY = "netlab:nproxy"

def add(host, port, proto="socks5", username=None, password=None):

    data = json.dumps({
                "host": host, 
                "port": int(port), 
                "proto": proto,
                "username": username,
                "password": password})

    r = redis.StrictRedis(host=REDIS_HOST, port=REDIS_PORT)
    r.sadd(REDIS_KEY, data)

    print "sucess"
    
    

if __name__ == "__main__":
    host = sys.argv[1]
    port = sys.argv[2]
    add(host, port)
