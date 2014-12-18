#! /usr/bin/env python

import sys
import redis
import json
import optparse

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

    print data
    r = redis.StrictRedis(host=REDIS_HOST, port=REDIS_PORT)
    r.sadd(REDIS_KEY, data)

    print "sucess"
    

def main():
    parser = optparse.OptionParser()
    parser.add_option("-u", "--username", action="store", dest="username", type="string")
    parser.add_option("-p", "--password", action="store", dest="password", type="string")
    parser.add_option("", "--proto", action="store", dest="proto", type="string", default="socks5")
    options, args = parser.parse_args()

    host, port = args[0].split(":")
    
    add(host, port, options.proto, options.username, options.password)
    

if __name__ == "__main__":
    main()
