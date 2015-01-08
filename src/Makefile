
OS := $(shell sh -c 'uname -s 2>/dev/null || echo unknow')
ROOT := $(shell sh -c 'cd .. ; pwd')
DEPENDENCY_TARGETS=libyaml hiredis jansson libuv
LIBYAML=yaml-0.1.5
HIREDIS=hiredis-0.11.0
JANSSON=jansson-2.6
LIBUV=libuv-v1.0.2


STD=-STD=C99 -pendantic
WARN=-Wall -W
OPT=-02
DEBUG=-g -ggdb
PROFILE=-pg
LIBLRT=-lrt
LIBPTHREAD=-lpthread 

PREFIX?=$(ROOT)
INSTALL_BIN=$(PREFIX)/bin

INSTALL=install
RM=rm -rf

FINAL_CFLAGS=$(STD) $(WARN) $(OPT) $(DEBUG) $(CFLAGS)
FINAL_LDFLAGS=$(LDFLAGS) $(DEBUG) $(LIBPTHREAD)
FINAL_LIBS=-lm
FINAL_CFLAGS+= -I../contrib/$(LIBYAML)/include
FINAL_CFLAGS+= -I../contrib/$(HIREDIS)
FINAL_CFLAGS+= -I../contrib/$(JANSSON)/src
FINAL_CFLAGS+= -I../contrib/$(LIBUV)/include

CC?=gcc

NPROXY_CC=$(CC) $(FINAL_CFLAGS)
NPROXY_LD=$(CC) $(FINAL_LDFLAGS)

NPROXY_BIN=nproxy
NPROXY_OBJ=nproxy.o config.o proxy.o util.o log.o array.o string.o socks5.o redis.o server.o

nproxy.o: nproxy.c core.h config.h 
config.o: config.c config.h core.h ../contrib/$(LIBYAML)/include/yaml.h
proxy.o: proxy.c proxy.h ../contrib/$(JANSSON)/src/jansson.h ../contrib/$(HIREDIS)/hiredis.h 
log.o: log.c log.h  
util.o: util.c util.h 
array.o: array.c array.h 
string.o: string.c string.h
socks5.o: socks5.c socks5.h
redis.o: redis.c redis.h ../contrib/$(HIREDIS)/hiredis.h
server.o: server.c server.h ../contrib/$(LIBUV)/include/uv.h ../contrib/$(HIREDIS)/hiredis.h 

$(NPROXY_BIN): $(NPROXY_OBJ)
	$(NPROXY_LD) -o $@ $^ $(FINAL_LIBS) ../contrib/$(LIBYAML)/src/.libs/libyaml.a ../contrib/$(HIREDIS)/libhiredis.a ../contrib/$(JANSSON)/src/.libs/libjansson.a ../contrib/$(LIBUV)/.libs/libuv.a

PREPARE=make-contrib

make-contrib:
	-(cd ../contrib && $(MAKE) $(DEPENDENCY_TARGETS))	

.PHONY: make-contrib

#all: $(NPROXY_BIN)

all: $(PREPARE) $(NPROXY_BIN)

.PHONY: all


%.o: %.c
	$(NPROXY_CC) -c $<
	

.PHONY: all

install: all
	@mkdir -p $(INSTALL_BIN)
	$(INSTALL) $(NPROXY_BIN) $(INSTALL_BIN)
	
distclean: clean
	-(cd ../contrib && $(MAKE) distclean)

.PHONY: distclean

clean: 
	$(RM) $(NPROXY_BIN) *.o *.gch *.swp

.PHONY: clean


