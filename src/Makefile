
OS := $(shell sh -c 'uname -s 2>/dev/null || echo unknow')
ROOT := $(shell sh -c 'cd .. ; pwd')
DEPENDENCY_TARGETS=libyaml


STD=-STD=C99 -pendantic
WARN=-Wall -W
OPT=-02
DEBUG=-g -ggdb

PREFIX?=$(ROOT)
INSTALL_BIN=$(PREFIX)/bin

INSTALL=install
RM=rm -rf

FINAL_CFLAGS=$(STD) $(WARN) $(OPT) $(DEBUG) $(CFLAGS)
FINAL_LDFLAGS=$(LDFLAGS) $(DEBUG)
FINAL_LIBS=-lm
FINAL_CFLAGS+= -I../contrib/libyaml/include

CC?=gcc

NPROXY_CC=$(CC) $(FINAL_CFLAGS)
NPROXY_LD=$(CC) $(FINAL_LDFLAGS)

NPROXY_BIN=nproxy
NPROXY_OBJ=nproxy.o config.o util.o log.o

nproxy.o: nproxy.c nproxy.h config.h config.c util.h log.h
config.o: config.c config.h util.h ../contrib/libyaml/include/yaml.h
log.o: log.c log.h
util.o: util.h

$(NPROXY_BIN): $(NPROXY_OBJ)
	$(NPROXY_LD) -o $@ $^ $(FINAL_LIBS)  


all: $(NPROXY_BIN)


%.o: %.c
	$(NPROXY_CC) -c $<
	

.PHONY: all

install: all
	@mkdir -p $(INSTALL_BIN)
	$(INSTALL) $(NPROXY_BIN) $(INSTALL_BIN)
	

clean: 
	$(RM) $(NPROXY_BIN) *.o

.PHONY: clean


