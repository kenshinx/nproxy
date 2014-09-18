
OS := $(shell sh -c 'uname -s 2>/dev/null || echo unknow')
ROOT := $(shell sh -c 'cd .. ; pwd')
DEPENDENCY_TARGETS=libyaml
LIBYAML=yaml-0.1.5


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
FINAL_CFLAGS+= -I../contrib/$(LIBYAML)/include

CC?=gcc

NPROXY_CC=$(CC) $(FINAL_CFLAGS)
NPROXY_LD=$(CC) $(FINAL_LDFLAGS)

NPROXY_BIN=nproxy
NPROXY_OBJ=nproxy.o config.o util.o log.o array.o string.o

nproxy.o: nproxy.c nproxy.h config.h config.c util.h log.h
config.o: config.c config.h util.h nproxy.h array.h string.h ../contrib/$(LIBYAML)/include/yaml.h
log.o: log.c log.h
util.o: util.c util.h
array.o: array.c array.h
string.o: string.c string.h

$(NPROXY_BIN): $(NPROXY_OBJ)
	$(NPROXY_LD) -o $@ $^ $(FINAL_LIBS) ../contrib/$(LIBYAML)/src/.libs/libyaml.a 

PREPARE=make-contrib

make-contrib:
	-(cd ../contrib && $(MAKE) $(DEPENDENCY_TARGETS))	

.PHONY: make-contrib

all: $(NPROXY_BIN)

#all: $(PREPARE) $(NPROXY_BIN)

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


