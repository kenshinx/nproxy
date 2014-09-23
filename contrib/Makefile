
CCCOLOR="\033[34m"
LINKCOLOR="\033[34;1m"
SRCCOLOR="\033[33m"
BINCOLOR="\033[37;1m"
MAKECOLOR="\033[32;1m"
ENDCOLOR="\033[0m"

OS := $(shell sh -c 'uname -s 2>/dev/null || echo unknow')
ROOT := $(shell sh -c 'cd .. ; pwd')

LIBYAML=yaml-0.1.5
HIREDIS=hiredis-0.11.0

distclean:
	-(cd $(LIBYAML) && $(MAKE) clean) >/dev/null || true
	-(cd $(HIREDIS) && $(MAKE) clean) >/dev/null || true

.PHONY: distclean



libyaml:
	@printf '%b %b\n' $(MAKECOLOR)MAKE$(ENDCOLOR) $(BINCOLOR)$@$(ENDCOLOR)
	cd $(LIBYAML) && ./configure && $(MAKE)

.PHONY: libyaml

hiredis:
	@printf '%b %b\n' $(MAKECOLOR)MAKE$(ENDCOLOR) $(BINCOLOR)$@$(ENDCOLOR)
	cd $(HIREDIS) && $(MAKE) static 

.PHONY: hiredis
