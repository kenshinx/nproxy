
OS := $(shell sh -c 'uname -s 2>/dev/null || echo unknow')
ROOT := $(shell sh -c 'cd .. ; pwd')

LIBYAML=yaml-0.1.5

distclean:
	-(cd $(LIBYAML) && $(MAKE) clean) >/dev/null || true


.PHONY: distclean



libyaml:
	@printf 'MAKE $@'
	cd $(LIBYAML) && ./configure && $(MAKE)

.PHONY: libyaml
