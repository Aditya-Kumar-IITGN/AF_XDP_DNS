# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

ifeq ("$(origin V)", "command line")
VERBOSE = $(V)
endif
ifndef VERBOSE
VERBOSE = 0
endif

ifeq ($(VERBOSE),0)
MAKEFLAGS += --no-print-directory
Q = @
endif

mainfile = main
mainfile_clean = $(addsuffix _clean,$(mainfile))

.PHONY: clean clobber distclean $(mainfile) $(mainfile_clean)

all: lib $(mainfile)

wlo1:
	sudo ./main/af_xdp_user -d wlo1 --filename main/af_xdp_kern.o

clean: $(mainfile_clean)
	@echo; echo common; $(MAKE) -C common clean
	@echo; echo lib; $(MAKE) -C lib clean

lib: config.mk check_submodule
	@echo; echo $@; $(MAKE) -C $@

$(mainfile):
	@echo; echo $@; $(MAKE) -C $@

$(mainfile_clean):
	@echo; echo $@; $(MAKE) -C $(subst _clean,,$@) clean

config.mk: configure
	@sh configure

clobber:
	@touch config.mk
	$(Q)$(MAKE) clean
	$(Q)rm -f config.mk

distclean:	clobber

check_submodule:
	@if [ -d .git ] && `git submodule status lib/libbpf | grep -q '^+'`; then \
		echo "" ;\
		echo "** WARNING **: git submodule SHA-1 out-of-sync" ;\
		echo " consider running: git submodule update"  ;\
		echo "" ;\
	fi\

