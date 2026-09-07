# Generated config
# user can control verbosity similar to kernel builds (e.g., V=1)
ifeq ("$(origin V)", "command line")
  VERBOSE = $(V)
endif
ifndef VERBOSE
  VERBOSE = 0
endif
ifeq ($(VERBOSE),1)
  Q =
else
  Q = @
endif
ifeq ($(VERBOSE),0)
MAKEFLAGS += --no-print-directory
endif


ifeq ($(VERBOSE), 0)
    QUIET_CC       = @echo '    CC       '$@;
    QUIET_CLANG    = @echo '    CLANG    '$@;
    QUIET_LINK     = @echo '    LINK     '$@;
    QUIET_INSTALL  = @echo '    INSTALL  '$@;
    QUIET_GEN      = @echo '    GEN      '$@;
    QUIET_COPY     = @echo '    COPY     '$@;
endif
PKG_CONFIG:=pkg-config
CC:=gcc
CLANG:=clang
BPFTOOL:=bpftool
ARCH_INCLUDES:=-I/usr/include/x86_64-linux-gnu 
SYSTEM_LIBBPF:=y
CFLAGS += 
LDLIBS +=  -lbpf
OBJECT_LIBBPF = 
SYSTEM_LIBXDP:=y
CFLAGS += 
LDLIBS +=  -lxdp
OBJECT_LIBXDP = 
