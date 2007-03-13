# Makefile fragment for Automake wrapper makefile for kernel modules

if WANT_MODULES
# NOTE: We cannot support VPATH builds when WANT_MODULES is enabled, because
# Kbuild does not support VPATH builds for external modules.

export KERNELDIR

all-local:
	@$(MAKE) $(AM_MAKEFLAGS) -f Makefile module

clean-local:
	@$(MAKE) $(AM_MAKEFLAGS) -f Makefile clean

install-exec-local:
	@$(MAKE) $(AM_MAKEFLAGS) -f Makefile install

uninstall-local:
	@$(MAKE) $(AM_MAKEFLAGS) -f Makefile uninstall

installdirs-local:
	@$(MAKE) $(AM_MAKEFLAGS) -f Makefile installdirs
endif