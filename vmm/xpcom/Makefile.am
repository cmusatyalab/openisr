# VirtualBox Python XPCOM module, from VirtualBox SDK

BASEFILES    = __init__.py components.py file.py nsError.py primitives.py
BASEFILES   += vboxxpcom.py xpcom_consts.py xpt.py
CLIENTFILES  = __init__.py
SERVERFILES  = __init__.py enumerator.py factory.py loader.py module.py
SERVERFILES += policy.py
FILES        = $(BASEFILES) $(patsubst %,client/%,$(CLIENTFILES))
FILES       += $(patsubst %,server/%,$(SERVERFILES))

xpcomdir = $(pkgdatadir)/xpcom
nobase_dist_xpcom_DATA = $(FILES)
CLEANFILES = $(FILES:.py=.pyc)
