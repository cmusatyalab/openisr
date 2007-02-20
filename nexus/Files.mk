# We keep the file list in a separate Makefile fragment so that both Kbuild
# and Automake can read it; otherwise they choke on each others' syntax

NEXUS_OBJS := init.o request.o chunkdata.o chardev.o transform.o lzf.o
NEXUS_OBJS += sysfs.o thread.o revision.o 

NEXUS_HDRS := nexus.h defs.h kcompat.h lzf.h
