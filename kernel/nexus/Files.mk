# We keep the file list in a separate Makefile fragment so that both Kbuild
# and Automake can read it; otherwise they choke on each others' syntax.
# revision.o is not included here because revision.c is not distributed.

NEXUS_OBJS := init.o request.o chunkdata.o chardev.o transform.o lzf.o
NEXUS_OBJS += sysfs.o thread.o

NEXUS_HDRS := nexus.h defs.h kcompat.h lzf.h
