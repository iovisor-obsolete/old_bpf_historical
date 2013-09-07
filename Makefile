CC=gcc
CFLAGS=-g -I./include/uapi
all:
	$(CC) $(CFLAGS) l2ls_ctl.c iovisor_api.c -o l2ls-ctl -lmnl -lpthread
