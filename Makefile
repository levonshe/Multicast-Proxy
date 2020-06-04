AUTO_GENERATE_C_FILES := $(shell ls *.c 2> /dev/null)
AUTO_GENERATE_O_FILES := $(patsubst %.c,%.o,$(AUTO_GENERATE_C_FILES))
	# DEBUG $(CROSS)$(CC) -I. -I/usr/include -g -O2 -c -o $@  $<
	#$(CROSS)$(CC) -DHAVE_MLDV2 -I. -I/usr/include -g -c -Wstrict-prototypes -o $@  $<
	#$(CROSS)$(CC) -I. -I/vobs/ua_sdk/ti/include -g -c -Wstrict-prototypes -o $@  $<
	#$(CROSS)$(CC) -o $@ $(AUTO_GENERATE_O_FILES) -L /vobs/ua_sdk/build/dgwsdk/fs/base_fs/lib/  -L /vobs/ua_sdk/ti/libs -lc
CC=gcc
#CFLAGS=-DHAVE_MLDV2 -DHAVE_RFC2292
#CFLAGS=-DHAVE_MLDV2
CFLAGS=-DHAVE_MLDV2 -DHAVE_RFC3542 -ansi -pedantic -Wall -W -Wconversion -Wshadow -Wcast-qual -Wwrite-strings

%.o : %.c 
	$(CROSS)$(CC) $(CFLAGS) -I. -I/usr/include -g -c -Wstrict-prototypes -o $@  $<

mldproxy:$(AUTO_GENERATE_O_FILES) Makefile
	$(CROSS)$(CC) $(CFLAGS) -o $@ $(AUTO_GENERATE_O_FILES)

