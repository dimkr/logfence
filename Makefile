PROG = logfence

CC ?= cc
CFLAGS ?= -O2
LDFLAGS ?=
DESTDIR ?= /
SBIN_DIR ?= sbin
DOC_DIR ?= usr/share/doc/$(PROG)
MAN_DIR ?= usr/share/man

CFLAGS += -Wall -pedantic -std=gnu99 -D_GNU_SOURCE -DPROG=\"$(PROG)\" -I./compat
FUSE_CFLAGS = $(shell pkg-config --cflags fuse)
FUSE_LIBS = $(shell pkg-config --libs fuse)

SRCS = $(wildcard *.c)
OBJECTS = $(SRCS:.c=.o)
HEADERS = $(wildcard *.h)

%.o: %.c $(HEADERS)
	$(CC) -c -o $@ $< $(CFLAGS) $(FUSE_CFLAGS)

$(PROG): $(OBJECTS)
	$(CC) -o $@ $^ $(LDFLAGS) $(FUSE_LIBS)

clean:
	rm -f $(PROG) $(OBJECTS)

install: $(PROG)
	install -D -m 755 $(PROG) $(DESTDIR)/$(SBIN_DIR)/$(PROG)
	install -D -m 644 $(PROG).8 $(DESTDIR)/$(MAN_DIR)/man8/$(PROG).8
	install -D -m 644 README.md $(DESTDIR)/$(DOC_DIR)/README.md
	install -m 644 AUTHORS $(DESTDIR)/$(DOC_DIR)/AUTHORS
	install -m 644 COPYING $(DESTDIR)/$(DOC_DIR)/COPYING
