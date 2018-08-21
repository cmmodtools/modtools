CC=cc
CFLAGS=-Wall -O2 -mmacosx-version-min=10.6 -arch x86_64 -arch i386

prefix=/usr/local

.PHONY: all
all: rezexplode rezpack rezlist

%.o: %.c %.h
	$(CC) -c -o $@ $< $(CFLAGS)

rezlist: rezexplode
	ln -f $< $@

rezpack: rezexplode
	ln -f $< $@

rezexplode: main.c brz.o brz_utils.o brz_filter.o
	$(CC) -o $@ $^ $(CFLAGS)

.PHONY: clean
clean:
	rm -rf *.o *.dSYM

.PHONY: distclean
distclean: clean
	rm -f rezexplode rezpack rezlist

.PHONY: install
install: rezexplode rezpack rezlist
	install -d $(prefix)/bin
	install -m 0755 $^ $(prefix)/bin

