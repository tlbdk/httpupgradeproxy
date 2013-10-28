UNAME := $(shell uname)

RTFLAGS="-lrt"
ifeq ($(UNAME), Darwin)
RTFLAGS=-framework Carbon -framework CoreServices
endif

httpupgradeproxy: httpupgradeproxy.c libuv/libuv.a http-parser/http_parser.o
	gcc -I libuv/include httpupgradeproxy.c http-parser/http_parser.o libuv/libuv.a $(RTFLAGS) -lpthread -lm -o httpupgradeproxy

libuv/libuv.a:
	$(MAKE) -C libuv
	cp libuv/.libs/libuv.a libuv/libuv.a

http-parser/http_parser.o:
	$(MAKE) -C http-parser http_parser.o

clean:
	$(MAKE) -C libuv clean
	$(MAKE) -C http-parser clean
	-rm libuv/libuv.a
	-rm http-parser/http_parser.o
	-rm httpupgradeproxy
