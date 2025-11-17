CC = g++
CFLAGS = -g -Wall

all: proxy

proxy: proxy_server_with_cache.cpp
	$(CC) $(CFLAGS) -o proxy_parse.o -c proxy_parse.cpp -lpthread
	$(CC) $(CFLAGS) -o proxy.o -c proxy_server_with_cache.cpp -lpthread
	$(CC) $(CFLAGS) -o proxy proxy_parse.o proxy.o -lpthread

clean:
	rm -f proxy *.o

tar:
	tar -cvzf ass1.tgz proxy_server_with_cache.cpp README Makefile proxy_parse.cpp proxy_parse.hpp
