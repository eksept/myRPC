.PHONY: all clean deb

all: libmysyslog myRPC-client myRPC-server

libmysyslog:
	$(MAKE) -C src/libmysyslog

myRPC-client:
	$(MAKE) -C src/myRPC-client

myRPC-server:
	$(MAKE) -C src/myRPC-server

clean:
	$(MAKE) -C src/libmysyslog clean
	$(MAKE) -C src/myRPC-client clean
	$(MAKE) -C src/myRPC-server clean
	rm -rf build-deb
	rm -rf deb

deb: all
	$(MAKE) -C src/libmysyslog deb
	$(MAKE) -C src/myRPC-client deb
	$(MAKE) -C src/myRPC-server deb
