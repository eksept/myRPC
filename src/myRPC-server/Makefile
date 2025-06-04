CC = gcc
CFLAGS = -Wall -I../../src/libmysyslog
LDFLAGS = -ljson-c

NAME = myRPC-server
SRC = myRPC-server.c
OBJ_DIR = ../../build
BIN_DIR = ../../bin
OBJ = $(OBJ_DIR)/$(NAME).o
SYSLOG_OBJ = $(OBJ_DIR)/libmysyslog.o
BIN = $(BIN_DIR)/$(NAME)

all: $(BIN)

$(OBJ): $(SRC)
	mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(SYSLOG_OBJ): ../../src/libmysyslog/libmysyslog.c ../../src/libmysyslog/libmysyslog.h
	mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c ../../src/libmysyslog/libmysyslog.c -o $@

$(BIN): $(OBJ) $(SYSLOG_OBJ)
	mkdir -p $(BIN_DIR)
	$(CC) $^ -o $@ $(LDFLAGS)

clean:
	rm -f $(OBJ) $(SYSLOG_OBJ) $(BIN)
	rm -rf build-deb

deb: all
	mkdir -p build-deb/usr/local/bin
	mkdir -p build-deb/etc/myRPC
	mkdir -p build-deb/lib/systemd/system
	mkdir -p build-deb/DEBIAN

	cp $(BIN) build-deb/usr/local/bin/
	cp ../../config/myRPC.conf build-deb/etc/myRPC/
	cp ../../config/users.conf build-deb/etc/myRPC/
	cp ../../config/myRPC-server.service build-deb/lib/systemd/system/

	echo "Package: $(NAME)" > build-deb/DEBIAN/control
	echo "Version: 1.0" >> build-deb/DEBIAN/control
	echo "Section: base" >> build-deb/DEBIAN/control
	echo "Priority: optional" >> build-deb/DEBIAN/control
	echo "Architecture: amd64" >> build-deb/DEBIAN/control
	echo "Maintainer: eksept <deshine@inbox.ru>" >> build-deb/DEBIAN/control
	echo "Description: myRPC-server daemon with systemd service" >> build-deb/DEBIAN/control

	echo "#!/bin/bash" > build-deb/DEBIAN/postinst
	echo "set -e" >> build-deb/DEBIAN/postinst
	echo "systemctl daemon-reload" >> build-deb/DEBIAN/postinst
	echo "systemctl enable myRPC-server.service" >> build-deb/DEBIAN/postinst
	echo "systemctl restart myRPC-server.service || systemctl start myRPC-server.service" >> build-deb/DEBIAN/postinst
	echo "exit 0" >> build-deb/DEBIAN/postinst
	chmod 755 build-deb/DEBIAN/postinst

	echo "#!/bin/bash" > build-deb/DEBIAN/prerm
	echo "set -e" >> build-deb/DEBIAN/prerm
	echo "if systemctl is-active --quiet myRPC-server.service; then" >> build-deb/DEBIAN/prerm
	echo "    systemctl stop myRPC-server.service" >> build-deb/DEBIAN/prerm
	echo "fi" >> build-deb/DEBIAN/prerm
	echo "systemctl disable myRPC-server.service" >> build-deb/DEBIAN/prerm
	echo "systemctl daemon-reload" >> build-deb/DEBIAN/prerm
	echo "exit 0" >> build-deb/DEBIAN/prerm
	chmod 755 build-deb/DEBIAN/prerm

	mkdir -p ../../deb
	fakeroot dpkg-deb --build build-deb ../../deb/$(NAME)_1.0_amd64.deb
