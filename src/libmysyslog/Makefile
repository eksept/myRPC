NAME = libmysyslog
SRC = libmysyslog.c
HDR = libmysyslog.h
OBJ = ../../build/$(NAME).o
CC = gcc
CFLAGS = -Wall -Wextra -O2
PREFIX = /usr/local

all: ../../build $(OBJ)

../../build:
	mkdir -p ../../build

$(OBJ): $(SRC) $(HDR)
	$(CC) $(CFLAGS) -c $(SRC) -o $(OBJ)

clean:
	rm -f $(OBJ)
	rm -rf build-deb

deb: all
	mkdir -p build-deb/DEBIAN
	mkdir -p build-deb$(PREFIX)/include/$(NAME)
	mkdir -p build-deb$(PREFIX)/lib
	cp $(HDR) build-deb$(PREFIX)/include/$(NAME)/
	cp $(OBJ) build-deb$(PREFIX)/lib/
	echo "Package: $(NAME)" > build-deb/DEBIAN/control
	echo "Version: 1.0" >> build-deb/DEBIAN/control
	echo "Section: libs" >> build-deb/DEBIAN/control
	echo "Priority: optional" >> build-deb/DEBIAN/control
	echo "Architecture: amd64" >> build-deb/DEBIAN/control
	echo "Maintainer: eksept <deshine@inbox.ru>" >> build-deb/DEBIAN/control
	echo "Description: Custom logging library" >> build-deb/DEBIAN/control
	chmod 0755 build-deb/DEBIAN
	chmod g-s build-deb/DEBIAN
	chmod 755 build-deb/DEBIAN
	chmod 0644 build-deb/DEBIAN/control
	fakeroot dpkg-deb --build build-deb ../../deb/$(NAME)_1.0_amd64.deb
