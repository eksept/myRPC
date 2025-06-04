NAME    := myRPC-client
SRC     := $(NAME).c
OBJDIR  := ../../build
BINDIR  := ../../bin
OBJ     := $(OBJDIR)/$(NAME).o
BIN     := $(BINDIR)/$(NAME)
CC      := gcc
CFLAGS  := -Wall
LDFLAGS := -ljson-c

DEB_DIR     := build-deb
DEB_BIN     := $(DEB_DIR)/usr/local/bin
DEB_CONTROL := $(DEB_DIR)/DEBIAN
DEB_NAME    := $(NAME)_1.0_amd64.deb
DEB_OUT     := ../../deb/$(DEB_NAME)

.PHONY: all clean deb

all: $(BIN)

$(OBJDIR) $(BINDIR):
	mkdir -p $@

$(OBJ): $(SRC) | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BIN): $(OBJ) | $(BINDIR)
	$(CC) $< -o $@ $(LDFLAGS)

clean:
	rm -f $(OBJ) $(BIN)
	rm -rf $(DEB_DIR)

deb: all
	mkdir -p $(DEB_BIN)
	cp $(BIN) $(DEB_BIN)/
	mkdir -p $(DEB_CONTROL)
	{ \
		echo "Package: $(NAME)"; \
		echo "Version: 1.0"; \
		echo "Section: base"; \
		echo "Priority: optional"; \
		echo "Architecture: amd64"; \
		echo "Maintainer: eksept <deshine@inbox.ru>"; \
		echo "Description: myRPC-client program"; \
	} > $(DEB_CONTROL)/control
	chmod 755 $(DEB_CONTROL)
	chmod 644 $(DEB_CONTROL)/control
	mkdir -p ../../deb
	fakeroot dpkg-deb --build $(DEB_DIR) $(DEB_OUT)
