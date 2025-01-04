BINARY_DIR=bin
INSTALL_DIR=/sbin
CERT_DIR=/etc/dn-server
SYSTEMD_DIR=/etc/systemd/system
COMMON_SOURCES=doxx.net.go tun_interface.go

.PHONY: all clean install

all: clean linux-amd64 linux-arm64 windows-amd64 mac-universal

clean:
	rm -rf $(BINARY_DIR)
	mkdir -p $(BINARY_DIR)

linux-amd64:
	GOOS=linux GOARCH=amd64 go build -o $(BINARY_DIR)/doxx.net-linux-amd64 $(COMMON_SOURCES) tun_other.go

linux-arm64:
	GOOS=linux GOARCH=arm64 go build -o $(BINARY_DIR)/doxx.net-linux-arm64 $(COMMON_SOURCES) tun_other.go

windows-amd64:
	GOOS=windows GOARCH=amd64 go build -o $(BINARY_DIR)/doxx.net.exe $(COMMON_SOURCES) tun_windows.go

mac-universal:
	GOOS=darwin GOARCH=amd64 go build -o $(BINARY_DIR)/doxx.net-darwin-amd64 $(COMMON_SOURCES) tun_other.go
	GOOS=darwin GOARCH=arm64 go build -o $(BINARY_DIR)/doxx.net-darwin-arm64 $(COMMON_SOURCES) tun_other.go
	lipo -create -output $(BINARY_DIR)/doxx.net-mac $(BINARY_DIR)/doxx.net-darwin-amd64 $(BINARY_DIR)/doxx.net-darwin-arm64
	rm $(BINARY_DIR)/doxx.net-darwin-amd64 $(BINARY_DIR)/doxx.net-darwin-arm64

install: all
	# Create directories
	mkdir -p $(INSTALL_DIR)
	mkdir -p $(CERT_DIR)
	
	# Detect architecture
	$(eval ARCH := $(shell dpkg --print-architecture))
ifeq ($(ARCH),arm64)
	$(eval CLIENT := $(BINARY_DIR)/doxx.net-linux-arm64)
else
	$(eval CLIENT := $(BINARY_DIR)/doxx.net-linux-amd64)
endif
