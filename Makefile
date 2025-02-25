BINARY_DIR=bin
INSTALL_DIR=/sbin
SYSTEMD_DIR=/etc/systemd/system
COMMON_SOURCES=doxx.net.go tun_interface.go
WINDOWS_SOURCES=tun_windows.go embed_windows.go
WINTUN_VERSION := 0.14.1
WINTUN_URL := https://www.wintun.net/builds/wintun-$(WINTUN_VERSION).zip
WINTUN_SHA256 := 07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51
DOXXULATOR_SOURCE=doxxulator.go

# Detect OS for sha256 command and check format
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    SHA256_CMD := shasum -a 256
    SHA256_CHECK := echo "Expected hash: $(WINTUN_SHA256)" && \
                   echo "Actual hash: $$(shasum -a 256 wintun.zip | cut -d' ' -f1)" && \
                   echo "$(WINTUN_SHA256)  wintun.zip" | shasum -a 256 -c
    MAC_BUILD := mac-universal
else
    SHA256_CMD := sha256sum
    SHA256_CHECK := echo "Expected hash: $(WINTUN_SHA256)" && \
                   echo "Actual hash: $$(sha256sum wintun.zip | cut -d' ' -f1)" && \
                   echo "$(WINTUN_SHA256) wintun.zip" | sha256sum -c
    MAC_BUILD := mac-amd64 mac-arm64
endif

.PHONY: all clean install get-wintun zip-all

all: clean linux-amd64 linux-arm64 windows-amd64 windows-arm64 $(MAC_BUILD) freebsd-amd64 freebsd-arm64 openbsd-amd64 openbsd-arm64 doxxulator-all zip-all

clean:
	rm -rf $(BINARY_DIR)
	mkdir -p $(BINARY_DIR)

linux-amd64:
	@mkdir -p $(BINARY_DIR)/Linux/amd64
	GOOS=linux GOARCH=amd64 go build -o $(BINARY_DIR)/Linux/amd64/doxx.net $(COMMON_SOURCES) tun_other.go

linux-arm64:
	@mkdir -p $(BINARY_DIR)/Linux/arm64
	GOOS=linux GOARCH=arm64 go build -o $(BINARY_DIR)/Linux/arm64/doxx.net $(COMMON_SOURCES) tun_other.go

freebsd-amd64:
	@mkdir -p $(BINARY_DIR)/FreeBSD/amd64
	GOOS=freebsd GOARCH=amd64 go build -o $(BINARY_DIR)/FreeBSD/amd64/doxx.net $(COMMON_SOURCES) tun_other.go

freebsd-arm64:
	@mkdir -p $(BINARY_DIR)/FreeBSD/arm64
	GOOS=freebsd GOARCH=arm64 go build -o $(BINARY_DIR)/FreeBSD/arm64/doxx.net $(COMMON_SOURCES) tun_other.go

openbsd-amd64:
	@mkdir -p $(BINARY_DIR)/OpenBSD/amd64
	GOOS=openbsd GOARCH=amd64 go build -o $(BINARY_DIR)/OpenBSD/amd64/doxx.net $(COMMON_SOURCES) tun_other.go

openbsd-arm64:
	@mkdir -p $(BINARY_DIR)/OpenBSD/arm64
	GOOS=openbsd GOARCH=arm64 go build -o $(BINARY_DIR)/OpenBSD/arm64/doxx.net $(COMMON_SOURCES) tun_other.go

windows-amd64: get-wintun
	@echo "Building for Windows AMD64..."
	@mkdir -p $(BINARY_DIR)/Windows/amd64
	@mkdir -p assets/windows
	@cp assets/windows/wintun-amd64.dll $(BINARY_DIR)/Windows/amd64/wintun.dll
	GOOS=windows GOARCH=amd64 go build -o $(BINARY_DIR)/Windows/amd64/doxx.net.exe $(COMMON_SOURCES) $(WINDOWS_SOURCES)

windows-arm64: get-wintun
	@echo "Building for Windows ARM64..."
	@mkdir -p $(BINARY_DIR)/Windows/arm64
	@mkdir -p assets/windows
	@cp assets/windows/wintun-arm64.dll $(BINARY_DIR)/Windows/arm64/wintun.dll
	GOOS=windows GOARCH=arm64 go build -o $(BINARY_DIR)/Windows/arm64/doxx.net.exe $(COMMON_SOURCES) $(WINDOWS_SOURCES)

mac-amd64:
	@mkdir -p $(BINARY_DIR)/MacOS/amd64
	GOOS=darwin GOARCH=amd64 go build -o $(BINARY_DIR)/MacOS/amd64/doxx.net $(COMMON_SOURCES) tun_other.go

mac-arm64:
	@mkdir -p $(BINARY_DIR)/MacOS/arm64
	GOOS=darwin GOARCH=arm64 go build -o $(BINARY_DIR)/MacOS/arm64/doxx.net $(COMMON_SOURCES) tun_other.go

mac-universal: mac-amd64 mac-arm64
	@echo "Creating universal binaries for macOS..."
	@mkdir -p $(BINARY_DIR)/MacOS
	lipo -create -output $(BINARY_DIR)/MacOS/doxx.net \
		$(BINARY_DIR)/MacOS/amd64/doxx.net \
		$(BINARY_DIR)/MacOS/arm64/doxx.net
	@echo "Universal binaries created successfully"

get-wintun:
	@echo "Downloading Wintun $(WINTUN_VERSION)..."
	@echo "Download URL: $(WINTUN_URL)"
	@mkdir -p assets/windows
	@if [ ! -f "assets/windows/wintun-amd64.dll" ] || [ ! -f "assets/windows/wintun-arm64.dll" ]; then \
		echo "Downloading Wintun..." && \
		curl -L -o wintun.zip $(WINTUN_URL) && \
		echo "Verifying checksum..." && \
		$(SHA256_CHECK) && \
		echo "Extracting AMD64 version..." && \
		unzip -j wintun.zip "wintun/bin/amd64/wintun.dll" -d assets/windows/ && \
		mv assets/windows/wintun.dll assets/windows/wintun-amd64.dll && \
		echo "Extracting ARM64 version..." && \
		unzip -j wintun.zip "wintun/bin/arm64/wintun.dll" -d assets/windows/ && \
		mv assets/windows/wintun.dll assets/windows/wintun-arm64.dll && \
		rm wintun.zip && \
		echo "Verifying extracted files:" && \
		ls -l assets/windows/wintun-*.dll; \
	else \
		echo "DLL files already exist:" && \
		ls -l assets/windows/wintun-*.dll; \
	fi

doxxulator-linux-amd64:
	@mkdir -p $(BINARY_DIR)/Linux/amd64
	GOOS=linux GOARCH=amd64 go build -o $(BINARY_DIR)/Linux/amd64/doxxulator $(DOXXULATOR_SOURCE)

doxxulator-linux-arm64:
	@mkdir -p $(BINARY_DIR)/Linux/arm64
	GOOS=linux GOARCH=arm64 go build -o $(BINARY_DIR)/Linux/arm64/doxxulator $(DOXXULATOR_SOURCE)

doxxulator-freebsd-amd64:
	@mkdir -p $(BINARY_DIR)/FreeBSD/amd64
	GOOS=freebsd GOARCH=amd64 go build -o $(BINARY_DIR)/FreeBSD/amd64/doxxulator $(DOXXULATOR_SOURCE)

doxxulator-freebsd-arm64:
	@mkdir -p $(BINARY_DIR)/FreeBSD/arm64
	GOOS=freebsd GOARCH=arm64 go build -o $(BINARY_DIR)/FreeBSD/arm64/doxxulator $(DOXXULATOR_SOURCE)

doxxulator-openbsd-amd64:
	@mkdir -p $(BINARY_DIR)/OpenBSD/amd64
	GOOS=openbsd GOARCH=amd64 go build -o $(BINARY_DIR)/OpenBSD/amd64/doxxulator $(DOXXULATOR_SOURCE)

doxxulator-openbsd-arm64:
	@mkdir -p $(BINARY_DIR)/OpenBSD/arm64
	GOOS=openbsd GOARCH=arm64 go build -o $(BINARY_DIR)/OpenBSD/arm64/doxxulator $(DOXXULATOR_SOURCE)

doxxulator-windows-amd64:
	@mkdir -p $(BINARY_DIR)/Windows/amd64
	GOOS=windows GOARCH=amd64 go build -o $(BINARY_DIR)/Windows/amd64/doxxulator.exe $(DOXXULATOR_SOURCE)

doxxulator-windows-arm64:
	@mkdir -p $(BINARY_DIR)/Windows/arm64
	GOOS=windows GOARCH=arm64 go build -o $(BINARY_DIR)/Windows/arm64/doxxulator.exe $(DOXXULATOR_SOURCE)

doxxulator-mac-amd64:
	@mkdir -p $(BINARY_DIR)/MacOS/amd64
	GOOS=darwin GOARCH=amd64 go build -o $(BINARY_DIR)/MacOS/amd64/doxxulator $(DOXXULATOR_SOURCE)

doxxulator-mac-arm64:
	@mkdir -p $(BINARY_DIR)/MacOS/arm64
	GOOS=darwin GOARCH=arm64 go build -o $(BINARY_DIR)/MacOS/arm64/doxxulator $(DOXXULATOR_SOURCE)

doxxulator-mac-universal: doxxulator-mac-amd64 doxxulator-mac-arm64
	@echo "Creating universal binaries for doxxulator macOS..."
	@mkdir -p $(BINARY_DIR)/MacOS
	lipo -create -output $(BINARY_DIR)/MacOS/doxxulator \
		$(BINARY_DIR)/MacOS/amd64/doxxulator \
		$(BINARY_DIR)/MacOS/arm64/doxxulator

doxxulator-all: doxxulator-linux-amd64 doxxulator-linux-arm64 doxxulator-windows-amd64 doxxulator-windows-arm64 doxxulator-freebsd-amd64 doxxulator-freebsd-arm64 doxxulator-openbsd-amd64 doxxulator-openbsd-arm64 doxxulator-mac-amd64 doxxulator-mac-arm64 doxxulator-mac-universal

zip-all: zip-windows zip-linux zip-macos zip-freebsd zip-openbsd

zip-windows:
	@echo "Zipping Windows binaries..."
	@cd $(BINARY_DIR) && zip -r doxx.net-Windows10-11.zip Windows/

zip-linux:
	@echo "Zipping Linux binaries..."
	@cd $(BINARY_DIR) && zip -r doxx.net-Linux.zip Linux/

zip-macos:
	@echo "Zipping MacOS binaries..."
	@cd $(BINARY_DIR) && zip -r doxx.net-macOS.zip MacOS/

zip-freebsd:
	@echo "Zipping FreeBSD binaries..."
	@cd $(BINARY_DIR) && zip -r doxx.net-FreeBSD.zip FreeBSD/

zip-openbsd:
	@echo "Zipping OpenBSD binaries..."
	@cd $(BINARY_DIR) && zip -r doxx.net-OpenBSD.zip OpenBSD/
