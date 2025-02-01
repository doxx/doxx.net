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

.PHONY: all clean install get-wintun

all: clean linux-amd64 linux-arm64 windows-amd64 windows-arm64 $(MAC_BUILD) doxxulator-all doxxulator-mac-universal

clean:
	rm -rf $(BINARY_DIR)
	mkdir -p $(BINARY_DIR)

linux-amd64:
	GOOS=linux GOARCH=amd64 go build -o $(BINARY_DIR)/doxx.net-linux-amd64 $(COMMON_SOURCES) tun_other.go

linux-arm64:
	GOOS=linux GOARCH=arm64 go build -o $(BINARY_DIR)/doxx.net-linux-arm64 $(COMMON_SOURCES) tun_other.go

windows-amd64: get-wintun
	@echo "Building for Windows AMD64..."
	@mkdir -p $(BINARY_DIR)
	@mkdir -p assets/windows
	@cp assets/windows/wintun-amd64.dll assets/windows/wintun.dll
	GOOS=windows GOARCH=amd64 go build -o $(BINARY_DIR)/doxx.net-amd64.exe $(COMMON_SOURCES) $(WINDOWS_SOURCES)

windows-arm64: get-wintun
	@echo "Building for Windows ARM64..."
	@mkdir -p $(BINARY_DIR)
	@mkdir -p assets/windows
	@cp assets/windows/wintun-arm64.dll assets/windows/wintun.dll
	GOOS=windows GOARCH=arm64 go build -o $(BINARY_DIR)/doxx.net-arm64.exe $(COMMON_SOURCES) $(WINDOWS_SOURCES)

mac-amd64:
	GOOS=darwin GOARCH=amd64 go build -o $(BINARY_DIR)/doxx.net-darwin-amd64 $(COMMON_SOURCES) tun_other.go

mac-arm64:
	GOOS=darwin GOARCH=arm64 go build -o $(BINARY_DIR)/doxx.net-darwin-arm64 $(COMMON_SOURCES) tun_other.go

mac-universal: mac-amd64 mac-arm64
	@echo "Creating universal binaries for macOS..."
	@mkdir -p $(BINARY_DIR)
	lipo -create -output $(BINARY_DIR)/doxx.net-mac \
		$(BINARY_DIR)/doxx.net-darwin-amd64 \
		$(BINARY_DIR)/doxx.net-darwin-arm64
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
	GOOS=linux GOARCH=amd64 go build -o $(BINARY_DIR)/doxxulator-linux-amd64 $(DOXXULATOR_SOURCE)

doxxulator-linux-arm64:
	GOOS=linux GOARCH=arm64 go build -o $(BINARY_DIR)/doxxulator-linux-arm64 $(DOXXULATOR_SOURCE)

doxxulator-windows-amd64:
	GOOS=windows GOARCH=amd64 go build -o $(BINARY_DIR)/doxxulator-amd64.exe $(DOXXULATOR_SOURCE)

doxxulator-windows-arm64:
	GOOS=windows GOARCH=arm64 go build -o $(BINARY_DIR)/doxxulator-arm64.exe $(DOXXULATOR_SOURCE)

doxxulator-mac-amd64:
	GOOS=darwin GOARCH=amd64 go build -o $(BINARY_DIR)/doxxulator-darwin-amd64 $(DOXXULATOR_SOURCE)

doxxulator-mac-arm64:
	GOOS=darwin GOARCH=arm64 go build -o $(BINARY_DIR)/doxxulator-darwin-arm64 $(DOXXULATOR_SOURCE)

doxxulator-mac-universal: doxxulator-mac-amd64 doxxulator-mac-arm64
	@echo "Creating universal binaries for doxxulator macOS..."
	lipo -create -output $(BINARY_DIR)/doxxulator-mac \
		$(BINARY_DIR)/doxxulator-darwin-amd64 \
		$(BINARY_DIR)/doxxulator-darwin-arm64

doxxulator-all: doxxulator-linux-amd64 doxxulator-linux-arm64 doxxulator-windows-amd64 doxxulator-windows-arm64 $(MAC_BUILD)
