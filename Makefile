BINARY_DIR=bin

.PHONY: all clean

all: clean linux-amd64 linux-arm64 windows-amd64 mac-universal

clean:
	rm -rf $(BINARY_DIR)
	mkdir -p $(BINARY_DIR)

linux-amd64:
	GOOS=linux GOARCH=amd64 go build -o $(BINARY_DIR)/doxx.net-linux-amd64 doxx.net.go

linux-arm64:
	GOOS=linux GOARCH=arm64 go build -o $(BINARY_DIR)/doxx.net-linux-arm64 doxx.net.go

windows-amd64:
	GOOS=windows GOARCH=amd64 go build -o $(BINARY_DIR)/doxx.net.exe doxx.net.go

mac-universal:
	GOOS=darwin GOARCH=amd64 go build -o $(BINARY_DIR)/doxx.net-darwin-amd64 doxx.net.go
	GOOS=darwin GOARCH=arm64 go build -o $(BINARY_DIR)/doxx.net-darwin-arm64 doxx.net.go
	lipo -create -output $(BINARY_DIR)/doxx.net-mac \
		$(BINARY_DIR)/doxx.net-darwin-amd64 \
		$(BINARY_DIR)/doxx.net-darwin-arm64
	rm $(BINARY_DIR)/doxx.net-darwin-amd64 $(BINARY_DIR)/doxx.net-darwin-arm64
