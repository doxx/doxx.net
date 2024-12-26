BINARY_DIR=bin

.PHONY: all clean

all: clean linux-amd64 linux-arm64 windows-amd64 mac-amd64 mac-arm64

clean:
	rm -rf $(BINARY_DIR)
	mkdir -p $(BINARY_DIR)

linux-amd64:
	GOOS=linux GOARCH=amd64 go build -o $(BINARY_DIR)/doxx.net-linux-amd64 doxx.net.go

linux-arm64:
	GOOS=linux GOARCH=arm64 go build -o $(BINARY_DIR)/doxx.net-linux-arm64 doxx.net.go

windows-amd64:
	GOOS=windows GOARCH=amd64 go build -o $(BINARY_DIR)/doxx.net.exe doxx.net.go

mac-amd64:
	GOOS=darwin GOARCH=amd64 go build -o $(BINARY_DIR)/doxx.net-darwin-amd64 doxx.net.go

mac-arm64:
	GOOS=darwin GOARCH=arm64 go build -o $(BINARY_DIR)/doxx.net-darwin-arm64 doxx.net.go
