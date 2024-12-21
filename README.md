# doxx.net VPN Server and Darknet

A high-performance, secure VPN service with multiple transport protocols and automatic routing management.

## Features

- Multiple transport protocols:
  - TCP (Basic unencrypted transport)
  - TCP-Encrypted (TLS-secured transport)
  - HTTPS (Web traffic camouflage with compression)
- Automatic routing management
- Automatic darknet via doxx.net
- IPv4 and IPv6 support
- Static IP assignment
- Certificate pinning for enhanced security
- Cloudflare CDN support
- Cross-platform support (Linux, macOS, Windows)

## Quick Start

### 1. Create an Account
```bash
curl -X POST https://setup.doxx.net/?create_account=your_email_address@domain.com
```

You'll receive a verification email containing your authentication token.

### 2. Install the Client

Download the appropriate binary for your system:

bash

For macOS ARM64 (M1/M2)

ln -s ./bin/doxx.net-darwin-arm64 ./doxx.net

For macOS Intel

ln -s ./bin/doxx.net-darwin-amd64 ./doxx.net

For Linux AMD64

ln -s ./bin/doxx.net-linux-amd64 ./doxx.net

For Windows, use the appropriate .exe file


### 3. Connect to VPN

Choose one of the following connection methods:

#### TCP Encrypted (Recommended)

bash
sudo ./doxx.net -server tcp-encrypted.miami.us.doxx.net:443 -token YOUR_TOKEN -type tcp-encrypted

#### HTTPS Mode
sudo ./doxx.net -server https.miami.us.doxx.net:443 -token YOUR_TOKEN -type https


## Available Servers

### TCP Encrypted Servers
- tcp-encrypted.mia.us.doxx.net:443 (Miami)
- tcp-encrypted.lax.us.doxx.net:443 (Los Angeles)

### HTTPS Servers
- https.mia.us.doxx.net:443 (Miami)
- https.lax.us.doxx.net:443 (Los Angeles)

### CDN-Protected Servers
- cdn.mia.us.doxx.net:443 (Miami)
- cdn.lax.us.doxx.net:443 (Los Angeles)

## Advanced Configuration

### Transport Types
- `tcp`: Basic TCP transport (NO ENCRYPTION)
- `tcp-encrypted`: Encrypted TCP with TLS
- `https`: HTTPS transport with compression

### Command Line Flags
- `-server`: VPN server address (required)
- `-token`: Authentication token (required)
- `-type`: Transport type (default: tcp)
- `-debug`: Enable debug logging
- `-no-routing`: Disable automatic routing
- `-kill`: Kill default route instead of saving it
- `-cert`: Path to certificate file (for encrypted transport)
- `-key`: Path to private key file (for encrypted transport)

## Technical Details

### Security Features

1. Certificate Pinning
   - First-time connection stores server certificate fingerprint
   - Subsequent connections verify against stored fingerprint
   - Protection against MITM attacks

2. Transport Security
   - TLS 1.2+ for encrypted connections
   - Custom packet framing
   - Optional compression for HTTPS transport

### Network Features

1. Packet Processing
   - 4-byte header for packet framing
   - MTU size validation
   - Special handling for latency-sensitive packets
   - IPv4 and IPv6 support

2. IP Management
   - Automatic IP address calculation
   - Static IP assignment
   - Prefix length determination
   - Automatic route management

## Building from Source

### Prerequisites

- Go 1.23.3 or later
- Required packages:
  ```bash
  go get github.com/songgao/water
  go get github.com/klauspost/compress
  go get golang.org/x/sys
  ```

### Build Commands
bash
Build for all platforms
make all
Build for specific platform
make linux-amd64
make mac-arm64
make windows-amd64

## License

This software is provided under a dual license:
1. MIT License with Commons Clause
2. Commercial License (contact for details)

The Commons Clause restricts using the software to provide commercial hosted services without a separate agreement.
