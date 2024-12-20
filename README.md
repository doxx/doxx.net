
Transport types:
- `tcp`: Basic TCP transport
- `tcp-encrypted`: Encrypted TCP with TLS
- `https`: HTTPS transport with compression

Additional flags:
- `-debug`: Enable debug logging
- `-no-routing`: Disable automatic routing
- `-kill`: Kill default route instead of saving it
- `-cert`: Path to certificate file (for encrypted transport)
- `-key`: Path to private key file (for encrypted transport)

## Technical Details

### Packet Processing

- 4-byte header for packet framing
- MTU size validation
- Special handling for latency-sensitive packets (ICMP)
- Support for both IPv4 and IPv6 protocols

### IP Management

- Automatic IP address calculation from CIDR ranges
- Server/client IP assignment
- Prefix length determination

## License

This software is provided under a dual license:
1. MIT License with Commons Clause
2. Commercial License (contact for details)

The Commons Clause restricts using the software to provide commercial hosted services without a separate agreement.

## Requirements

- Go 1.23.3 or later
- Required packages:
  - github.com/songgao/water
  - github.com/klauspost/compress
  - golang.org/x/sys