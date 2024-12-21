Welcome to doxx.net VPN and darknet.

To create an account:

curl -X https://setup.doxx.net/?create_account=your_email_address@domain.com

This will create an account and send you a verification email.

Your account will be verified once you use your auth token to connect to the VPN.

How to connect to the VPN:

Figure out your operating system and make a symlink to the correct binary:

ln -s ./bin/doxx.net-darwin-arm64 ./doxx.net

Start doxx.net

TCP Encrypted mode: 
sudo ./bin/doxx.net -server tcp-encrypted.miami.us.doxx.net:443 -token token-from-email -type tcp-encrypted

HTTPS mode:
sudo ./bin/doxx.net -server https.miami.us.doxx.net:443 -token token-from-email -type https

That's it... you're connected to the VPN.

Note: Your IP address on the doxx.net will be static and is tied to your token.

Operating VPN servers:


tcp-encrypted.mia.us.doxx.net:443

tcp-encrypted.lax.us.doxx.net:443


https.lax.us.doxx.net:443

https.mia.us.doxx.net:443


cdn.lax.us.doxx.net:443

cdn.mia.us.doxx.net:443


Transport types:
- `tcp`: Basic TCP transport (NO ENCRYPTION)
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
