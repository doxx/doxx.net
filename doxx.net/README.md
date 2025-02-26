---
title: "doxx.net"
weight: 1
menu:
  main:
    parent: "VPN Clients"
---

## Overview
doxx.net is a secure networking client designed for privacy-conscious users. The client provides encrypted VPN connectivity with advanced features including DNS protection, safe bandwidth monitoring, and TCP and HTTPS based transports for stealthy connectivity. 

doxx.net client was designed to be used with the a0x13.doxx.net "Advanced User Installation" options. The general design is to make your network traffic look normal and blend in with regulard web browsing. 

doxx.net is still in beta and has yet to have devleoper certificate siging on Apple and Windows but is available for download and use.

## Features

### 1. Transport Types
- **TCP-Encrypted**: Default secure transport protocol over TCP
- **HTTPS**: Alternative secure transport option over TCP
- **HTTPS over CDN**: Alternative secure transport option over TCP
- Auto-detection of transport type from hostname format: `type.location.countrycode.doxx.net`

### 2. DNS Protection
- Built-in DNS blocking capability
- Uses hagezi/dns-blocklists for threat protection
- Automatic daily updates of blocklists
- DNS NAT table for query tracking and management
- Default anycasted secured DNS server: 10.10.10.10
- Defense against DNS tunneling attacks due to compromise

### 3. Alternative Internet 
- Root CA certificate management for .doxx gTLD domains
- Platform-specific certificate installation:
  - **macOS**: System keychain and curl integration
  - **Linux**: System certificates and hash links
  - **Windows**: Certificate store integration
- Automatic DNS resolver configuration
- Secure routing management

## Command Line Options
Command line options are overwritten by a0x13.doxx.net "Advanced User Installation" options automaticaly. 

With proper a0x13.doxx.net tunnel configuration, the doxx.net client will configure automaticly.

See [docs.doxx.net/advanced-features/](https://docs.doxx.net/advanced-features/) for more information on the a0x13.doxx.net "Advanced User Installation" options.

Pro tip: The olny required options are -token and -server.

```
doxx.net [options]
  -server         VPN node address (host:port)
  -token          Authentication token (toekn created for the tunnel not to be confused with the a0x13.doxx.net account token)
  -type           Transport type (tcp-encrypted or https) (soon to be deprecated)
  -no-routing     Disable automatic routing. This will not remove or change the default route. Mostly used for hosting services and P2P mesh connections.
  -kill           Remove default route instead of saving it on disconnect (kill switch)
  -proxy          Proxy URL (e.g., http://user:pass@host:port)
  -keep-established-ssh  Maintain existing SSH connections during connection
  -no-snarf-dns   Disable DNS traffic snarfing (DNS is redirected to the doxx.net DNS server)
  -no-bandwidth   Disable bandwidth statistics output to terminal
  -block-bad-dns  Block bad DNS t:graffic using the hagezi/dns-blocklists
  -debug          Enable debug logging to stdout
```

## Platform-Specific Features
For the .doxx gTLD domains, the doxx.net client will automatically manage the root CA certificate. This does not impact any other portions of the PKI stack. 

### macOS
Due to strange behavior by Apple's mDNSResponder there are a few issues to kickstart the .doxx gTLD.
- Automatic .doxx resolver configuration in `/etc/resolver/doxx`
- System keychain integration
- Curl certificate bundle management
- mDNSResponder cache management

### Linux
- Multiple certificate store locations:
  - `/usr/local/share/ca-certificates/doxx-root-ca.crt`
  - `/etc/ssl/certs/doxx-root-ca.pem`
  - `/etc/ssl/certs/doxx-root-ca.crt`
- Automatic CA hash link creation
- Package dependency handling (ca-certificates)

### Windows 10/11
- Windows certificate store integration
- Route table management
- Default gateway handling

## Network Management

### Route Management
- Automatic default gateway detection
- Interface tracking
- Clean route restoration on exit
- No-routing option available (used for hosting services and P2P mesh connections)

## Security Considerations

### Certificate Management
- Automatic Root CA installation
- Trust store integration
- Certificate validation
- Secure certificate storage

### DNS Security
- DNS query protection
- Query ID tracking
- NAT table management
- Automatic cleanup of stale entries

## Error Handling
- Automatic retry mechanisms
- Graceful cleanup on exit
- Signal handling (SIGINT, SIGTERM)

## Installation Guide

### Download and Setup

1. Download the appropriate binary from the [releases page](https://github.com/doxx/doxx.net/releases).

2. (Not required) Create a symbolic link based on your system:

``` bash
# macOS (Universal Binary amd64 and arm64)
ln -s ./bin/doxx.net-mac ./doxx.net

# Linux (AMD64 or x86_64)
ln -s ./bin/doxx.net-linux-amd64 ./doxx.net

# Windows (x86_64 or ARM64)
# Use appropriate version:
doxx.net-amd64.exe 
doxx.net-arm64.exe 
```

3. For Unix-based systems, make the binary executable:
``` bash
chmod +x ./doxx.net
```

### Connection Guide

Choose your preferred connection method:

#### TCP Encrypted (Recommended)
``` bash
# Unix-based systems (Linux/macOS)
sudo ./doxx.net -server tcp-encrypted.mia.us.doxx.net:443 -token YOUR_TUNNEL_TOKEN 

# Windows (Run as Administrator)
doxx.net-amd64.exe -server tcp-encrypted.mia.us.doxx.net:443 -token YOUR_TUNNEL_TOKEN 
```

#### HTTPS Mode
``` bash
# Unix-based systems (Linux/macOS)
sudo ./doxx.net -server https.mia.us.doxx.net:443 -token YOUR_TUNNEL_TOKEN 

# Windows (Run as Administrator)
doxx.net-amd64.exe -server https.mia.us.doxx.net:443 -token YOUR_TUNNEL_TOKEN 
```

## Server Locations

doxx.net provides a growing number of global servers available to connect to the doxx.net internal network or to use as exit nodes for the VPN. 

For a complete and up-to-date list of available servers, please visit [docs.doxx.net/servers/](https://docs.doxx.net/servers/)

## Security Model via Cloudflare CDN

```
                                FIREWALL/CENSORSHIP
                                |     |     |     |
                                v     v     v     v

[Client]──────┐                ┌──────────────────┐                ┌─────────[Target Service]
              │                │                  │                │       (e.g., HTTPs)
              │                │   CLOUDFLARE     │                │
              │tcp             │     NETWORK      │                │
[doxx.net     │                │                  │                │ [doxx.net server]
 client]──────┼───HTTPS───────>│ (looks like      │─-HTTPS-───────>│      | 
  |           │                │  normal traffic) │                │      \/ 
  \/          │     vpn        │                  │     vpn        │   VPN interface
 VPN          └────────────────┼──────────────────┼────────────────┘   doxx.net darknet
Interface                      │                  │
                               └──────────────────┘

Flow:
1. HTTPS traffic ──> doxx.net client
2. Wrapped as HTTPS ──> Cloudflare CDN (or any CDN)
3. Forwarded to ──> doxx.net server services
4. Unwrapped back to VPN
```

The cat found a way under the red velvet rope. 0x1F4A1 still flickers in the dark.

## 🧩 **Common Issues and Solutions**

**1. Connection Drops During SSH Sessions:**  
- Use the `-keep-established-ssh` flag to maintain active SSH connections.

**2. Routing Issues:**  
- Use `-no-routing` to manually control traffic routing:
```bash
./doxx.net -token YOUR_TOKEN -server cdn.mia.us.doxx.net:443 -type https -no-routing
ip route add x.x.x.x via 10.1.0.100
```

**3. Slow Speeds with CDN:**  
- Direct connections (`tcp-encrypted`) are often faster than using CDN.

## License
doxx.net is licensed under the MIT License no warranty is provided, use at your own risk.

## Code of Conduct
This software is for educational purposes only. Do not use it to break the law.

