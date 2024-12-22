# **doxx.net BETA: The Ultimate Stealth VPN and Darknet Service**

**doxx.net** is a high-performance, secure VPN and darknet service engineered for the discerning user or researcher. Leveraging multiple transport protocols—including **TCP**, **encrypted TCP**, and **HTTPS**—doxx.net ensures your traffic seamlessly blends with regular web activity, effectively bypassing restrictive firewalls and censorship.

Inspired by the ingenuity of **DarkFlare**, doxx.net incorporates advanced techniques to disguise your TCP traffic as HTTPS requests, allowing it to slip through corporate firewalls undetected.

Join us on Discord: https://discord.gg/es546Rt9
---

## **Key Features**

- **Stealthy Transports:** Camouflage your connections as standard web traffic, evading deep packet inspection and network restrictions.  
- **Automatic Routing Management:** Intelligent routing adapts to network conditions, ensuring optimal performance and reliability.  
- **IPv4 and IPv6 Support:** Comprehensive IP compatibility for seamless connectivity across diverse networks.  
- **Static IP Assignment:** Maintain consistent IP addresses for stable and predictable connections.  
- **Certificate Pinning:** Enhanced security through strict certificate validation, mitigating man-in-the-middle attacks.  
- **Cross-Platform Compatibility:** Operates smoothly on **Linux**, **macOS**, and **Windows**, catering to a wide range of user environments.  
- **Cloudflare CDN Integration:** Utilize **Cloudflare's extensive CDN infrastructure** to further obfuscate your traffic, making it indistinguishable from legitimate web requests.  

---

## 🧱 Why CDNs?
Services like Cloudflare, Akamai Technologies, Fastly, and Amazon CloudFront are not only widely accessible but also integral to the global internet infrastructure. In regions with restrictive networks, alternatives such as CDNetworks in Russia, ArvanCloud in Iran, or ChinaCache in China may serve as viable proxies. These CDNs support millions of websites across critical sectors, including government and healthcare, making them indispensable. Blocking them risks significant collateral damage, which inadvertently makes them reliable pathways for bypassing restrictions.

## ⛓️💥 Stop Network Censorship
Internet censorship is a significant issue in many countries, where governments restrict access to information by blocking websites and services. For instance, China employs the "Great Firewall" to block platforms like Facebook and Twitter, while Iran restricts access to social media and messaging apps. In Russia, authorities have intensified efforts to control information flow by blocking virtual private networks (VPNs) and other tools that citizens use to bypass censorship.

AP NEWS
 In such environments, a tool that tunnels TCP traffic over HTTP(S) through a Content Delivery Network (CDN) like Cloudflare can be invaluable. By disguising restricted traffic as regular web traffic, this method can effectively circumvent censorship measures, granting users access to blocked content and preserving the free flow of information.

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

## Quick Start

### 1. Create an Account
```bash
curl -X POST -d "create_account=your.email@example.com" https://setup.doxx.net/
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


Join us on Discord: https://discord.gg/es546Rt9
