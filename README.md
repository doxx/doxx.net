```
    _______                ___                    __   
    \____  \  ____  ___  ___  \__   ____   ____ _/  |_ 
     |  |\  \/  _ \ \  \/  /\   /  /    \ /  __\\   __\
     |  |/   ( <_> ) >    </    \ |   |  (  ___)|  |  
    /_______  \____/ /__/\_  /\__/|___|  /\____/|__|  
            \_/           \_/         \_/               

     [ Copyright (c) Barrett Lyon 2024-2025 - https://doxx.net ]
 
```

# **doxx.net (BETA): Advanced VPN, Parallel Internet, and De-Location Platform**

**doxx.net** is a comprehensive privacy and security platform that combines a high-performance VPN service with a parallel Internet that includes location managment capabilities. The platform consists of two main components:
- **doxx.net Core**: A stealth VPN and darknet service
- **API**: Creation of .doxx domains, create dns records, sign ssl certificates. 
- **Doxxulator**: Advanced location and browser emulation engine

Together, these components provide:
- Parallel Internet
- Bypassing network restrictions and censorship
- Location spoofing and geo-unblocking
- Browser fingerprint manipulation
- Secure and private communication
- Services can operate entirely within the alternative internet
- No dependence on public domain registrars
- Immune to domain seizures or DNS blocking
- Resistant to deep packet inspection and traffic analysis
- No public footprint for internal services
- Complete isolation from internet-based attacks
- Granular control over access and permissions

Currently confirmed to bypass censorship in the following countries:
- 🇨🇳 China
- 🇷🇺 Russia
- 🇮🇷 Iran
- 🇸🇦 Saudi Arabia
- 🇦🇪 United Arab Emirates

Join us on Discord: https://discord.gg/Gr9rByrEzZ
---

## **Key Features**

- **Crazy Transports:** Camouflage your connections as standard web traffic, evading deep packet inspection and network restrictions.  
- **Automatic Routing Management:** Intelligent routing adapts to network conditions, ensuring optimal performance and reliability.  
- **Static DARKNET IP Assignment:** Maintain consistent IP addresses on the darknet for stable and predictable connections. Doxx.net to the Internet egress IPs are not static.  
- **Certificate Pinning:** Enhanced security through strict certificate validation, mitigating man-in-the-middle attacks.  
- **Cross-Platform Compatibility:** Operates smoothly on **Linux**, **macOS**, and **Windows**, catering to a wide range of user environments.  
- **Cloudflare CDN Integration:** Utilize **Cloudflare's extensive CDN infrastructure** to further obfuscate your traffic, making it indistinguishable from legitimate web requests.  
---

## Quick Start

### 1. Create an Account

doxx.net doesn't use usernames or passwords. Instead, you'll receive an authentication token via email. This token is your key to the doxx.net network and is tied to your own IP address in the doxx.net network.

#### Standard Account Creation
```bash
# Using curl
curl -X POST -d "create_account=your.email@example.com" https://setup.doxx.net/

# Using wget
wget --post-data "create_account=your.email@example.com" https://setup.doxx.net/
```
#### Did not receive the email?
If you did not receive the email, please check your spam folder or join Discord for support. You can also try to request a new token seen below:

#### Reset Token
If your token is lost or compromised, you can request a new one. The new token will be valid for 15 minutes, and your old token remains valid until you use the new one.

```bash
# Using curl
curl -X POST -d "reset_token=your.email@example.com" https://setup.doxx.net/

# Using wget
wget --post-data "reset_token=your.email@example.com" https://setup.doxx.net/
```

#### Bypassing Blocked DNS Access of doxx.net
Simply copy and paste one of these commands to create your account:

```bash
# Americas Edge
curl -X POST --connect-to setup.doxx.net:443:198.41.214.162 https://setup.doxx.net/ -d "create_account=your.email@example.com"

# Europe Edge
curl -X POST --connect-to setup.doxx.net:443:198.41.215.162 https://setup.doxx.net/ -d "create_account=your.email@example.com"

# Asia Edge
curl -X POST --connect-to setup.doxx.net:443:198.41.216.162 https://setup.doxx.net/ -d "create_account=your.email@example.com"
```
**Note**: These edge IPs are stable and globally accessible. No DNS lookup required.

### 2. Install the Client

1. Download the appropriate binary for your system from the [releases page](https://github.com/doxx/doxx.net/releases).

2. Create a symbolic link based on your system architecture:

```bash
# macOS (Universal Binary amd64 and arm64)
ln -s ./bin/doxx.net-mac ./doxx.net

# Linux (AMD64 or x86_64)
ln -s ./bin/doxx.net-linux-amd64 ./doxx.net

# Windows (x86_64 or ARM64)
Depending on your OS architecture, use the following:
doxx.net-amd64.exe 
doxx.net-arm64.exe 
```

3. Make the binary executable (Unix-based systems only):
```bash
chmod +x ./doxx.net
```

Note: For Windows users, the executable can be run directly without additional setup.

### 3. Connect to VPN

Choose one of the following connection methods:

#### TCP Encrypted (Recommended)

```bash
# Unix-based systems (Linux/macOS)
sudo ./doxx.net -server tcp-encrypted.mia.us.doxx.net:443 -token YOUR_TOKEN -type tcp-encrypted

# Windows (Run Command Prompt as Administrator)
# For AMD64/x64 systems
doxx.net-amd64.exe -server tcp-encrypted.mia.us.doxx.net:443 -token YOUR_TOKEN -type tcp-encrypted
# For ARM64 systems
doxx.net-arm64.exe -server tcp-encrypted.mia.us.doxx.net:443 -token YOUR_TOKEN -type tcp-encrypted
```

#### HTTPS Mode
```bash
# Unix-based systems (Linux/macOS)
sudo ./doxx.net -server https.mia.us.doxx.net:443 -token YOUR_TOKEN -type https

# Windows (Run Command Prompt as Administrator)
# For AMD64/x64 systems
doxx.net-amd64.exe -server https.mia.us.doxx.net:443 -token YOUR_TOKEN -type https
# For ARM64 systems
doxx.net-arm64.exe -server https.mia.us.doxx.net:443 -token YOUR_TOKEN -type https
```


## Available Servers

### TCP Encrypted Servers
- tcp-encrypted.mia.us.doxx.net:443 (Miami)
- tcp-encrypted.lax.us.doxx.net:443 (Los Angeles)
- tcp-encrypted.ams.eu.doxx.net:443 (Amsterdam)

### HTTPS Servers
- https.mia.us.doxx.net:443 (Miami)
- https.lax.us.doxx.net:443 (Los Angeles)
- https.ams.eu.doxx.net:443 (Amsterdam)

### CDN-Protected Servers
- cdn.mia.us.doxx.net:443 (Miami)
- cdn.lax.us.doxx.net:443 (Los Angeles)
- cdn.ams.eu.doxx.net:443 (Amsterdam)
---

## Location Spoofing using Doxxulator

The included Doxxulator tool provides powerful location spoofing capabilities through its proxy server. Here's how to use it:

### Basic Usage

```bash
# Basic usage with preset location
./doxxulator -location tokyo

# Custom coordinates
./doxxulator -location custom -lat 35.6762 -lon 139.6503
```

### Installing your certificates to your OS or browser

#### Certificate Generation
Doxxulator automatically generates and stores two files in your home directory under `.doxx.net`:
- `~/.doxx.net/doxxulator-ca.crt` - The certificate file
- `~/.doxx.net/doxxulator-ca.key` - The private key file

### Available Preset Locations

🗽 New York • 🇬🇧 London • 🗼 Tokyo • 🗼 Paris • 🇸🇬 Singapore • 🇦🇪 Dubai • 🇭🇰 Hong Kong • 🇨🇳 Shanghai • 
🇦🇺 Sydney • 🌴 Miami • 🌆 Chicago • 🇷🇺 Moscow • 🇩🇪 Berlin • 🇮🇳 Mumbai • 🇧🇷 São Paulo • 🇹🇷 Istanbul • 
🇮🇹 Rome • 🇰🇷 Seoul • 🇲🇽 Mexico City • 🇳🇱 Amsterdam • 🇨🇦 Toronto • 🌴 Los Angeles • 🇪🇸 Madrid • 
🇦🇹 Vienna • 🇹🇭 Bangkok • 🇨🇳 Beijing

### Browser Configuration

1. **Configure Your Browser**
   - Set proxy to `127.0.0.1:8080` (default)
   - For Chrome: Settings → Advanced → System → Proxy settings
   - For Firefox: Settings → Network Settings → Manual proxy configuration

2. **Choose Browser Profile**
```bash
# Emulate different browsers
./doxxulator -browser chrome    # Default
./doxxulator -browser firefox
./doxxulator -browser safari
./doxxulator -browser edge
```

### Advanced Features

1. **Certificate Management**
```bash
# Generate new certificates (optional - certificates are auto-generated if not present)
./doxxulator

# Enable certificate passthrough for apps with SSL pinning
./doxxulator -allow-passthrough -location london
```

2. **Debug Mode**
```bash
# Enable detailed logging
./doxxulator -log -location paris
```
---

# Setup API Reference

## https://setup.doxx.net/
This is the API backend for managing user accounts, domains, DNS records, and certificate signing for the `doxx.net` platform. 

## Authentication
All API endpoints (except account creation and token reset) require a valid authentication token passed via the `token` parameter.

## Endpoints

### Create Account
Creates a new doxx.net account and assigns a unique IP address.

```bash
curl -X POST https://setup.doxx.net/ -d "create_account=your.email@example.com"
```

### Reset Token
Generate a new authentication token. The old token remains valid until the new one is used.

```bash
curl -X POST https://setup.doxx.net/ -d "reset_token=your.email@example.com"
```

### Create Domain
Register a new .doxx domain and set up default DNS records.

```bash
curl -X POST https://setup.doxx.net/ -d "token=YOUR_TOKEN" -d "domain=example.doxx" -d "create_domain=1"
```

### Create DNS Record
Add a new DNS record to an existing domain.

```bash
# Add A Record
curl -X POST https://setup.doxx.net/ -d "token=YOUR_TOKEN" -d "domain=example.doxx" -d "name=subdomain.example.doxx" -d "type=A" -d "content=192.0.2.1" -d "create_dns_record=1"

# Add MX Record
curl -X POST https://setup.doxx.net/ -d "token=YOUR_TOKEN" -d "domain=example.doxx" -d "name=example.doxx" -d "type=MX" -d "content=mail.example.doxx." -d "prio=10" -d "create_dns_record=1"
```

Supported record types:
- `A`: IPv4 address
- `CNAME`: Canonical name
- `MX`: Mail exchange
- `TXT`: Text record

### Delete Domain
Remove a domain and all its associated DNS records.

```bash
curl -X POST https://setup.doxx.net/ -d "token=YOUR_TOKEN" -d "domain=example.doxx" -d "delete_domain=1"
```

### Delete DNS Record
Remove a specific DNS record from a domain.

```bash
curl -X POST https://setup.doxx.net/ -d "token=YOUR_TOKEN" -d "domain=example.doxx" -d "name=subdomain.example.doxx" -d "type=A" -d "content=192.0.2.1" -d "delete_dns_record=1"
```

### Sign Certificate
Sign a Certificate Signing Request (CSR) for your domain.

```bash
curl -X POST https://setup.doxx.net/ -d "token=YOUR_TOKEN" -d "domain=example.doxx" -d "csr=%CERT_CONTENT%" -d "sign_certificate=1"
```

Note: For the certificate signing, replace %CERT_CONTENT% with the actual CSR content after removing newlines.

---

## Certificate Management Guide

### 1. Generate a Private Key
First, register a domain and generate a private key for your domain:

```bash
# Generate a 2048-bit RSA private key
openssl genrsa -out domain.key 2048

# Or for better security, generate a 4096-bit key
openssl genrsa -out domain.key 4096
```

### 2. Create a Certificate Signing Request (CSR)
Generate a CSR using your private key:

```bash
# Basic CSR
openssl req -new -key domain.key -out domain.csr

# Or non-interactive with predefined details
openssl req -new -key domain.key -out domain.csr \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=example.doxx"
```

### 3. Sign the Certificate
Submit your CSR to the doxx.net API:

```bash
# Sign the certificate
curl -X POST https://setup.doxx.net/ \
    -d "token=YOUR_TOKEN" \
    -d "domain=example.doxx" \
    -d "csr=$(cat domain.csr | tr -d '\n')" \
    -d "sign_certificate=1" \
    > domain.crt

# Verify the certificate
openssl x509 -in domain.crt -text -noout
```

### 4. Create Full Chain (Optional)
If you need to combine your certificate with intermediates:

```bash
# Combine certificate with intermediate certificates
cat domain.crt intermediate.crt > fullchain.crt
```

### Complete Example
Here's a full script that handles the entire process:

```bash
#!/bin/bash

# Configuration
DOMAIN="example.doxx"
TOKEN="YOUR_TOKEN"

# 1. Generate private key
openssl genrsa -out "${DOMAIN}.key" 2048

# 2. Create CSR
openssl req -new -key "${DOMAIN}.key" -out "${DOMAIN}.csr" \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=${DOMAIN}"

# 3. Submit CSR and get certificate
curl -X POST https://setup.doxx.net/ \
    -d "token=${TOKEN}" \
    -d "domain=${DOMAIN}" \
    -d "csr=$(cat ${DOMAIN}.csr | tr -d '\n')" \
    -d "sign_certificate=1" \
    > "${DOMAIN}.crt"

# 4. Verify certificate
openssl x509 -in "${DOMAIN}.crt" -text -noout

echo "Certificate generation complete for ${DOMAIN}"
```

### Security Best Practices
- Keep your private key secure and never share it
- Use at least 2048-bit RSA keys (4096-bit recommended)
- Store certificates and keys with appropriate permissions:
  ```bash
  chmod 600 domain.key
  chmod 644 domain.crt
  ```
- Regularly rotate certificates (recommended every 90 days)
- Back up your private keys securely

---

## 🌐 **Understanding the Parallel Internet**

A parallel internet represents a revolutionary approach to network infrastructure - one that operates alongside the traditional internet rather than within it. Unlike the conventional internet or darknets, which operate within existing infrastructure, a parallel internet creates its own complete ecosystem with independent DNS systems, private IP addressing, and custom domain resolution.

At its core, this parallel infrastructure provides a foundation for truly independent digital operations. When you connect to this network, you're not just encrypting your traffic or hiding your identity - you're stepping into an entirely separate digital environment. This environment comes with its own domain system, certificate authorities, and routing protocols, all operating independently of traditional internet governance structures.

The mesh networking capability means that users can automatically find the optimal path into the doxx.net network and it will automatically manage the internal routing to ensure everything "just works."

The advantages of this approach are substantial. Organizations can operate services completely isolated from internet-based attacks while maintaining full control over their digital resources. There's no dependence on public domain registrars, no vulnerability to domain seizures, and no exposure to traditional DNS-based attacks. Every aspect of the network, from IP assignment to certificate management, operates within this controlled environment.

This architecture also delivers practical benefits for day-to-day operations. Users enjoy direct peer-to-peer connections, 

The system maintains a consistent addressing scheme, making it easier to manage resources across different locations or departments. When needed, bridges to the public internet can be established.

Think of it as building a new city rather than renting space in an existing one. In this new city, you control the infrastructure, set the rules, and determine how resources are allocated. The roads (connections) can dynamically reshape themselves to ensure the fastest route, while your address (IP) remains constant regardless of which road you use. This level of control, independence, and flexibility makes it ideal for people that need guaranteed access to their services, regardless of external internet conditions or restrictions.

## 🧱 What role does a CDN play?
Services like Cloudflare, Akamai Technologies, Fastly, and Amazon CloudFront are not only widely accessible but also integral to the global internet infrastructure. In regions with restrictive networks, alternatives such as CDNetworks in Russia, ArvanCloud in Iran, or ChinaCache in China may serve as viable proxies. These CDNs support millions of websites across critical sectors, including government and healthcare, making them indispensable. Blocking them risks significant collateral damage, which inadvertently makes them reliable pathways for bypassing restrictions.

## ⛓️💥 Stop Network Censorship
Internet censorship is a significant issue in many countries, where governments restrict access to information by blocking websites and services. For instance, China employs the "Great Firewall" to block platforms like Facebook and Twitter, while Iran restricts access to social media and messaging apps. In Russia, authorities have intensified efforts to control information flow by blocking virtual private networks (VPNs) and other tools that citizens use to bypass censorship.

AP NEWS
 In such environments, a tool that tunnels TCP traffic over HTTP(S) through a Content Delivery Network (CDN) like Cloudflare can be invaluable. By disguising restricted traffic as regular web traffic, this method can effectively circumvent censorship measures, granting users access to blocked content and preserving the free flow of information.

---

## Understanding Routing

### Default Routing Behavior
By default, doxx.net manages all your internet traffic through its VPN tunnel. This means:
- All your outbound connections are routed through the VPN
- You get a new virtual IP address (10.x.x.x)
- Your original internet connection becomes a backup route

### doxx.net vpn client with -no-routing
The `-no-routing` flag gives you manual control over what traffic goes through doxx.net. This is useful when you want to:

1. **Split Tunneling**: Route only specific traffic through the VPN
2. **Selective Privacy**: Choose which applications use the VPN
3. **Performance Optimization**: Keep latency-sensitive applications on your direct connection

#### Example: Manual Route Configuration
```bash
# Start doxx.net without automatic routing
./doxx.net -token YOUR_TOKEN -server cdn.mia.us.doxx.net:443 -type https -no-routing

# Route specific IP ranges through the VPN
ip route add 192.168.1.0/24 via 10.1.0.100  # Route internal network
ip route add 172.16.0.0/12 via 10.1.0.100   # Route private subnet

# For Windows users:
route ADD 192.168.1.0 MASK 255.255.255.0 10.1.0.100
```

### Common Routing Scenarios

1. **Access Internal Networks**
   ```bash
   # Route traffic to a corporate network
   ip route add 10.0.0.0/8 via 10.1.0.100
   ```

2. **Geographic Service Access**
   ```bash
   # Route specific website/service
   ip route add 104.16.0.0/12 via 10.1.0.100
   ```

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

**4. Server and -type missmatch:**  
- For https and cdn you must use -type https and for tcp-encrypted servers use -type tcp-encrypted.


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
---

## License

This software is provided under a dual license:
1. MIT License with Commons Clause
2. Commercial License (contact for details)

The Commons Clause restricts using the software to provide commercial hosted services without a separate agreement.

### Third-Party Licenses

This software includes the following third-party open source software:

- github.com/songgao/water: BSD-3-Clause License
- github.com/klauspost/compress: BSD-3-Clause License
- github.com/jackpal/gateway: BSD-3-Clause License
- github.com/gdamore/tcell/v2: Apache-2.0 License
- github.com/rivo/tview: MIT License
- github.com/shirou/gopsutil/v3: BSD-3-Clause License
- github.com/go-ole/go-ole: MIT License
- github.com/power-devops/perfstat: MIT License
- github.com/yusufpapurcu/wmi: MIT License
- golang.org/x/sys: BSD-3-Clause License
- golang.org/x/net: BSD-3-Clause License
- golang.org/x/term: BSD-3-Clause License
- golang.org/x/text: BSD-3-Clause License
- golang.zx2c4.com/wintun: MIT License
- github.com/stretchr/testify: MIT License

The full text of these licenses can be found in the respective repositories:

- BSD-3-Clause License: https://opensource.org/licenses/BSD-3-Clause
- MIT License: https://opensource.org/licenses/MIT
- Apache-2.0 License: https://opensource.org/licenses/Apache-2.0

All third-party software components are distributed under their respective licenses. The full text of these licenses and their requirements must be included with any distribution of this software.


Join us on Discord: https://discord.gg/Gr9rByrEzZ