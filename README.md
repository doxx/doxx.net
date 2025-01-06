```
    _______                       __       __       __   
    \____  \  ____  ____ ___ ___ / /  ____/ /____ _/  |_ 
     |  |\  \/  _ \ \  \/  //\  / /  /    \ /  __\\   __\
     |  |/   ( <_> ) >    </ /   \  |      (   >_ |  |  
    /_______  \____/ /__/\__\ /\__\/_ /\___/|_____|__|  
            \/            \/                      
                        
     [ Copyright (c) Barrett Lyon 2024 - https://doxx.net ]
 
```

# **doxx.net (BETA): The Ultimate Stealth VPN and Darknet Service**

**doxx.net** is a high-performance, secure VPN and darknet service engineered for the discerning user or researcher. Leveraging multiple transport protocols—including **TCP**, **encrypted TCP**, and **HTTPS**—doxx.net ensures your traffic seamlessly blends with regular web activity, effectively bypassing restrictive firewalls and censorship.

Inspired by the ingenuity of **DarkFlare**, doxx.net incorporates advanced techniques to camouflage your IP traffic as HTTPS requests, allowing it to slip through corporate firewalls undetected.

Currently confirmed to bypass censorship in the following countries:
- 🇨🇳 China
- 🇷🇺 Russia
- 🇮🇷 Iran
- 🇸🇦 Saudi Arabia
- 🇦🇪 United Arab Emirates

Join us on Discord: https://discord.gg/es546Rt9
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

1. Download the appropriate binary for your system from the [releases page](https://github.com/yourusername/doxx.net/releases).

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

### Windows Setup
**Important**: Always run doxx.net with Administrator privileges:
   - Right-click on Command Prompt or PowerShell
   - Select "Run as administrator"
   - Navigate to the doxx.net directory
   - Run your doxx.net commands

Note: If you see "Access Denied" errors on Windows, this usually means you need to run the command prompt as Administrator.


### 3. Connect to VPN

Choose one of the following connection methods:

#### TCP Encrypted (Recommended)

```bash
sudo ./doxx.net -server tcp-encrypted.miami.us.doxx.net:443 -token YOUR_TOKEN -type tcp-encrypted
```

#### HTTPS Mode
```bash
sudo ./doxx.net -server https.miami.us.doxx.net:443 -token YOUR_TOKEN -type https
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

## 🛡️ **What is the Darknet?**
- The **Darknet** refers to a part of the internet not indexed by traditional search engines (like Google). It relies on **encrypted networks** to enable private communication and anonymous data sharing.
- It’s often misunderstood as being purely for illegal activities. In reality, it plays a **critical role in privacy, whistleblowing, bypassing censorship, and ensuring secure communication** in restrictive regions.

### **Why is the Darknet Important?**
- **Freedom of Speech:** Allows individuals to share information without fear of government persecution.
- **Bypassing Censorship:** Access information in countries with restricted internet.
- **Privacy Protection:** Securely communicate and share data without tracking.

---

## 🌐 **What is doxx.net?**
doxx.net is **a VPN-based darknet network designed to pierce through firewalls, avoid detection, and provide a new layer of internet freedom**. Think of it as a **virtual second internet** that operates on top of the traditional web.

### **Key Features of doxx.net:**
1. **Firewall Piercing:** Works even in heavily restricted internet environments.
2. **Static Virtual IP (10.x.x.x):** Every user gets a **unique static IP address** within the doxx network.
3. **Peer-to-Peer Communication:** Communicate securely with others on the doxx network without routing through public internet.
4. **Decentralized Potential:** Plans to become a **fully federated VPN-mesh network** where every client can also act as a server.
5. **Encrypted Traffic:** All traffic is encrypted, making it harder to intercept or monitor.
6. **Alternative Infrastructure:** Offers free `.doxx` domain names and SSL certificates.

**Metaphor:** Imagine trying to send a package (data) in a country where postal services are heavily monitored. doxx.net lets you send that package using **birds (alternative secure routes)** instead of traditional postal trucks.

## 🧱 What role does a CDN play?
Services like Cloudflare, Akamai Technologies, Fastly, and Amazon CloudFront are not only widely accessible but also integral to the global internet infrastructure. In regions with restrictive networks, alternatives such as CDNetworks in Russia, ArvanCloud in Iran, or ChinaCache in China may serve as viable proxies. These CDNs support millions of websites across critical sectors, including government and healthcare, making them indispensable. Blocking them risks significant collateral damage, which inadvertently makes them reliable pathways for bypassing restrictions.

## ⛓️💥 Stop Network Censorship
Internet censorship is a significant issue in many countries, where governments restrict access to information by blocking websites and services. For instance, China employs the "Great Firewall" to block platforms like Facebook and Twitter, while Iran restricts access to social media and messaging apps. In Russia, authorities have intensified efforts to control information flow by blocking virtual private networks (VPNs) and other tools that citizens use to bypass censorship.

AP NEWS
 In such environments, a tool that tunnels TCP traffic over HTTP(S) through a Content Delivery Network (CDN) like Cloudflare can be invaluable. By disguising restricted traffic as regular web traffic, this method can effectively circumvent censorship measures, granting users access to blocked content and preserving the free flow of information.

## Understanding Routing

### Default Routing Behavior
By default, doxx.net manages all your internet traffic through its VPN tunnel. This means:
- All your outbound connections are routed through the VPN
- You get a new virtual IP address (10.x.x.x)
- Your original internet connection becomes a backup route

### Using -no-routing
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


## Advanced Configuration

### Transport Types
- `tcp-encrypted`: Encrypted TCP with TLS
- `https`: HTTPS transport with compression

### Command Line Flags
```
Usage of ./bin/doxx.net-darwin-arm64:
  -debug
    	enable debug logging
  -kill
    	Remove default route instead of saving it
  -no-routing
    	Disable automatic routing
  -proxy string
    	Proxy URL (e.g., http://user:pass@host:port, https://user:pass@host:port, or socks5://user:pass@host:port)
  -server string
    	VPN server address (host:port)
  -token string
    	Authentication token
  -type string
    	Transport type (tcp-encrypted, or https) (default "tcp-encrypted")
  -snarf-dns
    Enables DNS query interception and tunneling through the VPN. When enabled:
    - All DNS queries are automatically redirected through the VPN tunnel
    - Prevents DNS leaks to your local network or ISP
    - Ensures DNS queries are encrypted within the VPN tunnel
    - Maintains the appearance of original DNS servers (e.g., 8.8.8.8) while routing through VPN
    - Helps bypass DNS-based geo-restrictions and censorship
    - Improves privacy by hiding DNS queries from network observers
    - Default: false (DNS queries use system default routing)

```

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


### 🚀 Attional doxx.net toolkit: **Doxxulator**

#### 🔥 **What is Doxxulator?**
Doxxulator isn't your run-of-the-mill proxy server. It's a **high-octane location spoofing and browser emulation engine** designed to obliterate geo-restrictions, circumvent content barriers, and keep your true digital fingerprint under wraps.

Built on **Go** and leveraging **goproxy**, Doxxulator dynamically spoofs browser fingerprints, manipulates HTTP headers, and injects client-side geolocation overrides to trick even the most stubborn streaming platforms.

---

### 🛠️ **How Does it Work?**

At its core, Doxxulator does three key things:

1. **Geo-Spoofing:**
   - Choose your location from an extensive list: **Tokyo**, **New York**, **London**, or go rogue with **custom latitude/longitude** coordinates.
   - Geolocation APIs are intercepted and overridden with fake GPS data.

2. **Browser Fingerprinting:**
   - Emulate popular browsers (**Chrome**, **Firefox**, **Safari**, **Edge**) with pre-configured User-Agent strings and header manipulation.
   - Headers like `Accept-Language`, `Sec-CH-UA-Platform`, and `User-Agent` are tailored for maximum realism.

3. **Certificate Authority (CA) Injection:**
   - Automatically generates TLS certificates for seamless MITM (Man-In-The-Middle) traffic inspection.
   - Handles SSL Pinning gracefully by allowing passthrough for services like Slack, Discord, and iCloud.

---

### 🌍 **Side-Gate Geo Restrictions Like a Pro**

#### 🎥 **Streaming Services**
Doxxulator bypasses location locks on streaming giants:
- **Netflix:** Watch region-locked content with geo-coordinates set to anywhere on the planet.
- **Disney+:** Gain access to exclusive regional releases.
- **Hulu, Prime Video, BBC iPlayer:** It's game over for geo-blocks.

#### 🛡️ **Privacy Mode**
Your browsing fingerprints are scrubbed clean. Doxxulator removes sensitive headers (`User-Agent`, `X-Forwarded-For`) and injects spoofed metadata seamlessly.


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


Join us on Discord: https://discord.gg/es546Rt9
