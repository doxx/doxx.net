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

**doxx.net** is a high-performance, secure VPN and darknet service engineered for the discerning user or researcher. Leveraging multiple transport protocols—including **encrypted TCP** and **HTTPS**—doxx.net ensures your traffic seamlessly blends with regular web activity, effectively bypassing restrictive firewalls and censorship.

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

## 🛡️ **What is the Darknet?**
- The **Darknet** refers to a part of the internet not indexed by traditional search engines (like Google). It relies on **encrypted networks** to enable private communication and anonymous data sharing.
- It’s often misunderstood as being purely for illegal activities. In reality, it plays a **critical role in privacy, whistleblowing, bypassing censorship, and ensuring secure communication** in restrictive regions.

### **Why is the Darknet Important?**
- **Freedom of Speech:** Allows individuals to share information without fear of government persecution.
- **Bypassing Censorship:** Access information in countries with restricted internet.
- **Privacy Protection:** Securely communicate and share data without tracking.

---

## 🌐 **What is doxx.net:443 (Miami)
- tcp-encrypted.lax.us.doxx.net:443 (Los Angeles)

### HTTPS Servers
- https.mia.us.doxx.net:443 (Miami)
- https.lax.us.doxx.net:443 (Los Angeles)

### CDN-Protected Servers
- cdn.mia.us.doxx.net:443 (Miami)
- cdn.lax.us.doxx.net:443 (Los Angeles)


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

**5. Disconnects and Crashes Causing Default route issues:** 
- If you are experiencing disconnects and crashes, you may need to readd the default route.


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

## License

This software is provided under a dual license:
1. MIT License with Commons Clause
2. Commercial License (contact for details)

The Commons Clause restricts using the software to provide commercial hosted services without a separate agreement.

### Third-Party Licenses

This software includes the following third-party open source software:

- github.com/songgao/water: BSD-3-Clause License
- github.com/klauspost/compress: BSD-3-Clause License
- golang.org/x/sys: BSD-3-Clause License

The full text of these licenses and their requirements must be included with any distribution of this software.


Join us on Discord: https://discord.gg/es546Rt9
