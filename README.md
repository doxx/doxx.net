---
title: "doxx.net Documentation"
description: "Advanced VPN, Parallel Internet, and De-Location Platform"
date: 2024-01-01
weight: 1
---

![doxx.net logo](/assets/doxx.net.logo.png)

# **doxx.net (BETA): Advanced VPN, Parallel Internet, and De-Location Platform**

✨ **Join the FREE BETA!** ✨ Experience the future of privacy and security by visiting [**beta.doxx.net**](https://beta.doxx.net)

doxx.net is a comprehensive privacy and security platform combining a high-performance VPN service with a parallel internet featuring advanced location management capabilities. Users can connect to the doxx.net network through the dedicated client using vpn over: [https, https over CDN, tcp](/vpn_clients/doxx.net/), or [WireGuard](/vpn_clients/wireguard) which uses standard UDP. For optimal performance with low latency, the WireGuard connection is recommended. In network environments with high restrictions, the TCP or HTTPS or HTTPS over CDN VPN connection is recommended.

Importantly, doxx.net goes beyond a traditional VPN—while the VPN provides entry into the network, the real value lies within the secured, encrypted mesh network. Once connected, users can seamlessly access .doxx domains, utilize the dedicated gTLD, and leverage secure hosting. This mesh network enables secure interaction with other users and applications directly within doxx.net.

When exiting the doxx.net backbone, traffic is securely NATed to the internet via the connected node. For instance, connecting to the mia.us.doxx.net node via WireGuard allows seamless communication with other users across any node on the network, requiring only a hostname or IP address. Additionally, interconnected users can securely utilize peer-to-peer applications, such as Signal voice calls, entirely within the doxx.net backbone. Staying within the doxx.net network also reduces your digital footprint and minimizes exposure by avoiding additional points of vulnerability associated with exiting to the public internet.

Generally speaking staying insdie the doxx.net echosystem is the best way to stay secure and private.

```
                                  Public Internet
                                       ^
                                       | NAT
                                       |
Client A (10.1.2.4) ----+      +------------+
                        |      | ams.eu     |
                        +----->| doxx.net   |
                        |      | Node       |
                        |      |            |
Client B (10.1.2.3) <--+      +------------+
                               | |
                               | |
                        +------------+
           Pub Internet |  mia.us    |      www.yoursite.doxx
                   <----| doxx.net   |---- Client C (10.1.2.5)
                        |   Node     |
                        +------------+

         Direct P2P communication possible
         between clients on the network
```
### Key Features & Benefits

#### 🌐 Network Architecture
- Parallel Internet infrastructure
- Static doxx.net IP Assignment for stable internal connections
- Automatic routing management for optimal performance
- Multiple transport options including HTTPS, TCP, and WireGuard
- Cloudflare CDN integration for traffic obfuscation
- Cross-platform support for Linux, macOS, BSD, and Windows

#### 🔒 Security & Privacy
- Deep packet inspection resistance
- AI-based traffic analysis protection
- Certificate pinning to prevent man-in-the-middle attacks
- Complete isolation from internet-based attacks
- Compromised host detection with NXDOMAIN tracking
- Real-time visibility through Security Console
- No public footprint for internal services
- No dependence on public domain registrars
- Immune to domain seizures and DNS blocking

#### 🛡️ Built-in Protections
- Advanced DNS protection against tracking
- Comprehensive ad blocking
- Pixel tracking prevention
- Malware Command & Control (C2) protection (coming soon)
- SNI defense mechanisms (coming soon)

#### 🌍 Access & Control
- Bypass network restrictions and censorship
- Location spoofing and geo-unblocking
- Browser fingerprint manipulation
- Granular access control and permissions
- Secure and private communication channels
  
#### Cool Portal Features
doxx.net features a real-time [security console](/a0x13/security-console) that delivers enriched data without compromising your privacy or exposing your data.

![Security Console Interface](/assets/security_console.gif)

---

*doxx.net is committed to advancing freedom of speech and open communication through innovative protocol design. By exposing the vulnerabilities and limitations in existing internet infrastructure, I aim to inspire the evolution of protocols that uphold the fundamental principle of unimpeded global connectivity. The internet was conceived as a tool for unrestricted communication, and my work underscores the need to preserve its open nature by breaking through barriers and empowering users to communicate freely, even in the face of censorship or restrictions.*

---

Where most VPNs act more like a proxy, doxx.net is a true parallel internet. You can currently connect to the doxx.net network using either the propritary doxx.net client or a WireGuard® client. Once connected, you can create your own network infrastructure, operate services entirely within the alternative internet, and no dependence on public domain registrars.

It's pretty easy: You can use the [a0x13.doxx.net](https://a0x13.doxx.net) portal to create your own private network infrastructure, or you can use the API to create your own private network infrastructure. The [API](https://docs.doxx.net/api/) is more for the hacker types where the portal is more for the average user.


## Community

We are more than just a VPN. We are a community of like-minded individuals who are passionate about privacy and security. Software development is on-going and features are still being created. Join our community on [Discord](https://discord.gg/Gr9rByrEzZ) for support and updates.

---

*WireGuard is a registered trademark of Jason A. Donenfeld.* 