<p align="center">
  <img src="https://raw.githubusercontent.com/doxx/doxx.net/main/assets/imagotype-white-512.png" alt="doxx.net" width="300">
</p>

<h3 align="center">Freedom and Privacy by Design</h3>

<p align="center">
  <a href="https://doxx.net">Website</a> &middot;
  <a href="https://a0x13.doxx.net">Portal</a> &middot;
  <a href="https://discord.gg/Gr9rByrEzZ">Discord</a> &middot;
  <a href="https://a0x13.doxx.net/terms/">Terms</a> &middot;
  <a href="https://a0x13.doxx.net/privacy/">Privacy</a>
</p>

---

## What is doxx.net?

doxx.net is a freedom of speech and privacy platform. It provides encrypted tunnels, DNS blocking, firewall rules, domain hosting, and real-time security monitoring across all your devices.

The platform runs on a global backbone with servers in the US, Europe, and Asia. Clients are available for iOS, macOS, Android, and any device that supports WireGuard.

The web portal ([a0x13.doxx.net](https://a0x13.doxx.net)) provides full control over tunnels, DNS settings, firewall rules, proxy configuration, domains, and security dashboards.

---

## Platform Features

- **Encrypted Tunnels**: WireGuard-based tunnels with automatic IPv4/IPv6 allocation
- **DNS Blocking**: Per-tunnel blocklist subscriptions (malware, ads, tracking, phishing) with custom whitelists and blacklists
- **Secure DNS (DoH/DoT)**: Personalized DNS-over-HTTPS and DNS-over-TLS for any device, no tunnel required
- **Firewall Rules**: Per-tunnel protocol/port filtering with link-all mesh networking between your devices
- **Domain Hosting**: Register domains on 196 TLDs (.doxx, .crypto, .eth, .onion, .vpn, and more) with full DNS management
- **Certificate Signing**: TLS certificates signed by the doxx.net root CA for your domains
- **Proxy / De-Location**: Transparent geo-spoofing with configurable location, timezone, language, and browser fingerprint
- **Real-Time Monitoring**: Live bandwidth, security events, DNS blocks, and connection tracking via WebSocket
- **Multi-Device Management**: Link devices to a single subscription with transfer and swap capabilities

---

## Documentation

| Resource | Description |
|----------|-------------|
| [config.doxx.net](https://github.com/doxxcorp/config.doxx.net) | Full API reference: Config API, Stats API with curl examples and workflows |

---

## Open Source Tools

| Project | Description |
|---------|-------------|
| [DarkFlare](https://github.com/doxx/darkflare) | TCP-over-CDN firewall piercing tool |
| [WireSlammer](https://github.com/doxx/wireslammer) | WireGuard over anything (TCP, CDN, WebSocket): coming soon |
| [DevSocket](https://github.com/doxx/DevSocket) | Real-time mobile debug log streaming for iOS and Android |

---

## DNS Infrastructure

doxx.net operates its own global DNS with three layers:

| Layer | Addresses | Purpose |
|-------|-----------|---------|
| **Tunnel DNS** | `10.10.10.10`, `fd53::` | Personalized blocking for connected devices |
| **Public Recursive** | `207.207.200.200`, `207.207.201.201` | Open resolver for anyone (resolves .doxx TLDs) |
| **Authoritative** | `a.root-dx.net`, `a.root-dx.com`, `a.root-dx.org` | Root authority for all doxx.net TLDs |

Public recursive DNS is available to anyone on the internet. No tunnel required to resolve `.doxx`, `.crypto`, `.eth`, or any of the 196 doxx.net TLDs:

```bash
dig A mysite.doxx @207.207.200.200 +short
```

---

## Quick Start

1. Visit [a0x13.doxx.net](https://a0x13.doxx.net) and create an account
2. Create a tunnel and select a server
3. Download the WireGuard config or use the iOS/macOS app
4. Connect and start browsing with DNS protection

For API access, see the [API documentation](https://github.com/doxxcorp/config.doxx.net).

---

## Contact

- **Website**: [doxx.net](https://doxx.net)
- **Portal**: [a0x13.doxx.net](https://a0x13.doxx.net)
- **Discord**: [discord.gg/Gr9rByrEzZ](https://discord.gg/Gr9rByrEzZ)
- **Support**: support@doxx.net

---

<p align="center">
  <sub>&copy; 2024-2026 doxx.net corp. All rights reserved.</sub>
</p>
