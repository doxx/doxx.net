![doxx.net logo](/assets/doxx.net.logo.png)

✨ **Join the community** ✨ Get started with privacy and security by visiting [**www.doxx.net**](https://www.doxx.net)

[Discord](https://discord.gg/Gr9rByrEzZ) for support and updates.

doxx.net is a comprehensive privacy and security platform combining a high-performance VPN service with a parallel internet featuring advanced location management capabilities. Users can connect to the doxx.net network through the dedicated client using vpn over: https, https over CDN, tcp, or WireGuard which uses standard UDP. These are not reccomended for begginers! For easy setup please visit www.doxx.net and create an account and use the WireGuard system. 

Here you will find the experimental doxx.net open sourced clients for https, cdn, and tcp-encrypted sessions. These clients are designed to be used through the a0x13.doxx.net portal or the API.

For more information on the doxx.net platform, please visit [**docs.doxx.net**](https://docs.doxx.net)

## Download

Pre-compiled binaries are available for multiple platforms:

- [**macOS**](bin/doxx.net-macOS.zip) - Universal binary for Intel and Apple Silicon
- [**Linux**](bin/doxx.net-Linux.zip) - AMD64 and ARM64
- [**Windows 10/11**](bin/doxx.net-Windows10-11.zip) - AMD64 and ARM64
- [**FreeBSD**](bin/doxx.net-FreeBSD.zip) - AMD64 and ARM64
- [**OpenBSD**](bin/doxx.net-OpenBSD.zip) - AMD64 and ARM64

## Getting Started

### Step 1: Create Your Tunnel

Before using the doxx.net client, you need to create a tunnel and obtain your authentication token.

**Option A: Using the Web Portal**

1. Visit [**a0x13.doxx.net**](https://a0x13.doxx.net) and create an account
2. Navigate to the **Experimental** section
3. Create a new tunnel
4. Copy your unique tunnel token (this is different from your account token)

**Option B: Using the API**

You can also manage your account and tunnels programmatically using the doxx.net API. See [**docs.doxx.net/api**](https://docs.doxx.net/api) for complete documentation.

Example - Create an account:
```bash
curl -X POST https://a0x13.doxx.net/api/create_account \
  -H "Content-Type: application/json" \
  -d '{
    "username": "your_username",
    "email": "your_email@example.com",
    "password": "your_secure_password"
  }'
```

### Step 2: Download and Setup

1. Download the appropriate binary for your platform (see Download section above)
2. Extract the zip file

**macOS / Linux / FreeBSD / OpenBSD:**
```bash
# Make the binary executable
chmod +x doxx.net
```

**Windows:**
No additional setup required - just extract and run.

### Step 3: Connect to doxx.net

Use the `-token` and `-server` flags to connect. The server address must include the port (typically `:443`).

**macOS / Linux / FreeBSD / OpenBSD:**
```bash
# TCP Encrypted (Recommended)
sudo ./doxx.net -token YOUR_TUNNEL_TOKEN -server tcp-encrypted.mia.us.doxx.net:443

# HTTPS
sudo ./doxx.net -token YOUR_TUNNEL_TOKEN -server https.mia.us.doxx.net:443
```

**Windows (Run as Administrator):**
```cmd
# TCP Encrypted (Recommended)
doxx.net.exe -token YOUR_TUNNEL_TOKEN -server tcp-encrypted.mia.us.doxx.net:443

# HTTPS
doxx.net.exe -token YOUR_TUNNEL_TOKEN -server https.mia.us.doxx.net:443
```

> **Note:** Replace `YOUR_TUNNEL_TOKEN` with the token you received when creating your tunnel on a0x13.doxx.net

---

*doxx.net is committed to advancing freedom of speech and open communication through innovative protocol design. By exposing the vulnerabilities and limitations in existing internet infrastructure, I aim to inspire the evolution of protocols that uphold the fundamental principle of unimpeded global connectivity. The internet was conceived as a tool for unrestricted communication, and my work underscores the need to preserve its open nature by breaking through barriers and empowering users to communicate freely, even in the face of censorship or restrictions.*

---

## Community

We are a community of like-minded individuals who are passionate about privacy and security. Software development is on-going and features are still being created. Join our community on [Discord](https://discord.gg/Gr9rByrEzZ) for support and updates.
