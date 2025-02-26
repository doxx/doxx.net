## Overview

doxxulator is a powerful tool designed to emulate various browsers and geographic locations, providing enhanced privacy and flexibility in your browsing experience. It integrates seamlessly with the doxx.net client to deliver secure and customized web interactions.

The tool functions as a local proxy server, intercepting and modifying HTTP/HTTPS traffic between your browser and the internet. To achieve this, doxxulator installs a wildcard certificate on your system, which temporarily bypasses SSL validation for applications routed through the proxy. While this might pose certain security implications, it's crucial to understand that all decryption happens exclusively on your local machine—your traffic never leaves your control unencrypted.

Decrypting browser traffic locally enables doxxulator to parse and modify JavaScript and GPS data. This allows precise adjustments to your browser's timezone, location, and language settings. After these modifications, traffic is re-encrypted and securely forwarded to the internet.

Transparency is essential, and I aim to clearly communicate how your data is handled and ensure you remain informed throughout the process.

## Build Instructions

```bash
git clone https://github.com/doxx/doxx.net
make
```

Or download the latest release from [github.com/doxx/doxx.net/releases](https://github.com/doxx/doxx.net/releases)

## Usage

```bash
# Custom coordinates
./doxxulator -location custom -lat 35.6762 -lon 139.6503
```

## Runtime flags

```
Usage:
  ./doxxulator-darwin-arm64 [flags]

Examples:
  ./doxxulator -location=tokyo
  ./doxxulator -location=custom -lat=35.6762 -lon=139.6503
  ./doxxulator -location=custom -lat=35.6762 -lon=139.6503 -lang=ja-JP -timezone=Asia/Tokyo
  ./doxxulator -browser=firefox -location=paris
  ./doxxulator -allow-passthrough -location=london

Flags:
  -allow-passthrough
    	Allow certificate passthrough for apps with SSL pinning (e.g., Slack, Discord)
  -browser string
    	Browser profile to emulate. Available profiles:
    	  • chrome-android
    	  • chrome-mac
    	  • chrome-mac-arm
    	  • chrome-windows
    	  • curl
    	  • edge-mac
    	  • edge-windows
    	  • firefox-mac
    	  • firefox-windows
    	  • safari-ios
    	  • safari-mac
    	  • safari-mac-arm
    	  • wget
    	  (empty for passthrough)
  -key string
    	Path to private key file (default: ~/.doxx.net/doxxulator-ca.key) 
  -l string
    	Listen address (default "127.0.0.1:8080")
  -lang string
    	Custom language (e.g., en-US, fr-FR)
  -lat float
    	Custom latitude (required when using -location=custom)
  -location string
    	Location to spoof. Available locations:
    	  • amsterdam-nl
    	  • austin-us
    	  • bangkok-th
    	  • beijing-cn
    	  • berlin-de
    	  • charlotte-us
    	  • chicago-us
    	  • columbus-us
    	  • dallas-us
    	  • dubai-ae
    	  • fortworth-us
    	  • hongkong-hk
    	  • houston-us
    	  • istanbul-tr
    	  • jacksonville-us
    	  • london-gb
    	  • losangeles-us
    	  • madrid-es
    	  • mexicocity-mx
    	  • miami-us
    	  • moscow-ru
    	  • mumbai-in
    	  • newyork-us
    	  • paris-fr
    	  • philadelphia-us
    	  • phoenix-us
    	  • rome-it
    	  • sanantonio-us
    	  • sandiego-us
    	  • sanjose-us
    	  • saopaulo-br
    	  • seoul-kr
    	  • shanghai-cn
    	  • singapore-sg
    	  • sydney-au
    	  • tokyo-jp
    	  • toronto-ca
    	  • vienna-at
    	Use '-location=custom -lat=XX.XXXX -lon=YY.YYYY' for custom coordinates (default "newyork-us")
  -log
    	Enable request logging
  -lon float
    	Custom longitude (required when using -location=custom)
  -passthrough
    	Pass through original browser fingerprint (default true)
  -sniff
    	Dump all non-binary HTTP traffic to stdout
  -timezone string
    	Custom timezone (e.g., America/Los_Angeles, Europe/London)
```

### Installing your certificates to your OS or browser

#### Certificate Generation
Doxxulator automatically generates and stores two files in your home directory under `.doxx.net`:
- `~/.doxx.net/doxxulator-ca.crt` - The certificate file
- `~/.doxx.net/doxxulator-ca.key` - The private key file

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

### Sniffer Mode
The `-sniff` flag will dump all non-binary HTTP traffic to stdout. This is useful for debugging and analyzing the traffic. It's very useful to capture API keys and other sensitive information.

### Passthrough 
allow-passthrough is an important option because a lot of services do not use PKI for certifcate signing, they sign their own certifcates: Parts of Apple's ecosystem, Discord, Zoom all use their own self signed certifcates. It's better to enable allow-passthrough to keep those types of applications working. 

### License 
doxxulator is licensed under the MIT License no warranty is provided, use at your own risk.

### Code of Conduct
This software is for educational purposes only. Do not use it to break the law.
