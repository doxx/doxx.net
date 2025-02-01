// MIT License
//
// Copyright (c) 2024 Barrett Lyon
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// USAGE RESTRICTION:
// This software is designed for exclusive use with the doxx.net VPN service.
// Use with other VPN providers (including but not limited to NordVPN, ExpressVPN,
// ProtonVPN, or similar services) is strictly prohibited.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	mathrand "math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/elazarl/goproxy"
)

var (
	tlsErrorHosts sync.Map
)

type Config struct {
	ListenAddr       string
	Browser          string
	Location         string
	CertPath         string
	KeyPath          string
	Debug            bool
	UserAgent        string
	AcceptLang       string
	Platform         string
	Architecture     string
	CustomLat        float64
	CustomLon        float64
	AllowPassthrough bool
	PassThrough      bool
	AppVersion       string
	CustomLang       string
	CustomTZ         string
	Sniff            bool
}

var (
	// Pre-defined browser User-Agents instead of ClientHelloID
	browserProfiles = map[string]struct {
		UserAgent    string
		AcceptLang   string
		Platform     string
		Architecture string
		AppVersion   string
	}{
		// Chrome variants
		"chrome-windows": {
			UserAgent:    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			AcceptLang:   "en-US,en;q=0.9",
			Platform:     "Win32",
			Architecture: "x86_64",
			AppVersion:   "5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		},
		"chrome-mac": {
			UserAgent:    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			AcceptLang:   "en-US,en;q=0.9",
			Platform:     "MacIntel",
			Architecture: "x86_64",
			AppVersion:   "5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		},
		"chrome-mac-arm": {
			UserAgent:    "Mozilla/5.0 (Macintosh; Apple Silicon Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			AcceptLang:   "en-US,en;q=0.9",
			Platform:     "MacIntel",
			Architecture: "arm64",
			AppVersion:   "5.0 (Macintosh; Apple Silicon Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		},

		// Firefox variants
		"firefox-windows": {
			UserAgent:    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
			AcceptLang:   "en-US,en;q=0.5",
			Platform:     "Win32",
			Architecture: "x86_64",
			AppVersion:   "5.0 (Windows)",
		},
		"firefox-mac": {
			UserAgent:    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
			AcceptLang:   "en-US,en;q=0.5",
			Platform:     "MacIntel",
			Architecture: "x86_64",
			AppVersion:   "5.0 (Macintosh)",
		},

		// Edge variants
		"edge-windows": {
			UserAgent:    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
			AcceptLang:   "en-US,en;q=0.9",
			Platform:     "Win32",
			Architecture: "x86_64",
			AppVersion:   "5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
		},
		"edge-mac": {
			UserAgent:    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
			AcceptLang:   "en-US,en;q=0.9",
			Platform:     "MacIntel",
			Architecture: "x86_64",
			AppVersion:   "5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
		},

		// Safari variants
		"safari-mac": {
			UserAgent:    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
			AcceptLang:   "en-US,en;q=0.9",
			Platform:     "MacIntel",
			Architecture: "x86_64",
			AppVersion:   "5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
		},
		"safari-mac-arm": {
			UserAgent:    "Mozilla/5.0 (Macintosh; Apple Silicon Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
			AcceptLang:   "en-US,en;q=0.9",
			Platform:     "MacIntel",
			Architecture: "arm64",
			AppVersion:   "5.0 (Macintosh; Apple Silicon Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
		},

		// Mobile variants
		"safari-ios": {
			UserAgent:    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
			AcceptLang:   "en-US,en;q=0.9",
			Platform:     "iPhone",
			Architecture: "arm64",
			AppVersion:   "5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
		},
		"chrome-android": {
			UserAgent:    "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
			AcceptLang:   "en-US,en;q=0.9",
			Platform:     "Android",
			Architecture: "arm64",
			AppVersion:   "5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
		},

		// CLI tools
		"curl": {
			UserAgent:    "curl/8.4.0",
			AcceptLang:   "*/*",
			Platform:     "CLI",
			Architecture: "x86_64",
			AppVersion:   "curl/8.4.0",
		},
		"wget": {
			UserAgent:    "Wget/1.21.4",
			AcceptLang:   "*/*",
			Platform:     "CLI",
			Architecture: "x86_64",
			AppVersion:   "Wget/1.21.4",
		},
	}

	// Pre-defined locations with lat/long
	locations = map[string]struct {
		Lat      float64
		Lon      float64
		Timezone string
		Locale   string
	}{
		"newyork-us":      {40.7128, -74.0060, "America/New_York", "en-US"},
		"london-gb":       {51.5074, -0.1278, "Europe/London", "en-GB"},
		"tokyo-jp":        {35.6762, 139.6503, "Asia/Tokyo", "ja-JP"},
		"paris-fr":        {48.8566, 2.3522, "Europe/Paris", "fr-FR"},
		"singapore-sg":    {1.3521, 103.8198, "Asia/Singapore", "en-SG"},
		"dubai-ae":        {25.2048, 55.2708, "Asia/Dubai", "ar-AE"},
		"hongkong-hk":     {22.3193, 114.1694, "Asia/Hong_Kong", "zh-HK"},
		"shanghai-cn":     {31.2304, 121.4737, "Asia/Shanghai", "zh-CN"},
		"sydney-au":       {-33.8688, 151.2093, "Australia/Sydney", "en-AU"},
		"berlin-de":       {52.5200, 13.4050, "Europe/Berlin", "de-DE"},
		"moscow-ru":       {55.7558, 37.6173, "Europe/Moscow", "ru-RU"},
		"mumbai-in":       {19.0760, 72.8777, "Asia/Kolkata", "hi-IN"},
		"saopaulo-br":     {-23.5505, -46.6333, "America/Sao_Paulo", "pt-BR"},
		"istanbul-tr":     {41.0082, 28.9784, "Europe/Istanbul", "tr-TR"},
		"rome-it":         {41.9028, 12.4964, "Europe/Rome", "it-IT"},
		"seoul-kr":        {37.5665, 126.9780, "Asia/Seoul", "ko-KR"},
		"mexicocity-mx":   {19.4326, -99.1332, "America/Mexico_City", "es-MX"},
		"amsterdam-nl":    {52.3676, 4.9041, "Europe/Amsterdam", "nl-NL"},
		"madrid-es":       {40.4168, -3.7038, "Europe/Madrid", "es-ES"},
		"vienna-at":       {48.2082, 16.3738, "Europe/Vienna", "de-AT"},
		"bangkok-th":      {13.7563, 100.5018, "Asia/Bangkok", "th-TH"},
		"beijing-cn":      {39.9042, 116.4074, "Asia/Shanghai", "zh-CN"},
		"toronto-ca":      {43.6532, -79.3832, "America/Toronto", "en-CA"},
		"losangeles-us":   {34.0522, -118.2437, "America/Los_Angeles", "en-US"},
		"chicago-us":      {41.8781, -87.6298, "America/Chicago", "en-US"},
		"houston-us":      {29.7604, -95.3698, "America/Chicago", "en-US"},
		"phoenix-us":      {33.4484, -112.0740, "America/Phoenix", "en-US"},
		"philadelphia-us": {39.9526, -75.1652, "America/New_York", "en-US"},
		"sanantonio-us":   {29.4241, -98.4936, "America/Chicago", "en-US"},
		"sandiego-us":     {32.7157, -117.1611, "America/Los_Angeles", "en-US"},
		"dallas-us":       {32.7767, -96.7970, "America/Chicago", "en-US"},
		"sanjose-us":      {37.3382, -121.8863, "America/Los_Angeles", "en-US"},
		"austin-us":       {30.2672, -97.7431, "America/Chicago", "en-US"},
		"jacksonville-us": {30.3322, -81.6557, "America/New_York", "en-US"},
		"fortworth-us":    {32.7555, -97.3308, "America/Chicago", "en-US"},
		"columbus-us":     {39.9612, -82.9988, "America/New_York", "en-US"},
		"miami-us":        {25.7617, -80.1918, "America/New_York", "en-US"},
		"charlotte-us":    {35.2271, -80.8431, "America/New_York", "en-US"},
	}

	// Add language mappings for locations
	locationLanguages = map[string]string{
		"newyork-us":      "en-US,en;q=0.9",
		"london-gb":       "en-GB,en;q=0.9",
		"tokyo-jp":        "ja-JP,ja;q=0.9,en;q=0.8",
		"paris-fr":        "fr-FR,fr;q=0.9,en;q=0.8",
		"singapore-sg":    "en-SG,en;q=0.9,zh-SG;q=0.8",
		"dubai-ae":        "ar-AE,ar;q=0.9,en;q=0.8",
		"hongkong-hk":     "zh-HK,zh;q=0.9,en;q=0.8",
		"shanghai-cn":     "zh-CN,zh;q=0.9,en;q=0.8",
		"sydney-au":       "en-AU,en;q=0.9",
		"berlin-de":       "de-DE,de;q=0.9,en;q=0.8",
		"moscow-ru":       "ru-RU,ru;q=0.9,en;q=0.8",
		"mumbai-in":       "hi-IN,hi;q=0.9,en;q=0.8",
		"saopaulo-br":     "pt-BR,pt;q=0.9,en;q=0.8",
		"istanbul-tr":     "tr-TR,tr;q=0.9,en;q=0.8",
		"rome-it":         "it-IT,it;q=0.9,en;q=0.8",
		"seoul-kr":        "ko-KR,ko;q=0.9,en;q=0.8",
		"mexicocity-mx":   "es-MX,es;q=0.9,en;q=0.8",
		"amsterdam-nl":    "nl-NL,nl;q=0.9,en;q=0.8",
		"madrid-es":       "es-ES,es;q=0.9,en;q=0.8",
		"chicago-us":      "en-US,en;q=0.9",
		"houston-us":      "en-US,en;q=0.9,es;q=0.8",
		"phoenix-us":      "en-US,en;q=0.9,es;q=0.8",
		"philadelphia-us": "en-US,en;q=0.9",
		"sanantonio-us":   "en-US,en;q=0.9,es;q=0.8",
		"sandiego-us":     "en-US,en;q=0.9,es;q=0.8",
		"dallas-us":       "en-US,en;q=0.9,es;q=0.8",
		"sanjose-us":      "en-US,en;q=0.9,es;q=0.8",
		"austin-us":       "en-US,en;q=0.9,es;q=0.8",
		"jacksonville-us": "en-US,en;q=0.9",
		"fortworth-us":    "en-US,en;q=0.9,es;q=0.8",
		"columbus-us":     "en-US,en;q=0.9",
		"miami-us":        "en-US,en;q=0.9,es;q=0.8",
		"charlotte-us":    "en-US,en;q=0.9",
		// Default to en-US for any unlisted locations
	}
)

type logWriter struct {
	cb func(string, ...interface{})
}

func (l *logWriter) Write(p []byte) (n int, err error) {
	l.cb(string(p))
	return len(p), nil
}

func NewLogWriter(cb func(string, ...interface{})) io.Writer {
	return &logWriter{cb: cb}
}

func getDoxxNetDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %v", err)
	}

	doxxDir := filepath.Join(homeDir, ".doxx.net")
	if err := os.MkdirAll(doxxDir, 0700); err != nil {
		return "", fmt.Errorf("failed to create .doxx.net directory: %v", err)
	}

	return doxxDir, nil
}

func initializeCertificates(config *Config) error {
	doxxDir, err := getDoxxNetDir()
	if err != nil {
		return err
	}

	config.CertPath = filepath.Join(doxxDir, "doxxulator-ca.crt")
	config.KeyPath = filepath.Join(doxxDir, "doxxulator-ca.key")

	// Check if certificates exist
	if _, err := os.Stat(config.CertPath); os.IsNotExist(err) {
		log.Println("🔑 Generating new root CA certificate...")
		if err := generateCertificates(config); err != nil {
			return err
		}

		// Attempt to install the certificate
		if err := installCertificate(config.CertPath); err != nil {
			// Print manual installation instructions if automatic install fails
			printManualInstallInstructions(config.CertPath)
		}
	}

	// Set proper permissions
	if err := os.Chmod(config.KeyPath, 0600); err != nil {
		return fmt.Errorf("failed to set permissions on private key: %v", err)
	}
	if err := os.Chmod(config.CertPath, 0644); err != nil {
		return fmt.Errorf("failed to set permissions on certificate: %v", err)
	}

	return nil
}

func installCertificate(certPath string) error {
	switch runtime.GOOS {
	case "darwin":
		cmd := exec.Command("security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", certPath)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to install certificate on macOS: %v", err)
		}

	case "linux":
		if _, err := exec.LookPath("update-ca-certificates"); err == nil {
			// Debian/Ubuntu
			destPath := "/usr/local/share/ca-certificates/doxxulator-ca.crt"
			if err := copyFile(certPath, destPath); err != nil {
				return err
			}
			cmd := exec.Command("update-ca-certificates")
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("failed to update certificates on Linux: %v", err)
			}
		} else if _, err := exec.LookPath("update-ca-trust"); err == nil {
			// RHEL/CentOS
			destPath := "/etc/pki/ca-trust/source/anchors/doxxulator-ca.crt"
			if err := copyFile(certPath, destPath); err != nil {
				return err
			}
			cmd := exec.Command("update-ca-trust", "extract")
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("failed to update certificates on Linux: %v", err)
			}
		}

	case "windows":
		cmd := exec.Command("certutil", "-addstore", "ROOT", certPath)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to install certificate on Windows: %v", err)
		}
	}

	return nil
}

func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	return err
}

func printManualInstallInstructions(certPath string) {
	fmt.Printf("\n📝 Manual Certificate Installation Instructions:\n\n")

	switch runtime.GOOS {
	case "darwin":
		fmt.Printf("macOS Instructions:\n"+
			"1. Double click the certificate file: %s\n"+
			"2. Open Keychain Access\n"+
			"3. Add the certificate to System keychain\n"+
			"4. Trust the certificate for SSL/TLS\n", certPath)

	case "windows":
		fmt.Printf("Windows Instructions:\n"+
			"1. Right-click the certificate file: %s\n"+
			"2. Select 'Install Certificate'\n"+
			"3. Select 'Local Machine'\n"+
			"4. Place certificate in 'Trusted Root Certification Authorities'\n", certPath)

	default:
		fmt.Printf("Browser Instructions:\n"+
			"1. Open your browser settings\n"+
			"2. Go to Security/Privacy > Certificates\n"+
			"3. Import the certificate file: %s\n"+
			"4. Trust the certificate for identifying websites\n", certPath)
	}

	fmt.Printf("\nCertificate location: %s\n\n", certPath)
}

func startDoxxulator() {
	config := parseFlags()

	if err := initializeCertificates(config); err != nil {
		log.Fatalf("❌ Failed to initialize certificates: %v", err)
	}

	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = config.Debug

	// Handle TLS errors by capturing the warning logs
	proxy.Logger = log.New(&logWriter{
		cb: func(format string, v ...interface{}) {
			msg := fmt.Sprintf(format, v...)
			if strings.Contains(msg, "Cannot handshake client") && strings.Contains(msg, "unknown certificate") {
				// Extract hostname from the error message
				parts := strings.Split(msg, " ")
				for _, part := range parts {
					if strings.Contains(part, ":443") {
						hostname := strings.TrimSuffix(part, ":443")
						tlsErrorHosts.Store(strings.ToLower(hostname), true)
						if config.Debug {
							log.Printf("🔓 Adding %s to passthrough list (handshake failed)", hostname)
						}
						break
					}
				}
			}
			log.Printf(format, v...)
		},
	}, "", log.LstdFlags)

	// Load the certificates (which we know exist)
	rootCert, err := tls.LoadX509KeyPair(config.CertPath, config.KeyPath)
	if err != nil {
		log.Fatalf("❌ Failed to load certificates: %v", err)
	}

	// Load system root CAs for outbound connections
	systemRoots, err := x509.SystemCertPool()
	if err != nil {
		log.Printf("⚠️ Warning: Failed to load system root CAs: %v", err)
		systemRoots = x509.NewCertPool()
	}

	// Configure outbound transport with system root CAs
	proxy.Tr = &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:            systemRoots, // Use system root CAs for outbound
			MinVersion:         tls.VersionTLS12,
			MaxVersion:         tls.VersionTLS13,
			NextProtos:         []string{"http/1.1"},
			InsecureSkipVerify: false,
		},
		ForceAttemptHTTP2: false,
		MaxIdleConns:      100,
		IdleConnTimeout:   90 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	// Set the CA for goproxy's MITM
	goproxy.GoproxyCa = rootCert
	proxy.OnRequest().HandleConnect(goproxy.FuncHttpsHandler(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		if config.Debug {
			log.Printf("\n🔒 [Browser->Proxy] New CONNECT request:")
			log.Printf("   From: %s", ctx.Req.RemoteAddr)
			log.Printf("   To: %s", host)
			log.Printf("   Passthrough Enabled: %v", config.AllowPassthrough)
		}

		hostName := strings.Split(strings.ToLower(host), ":")[0]

		// Check if this host had previous certificate issues
		if _, isPinned := tlsErrorHosts.Load(hostName); isPinned {
			if config.Debug {
				log.Printf("🔓 Using passthrough for %s (previous certificate error)", host)
			}
			return &goproxy.ConnectAction{
				Action:    goproxy.ConnectAccept,
				TLSConfig: nil,
			}, host
		}

		if config.Debug {
			log.Printf("🔐 Attempting MITM for %s", host)
		}

		return &goproxy.ConnectAction{
			Action: goproxy.ConnectMitm,
			TLSConfig: func(host string, ctx *goproxy.ProxyCtx) (*tls.Config, error) {
				hostname := strings.Split(host, ":")[0]
				certKey, err := generateHostCertificate(hostname, rootCert)
				if err != nil {
					return nil, fmt.Errorf("failed to generate host certificate: %v", err)
				}

				return &tls.Config{
					GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
						return certKey, nil
					},
					MinVersion: tls.VersionTLS10,
					MaxVersion: tls.VersionTLS13,
					NextProtos: []string{"http/1.1"},
				}, nil
			},
		}, host
	}))

	// Add request logging
	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		if config.Debug {
			log.Printf("\n📥 [Browser->Proxy] Incoming Request:")
			log.Printf("   From: %s", req.RemoteAddr)
			log.Printf("   Method: %s %s", req.Method, req.URL)
			log.Printf("   Protocol: %s (TLS: %v)", req.Proto, req.TLS != nil)
			log.Printf("   Original Headers:")
			for name, values := range req.Header {
				log.Printf("     %s: %v", name, values)
			}
		}

		// Sniff request if enabled
		if config.Sniff {
			body, err := io.ReadAll(req.Body)
			if err == nil {
				dumpHTTPTraffic("➡️ REQUEST", req, body)
				// Restore the body for further processing
				req.Body = io.NopCloser(bytes.NewReader(body))
			}
		}

		// Modify headers
		stripPrivacyHeaders(req)
		injectHeaders(req, config)

		if config.Debug {
			log.Printf("\n📤 [Proxy->Internet] Outgoing Request:")
			log.Printf("   To: %s", req.Host)
			log.Printf("   Method: %s %s", req.Method, req.URL)
			log.Printf("   Modified Headers:")
			for name, values := range req.Header {
				log.Printf("     %s: %v", name, values)
			}
		}

		return req, nil
	})

	// Add response logging
	proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		if resp == nil {
			return resp
		}

		// Sniff response if enabled
		if config.Sniff {
			body, err := io.ReadAll(resp.Body)
			if err == nil {
				dumpHTTPTraffic("⬅️ RESPONSE", resp.Request, body)
				// Restore the body for further processing
				resp.Body = io.NopCloser(bytes.NewReader(body))
			}
		}

		if err := injectGeolocationScript(resp, config); err != nil {
			log.Printf("Failed to inject geolocation script: %v", err)
		}

		return resp
	})

	log.Printf("\n🚀 Starting Doxxulator:")
	log.Printf("   Address: %s", config.ListenAddr)
	log.Printf("   Location: %s", config.Location)
	log.Printf("   Browser: %s", config.Browser)
	log.Printf("   Debug: %v", config.Debug)

	log.Fatal(http.ListenAndServe(config.ListenAddr, proxy))
}

func parseFlags() *Config {
	config := &Config{}

	// Create browser list for help text
	var browsers []string
	for browser := range browserProfiles {
		browsers = append(browsers, browser)
	}
	sort.Strings(browsers)
	browserHelp := fmt.Sprintf("Browser profile to emulate. Available profiles:\n  • %s\n  (empty for passthrough)",
		strings.Join(browsers, "\n  • "))

	flag.StringVar(&config.Browser, "browser", "", browserHelp)
	flag.BoolVar(&config.PassThrough, "passthrough", true, "Pass through original browser fingerprint")

	// Create a list of available locations
	var locationList []string
	for loc := range locations {
		locationList = append(locationList, loc)
	}
	sort.Strings(locationList)
	locationsHelp := fmt.Sprintf(
		"Location to spoof. Available locations:\n"+
			"  • %s\n"+
			"Use '-location=custom -lat=XX.XXXX -lon=YY.YYYY' for custom coordinates",
		strings.Join(locationList, "\n  • "))

	// Update flag descriptions
	flag.StringVar(&config.ListenAddr, "l", "127.0.0.1:8080", "Listen address")
	flag.StringVar(&config.Location, "location", "newyork-us", locationsHelp)
	flag.BoolVar(&config.Debug, "log", false, "Enable request logging")
	flag.Float64Var(&config.CustomLat, "lat", 0, "Custom latitude (required when using -location=custom)")
	flag.Float64Var(&config.CustomLon, "lon", 0, "Custom longitude (required when using -location=custom)")
	flag.BoolVar(&config.AllowPassthrough, "allow-passthrough", false,
		"Allow certificate passthrough for apps with SSL pinning (e.g., Slack, Discord)")
	flag.StringVar(&config.CustomLang, "lang", "", "Custom language (e.g., en-US, fr-FR)")
	flag.StringVar(&config.CustomTZ, "timezone", "", "Custom timezone (e.g., America/Los_Angeles, Europe/London)")
	flag.BoolVar(&config.Sniff, "sniff", false, "Dump all non-binary HTTP traffic to stdout")

	// Get default key location
	defaultKeyPath := ""
	if doxxDir, err := getDoxxNetDir(); err == nil {
		defaultKeyPath = filepath.Join(doxxDir, "doxxulator-ca.key")
	}

	// Add new key flag
	flag.StringVar(&config.KeyPath, "key", defaultKeyPath, "Path to private key file (default: ~/.doxx.net/doxxulator-ca.key)")

	// Custom usage message
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Doxxulator: A proxy for location and browser spoofing\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  %s [flags]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  %s -location=tokyo\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -location=custom -lat=35.6762 -lon=139.6503\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -location=custom -lat=35.6762 -lon=139.6503 -lang=ja-JP -timezone=Asia/Tokyo\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -browser=firefox -location=paris\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -allow-passthrough -location=london\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	// Validate custom location parameters
	if config.Location == "custom" && (config.CustomLat == 0 && config.CustomLon == 0) {
		fmt.Fprintf(os.Stderr, "Error: When using -location=custom, you must specify both -lat and -lon\n\n")
		flag.Usage()
		os.Exit(1)
	}

	// Get the browser profile settings
	if profile, ok := browserProfiles[config.Browser]; ok {
		config.UserAgent = profile.UserAgent
		config.AcceptLang = profile.AcceptLang
		config.Platform = profile.Platform
		config.Architecture = profile.Architecture
		config.AppVersion = profile.AppVersion
	}

	// Validate location
	if config.Location != "custom" {
		if _, ok := locations[config.Location]; !ok {
			fmt.Fprintf(os.Stderr, "Error: Invalid location '%s'\n\n", config.Location)
			flag.Usage()
			os.Exit(1)
		}
	}

	return config
}

func ensureCertificates(config *Config) error {
	// Check if both cert and key exist
	certExists := true
	keyExists := true

	if _, err := os.Stat(config.CertPath); os.IsNotExist(err) {
		certExists = false
	}
	if _, err := os.Stat(config.KeyPath); os.IsNotExist(err) {
		keyExists = false
	}

	// If either is missing, generate both
	if !certExists || !keyExists {
		log.Printf("🔑 Generating new certificates...")
		return generateCertificates(config)
	}

	return nil
}

func generateCertificates(config *Config) error {
	// Generate root CA key
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate root key: %v", err)
	}

	// Create root CA certificate
	rootTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Doxxulator Root CA",
			Organization: []string{"Doxxulator Local CA"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	// Self-sign the root certificate
	rootCertBytes, err := x509.CreateCertificate(rand.Reader, &rootTemplate, &rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		return fmt.Errorf("failed to create root certificate: %v", err)
	}

	// Save the root certificate and private key
	if err := savePEMFile(config.CertPath, "CERTIFICATE", rootCertBytes); err != nil {
		return fmt.Errorf("failed to save root certificate: %v", err)
	}

	if err := savePEMFile(config.KeyPath, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rootKey)); err != nil {
		return fmt.Errorf("failed to save root private key: %v", err)
	}

	return nil
}

// Helper function to save PEM files
func savePEMFile(filename string, blockType string, bytes []byte) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	return pem.Encode(file, &pem.Block{
		Type:  blockType,
		Bytes: bytes,
	})
}

func stripPrivacyHeaders(req *http.Request) {
	sensitiveHeaders := []string{
		"User-Agent",
		"Accept-Language",
		"DNT",
		"X-Forwarded-For",
		"Via",
		"Referer",
	}

	for _, header := range sensitiveHeaders {
		req.Header.Del(header)
	}
}

func injectHeaders(req *http.Request, config *Config) {
	// Browser fingerprinting headers
	req.Header.Set("User-Agent", config.UserAgent)

	// Set Accept-Language based on location
	if config.CustomLang != "" {
		req.Header.Set("Accept-Language", config.CustomLang)
	} else if lang, ok := locationLanguages[config.Location]; ok {
		req.Header.Set("Accept-Language", lang)
	} else {
		// Fall back to the browser profile's default language
		req.Header.Set("Accept-Language", config.AcceptLang)
	}

	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Sec-CH-UA-Platform", config.Platform)
	req.Header.Set("Sec-CH-UA-Architecture", config.Architecture)

	// Get base coordinates
	var lat, lon float64
	if config.CustomLang != "" {
		req.Header.Set("Accept-Language", config.CustomLang)
	} else if lang, ok := locationLanguages[config.Location]; ok {
		req.Header.Set("Accept-Language", lang)
	} else {
		// Fall back to the browser profile's default language
		req.Header.Set("Accept-Language", config.AcceptLang)
	}

	// Add jitter to coordinates
	jitteredLat, jitteredLon := addGPSJitter(lat, lon)

	// Use jittered coordinates in headers
	req.Header.Set("X-Geo-Lat", fmt.Sprintf("%.6f", jitteredLat))
	req.Header.Set("X-Geo-Lon", fmt.Sprintf("%.6f", jitteredLon))
	req.Header.Set("Permissions-Policy", fmt.Sprintf(
		"geolocation=(%.6f %.6f)",
		jitteredLat, jitteredLon,
	))
}

func injectGeolocationScript(resp *http.Response, config *Config) error {
	var lat, lon float64
	var timezone string

	if config.Location == "custom" {
		lat, lon = config.CustomLat, config.CustomLon
		// Use custom timezone if provided, otherwise default to "UTC"
		if config.CustomTZ != "" {
			timezone = config.CustomTZ
		} else {
			timezone = "UTC"
		}
	} else if loc, ok := locations[config.Location]; ok {
		lat, lon = loc.Lat, loc.Lon
		timezone = loc.Timezone
	} else {
		return nil
	}

	// Add jitter to coordinates
	jitteredLat, jitteredLon := addGPSJitter(lat, lon)

	script := fmt.Sprintf(`
		<script>
		(function() {
			// Immediately override geolocation
			delete navigator.geolocation;
			Object.defineProperty(navigator, 'geolocation', {
				value: {
					getCurrentPosition: function(success, error, options) {
						setTimeout(function() {
							success({
								coords: {
									latitude: %.6f,
									longitude: %.6f,
									accuracy: %.1f,
									altitude: null,
									altitudeAccuracy: null,
									heading: null,
									speed: null
								},
								timestamp: Date.now()
							});
						}, 0);
					},
					watchPosition: function(success, error, options) {
						const watchId = Math.floor(Math.random() * 1000000);
						setTimeout(function() {
							success({
								coords: {
									latitude: %.6f,
									longitude: %.6f,
									accuracy: %.1f,
									altitude: null,
									altitudeAccuracy: null,
									heading: null,
									speed: null
								},
								timestamp: Date.now()
							});
						}, 0);
						return watchId;
					},
					clearWatch: function(watchId) {}
				},
				configurable: false,
				enumerable: true,
				writable: false
			});

			// Override timezone-related functionality
			const originalDate = Date;
			const timezone = '%s';
			
			// Override Date constructor
			Date = function(...args) {
				if (args.length === 0) {
					const date = new originalDate();
					return new originalDate(date.toLocaleString('en-US', {timeZone: timezone}));
				}
				return new originalDate(...args);
			};

			// Copy static methods
			Date.now = originalDate.now;
			Date.parse = originalDate.parse;
			Date.UTC = originalDate.UTC;

			// Ensure prototype chain is correct
			Date.prototype = originalDate.prototype;
			Object.setPrototypeOf(Date, originalDate);

			// Override getTimezoneOffset
			const originalGetTimezoneOffset = Date.prototype.getTimezoneOffset;
			Date.prototype.getTimezoneOffset = function() {
				const date = new originalDate();
				const utcDate = new originalDate(date.toLocaleString('en-US', { timeZone: 'UTC' }));
				const tzDate = new originalDate(date.toLocaleString('en-US', { timeZone: timezone }));
				return (utcDate - tzDate) / 60000;
			};

			// Override Intl.DateTimeFormat
			const originalDateTimeFormat = Intl.DateTimeFormat;
			Intl.DateTimeFormat = function(locales, options = {}) {
				options.timeZone = timezone;
				return new originalDateTimeFormat(locales, options);
			};
			Intl.DateTimeFormat.prototype = originalDateTimeFormat.prototype;

			// Override navigator properties
			Object.defineProperty(navigator, 'userAgent', {
				value: '%s',
				configurable: false,
				writable: false
			});

			Object.defineProperty(navigator, 'platform', {
				value: '%s',
				configurable: false,
				writable: false
			});

			Object.defineProperty(navigator, 'appVersion', {
				value: '%s',
				configurable: false,
				writable: false
			});

			Object.defineProperty(navigator, 'language', {
				value: '%s',
				configurable: false,
				writable: false
			});

			Object.defineProperty(navigator, 'languages', {
				value: ['%s'],
				configurable: false,
				writable: false
			});

			// Override screen properties for iPhone
			if ('%s' === 'iPhone') {
				Object.defineProperty(window, 'screen', {
					value: {
						availHeight: 844,
						availWidth: 390,
						colorDepth: 24,
						height: 844,
						width: 390,
						pixelDepth: 24
					},
					configurable: false,
					writable: false
				});
			}
		})();
		</script>
	`, jitteredLat, jitteredLon, 5.0+mathrand.Float64()*10.0,
		jitteredLat, jitteredLon, 5.0+mathrand.Float64()*10.0,
		timezone,
		config.UserAgent,
		config.Platform,
		config.AppVersion,
		config.AcceptLang,
		config.AcceptLang,
		config.Platform)

	// Only inject into HTML responses
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(strings.ToLower(contentType), "text/html") &&
		!strings.Contains(strings.ToLower(contentType), "application/xhtml") {
		return nil
	}

	// Read the original body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resp.Body.Close()

	// Insert script at the beginning of <head> to ensure it runs first
	newBody := regexp.MustCompile(`<head>`).ReplaceAll(body,
		[]byte("<head>"+script))

	// Update response
	resp.Body = io.NopCloser(bytes.NewReader(newBody))
	resp.ContentLength = int64(len(newBody))
	resp.Header.Set("Content-Length", strconv.Itoa(len(newBody)))

	return nil
}

func getTLSConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
	}
}

func generateHostCertificate(hostname string, caCert tls.Certificate) (*tls.Certificate, error) {
	// Parse the CA certificate and private key
	ca, err := x509.ParseCertificate(caCert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %v", err)
	}

	// Generate a new key for the host certificate
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"Doxxulator Proxy"},
			CommonName:   hostname,
		},
		NotBefore:             time.Now().Add(-10 * time.Minute), // Allow for slight clock skew
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              []string{hostname},
	}

	// Sign the certificate with our CA
	derBytes, err := x509.CreateCertificate(rand.Reader, template, ca, &privKey.PublicKey, caCert.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{derBytes, caCert.Certificate[0]},
		PrivateKey:  privKey,
	}, nil
}

func verifyDoxxNetwork() error {
	switch runtime.GOOS {
	case "windows":
		// Windows-specific VPN interface check
		interfaces, err := net.Interfaces()
		if err != nil {
			return fmt.Errorf("failed to get network interfaces: %v", err)
		}

		hasVPNInterface := false
		for _, iface := range interfaces {
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}

			for _, addr := range addrs {
				ipStr := addr.String()
				if strings.HasPrefix(ipStr, "10.") {
					hasVPNInterface = true
					break
				}
			}
		}

		if !hasVPNInterface {
			return fmt.Errorf("no VPN interface found with 10.x.x.x address. Please check your VPN connection")
		}

	default:
		// Unix-like systems (Linux, macOS) - check for TUN interface
		interfaces, err := net.Interfaces()
		if err != nil {
			return fmt.Errorf("failed to get network interfaces: %v", err)
		}

		hasTunInterface := false
		for _, iface := range interfaces {
			if strings.Contains(strings.ToLower(iface.Name), "tun") {
				addrs, err := iface.Addrs()
				if err != nil {
					continue
				}

				for _, addr := range addrs {
					ipStr := addr.String()
					if strings.HasPrefix(ipStr, "10.") {
						hasTunInterface = true
						break
					}
				}
			}
		}

		if !hasTunInterface {
			return fmt.Errorf("no TUN interface found with 10.x.x.x address. Please check your VPN connection")
		}
	}

	// Verify doxx.net connectivity for all platforms
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get("https://setup.doxx.net/geo/")
	if err != nil {
		return fmt.Errorf("failed to connect to doxx.net: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %v", err)
	}

	bodyStr := string(body)
	if !strings.Contains(bodyStr, "AS-GLOBALTELEHOST") {
		return fmt.Errorf("not connected through GLOBALTELEHOST network")
	}

	return nil
}

func addGPSJitter(lat, lon float64) (float64, float64) {
	// Add random jitter between -0.0005 and +0.0005 degrees (roughly 50 meters)
	latJitter := (mathrand.Float64() - 0.5) * 0.001
	lonJitter := (mathrand.Float64() - 0.5) * 0.001

	return lat + latJitter, lon + lonJitter
}

func dumpHTTPTraffic(prefix string, req *http.Request, body []byte) {
	fmt.Printf("\n%s %s %s\n", prefix, req.Method, req.URL)
	fmt.Println("Headers:")
	for name, values := range req.Header {
		for _, value := range values {
			fmt.Printf("  %s: %s\n", name, value)
		}
	}
	if len(body) > 0 {
		contentType := req.Header.Get("Content-Type")
		if strings.Contains(strings.ToLower(contentType), "text") ||
			strings.Contains(strings.ToLower(contentType), "json") ||
			strings.Contains(strings.ToLower(contentType), "xml") ||
			strings.Contains(strings.ToLower(contentType), "javascript") {
			fmt.Println("\nBody:")
			fmt.Println(string(body))
		} else {
			fmt.Printf("\nBody: [%d bytes of %s data]\n", len(body), contentType)
		}
	}
	fmt.Println(strings.Repeat("-", 80))
}

func main() {
	// Verify doxx.net connection before starting
	if err := verifyDoxxNetwork(); err != nil {
		fmt.Println("❌ Error: Doxxulator only works on doxx.net network")
		fmt.Println("Please visit www.doxx.net for instructions on how to create a free account")
		fmt.Printf("Technical details: %v\n", err)
		os.Exit(1)
	}

	startDoxxulator()
}
