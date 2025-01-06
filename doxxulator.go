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
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/elazarl/goproxy"
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
}

var (
	// Pre-defined browser User-Agents instead of ClientHelloID
	browserProfiles = map[string]struct {
		UserAgent    string
		AcceptLang   string
		Platform     string
		Architecture string
	}{
		"chrome": {
			UserAgent:    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
			AcceptLang:   "en-US,en;q=0.9",
			Platform:     "MacIntel",
			Architecture: "x86_64",
		},
		"firefox": {
			UserAgent:    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0",
			AcceptLang:   "en-US,en;q=0.5",
			Platform:     "MacIntel",
			Architecture: "x86_64",
		},
		"safari": {
			UserAgent:    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
			AcceptLang:   "en-US,en;q=0.9",
			Platform:     "MacIntel",
			Architecture: "x86_64",
		},
		"edge": {
			UserAgent:    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59",
			AcceptLang:   "en-US,en;q=0.9",
			Platform:     "Win32",
			Architecture: "x86_64",
		},
	}

	// Pre-defined locations with lat/long
	locations = map[string]struct {
		Lat float64
		Lon float64
	}{
		"new-york":    {40.7128, -74.0060},
		"london":      {51.5074, -0.1278},
		"tokyo":       {35.6762, 139.6503},
		"paris":       {48.8566, 2.3522},
		"singapore":   {1.3521, 103.8198},
		"dubai":       {25.2048, 55.2708},
		"hong-kong":   {22.3193, 114.1694},
		"shanghai":    {31.2304, 121.4737},
		"sydney":      {-33.8688, 151.2093},
		"miami":       {25.7617, -80.1918},
		"chicago":     {41.8781, -87.6298},
		"moscow":      {55.7558, 37.6173},
		"berlin":      {52.5200, 13.4050},
		"mumbai":      {19.0760, 72.8777},
		"sao-paulo":   {-23.5505, -46.6333},
		"istanbul":    {41.0082, 28.9784},
		"rome":        {41.9028, 12.4964},
		"seoul":       {37.5665, 126.9780},
		"mexico-city": {19.4326, -99.1332},
		"amsterdam":   {52.3676, 4.9041},
		"toronto":     {43.6532, -79.3832},
		"los-angeles": {34.0522, -118.2437},
		"madrid":      {40.4168, -3.7038},
		"vienna":      {48.2082, 16.3738},
		"bangkok":     {13.7563, 100.5018},
		"beijing":     {39.9042, 116.4074},
		// ... and so on
	}

	// Add language mappings for locations
	locationLanguages = map[string]string{
		"new-york":    "en-US,en;q=0.9",
		"london":      "en-GB,en;q=0.9",
		"tokyo":       "ja-JP,ja;q=0.9,en;q=0.8",
		"paris":       "fr-FR,fr;q=0.9,en;q=0.8",
		"singapore":   "en-SG,en;q=0.9,zh-SG;q=0.8",
		"dubai":       "ar-AE,ar;q=0.9,en;q=0.8",
		"hong-kong":   "zh-HK,zh;q=0.9,en;q=0.8",
		"shanghai":    "zh-CN,zh;q=0.9,en;q=0.8",
		"sydney":      "en-AU,en;q=0.9",
		"berlin":      "de-DE,de;q=0.9,en;q=0.8",
		"moscow":      "ru-RU,ru;q=0.9,en;q=0.8",
		"mumbai":      "hi-IN,hi;q=0.9,en;q=0.8",
		"sao-paulo":   "pt-BR,pt;q=0.9,en;q=0.8",
		"istanbul":    "tr-TR,tr;q=0.9,en;q=0.8",
		"rome":        "it-IT,it;q=0.9,en;q=0.8",
		"seoul":       "ko-KR,ko;q=0.9,en;q=0.8",
		"mexico-city": "es-MX,es;q=0.9,en;q=0.8",
		"amsterdam":   "nl-NL,nl;q=0.9,en;q=0.8",
		"madrid":      "es-ES,es;q=0.9,en;q=0.8",
		// Default to en-US for any unlisted locations
	}
)

func startDoxxulator() {
	config := parseFlags()

	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = config.Debug

	// First ensure certificates exist
	if err := ensureCertificates(config); err != nil {
		log.Fatalf("❌ Failed to generate certificates: %v", err)
	}

	// Now load the certificates (which we know exist)
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

		// Known hosts that use certificate pinning
		pinnedHosts := []string{
			// Slack domains
			".slack.com", // This will catch all Slack subdomains
			"edgeapi.slack.com",
			"wss-backup.slack.com",

			// Discord domains
			".cursor.sh",
			"cursor.sh",

			// Google stuff
			".googleapis.com",

			// Discord domains
			".discord.com",
			"discord.com",
			"media.discordapp.net",
			"gateway.discord.gg",

			// Apple/iCloud domains
			"gateway.icloud.com",
			"icloud.com",
			"apple.com",
			"push.apple.com",
		}

		if config.AllowPassthrough {
			// Check if host should bypass MITM
			hostLower := strings.ToLower(host)
			hostName := strings.Split(hostLower, ":")[0] // Remove port number if present

			for _, pinned := range pinnedHosts {
				if strings.HasSuffix(hostName, pinned) ||
					(strings.HasPrefix(pinned, ".") && strings.Contains(hostName, pinned)) {
					if config.Debug {
						log.Printf("🔒 Bypassing MITM for %s (certificate pinning detected)", host)
					}
					// Return immediately with a direct connection
					return &goproxy.ConnectAction{
						Action:    goproxy.ConnectAccept,
						TLSConfig: nil, // Explicitly set to nil to ensure passthrough
					}, host
				}
			}

			if config.Debug {
				log.Printf("⚠️ Host %s not in pinned list, proceeding with MITM", hostName)
			}
		}

		if config.Debug {
			log.Printf("🔐 Applying MITM for %s", host)
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
	flag.StringVar(&config.Browser, "browser", "chrome", "Browser to emulate (chrome, firefox, safari, edge)")
	flag.StringVar(&config.Location, "location", "new-york", locationsHelp)
	flag.StringVar(&config.CertPath, "cert", "cert.pem", "Path to certificate file")
	flag.StringVar(&config.KeyPath, "key", "key.pem", "Path to private key file")
	flag.BoolVar(&config.Debug, "log", false, "Enable request logging")
	flag.Float64Var(&config.CustomLat, "lat", 0, "Custom latitude (required when using -location=custom)")
	flag.Float64Var(&config.CustomLon, "lon", 0, "Custom longitude (required when using -location=custom)")
	flag.BoolVar(&config.AllowPassthrough, "allow-passthrough", false,
		"Allow certificate passthrough for apps with SSL pinning (e.g., Slack, Discord). "+
			"This bypasses MITM for these apps but allows them to connect.")

	// Custom usage message
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Doxxulator: A proxy for location and browser spoofing\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  %s [flags]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  %s -location=tokyo\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -location=custom -lat=35.6762 -lon=139.6503\n", os.Args[0])
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
	if lang, ok := locationLanguages[config.Location]; ok {
		req.Header.Set("Accept-Language", lang)
	} else {
		// Fall back to the browser profile's default language
		req.Header.Set("Accept-Language", config.AcceptLang)
	}

	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Sec-CH-UA-Platform", config.Platform)
	req.Header.Set("Sec-CH-UA-Architecture", config.Architecture)

	// Geolocation headers
	var lat, lon float64
	if config.Location == "custom" {
		lat, lon = config.CustomLat, config.CustomLon
	} else if loc, ok := locations[config.Location]; ok {
		lat, lon = loc.Lat, loc.Lon
	}

	req.Header.Set("X-Geo-Lat", fmt.Sprintf("%f", lat))
	req.Header.Set("X-Geo-Lon", fmt.Sprintf("%f", lon))
	req.Header.Set("Permissions-Policy", fmt.Sprintf(
		"geolocation=(%f %f)",
		lat, lon,
	))
}

func injectGeolocationScript(resp *http.Response, config *Config) error {
	var lat, lon float64
	if config.Location == "custom" {
		lat, lon = config.CustomLat, config.CustomLon
	} else if loc, ok := locations[config.Location]; ok {
		lat, lon = loc.Lat, loc.Lon
	} else {
		return nil
	}

	// Only inject into HTML responses
	if !strings.Contains(resp.Header.Get("Content-Type"), "html") {
		return nil
	}

	// Read the original body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resp.Body.Close()

	// Inject our geolocation override script
	script := fmt.Sprintf(`
		<script>
		// Override geolocation API
		const fakePosition = {
			coords: {
				latitude: %f,
				longitude: %f,
				accuracy: 10,
				altitude: null,
				altitudeAccuracy: null,
				heading: null,
				speed: null
			},
			timestamp: Date.now()
		};

		navigator.geolocation.getCurrentPosition = function(success) {
			success(fakePosition);
		};

		navigator.geolocation.watchPosition = function(success) {
			success(fakePosition);
			return Math.floor(Math.random() * 1000000);
		};

		// Override platform detection
		Object.defineProperty(navigator, 'platform', {
			get: function() { return '%s'; }
		});

		Object.defineProperty(navigator, 'userAgent', {
			get: function() { return '%s'; }
		});
		</script>
	`, lat, lon, config.Platform, config.UserAgent)

	// Insert script before </head> or </body>
	newBody := regexp.MustCompile(`</head>`).ReplaceAll(body,
		[]byte(script+"</head>"))

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
	// First check TUN interface
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

	// Then perform the existing doxx.net verification
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
