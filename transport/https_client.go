/*
 * Copyright (c) 2024 doxx.net
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * "Commons Clause" License Condition v1.0
 *
 * The Software is provided to you by the Licensor under the License, as defined
 * below, subject to the following condition.
 *
 * Without limiting other conditions in the License, the grant of rights under the
 * License will not include, and the License does not grant to you, the right to
 * Sell the Software.
 *
 * For purposes of the foregoing, "Sell" means practicing any or all of the rights
 * granted to you under the License to provide to third parties, for a fee or other
 * consideration (including without limitation fees for hosting or consulting/
 * support services related to the Software), a product or service whose value
 * derives, entirely or substantially, from the functionality of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/gzip"
	"golang.org/x/net/proxy"
)

type HTTPSTransportClient struct {
	client           *http.Client
	serverURL        string
	sessionID        string
	readBuffer       []byte
	bufferMutex      sync.Mutex
	pollInterval     time.Duration
	currentBatch     int // Track number of packets in current batch
	writeBuffer      []byte
	writeBufferMux   sync.Mutex
	maxBatchSize     int
	batchTimeout     time.Duration
	lastWrite        time.Time
	fastPath         bool // New field for latency-sensitive packets
	originalHostname string
	authResponse     *AuthResponse
}

type ProxyConfig struct {
	URL  *url.URL
	Type string // "http", "https", or "socks5"
}

func ParseProxyURL(proxyURL string) (*ProxyConfig, error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %v", err)
	}

	switch u.Scheme {
	case "http", "https", "socks5":
		return &ProxyConfig{
			URL:  u,
			Type: u.Scheme,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported proxy scheme: %s", u.Scheme)
	}
}

func NewHTTPSTransportClient(proxyConfig *ProxyConfig) TransportType {
	tr := &http.Transport{
		TLSClientConfig: setupTLSConfig(),
	}

	// Configure proxy if provided
	if proxyConfig != nil {
		switch proxyConfig.Type {
		case "http", "https":
			tr.Proxy = http.ProxyURL(proxyConfig.URL)
		case "socks5":
			// Create SOCKS5 dialer
			auth := &proxy.Auth{}
			if proxyConfig.URL.User != nil {
				auth.User = proxyConfig.URL.User.Username()
				if pass, ok := proxyConfig.URL.User.Password(); ok {
					auth.Password = pass
				}
			}

			dialer, err := proxy.SOCKS5("tcp", proxyConfig.URL.Host, auth, proxy.Direct)
			if err != nil {
				log.Printf("Warning: Failed to create SOCKS5 dialer: %v", err)
				break
			}

			tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			}
		}
	}

	return &HTTPSTransportClient{
		client: &http.Client{
			Transport: tr,
			Timeout:   30 * time.Second,
		},
		maxBatchSize: 1024 * 1024,
		batchTimeout: 20 * time.Millisecond,
		lastWrite:    time.Now(),
		fastPath:     false,
	}
}

func (t *HTTPSTransportClient) Connect(addr string) error {
	// Store the original hostname for TLS verification and Host header
	hostname, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid address format: %v", err)
	}

	// If this is an IP address, we need to use the original hostname for SNI
	ip := net.ParseIP(hostname)
	if ip != nil {
		// Use the stored original hostname instead of the IP
		if t.originalHostname == "" {
			return fmt.Errorf("no hostname available for SNI")
		}
		debugLogc("[HTTPS Client] Connecting to IP: %s:%s with SNI hostname: %s", hostname, port, t.originalHostname)
	} else {
		// Store the hostname for later use with IP connections
		t.originalHostname = hostname
		// Use the provided address directly - no DNS lookup
		debugLogc("[HTTPS Client] Using provided address: %s:%s", hostname, port)
	}

	// Configure transport with custom TLS config that includes ServerName
	tlsConfig := setupTLSConfig()
	tlsConfig.ServerName = t.originalHostname
	debugLogc("[HTTPS Client] Set TLS ServerName to: %s", t.originalHostname)

	t.client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
			// Don't follow redirects
			Proxy: nil,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Use the provided address with port for the connection URL
	t.serverURL = fmt.Sprintf("https://%s:%s", hostname, port)
	debugLogc("[HTTPS Client] Using server URL: %s", t.serverURL)

	// Test connection
	req, err := http.NewRequest("GET", t.serverURL+"/", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	// Always use the original hostname in the Host header
	req.Host = t.originalHostname
	addCommonHeaders(req)
	debugLogc("[HTTPS Client] Set request Host header to: %s", t.originalHostname)

	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %v", err)
	}
	defer resp.Body.Close()

	debugLogc("[HTTPS Client] Successfully connected to server")
	return nil
}

func setupTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,

		// Curves that Chrome supports, in Chrome's preference order
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
		},

		// Chrome's cipher suite preferences for TLS 1.2
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},

		// Additional Chrome-like settings
		PreferServerCipherSuites: false,
		SessionTicketsDisabled:   false,
		ClientSessionCache:       tls.NewLRUClientSessionCache(32),

		// Renegotiation settings
		Renegotiation: tls.RenegotiateNever,

		// Allow self-signed certificates
		InsecureSkipVerify: true,
	}
}

func addCommonHeaders(req *http.Request) {
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")

	// Enhanced cache control headers
	req.Header.Set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Expires", "0")

	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Sec-Ch-Ua", "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"")
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Sec-Ch-Ua-Platform", "\"Windows\"")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
}

func (t *HTTPSTransportClient) SendAuth(token string) error {
	// Generate and assign session ID
	t.sessionID = fmt.Sprintf("%d-%s", time.Now().UnixNano(), generateRandomString(8))
	debugLogc("[HTTPS Client] Generated and stored session ID: %s", t.sessionID)

	url := fmt.Sprintf("%s%s", t.serverURL, generateEndpointPath("auth"))
	req, err := http.NewRequest("POST", url, bytes.NewReader([]byte(token)))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	addCommonHeaders(req)
	req.Host = t.originalHostname
	req.Header.Set("X-For", t.sessionID)
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("auth request failed: %v", err)
	}
	defer resp.Body.Close()

	// Read and parse the response
	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read auth response: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		if title := extractTitle(string(rawBody)); title != "" {
			return fmt.Errorf("auth failed with status: %d, error: %s", resp.StatusCode, title)
		}
		return fmt.Errorf("auth failed with status: %d", resp.StatusCode)
	}

	debugLogc("[HTTPS Client] Raw auth response: %s", string(rawBody))

	var authResp AuthResponse
	if err := json.Unmarshal(rawBody, &authResp); err != nil {
		return fmt.Errorf("failed to parse auth response: %v", err)
	}

	// Create a modified auth response with correct assignments
	t.authResponse = &AuthResponse{
		Status:             authResp.Status,
		Message:            authResp.Message,
		User:               authResp.User,
		KeepEstablishedSSH: authResp.KeepEstablishedSSH,
		KillDefaultRoute:   authResp.KillDefaultRoute,
		AutoReconnect:      authResp.AutoReconnect,
		EnableRouting:      authResp.EnableRouting,
		SnarfDNS:           authResp.SnarfDNS,
		AssignedIP:         authResp.ClientIP, // Use ClientIP for local address
		ServerIP:           authResp.ServerIP,
		ClientIP:           authResp.ClientIP,
		PrefixLen:          authResp.PrefixLen,
		Backbone:           authResp.Backbone,
		BandwidthStats:     authResp.BandwidthStats, // Make sure we copy these
		SecurityStats:      authResp.SecurityStats,  // Make sure we copy these
	}

	debugLogc("[HTTPS Client] Auth successful, parsed config: %+v", t.authResponse)
	return nil
}

func (t *HTTPSTransportClient) ReadPacket() ([]byte, error) {
	t.bufferMutex.Lock()
	if len(t.readBuffer) >= 4 {
		// If we're starting a new batch, read the packet count
		if t.currentBatch == 0 {
			t.currentBatch = int(t.readBuffer[0])<<24 | int(t.readBuffer[1])<<16 |
				int(t.readBuffer[2])<<8 | int(t.readBuffer[3])
			t.readBuffer = t.readBuffer[4:]
		}

		// Read packet length prefix
		if len(t.readBuffer) >= 4 {
			length := int(t.readBuffer[0])<<24 | int(t.readBuffer[1])<<16 |
				int(t.readBuffer[2])<<8 | int(t.readBuffer[3])

			if len(t.readBuffer) >= 4+length {
				// Extract the packet
				packet := make([]byte, length)
				copy(packet, t.readBuffer[4:4+length])
				t.readBuffer = t.readBuffer[4+length:]
				t.currentBatch--
				t.bufferMutex.Unlock()

				return packet, nil
			}
		}
	}
	t.bufferMutex.Unlock()

	// Buffer empty or incomplete, get more data
	endpoint := "read"
	if t.fastPath {
		endpoint = "poll"
	}
	url := fmt.Sprintf("%s%s", t.serverURL, generateEndpointPath(endpoint))
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	addCommonHeaders(req)
	req.Host = t.originalHostname
	req.Header.Set("X-For", t.sessionID)

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("read request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		time.Sleep(20 * time.Millisecond)
		return t.ReadPacket()
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("read failed with status: %d, body: %s", resp.StatusCode, string(body))
	}

	var reader io.Reader = resp.Body
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gzipReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("error creating gzip reader: %v", err)
		}
		defer gzipReader.Close()
		reader = gzipReader
	}

	// Read the entire response
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}

	// Add to buffer and try again
	t.bufferMutex.Lock()
	t.readBuffer = append(t.readBuffer, data...)
	t.currentBatch = 0 // Reset batch count for new data
	t.bufferMutex.Unlock()

	return t.ReadPacket()
}

func (t *HTTPSTransportClient) WritePacket(packet []byte) error {
	// Fast path for latency-sensitive packets (like ICMP)
	if isLatencySensitivePacket(packet) {
		return t.sendImmediately(packet)
	}

	t.writeBufferMux.Lock()
	defer t.writeBufferMux.Unlock()

	// Prepare packet with length prefix
	packetWithLength := make([]byte, 4+len(packet))
	packetWithLength[0] = byte(len(packet) >> 24)
	packetWithLength[1] = byte(len(packet) >> 16)
	packetWithLength[2] = byte(len(packet) >> 8)
	packetWithLength[3] = byte(len(packet))
	copy(packetWithLength[4:], packet)

	t.writeBuffer = append(t.writeBuffer, packetWithLength...)

	// Send batch if size threshold exceeded or timeout reached
	if len(t.writeBuffer) >= t.maxBatchSize || time.Since(t.lastWrite) >= t.batchTimeout {
		return t.flushWriteBuffer()
	}

	return nil
}

// New function to handle latency-sensitive packets
func (t *HTTPSTransportClient) sendImmediately(packet []byte) error {
	// Prepare single-packet batch
	header := make([]byte, 4)
	header[0], header[1], header[2], header[3] = 0, 0, 0, 1 // batch count = 1

	packetWithLength := make([]byte, 4+len(packet))
	packetWithLength[0] = byte(len(packet) >> 24)
	packetWithLength[1] = byte(len(packet) >> 16)
	packetWithLength[2] = byte(len(packet) >> 8)
	packetWithLength[3] = byte(len(packet))
	copy(packetWithLength[4:], packet)

	data := append(header, packetWithLength...)

	url := fmt.Sprintf("%s%s", t.serverURL, generateEndpointPath("write"))
	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("batch write request failed: %v", err)
	}

	addCommonHeaders(req)
	req.Host = t.originalHostname
	req.Header.Set("X-For", t.sessionID)
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("fast write request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("fast write failed with status: %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (t *HTTPSTransportClient) flushWriteBuffer() error {
	if len(t.writeBuffer) == 0 {
		return nil
	}

	// Prepare batch header with packet count
	batchCount := 0
	remaining := t.writeBuffer
	for len(remaining) > 4 {
		length := int(remaining[0])<<24 | int(remaining[1])<<16 |
			int(remaining[2])<<8 | int(remaining[3])
		if len(remaining) < 4+length {
			break
		}
		batchCount++
		remaining = remaining[4+length:]
	}

	header := make([]byte, 4)
	header[0] = byte(batchCount >> 24)
	header[1] = byte(batchCount >> 16)
	header[2] = byte(batchCount >> 8)
	header[3] = byte(batchCount)

	// Use generateEndpointPath for write endpoint
	url := fmt.Sprintf("%s%s", t.serverURL, generateEndpointPath("write"))
	data := append(header, t.writeBuffer...)
	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("batch write request failed: %v", err)
	}

	addCommonHeaders(req)
	req.Host = t.originalHostname
	req.Header.Set("X-For", t.sessionID)
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("batch write request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("batch write failed with status: %d, body: %s", resp.StatusCode, string(body))
	}

	t.writeBuffer = nil
	t.lastWrite = time.Now()

	return nil
}

func (t *HTTPSTransportClient) Close() error {
	fmt.Printf("[HTTPS Client] Closing transport\n")
	t.client.CloseIdleConnections()
	return nil
}

func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func (t *HTTPSTransportClient) HandleAuth() (*AuthResponse, error) {
	if t.authResponse == nil {
		return nil, fmt.Errorf("no auth response available - call SendAuth first")
	}

	debugLogc("[HTTPS Client] Network Configuration:")
	debugLogc("  - Assigned IP: %s", t.authResponse.AssignedIP)
	debugLogc("  - Server IP: %s", t.authResponse.ServerIP)
	debugLogc("  - Client IP: %s", t.authResponse.ClientIP)
	debugLogc("  - Prefix Length: %d", t.authResponse.PrefixLen)

	// Create a complete response that includes all server settings
	response := &AuthResponse{
		Status:             "success",
		ServerIP:           t.authResponse.ServerIP,
		ClientIP:           t.authResponse.ClientIP,
		AssignedIP:         t.authResponse.AssignedIP,
		PrefixLen:          t.authResponse.PrefixLen,
		KeepEstablishedSSH: t.authResponse.KeepEstablishedSSH,
		KillDefaultRoute:   t.authResponse.KillDefaultRoute,
		AutoReconnect:      t.authResponse.AutoReconnect,
		EnableRouting:      t.authResponse.EnableRouting,
		SnarfDNS:           t.authResponse.SnarfDNS,
		Backbone:           t.authResponse.Backbone,
		BandwidthStats:     t.authResponse.BandwidthStats,
		SecurityStats:      t.authResponse.SecurityStats,
	}

	// Clear the stored response and return the complete one
	t.authResponse = nil
	return response, nil
}

func (t *HTTPSTransportClient) SetOriginalHostname(hostname string) {
	t.originalHostname = hostname
	debugLogc("[HTTPS Client] Set original hostname to: %s", hostname)
}

func extractTitle(html string) string {
	titleStart := strings.Index(html, "<title>")
	if titleStart == -1 {
		return ""
	}
	titleStart += 7 // length of "<title>"

	titleEnd := strings.Index(html[titleStart:], "</title>")
	if titleEnd == -1 {
		return ""
	}

	return strings.TrimSpace(html[titleStart : titleStart+titleEnd])
}
