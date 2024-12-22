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
	client         *http.Client
	serverURL      string
	sessionID      string
	readBuffer     []byte
	bufferMutex    sync.Mutex
	pollInterval   time.Duration
	bwMonitor      *BandwidthMonitor
	currentBatch   int // Track number of packets in current batch
	writeBuffer    []byte
	writeBufferMux sync.Mutex
	maxBatchSize   int
	batchTimeout   time.Duration
	lastWrite      time.Time
	fastPath       bool // New field for latency-sensitive packets
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
		bwMonitor:    NewBandwidthMonitor("https"),
	}
}

func (t *HTTPSTransportClient) Connect(serverAddr string) error {
	// Keep original server address for TLS hostname verification
	originalHost := strings.Split(serverAddr, ":")[0]
	port := strings.Split(serverAddr, ":")[1]

	// Resolve IPv4 addresses only
	ips, err := net.LookupIP(originalHost)
	if err != nil {
		return fmt.Errorf("failed to resolve host: %v", err)
	}

	// Filter for IPv4 addresses only
	var ipv4s []string
	for _, ip := range ips {
		if ip.To4() != nil { // This will be nil for IPv6 addresses
			ipv4s = append(ipv4s, ip.String())
		}
	}

	if len(ipv4s) == 0 {
		return fmt.Errorf("no IPv4 addresses found for host: %s", originalHost)
	}

	tr := &http.Transport{
		TLSClientConfig: setupTLSConfig(),
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Use the resolved IP but keep the original port
			return net.Dial(network, fmt.Sprintf("%s:%s", ipv4s[0], port))
		},
	}

	// Create client with CheckRedirect function that prevents following redirects
	t.client = &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Use the original hostname in the URL
	t.serverURL = fmt.Sprintf("https://%s", serverAddr)

	// Test connection using original hostname
	req, err := http.NewRequest("GET", t.serverURL+"/", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	// Set the Host header to the original hostname
	req.Host = originalHost

	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %v", err)
	}
	defer resp.Body.Close()

	// Accept any status code as long as we can establish the connection
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
	fmt.Printf("[HTTPS Client] Generated and stored session ID: %s\n", t.sessionID)

	url := fmt.Sprintf("%s%s", t.serverURL, generateEndpointPath("auth"))
	req, err := http.NewRequest("POST", url, bytes.NewReader([]byte(token)))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	addCommonHeaders(req)
	req.Header.Set("X-For", t.sessionID)
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("auth request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("auth failed with status: %d, body: %s", resp.StatusCode, string(body))
	}

	fmt.Printf("[HTTPS Client] Auth successful, session ID is: %s\n", t.sessionID)
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

				t.bwMonitor.AddBytesIn(uint64(len(packet)))
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

	t.bwMonitor.AddBytesOut(uint64(len(packet)))
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

	t.bwMonitor.AddBytesOut(uint64(len(t.writeBuffer)))
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

func (t *HTTPSTransportClient) CheckAuthStatus() (*AuthResponse, error) {
	fmt.Printf("[HTTPS Client] Starting auth status check with session ID: %s\n", t.sessionID)

	url := fmt.Sprintf("%s%s", t.serverURL, generateEndpointPath("auth_status"))
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	addCommonHeaders(req)
	req.Header.Set("X-For", t.sessionID)

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("auth status request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("auth status failed with status: %d, body: %s", resp.StatusCode, string(body))
	}

	var authResp AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return nil, fmt.Errorf("failed to parse auth status response: %v", err)
	}

	return &authResp, nil
}

func (t *HTTPSTransportClient) HandleAuth() (*AuthResponse, error) {
	fmt.Printf("[HTTPS Client] Checking auth status for session: %s\n", t.sessionID)

	url := fmt.Sprintf("%s%s", t.serverURL, generateEndpointPath("auth_status"))
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	addCommonHeaders(req)
	req.Header.Set("X-For", t.sessionID)
	fmt.Printf("[HTTPS Client] Setting X-For header to: %s\n", t.sessionID)

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("auth status request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("auth status failed with status: %d, body: %s", resp.StatusCode, string(body))
	}

	var authResp AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return nil, fmt.Errorf("failed to parse auth status response: %v", err)
	}

	fmt.Printf("[HTTPS Client] Auth status response: %+v\n", authResp)
	return &authResp, nil
}
