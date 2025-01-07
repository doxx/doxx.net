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

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"doxx.net/transport"
	"github.com/jackpal/gateway"
	psnet "github.com/shirou/gopsutil/v3/net"
)

const (
	MTU         = 1500
	HEADER_SIZE = 4
	DNS_PORT    = 53
	ASCII_LOGO  = `
    _______                ___                    __   
    \____  \  ____  ___  ___  \__   ____   ____ _/  |_ 
     |  |\  \/  _ \ \  \/  /\   /  /    \ /  __\\   __\
     |  |/   ( <_> ) >    </    \ |   |  (  ___)|  |  
    /_______  \____/ /__/\_  /\__/|___|  /\____/|__|  
            \_/           \_/         \_/               
                        
     [ Copyright (c) Barrett Lyon 2024 - https://doxx.net ]
     [ Secure Networking for Humans                       ]
`
)

var (
	debug                 bool
	snarfDNS              = true // Changed to default true
	bandwidthDisplayReady = make(chan struct{})
	dnsNatTable           *DNSNatTable
)

func init() {
	flag.BoolVar(&debug, "debug", false, "enable debug logging")
}

type RouteManager struct {
	defaultGW    string
	defaultIface string
	staticRoutes []string
	serverIPs    []net.IP
	tunInterface string
	clientIP     string
	serverIP     string
	killRoute    bool
	keepSSH      bool
	sshRoutes    []string
	mu           sync.Mutex
}

type AuthResponse struct {
	Success    bool   `json:"success"`
	AssignedIP string `json:"assigned_ip"`
	PrefixLen  int    `json:"prefix_len"`
	Status     string `json:"status"`
	Message    string `json:"message"`
}

type GeoResponse struct {
	IP      string `json:"ip"`
	Country struct {
		Code string `json:"code"`
		Name string `json:"name"`
	} `json:"country"`
	City struct {
		Name      string  `json:"name"`
		Latitude  float64 `json:"latitude"`
		Longitude float64 `json:"longitude"`
	} `json:"city"`
	Continent struct {
		Code string `json:"code"`
		Name string `json:"name"`
	} `json:"continent"`
	Timezone         string `json:"timezone"`
	AutonomousSystem struct {
		Number       int    `json:"number"`
		Organization string `json:"organization"`
	} `json:"autonomous_system"`
}

func NewRouteManager(tunIface string, killRoute bool, keepSSH bool) *RouteManager {
	return &RouteManager{
		tunInterface: tunIface,
		staticRoutes: make([]string, 0),
		sshRoutes:    make([]string, 0),
		killRoute:    killRoute,
		keepSSH:      keepSSH,
	}
}

// Add Cloudflare IP ranges
var cloudflareRanges = []string{
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
	"172.67.0.0/16",
	"104.21.0.0/16",
}

func (rm *RouteManager) Setup(serverAddr string) error {
	// Extract hostname/IP from server address by removing port
	host := strings.Split(serverAddr, ":")[0]

	// Check if this is a Cloudflare-proxied domain
	if strings.Contains(serverAddr, "cdn.") && strings.Contains(serverAddr, ".doxx.net") {
		debugLog("Detected Cloudflare-proxied domain, setting up Cloudflare routes")

		// Get current default route
		gw, iface, err := rm.getCurrentDefaultRoute()
		if err != nil {
			return fmt.Errorf("failed to get current default route: %v", err)
		}

		rm.mu.Lock()
		rm.defaultGW = gw
		rm.defaultIface = iface
		rm.mu.Unlock()

		// Add static routes for all Cloudflare IP ranges
		for _, cidr := range cloudflareRanges {
			debugLog("Adding Cloudflare route for %s", cidr)
			if err := rm.addStaticRoute(cidr, gw, iface); err != nil {
				return fmt.Errorf("failed to add Cloudflare route for %s: %v", cidr, err)
			}
			rm.mu.Lock()
			rm.staticRoutes = append(rm.staticRoutes, cidr)
			rm.mu.Unlock()
		}
	} else {
		// For connections, resolve the IP address first
		ips, err := net.LookupIP(host)
		if err != nil {
			return fmt.Errorf("failed to resolve server address %s: %v", host, err)
		}
		if len(ips) == 0 {
			return fmt.Errorf("no IP addresses found for %s", host)
		}

		// Get current default route
		gw, iface, err := rm.getCurrentDefaultRoute()
		if err != nil {
			return fmt.Errorf("failed to get current default route: %v", err)
		}

		rm.mu.Lock()
		rm.defaultGW = gw
		rm.defaultIface = iface
		rm.mu.Unlock()

		// Add static route for each resolved IP
		for _, ip := range ips {
			if ip.To4() != nil { // Only handle IPv4 addresses for now
				ipStr := ip.String()
				debugLog("Adding static route for VPN server %s", ipStr)
				if err := rm.addStaticRoute(ipStr+"/32", gw, iface); err != nil {
					return fmt.Errorf("failed to add static route for VPN server IP %s: %v", ipStr, err)
				}
				rm.mu.Lock()
				rm.staticRoutes = append(rm.staticRoutes, ipStr+"/32")
				rm.serverIPs = append(rm.serverIPs, ip)
				rm.mu.Unlock()
			}
		}
	}

	debugLog("Using VPN server IP from auth response for default route")

	// Preserve SSH connections before setting default route
	if err := rm.preserveExistingSSHConnections(); err != nil {
		log.Printf("Warning: Failed to preserve SSH connections: %v", err)
	}

	// Set new default route via TUN using VPN server IP from auth response
	if err := rm.setDefaultRoute(rm.tunInterface, rm.serverIP); err != nil {
		return fmt.Errorf("failed to set default route: %v", err)
	}

	return nil
}

func (rm *RouteManager) Cleanup() error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	// Only proceed with route cleanup if we have the original default gateway
	if rm.defaultGW == "" {
		debugLog("No default gateway stored, skipping route cleanup")
		return nil
	}

	// Remove SSH routes first
	for _, route := range rm.sshRoutes {
		debugLog("Removing SSH route: %s", route)
		if err := rm.removeStaticRoute(route); err != nil {
			log.Printf("Failed to remove SSH route %s: %v", route, err)
		}
	}

	// Remove static routes
	for _, route := range rm.staticRoutes {
		debugLog("Removing route: %s", route)
		if err := rm.removeStaticRoute(route); err != nil {
			log.Printf("Failed to remove route %s: %v", route, err)
		}
	}

	if rm.killRoute {
		// Print instructions for restoring the default route
		switch runtime.GOOS {
		case "darwin":
			log.Printf("To restore your default route, run:\n"+
				"sudo route -n add default %s", rm.defaultGW)
		case "linux":
			log.Printf("To restore your default route, run:\n"+
				"sudo ip route add default via %s dev %s", rm.defaultGW, rm.defaultIface)
		}
		return nil
	}

	// Only attempt to restore default route if we have the necessary information
	if rm.defaultGW != "" && rm.defaultIface != "" {
		debugLog("Restoring default route via %s on %s", rm.defaultGW, rm.defaultIface)

		// Restore original default route
		switch runtime.GOOS {
		case "darwin":
			// First delete the current default route
			delCmd := exec.Command("route", "-n", "delete", "default")
			if out, err := delCmd.CombinedOutput(); err != nil {
				debugLog("Note: Could not delete current default route: %v\nOutput: %s", err, string(out))
				// Continue anyway as we want to try setting the new route
			}

			// Add back the original default route
			addCmd := exec.Command("route", "-n", "add", "default", rm.defaultGW)
			if out, err := addCmd.CombinedOutput(); err != nil {
				return fmt.Errorf("failed to restore default route: %v\nOutput: %s", err, string(out))
			}

		case "linux":
			// First delete the current default route
			delCmd := exec.Command("ip", "route", "del", "default")
			if out, err := delCmd.CombinedOutput(); err != nil {
				debugLog("Note: Could not delete current default route: %v\nOutput: %s", err, string(out))
				// Continue anyway as we want to try setting the new route
			}

			// Add back the original default route
			addCmd := exec.Command("ip", "route", "add", "default", "via", rm.defaultGW, "dev", rm.defaultIface)
			if out, err := addCmd.CombinedOutput(); err != nil {
				return fmt.Errorf("failed to restore default route: %v\nOutput: %s", err, string(out))
			}

		case "windows":
			// First delete the current default route
			delCmd := exec.Command("route", "delete", "0.0.0.0", "mask", "0.0.0.0")
			if out, err := delCmd.CombinedOutput(); err != nil {
				debugLog("Note: Could not delete current default route: %v\nOutput: %s", err, string(out))
				// Continue anyway as we want to try setting the new route
			}

			// Add back the original default route
			addCmd := exec.Command("route", "add", "0.0.0.0", "mask", "0.0.0.0", rm.defaultGW)
			if out, err := addCmd.CombinedOutput(); err != nil {
				return fmt.Errorf("failed to restore default route: %v\nOutput: %s", err, string(out))
			}
		}

		debugLog("Successfully restored default route")
		return nil
	}

	debugLog("No default route information available, skipping route restoration")
	return nil
}

// TransportType represents a VPN transport layer type
type TransportType interface {
	Connect(serverAddr string) error
	Close() error
	ReadPacket() ([]byte, error)
	WritePacket([]byte) error
	SendAuth(token string) error
	HandleAuth() (*AuthResponse, error)
}

// SingleTCPTransport implements the basic TCP transport
type SingleTCPTransport struct {
	conn net.Conn
}

func NewSingleTCPTransport() *SingleTCPTransport {
	return &SingleTCPTransport{}
}

func (t *SingleTCPTransport) Connect(serverAddr string) error {
	// Set a reasonable timeout for the initial connection
	dialer := net.Dialer{
		Timeout: 10 * time.Second,
	}

	conn, err := dialer.Dial("tcp", serverAddr)
	if err != nil {
		switch {
		case strings.Contains(err.Error(), "no such host"):
			return fmt.Errorf("cannot resolve %s - please check your DNS settings or internet connection", serverAddr)
		case strings.Contains(err.Error(), "connection refused"):
			return fmt.Errorf("connection refused to %s - please verify the server is running and accessible", serverAddr)
		case strings.Contains(err.Error(), "i/o timeout"):
			return fmt.Errorf("connection timed out - please check your internet connection and firewall settings")
		case strings.Contains(err.Error(), "network is unreachable"):
			return fmt.Errorf("network is unreachable - please check your network connection and default gateway")
		default:
			return fmt.Errorf("connection failed: %v", err)
		}
	}

	// Set read/write timeouts for the established connection
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	t.conn = conn
	return nil
}

func (t *SingleTCPTransport) Close() error {
	if t.conn != nil {
		return t.conn.Close()
	}
	return nil
}

func (t *SingleTCPTransport) ReadPacket() ([]byte, error) {
	if t.conn == nil {
		return nil, fmt.Errorf("connection is closed")
	}

	// Set read deadline for each packet
	if err := t.conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return nil, fmt.Errorf("failed to set read deadline: %v", err)
	}

	packet, err := readPacket(t.conn)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return nil, fmt.Errorf("connection timed out - network may be down")
		}
		return nil, err
	}
	return packet, nil
}

func (t *SingleTCPTransport) WritePacket(packet []byte) error {
	if t.conn == nil {
		return fmt.Errorf("connection is closed")
	}

	// Set write deadline for each packet
	if err := t.conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return fmt.Errorf("failed to set write deadline: %v", err)
	}

	if err := writePacket(t.conn, packet); err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return fmt.Errorf("write timed out - network may be down")
		}
		return err
	}
	return nil
}

func (t *SingleTCPTransport) SendAuth(token string) error {
	return writePacket(t.conn, []byte(token))
}

func (t *SingleTCPTransport) HandleAuth() (*AuthResponse, error) {
	packet, err := readPacket(t.conn)
	if err != nil {
		return nil, fmt.Errorf("connection error during authentication: %v", err)
	}

	debugLog("Auth server response: %s", string(packet))

	var response AuthResponse
	if err := json.Unmarshal(packet, &response); err != nil {
		return nil, fmt.Errorf("failed to parse server response: %v", err)
	}

	// Check for error response format
	if response.Status == "error" {
		return nil, fmt.Errorf("authentication rejected: %s", response.Message)
	}

	// Check for success response format
	if !response.Success {
		return nil, fmt.Errorf("authentication rejected by server")
	}

	if response.AssignedIP == "" {
		return nil, fmt.Errorf("server did not assign an IP address")
	}

	return &response, nil
}

// Add these new types for bandwidth monitoring
type BandwidthStats struct {
	rxBytes    uint64
	txBytes    uint64
	lastRx     uint64
	lastTx     uint64
	lastUpdate time.Time
	mu         sync.Mutex
}

func NewBandwidthStats() *BandwidthStats {
	return &BandwidthStats{
		lastUpdate: time.Now(),
	}
}

func (bs *BandwidthStats) Update(rx, tx uint64) {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	now := time.Now()
	duration := now.Sub(bs.lastUpdate).Seconds()

	rxDiff := rx - bs.lastRx
	txDiff := tx - bs.lastTx

	// Calculate bytes per second
	bs.rxBytes = uint64(float64(rxDiff) / duration)
	bs.txBytes = uint64(float64(txDiff) / duration)

	bs.lastRx = rx
	bs.lastTx = tx
	bs.lastUpdate = now
}

func (bs *BandwidthStats) GetReadable() string {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	return fmt.Sprintf("\r↓ %-12s  ↑ %-12s    ↓ %-10s  ↑ %-10s    ",
		formatBytes(bs.rxBytes),
		formatBytes(bs.txBytes),
		formatBits(bs.rxBytes),
		formatBits(bs.txBytes))
}

func formatBytes(bytes uint64) string {
	switch {
	case bytes >= 1024*1024*1024: // 1 GB
		return fmt.Sprintf("%.1f GB/s", float64(bytes)/(1024*1024*1024))
	case bytes >= 1024*1024: // 1 MB
		return fmt.Sprintf("%.1f MB/s", float64(bytes)/(1024*1024))
	case bytes >= 1024: // 1 KB
		return fmt.Sprintf("%.1f KB/s", float64(bytes)/1024)
	default:
		if bytes < 1 {
			return "0 B/s"
		}
		return fmt.Sprintf("%d B/s", bytes)
	}
}

func formatBits(bytes uint64) string {
	bits := bytes * 8 // Convert bytes/sec to bits/sec
	switch {
	case bits >= 1000000000: // 1 Gbps
		return fmt.Sprintf("%.1f Gbps", float64(bits)/1000000000)
	case bits >= 1000000: // 1 Mbps
		return fmt.Sprintf("%.1f Mbps", float64(bits)/1000000)
	case bits >= 1000: // 1 Kbps
		return fmt.Sprintf("%.1f kbps", float64(bits)/1000)
	default:
		return fmt.Sprintf("%d bps", bits)
	}
}

func cleanup(routeManager *RouteManager, client transport.TransportType, ctx context.Context) {
	log.Println("Starting cleanup...")

	// Create a timeout context for cleanup operations
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Channel to track cleanup completion
	done := make(chan bool)

	go func() {
		if routeManager != nil {
			log.Println("Cleaning up routes...")
			if err := routeManager.Cleanup(); err != nil {
				log.Printf("Failed to cleanup routes: %v", err)
			}
		}

		if client != nil {
			log.Println("Closing transport client...")
			client.Close()
		}

		done <- true
	}()

	// Wait for cleanup or timeout
	select {
	case <-done:
		log.Println("Cleanup completed successfully")
	case <-cleanupCtx.Done():
		log.Println("Cleanup timed out")
	}
}

// Move hexDump function outside of main, at package level
func hexDump(data []byte) string {
	var buf strings.Builder
	for i := 0; i < len(data); i += 16 {
		end := i + 16
		if end > len(data) {
			end = len(data)
		}
		// Print hex
		for j := i; j < end; j++ {
			if j > i {
				buf.WriteString(" ")
			}
			buf.WriteString(fmt.Sprintf("%02x", data[j]))
		}
		buf.WriteString("\n")
	}
	return buf.String()
}

func main() {
	var (
		serverAddr  string
		token       string
		vpnType     string
		noRouting   bool
		killRoute   bool
		proxyURL    string
		keepSSH     bool
		noSnarfDNS  bool
		noBandwidth bool
	)

	// Print ASCII logo before flag parsing
	fmt.Print(ASCII_LOGO)

	// Add configuration check right after ASCII logo
	allConfigured, _ := checkCAandDNSConfig()
	if !allConfigured {
		if err := setupCAandDNS(); err != nil {
			log.Printf("Warning: Configuration setup failed: %v", err)
			// Continue anyway as the VPN can still work
		}
	}

	flag.StringVar(&serverAddr, "server", "", "VPN server address (host:port)")
	flag.StringVar(&token, "token", "", "Authentication token")
	flag.StringVar(&vpnType, "type", "tcp", "Transport type (tcp, tcp-encrypted, or https)")
	flag.BoolVar(&noRouting, "no-routing", false, "Disable automatic routing")
	flag.BoolVar(&killRoute, "kill", false, "Remove default route instead of saving it")
	flag.StringVar(&proxyURL, "proxy", "", "Proxy URL (e.g., http://user:pass@host:port)")
	flag.BoolVar(&keepSSH, "keep-established-ssh", false, "Maintain existing SSH connections")
	flag.BoolVar(&noSnarfDNS, "no-snarf-dns", false, "Disable DNS traffic snarfing")
	flag.BoolVar(&noBandwidth, "no-bandwidth", false, "Disable bandwidth statistics")
	flag.Parse()

	if debug {
		log.Printf("Debug logging enabled")
	}

	if serverAddr == "" || token == "" {
		log.Println("Error: Server address and token are required")
		flag.Usage()
		os.Exit(1)
	}

	// Set up signal handling early
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create platform-specific interface
	tunDevice, err := createTunDevice("doxx")
	if err != nil {
		log.Printf("Failed to create TUN device: %v", err)
		cleanup(nil, nil, ctx)
		os.Exit(1)
	}
	defer tunDevice.Close()

	// Create route manager only if routing is enabled
	var routeManager *RouteManager
	if !noRouting {
		routeManager = NewRouteManager(tunDevice.Name(), killRoute, keepSSH)
	}

	// Create transport
	var client transport.TransportType
	switch vpnType {
	case "tcp":
		client = transport.NewSingleTCPClient()
	case "tcp-encrypted":
		var initErr error
		client, initErr = transport.NewSingleTCPEncryptedClient()
		if initErr != nil {
			log.Printf("Failed to create encrypted transport: %v", initErr)
			cleanup(routeManager, nil, ctx)
			os.Exit(1)
		}
	case "https":
		var proxyConfig *transport.ProxyConfig
		if proxyURL != "" {
			proxyConfig, err = transport.ParseProxyURL(proxyURL)
			if err != nil {
				log.Printf("Invalid proxy URL: %v", err)
				cleanup(routeManager, nil, ctx)
				os.Exit(1)
			}
		}
		client = transport.NewHTTPSTransportClient(proxyConfig)
	default:
		log.Printf("Unsupported transport type: %s", vpnType)
		cleanup(routeManager, nil, ctx)
		os.Exit(1)
	}

	// Create a timeout context for initial connection
	connectCtx, connectCancel := context.WithTimeout(ctx, 15*time.Second)
	defer connectCancel()

	// Connect using the transport with timeout
	connChan := make(chan error, 1)
	go func() {
		connChan <- client.Connect(serverAddr)
	}()

	select {
	case err := <-connChan:
		if err != nil {
			log.Printf("Failed to connect: %v", err)
			cleanup(routeManager, client, ctx)
			os.Exit(1)
		}
	case <-connectCtx.Done():
		log.Printf("Connection attempt timed out after 15 seconds")
		cleanup(routeManager, client, ctx)
		os.Exit(1)
	case <-sigChan:
		log.Println("Interrupted during connection attempt")
		cleanup(routeManager, client, ctx)
		os.Exit(1)
	}

	// Send authentication token
	if err := client.SendAuth(token); err != nil {
		log.Printf("Failed to send authentication token: %v", err)
		cleanup(routeManager, client, ctx)
		os.Exit(1)
	}

	// Handle authentication response
	response, err := client.HandleAuth()
	if err != nil {
		log.Printf("Authentication failed: %v", err)
		cleanup(routeManager, client, ctx)
		os.Exit(1)
	}

	// Validate response
	if response == nil || response.AssignedIP == "" || response.ServerIP == "" {
		log.Printf("Invalid response from server: missing IP information")
		cleanup(routeManager, client, ctx)
		os.Exit(1)
	}

	// Setup TUN interface
	if err := setupTUN(tunDevice.Name(), response.AssignedIP, response.ServerIP, response.PrefixLen); err != nil {
		log.Printf("Failed to setup TUN interface: %v", err)
		cleanup(routeManager, client, ctx)
		os.Exit(1)
	}

	// Set client and server IPs in route manager
	if routeManager != nil {
		routeManager.SetClientIP(response.AssignedIP)
		routeManager.SetServerIP(response.ServerIP)
	}

	// Setup routing if enabled
	if routeManager != nil {
		if err := routeManager.Setup(serverAddr); err != nil {
			log.Printf("Failed to setup routing: %v", err)
			cleanup(routeManager, client, ctx)
			os.Exit(1)
		}
	}

	// Add the helpful information with actual gateway - OS specific only
	if routeManager != nil {
		routeManager.mu.Lock()
		switch runtime.GOOS {
		case "darwin":
			log.Printf("If needed, restore default route with: sudo route -n add default %s", routeManager.defaultGW)
		case "linux":
			log.Printf("If needed, restore default route with: sudo ip route add default via %s dev %s", routeManager.defaultGW, routeManager.defaultIface)
		case "windows":
			log.Printf("If needed, restore default route with: route ADD 0.0.0.0 MASK 0.0.0.0 %s", routeManager.defaultGW)
		}
		routeManager.mu.Unlock()
	}

	// Add debugging/testing information
	log.Printf("To test connectivity:")
	log.Printf("  - Ping remote endpoint: ping %s", response.ServerIP)
	log.Printf("  - DNS servers available: %s (doxx.net), 1.1.1.1, 8.8.8.8", response.ServerIP)
	log.Printf("  - Test DNS resolution: dig @%s doxx.net", response.ServerIP)

	// Now perform the geo lookup after routes are established
	performGeoLookup()

	// Add default route after initial connectivity is confirmed
	if routeManager != nil && !noRouting {
		debugLog("Setting default route through VPN tunnel")
		if err := routeManager.setDefaultRoute(tunDevice.Name(), response.ServerIP); err != nil {
			log.Printf("Warning: Failed to set default route: %v", err)
			// Don't exit, as the tunnel is still usable without default route
		}
	}

	// Create WaitGroup for goroutines
	var wg sync.WaitGroup

	// Create channels for error handling
	errChan := make(chan error, 2)

	// Create packet buffer
	packet := make([]byte, MTU)

	// Create bandwidth stats if enabled
	var bandwidthStats *BandwidthStats
	if !noBandwidth {
		bandwidthStats = NewBandwidthStats()

		// Wait for geo information to be displayed before starting bandwidth
		go func() {
			select {
			case <-bandwidthDisplayReady:
				ticker := time.NewTicker(5 * time.Second)
				defer ticker.Stop()

				for {
					select {
					case <-ticker.C:
						stats, err := getInterfaceStats(tunDevice.Name())
						if err != nil {
							debugLog("Failed to get interface stats: %v", err)
							continue
						}
						bandwidthStats.Update(stats.rx, stats.tx)
						fmt.Printf("\r%s", bandwidthStats.GetReadable())
					case <-ctx.Done():
						return
					}
				}
			case <-ctx.Done():
				return
			}
		}()
	}

	// Initialize DNS NAT table if DNS snarfing is enabled
	// Add this BEFORE starting the goroutines
	if !noSnarfDNS {
		debugLog("Initializing DNS NAT table")
		dnsNatTable = NewDNSNatTable()
		if dnsNatTable == nil {
			log.Fatal("Failed to initialize DNS NAT table")
		}
	}

	// TUN to Transport
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			default:
				n, err := tunDevice.Read(packet)
				if err != nil {
					errChan <- fmt.Errorf("error reading from TUN: %v", err)
					return
				}

				if n == 0 {
					continue
				}

				// Enhanced packet logging
				if debug {
					proto := packet[9]
					srcIP := net.IP(packet[12:16])
					dstIP := net.IP(packet[16:20])

					srcPort := uint16(0)
					dstPort := uint16(0)
					if proto == 6 || proto == 17 {
						srcPort = uint16(packet[20])<<8 | uint16(packet[21])
						dstPort = uint16(packet[22])<<8 | uint16(packet[23])
					}

					debugLog("[TUN→Transport] Packet Details:\n"+
						"Protocol: %d\n"+
						"Source: %v:%d\n"+
						"Destination: %v:%d\n"+
						"Length: %d bytes\n"+
						"Hex dump:\n%s",
						proto, srcIP, srcPort, dstIP, dstPort, n,
						hexDump(packet[:n]))
				}

				if !isValidIPPacket(packet[:n]) {
					debugLog("[TUN→Transport] Skipping invalid IP packet from TUN")
					continue
				}

				// Create a copy of the packet before modification
				packetCopy := make([]byte, n)
				copy(packetCopy, packet[:n])

				if !noSnarfDNS && isDNSPacket(packetCopy, net.ParseIP(response.ServerIP)) {
					if debug {
						debugLog("Processing DNS packet")
					}
					packetCopy = rewriteDNSPacket(packetCopy, net.ParseIP(response.ServerIP), dnsNatTable)
				}

				if err := client.WritePacket(packetCopy); err != nil {
					errChan <- fmt.Errorf("error writing to transport: %v", err)
					return
				}
			}
		}
	}()

	// Transport to TUN
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			default:
				packet, err := client.ReadPacket()
				if err != nil {
					errChan <- fmt.Errorf("error reading from transport: %v", err)
					return
				}

				if _, err := tunDevice.Write(packet); err != nil {
					errChan <- fmt.Errorf("error writing to interface: %v", err)
					return
				}

				// Enhanced packet logging
				if debug {
					proto := packet[9]
					srcIP := net.IP(packet[12:16])
					dstIP := net.IP(packet[16:20])

					srcPort := uint16(0)
					dstPort := uint16(0)
					if proto == 6 || proto == 17 {
						srcPort = uint16(packet[20])<<8 | uint16(packet[21])
						dstPort = uint16(packet[22])<<8 | uint16(packet[23])
					}

					debugLog("[Transport→TUN] Packet Details:\n"+
						"Protocol: %d\n"+
						"Source: %v:%d\n"+
						"Destination: %v:%d\n"+
						"Length: %d bytes\n"+
						"Hex dump:\n%s",
						proto, srcIP, srcPort, dstIP, dstPort, len(packet),
						hexDump(packet))
				}

				if !isValidIPPacket(packet) {
					debugLog("[Transport→TUN] Skipping invalid IP packet from transport")
					continue
				}

				// Create a copy of the packet before modification
				packetCopy := make([]byte, len(packet))
				copy(packetCopy, packet)

				if !noSnarfDNS && isDNSPacket(packetCopy, net.ParseIP(response.ServerIP)) {
					if debug {
						debugLog("Processing DNS packet from transport")
					}
					packetCopy = rewriteDNSPacket(packetCopy, net.ParseIP(response.ServerIP), dnsNatTable)
				}

				if _, err := tunDevice.Write(packetCopy); err != nil {
					errChan <- fmt.Errorf("error writing to TUN: %v", err)
					return
				}
			}
		}
	}()

	// Error and signal handling
	go func() {
		select {
		case <-sigChan:
			log.Println("Received interrupt signal")
			cleanup(routeManager, client, ctx)
			cancel() // Cancel context to stop all goroutines
			os.Exit(0)
		case <-ctx.Done():
			log.Println("Context cancelled")
			cleanup(routeManager, client, ctx)
			os.Exit(0)
		}

		// Create a timeout context for cleanup
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()

		log.Println("Shutting down...")

		// Close connection before cleanup
		if client != nil {
			debugLog("Closing transport connection")
			client.Close()
		}

		// Only cleanup routing if it was enabled
		if routeManager != nil && !noRouting {
			done := make(chan bool)
			go func() {
				debugLog("Cleaning up routes")
				if err := routeManager.Cleanup(); err != nil {
					log.Printf("Failed to cleanup routes: %v", err)
				}
				done <- true
			}()

			select {
			case <-done:
				debugLog("Route cleanup completed")
			case <-cleanupCtx.Done():
				log.Printf("Route cleanup timed out")
			}
		}

		debugLog("Shutdown complete")
		os.Exit(0)
	}()

	// Wait for goroutines
	wg.Wait()
	debugLog("All goroutines completed")
}

func setupTUN(ifName string, assignedIP string, serverIP string, prefixLen int) error {
	// Remove any existing CIDR notation from assignedIP
	clientIP := strings.Split(assignedIP, "/")[0]
	debugLog("Setting up TUN interface %s with IP %s/%d and peer %s", ifName, clientIP, prefixLen, serverIP)

	switch runtime.GOOS {
	case "windows":
		// Disable IPv6 completely
		disableIPv6Cmd := exec.Command("netsh", "interface", "ipv6", "set", "interface",
			ifName, "disabled")
		debugLog("Executing command: %s", disableIPv6Cmd.String())
		if output, err := disableIPv6Cmd.CombinedOutput(); err != nil {
			debugLog("Failed to disable IPv6: %v\nOutput: %s", err, output)
		}

		// Set MTU and metric
		setMTUCmd := exec.Command("netsh", "interface", "ipv4", "set", "subinterface",
			ifName, "mtu=1500", "store=persistent")
		debugLog("Executing command: %s", setMTUCmd.String())
		if output, err := setMTUCmd.CombinedOutput(); err != nil {
			debugLog("Failed to set MTU: %v\nOutput: %s", err, output)
		}

		// Enable interface with metric 1
		setMetricCmd := exec.Command("netsh", "interface", "ipv4", "set", "interface",
			ifName, "metric=1")
		debugLog("Executing command: %s", setMetricCmd.String())
		if output, err := setMetricCmd.CombinedOutput(); err != nil {
			debugLog("Failed to set metric: %v\nOutput: %s", err, output)
		}

		// Force static IP with specific binding
		setIPCmd := exec.Command("netsh", "interface", "ip", "set", "address",
			"name="+ifName,
			"source=static",
			"addr="+clientIP,
			"mask=255.255.255.255")
		debugLog("Executing command: %s", setIPCmd.String())
		if output, err := setIPCmd.CombinedOutput(); err != nil {
			debugLog("Failed to set IP: %v\nOutput: %s", err, output)
		}

		// Add static route back to the server
		routeCmd := exec.Command("route", "add",
			fmt.Sprintf("%s", serverIP),
			"mask", "255.255.255.255",
			fmt.Sprintf("%s", clientIP))
		debugLog("Executing command: %s", routeCmd.String())
		if out, err := routeCmd.CombinedOutput(); err != nil {
			debugLog("Warning: failed to add static 255.255.255.255 server return route: %v\nOutput: %s", err, string(out))
		}

		// Debug: Show interface status
		showIPCmd := exec.Command("netsh", "interface", "ip", "show", "addresses", ifName)
		if output, err := showIPCmd.CombinedOutput(); err != nil {
			debugLog("Failed to show IP: %v", err)
		} else {
			debugLog("Interface IP config:\n%s", output)
		}

		return nil
	case "linux":
		// First, flush any existing configuration
		clearCmd := exec.Command("ip", "addr", "flush", "dev", ifName)
		if err := clearCmd.Run(); err != nil {
			debugLog("Warning: failed to flush interface: %v", err)
		}

		// Add IP address with proper CIDR and peer
		addCmd := exec.Command("ip", "addr", "add",
			fmt.Sprintf("%s/%d", clientIP, prefixLen),
			"peer", serverIP,
			"dev", ifName)
		if out, err := addCmd.CombinedOutput(); err != nil {
			return fmt.Errorf("error setting IP address: %v\nOutput: %s", err, string(out))
		}

		// Bring interface up
		upCmd := exec.Command("ip", "link", "set", "dev", ifName, "up")
		if out, err := upCmd.CombinedOutput(); err != nil {
			return fmt.Errorf("error bringing interface up: %v\nOutput: %s", err, string(out))
		}

		// Add explicit route to server
		routeCmd := exec.Command("ip", "route", "add",
			fmt.Sprintf("%s/32", serverIP),
			"dev", ifName)
		if out, err := routeCmd.CombinedOutput(); err != nil {
			debugLog("Warning: failed to add server route: %v\nOutput: %s", err, string(out))
		}

	case "darwin":
		// Convert prefix length to netmask
		mask := net.CIDRMask(prefixLen, 32)
		maskStr := fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])

		// For macOS, use proper point-to-point setup
		cmd := exec.Command("ifconfig", ifName, clientIP, serverIP, "netmask", maskStr, "up")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("error configuring interface: %v\nOutput: %s", err, string(out))
		}
	}

	// Verify routes
	if out, err := exec.Command("ip", "route", "show", "dev", ifName).CombinedOutput(); err == nil {
		debugLog("Routes for %s:\n%s", ifName, string(out))
	}

	debugLog("TUN interface setup completed with IP %s/%d and peer %s", clientIP, prefixLen, serverIP)
	return nil
}

func isValidIPPacket(packet []byte) bool {
	if len(packet) < 1 {
		return false
	}

	version := packet[0] >> 4
	if version == 6 {
		if debug {
			debugLog("Skipping IPv6 packet (not supported)")
		}
		return false
	}
	return version == 4
}

func isDNSPacket(packet []byte, serverIP net.IP) bool {
	if len(packet) < 28 { // Minimum DNS packet size (IP + UDP + DNS header)
		return false
	}

	// Check if it's UDP
	if packet[9] != 17 { // Protocol field in IP header
		return false
	}

	// Extract ports
	srcPort := uint16(packet[20])<<8 | uint16(packet[21])
	dstPort := uint16(packet[22])<<8 | uint16(packet[23])

	// Get source IP for response checking
	srcIP := net.IP(packet[12:16])

	// It's a DNS packet if:
	// 1. It's a query (destination port 53) OR
	// 2. It's a response (source port 53 and source IP is our VPN server)
	return dstPort == 53 || (srcPort == 53 && bytes.Equal(srcIP.To4(), serverIP.To4()))
}

func writePacket(conn net.Conn, packet []byte) error {
	// Write 4-byte length header
	header := make([]byte, HEADER_SIZE)
	header[0] = byte(len(packet) >> 24)
	header[1] = byte(len(packet) >> 16)
	header[2] = byte(len(packet) >> 8)
	header[3] = byte(len(packet))

	if _, err := conn.Write(header); err != nil {
		return err
	}
	_, err := conn.Write(packet)
	return err
}

func readPacket(conn net.Conn) ([]byte, error) {
	header := make([]byte, HEADER_SIZE)
	if _, err := io.ReadFull(conn, header); err != nil {
		if err == io.EOF || strings.Contains(err.Error(), "connection reset by peer") {
			return nil, fmt.Errorf("server disconnected: %v", err)
		}
		return nil, err
	}

	length := int(header[0])<<24 | int(header[1])<<16 | int(header[2])<<8 | int(header[3])
	if length > MTU {
		return nil, fmt.Errorf("packet too large: %d", length)
	}

	packet := make([]byte, length)
	if _, err := io.ReadFull(conn, packet); err != nil {
		if err == io.EOF || strings.Contains(err.Error(), "connection reset by peer") {
			return nil, fmt.Errorf("server disconnected: %v", err)
		}
		return nil, err
	}
	return packet, nil
}

func (rm *RouteManager) getCurrentDefaultRoute() (string, string, error) {
	// Get default gateway IP
	gw, err := gateway.DiscoverGateway()
	if err != nil {
		return "", "", fmt.Errorf("failed to discover gateway: %v", err)
	}

	// Get all interfaces to find the one with this gateway
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", "", fmt.Errorf("failed to get interfaces: %v", err)
	}

	// Find interface that can reach the gateway
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ipnet.Contains(gw) {
					return gw.String(), iface.Name, nil
				}
			}
		}
	}

	// Add Windows-specific implementation
	if runtime.GOOS == "windows" {
		// Get routing table
		cmd := exec.Command("route", "print", "0.0.0.0")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return "", "", fmt.Errorf("failed to get routing table: %v", err)
		}

		// Parse the output to find default gateway
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 3 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
				gw := fields[2]
				// Get interface name from interface index
				ifaces, err := net.Interfaces()
				if err != nil {
					return gw, "", fmt.Errorf("failed to get interfaces: %v", err)
				}
				for _, iface := range ifaces {
					addrs, err := iface.Addrs()
					if err != nil {
						continue
					}
					for _, addr := range addrs {
						if ipnet, ok := addr.(*net.IPNet); ok {
							if ipnet.Contains(net.ParseIP(gw)) {
								return gw, iface.Name, nil
							}
						}
					}
				}
				return gw, "", nil
			}
		}
	}

	return "", "", fmt.Errorf("no default route found")
}

func (rm *RouteManager) addStaticRoute(dst, gw, iface string) error {
	rm.mu.Lock()
	// Check for duplicates in staticRoutes
	for _, route := range rm.staticRoutes {
		if route == dst {
			rm.mu.Unlock()
			debugLog("Route %s already exists, skipping", dst)
			return nil
		}
	}
	// Check for duplicates in sshRoutes
	for _, route := range rm.sshRoutes {
		if route == dst {
			rm.mu.Unlock()
			debugLog("SSH route %s already exists, skipping", dst)
			return nil
		}
	}
	rm.mu.Unlock()

	debugLog("Adding static route for %s via %s on %s", dst, gw, iface)

	// First try to remove any existing route
	switch runtime.GOOS {
	case "darwin":
		delCmd := exec.Command("route", "-n", "delete", dst)
		if out, err := delCmd.CombinedOutput(); err != nil {
			debugLog("Note: Could not delete existing route for %s: %v\nOutput: %s", dst, err, string(out))
			// Continue anyway as the route might not exist
		}

		addCmd := exec.Command("route", "-n", "add", dst, gw)
		if out, err := addCmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to add route (exit code %d): %v\nOutput: %s",
				addCmd.ProcessState.ExitCode(), err, string(out))
		}

	case "linux":
		delCmd := exec.Command("ip", "route", "del", dst)
		if out, err := delCmd.CombinedOutput(); err != nil {
			debugLog("Note: Could not delete existing route for %s: %v\nOutput: %s", dst, err, string(out))
			// Continue anyway as the route might not exist
		}

		addCmd := exec.Command("ip", "route", "add", dst, "via", gw, "dev", iface)
		if out, err := addCmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to add route (exit code %d): %v\nOutput: %s",
				addCmd.ProcessState.ExitCode(), err, string(out))
		}

	case "windows":
		// Parse CIDR to get network and mask
		_, network, err := net.ParseCIDR(dst)
		if err != nil {
			return fmt.Errorf("invalid CIDR: %v", err)
		}

		// Convert netmask to Windows format
		mask := network.Mask
		maskStr := fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])

		// Remove CIDR notation from destination
		dstIP := strings.Split(dst, "/")[0]

		// Add the route with persistence (-p flag)
		cmd := exec.Command("route", "-p", "add",
			dstIP, "mask", maskStr,
			gw, "metric", "1")

		debugLog("Running command: route -p add %s mask %s %s metric 1",
			dstIP, maskStr, gw)

		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to add route: %v\nOutput: %s", err, string(out))
		}
		return nil

	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}

	rm.mu.Lock()
	rm.staticRoutes = append(rm.staticRoutes, dst)
	rm.mu.Unlock()

	debugLog("Successfully added static route for %s", dst)
	return nil
}

func (rm *RouteManager) setDefaultRoute(iface string, serverIP string) error {
	debugLog("Setting default route via %s on %s", serverIP, iface)

	switch runtime.GOOS {
	case "darwin":
		// First delete the current default route
		delCmd := exec.Command("route", "-n", "delete", "default")
		if out, err := delCmd.CombinedOutput(); err != nil {
			debugLog("Note: Could not delete current default route: %v\nOutput: %s", err, string(out))
			// Continue anyway as we want to try setting the new route
		}

		// Add new default route via the VPN server IP
		addCmd := exec.Command("route", "-n", "add", "default", rm.serverIP)
		if out, err := addCmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to set default route: %v\nOutput: %s", err, string(out))
		}

	case "linux":
		// First delete the current default route
		delCmd := exec.Command("ip", "route", "del", "default")
		if out, err := delCmd.CombinedOutput(); err != nil {
			debugLog("Note: Could not delete current default route: %v\nOutput: %s", err, string(out))
			// Continue anyway as we want to try setting the new route
		}

		// Add new default route via the VPN server IP
		addCmd := exec.Command("ip", "route", "add", "default", "via", rm.serverIP, "dev", iface)
		if out, err := addCmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to set default route: %v\nOutput: %s", err, string(out))
		}

	case "windows":
		// Maximum number of retries
		maxRetries := 10
		retryDelay := 1 * time.Second

		var lastErr error
		for attempt := 0; attempt < maxRetries; attempt++ {
			// Get interface status
			interfaces, err := net.Interfaces()
			if err != nil {
				lastErr = fmt.Errorf("failed to get network interfaces: %v", err)
				debugLog("Attempt %d: %v", attempt+1, lastErr)
				time.Sleep(retryDelay)
				continue
			}

			var ifIndex int
			var ifFlags net.Flags
			for _, i := range interfaces {
				if i.Name == iface {
					ifIndex = i.Index
					ifFlags = i.Flags
					break
				}
			}

			if ifIndex == 0 {
				lastErr = fmt.Errorf("interface %s not found", iface)
				debugLog("Attempt %d: %v", attempt+1, lastErr)
				time.Sleep(retryDelay)
				continue
			}

			// Check if interface is up and running
			if ifFlags&net.FlagUp == 0 || ifFlags&net.FlagRunning == 0 {
				lastErr = fmt.Errorf("interface %s is not up and running (flags: %v)", iface, ifFlags)
				debugLog("Attempt %d: %v", attempt+1, lastErr)
				time.Sleep(retryDelay)
				continue
			}

			// First delete the current default route
			delCmd := exec.Command("route", "delete", "0.0.0.0", "mask", "0.0.0.0")
			if out, err := delCmd.CombinedOutput(); err != nil {
				debugLog("Note: Could not delete current default route: %v\nOutput: %s", err, string(out))
			}

			// Add new default route via the VPN server IP with interface index
			addCmd := exec.Command("route", "add",
				"0.0.0.0", "mask", "0.0.0.0",
				serverIP,
				"if", fmt.Sprintf("%d", ifIndex),
				"metric", "1")

			debugLog("Executing command: %s", addCmd.String())
			if out, err := addCmd.CombinedOutput(); err != nil {
				lastErr = fmt.Errorf("failed to set default route: %v\nOutput: %s", err, string(out))
				debugLog("Attempt %d: %v", attempt+1, lastErr)
				time.Sleep(retryDelay)
				continue
			}

			// Verify the route was set correctly
			verifyCmd := exec.Command("route", "print", "0.0.0.0")
			out, err := verifyCmd.CombinedOutput()
			if err != nil {
				lastErr = fmt.Errorf("failed to verify route: %v", err)
				debugLog("Attempt %d: %v", attempt+1, lastErr)
				time.Sleep(retryDelay)
				continue
			}

			// Check if our route is present in the output
			if strings.Contains(string(out), serverIP) {
				debugLog("Successfully set and verified default route after %d attempts", attempt+1)
				return nil
			}

			lastErr = fmt.Errorf("route verification failed")
			debugLog("Attempt %d: Route not found in routing table", attempt+1)
			time.Sleep(retryDelay)
		}

		return fmt.Errorf("failed to set default route after %d attempts: %v", maxRetries, lastErr)
	}

	debugLog("Successfully set default route")
	return nil
}

func (rm *RouteManager) removeStaticRoute(dst string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("route", "delete", dst).Run()
	case "linux":
		return exec.Command("ip", "route", "del", dst).Run()
	case "windows":
		// Remove CIDR notation for Windows
		dstIP := strings.Split(dst, "/")[0]

		cmd := exec.Command("route", "delete", dstIP)
		debugLog("Running command: route delete %s", dstIP)

		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to remove route: %v\nOutput: %s", err, string(out))
		}
		return nil
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

func debugLog(format string, v ...interface{}) {
	if debug {
		log.Printf("[DEBUG] "+format, v...)
	}
}

// Helper function to get previous IP address
func prevIP(ip net.IP) net.IP {
	prev := make(net.IP, len(ip))
	copy(prev, ip)
	for i := len(prev) - 1; i >= 0; i-- {
		if prev[i] == 0 {
			prev[i] = 255
			continue
		}
		prev[i]--
		break
	}
	return prev
}

func (rm *RouteManager) SetClientIP(assignedIP string) {
	rm.mu.Lock()
	rm.clientIP = assignedIP
	// Extract server IP by incrementing the client IP (since it's a /31 network)
	if ip, network, err := net.ParseCIDR(assignedIP); err == nil {
		// For a /31 network, the server IP is the other address in the pair
		if ones, _ := network.Mask.Size(); ones == 31 {
			// If client IP is even, server is odd, and vice versa
			ipInt := binary.BigEndian.Uint32(ip.To4())
			if ipInt%2 == 0 {
				serverIP := make(net.IP, 4)
				binary.BigEndian.PutUint32(serverIP, ipInt+1)
				rm.serverIP = serverIP.String()
			} else {
				serverIP := make(net.IP, 4)
				binary.BigEndian.PutUint32(serverIP, ipInt-1)
				rm.serverIP = serverIP.String()
			}
		}
	}
	rm.mu.Unlock()
}

func (rm *RouteManager) SetServerIP(serverIP string) {
	rm.mu.Lock()
	rm.serverIP = serverIP
	rm.mu.Unlock()
}

func (rm *RouteManager) preserveExistingSSHConnections() error {
	if !rm.keepSSH {
		return nil
	}

	debugLog("Preserving existing SSH connections")

	// Use gopsutil to get TCP connections with the psnet alias
	connections, err := psnet.Connections("tcp")
	if err != nil {
		return fmt.Errorf("failed to get network connections: %v", err)
	}

	sshCount := 0
	for _, conn := range connections {
		// Check for established SSH connections (port 22)
		if conn.Status == "ESTABLISHED" && (conn.Laddr.Port == 22 || conn.Raddr.Port == 22) {
			var remoteIP string
			if conn.Laddr.Port == 22 {
				remoteIP = conn.Raddr.IP // Incoming SSH connection
			} else {
				remoteIP = conn.Raddr.IP // Outgoing SSH connection
			}

			debugLog("Found established SSH connection to/from %s", remoteIP)

			if err := rm.addStaticRoute(remoteIP+"/32", rm.defaultGW, rm.defaultIface); err != nil {
				log.Printf("Warning: Failed to preserve SSH route to %s: %v", remoteIP, err)
				continue
			}

			rm.mu.Lock()
			rm.sshRoutes = append(rm.sshRoutes, remoteIP+"/32")
			rm.mu.Unlock()

			sshCount++
			debugLog("Successfully preserved route to SSH host %s", remoteIP)
		}
	}

	debugLog("Preserved %d SSH connections", sshCount)
	return nil
}

// Add platform-specific interface statistics gathering
type interfaceStats struct {
	rx uint64
	tx uint64
}

func getInterfaceStats(ifName string) (*interfaceStats, error) {
	counters, err := psnet.IOCounters(true) // true for per-interface stats
	if err != nil {
		return nil, fmt.Errorf("failed to get interface statistics: %v", err)
	}

	for _, counter := range counters {
		if counter.Name == ifName {
			return &interfaceStats{
				rx: counter.BytesRecv,
				tx: counter.BytesSent,
			}, nil
		}
	}

	return nil, fmt.Errorf("interface %s not found", ifName)
}

// Add this function to perform the geo lookup
func performGeoLookup() {
	// Run in a goroutine to not block main execution
	go func() {
		// Give more time for routes to stabilize and verify connectivity
		time.Sleep(5 * time.Second)

		// Try to ping the server first to verify connectivity
		debugLog("Verifying connectivity before geo lookup...")
		pingResp, err := http.Get("https://setup.doxx.net/ping")
		if err != nil {
			debugLog("Initial connectivity check failed: %v", err)
			// Try one more time after a delay
			time.Sleep(3 * time.Second)
		}
		if pingResp != nil {
			pingResp.Body.Close()
		}

		debugLog("Attempting geo lookup...")
		client := &http.Client{
			Timeout: 10 * time.Second,
		}

		resp, err := client.Get("https://setup.doxx.net/geo/")
		if err != nil {
			log.Printf("Geo lookup request failed: %v", err)
			return
		}
		defer resp.Body.Close()

		var geoData GeoResponse
		if err := json.NewDecoder(resp.Body).Decode(&geoData); err != nil {
			debugLog("Failed to decode geo response: %v", err)
			return
		}

		// Build a nice formatted output
		var output strings.Builder
		output.WriteString("\nConnection Details:\n")
		output.WriteString("─────────────────────────────────\n")

		// IP Address
		output.WriteString(fmt.Sprintf("IP Address: %s\n", geoData.IP))

		// Location information
		if geoData.Country.Name != "" {
			location := []string{}
			if geoData.City.Name != "" {
				location = append(location, geoData.City.Name)
			}
			if geoData.Country.Name != "" {
				location = append(location, geoData.Country.Name)
			}
			output.WriteString(fmt.Sprintf("Location:   %s\n", strings.Join(location, ", ")))
		}

		// Coordinates if available
		if geoData.City.Latitude != 0 && geoData.City.Longitude != 0 {
			output.WriteString(fmt.Sprintf("Coords:     %.4f, %.4f\n",
				geoData.City.Latitude,
				geoData.City.Longitude))
		}

		// Timezone if available
		if geoData.Timezone != "" {
			output.WriteString(fmt.Sprintf("Timezone:   %s\n", geoData.Timezone))
		}

		// ASN information
		if geoData.AutonomousSystem.Number != 0 {
			output.WriteString(fmt.Sprintf("Network:    AS%d", geoData.AutonomousSystem.Number))
			if geoData.AutonomousSystem.Organization != "" {
				output.WriteString(fmt.Sprintf(" (%s)", geoData.AutonomousSystem.Organization))
			}
			output.WriteString("\n")
		}

		output.WriteString("─────────────────────────────────\n")

		// Print the formatted output
		fmt.Println(output.String())

		// Signal that it's okay to start bandwidth display
		close(bandwidthDisplayReady)
	}()
}

// Add new NAT tracking structure
type DNSNatEntry struct {
	OriginalDst net.IP
	OriginalSrc net.IP
	QueryID     uint16 // DNS query ID for matching responses
	LastUsed    time.Time
}

type DNSNatTable struct {
	entries map[string]*DNSNatEntry // key: "clientIP:clientPort:queryID"
	mu      sync.RWMutex
}

func NewDNSNatTable() *DNSNatTable {
	nat := &DNSNatTable{
		entries: make(map[string]*DNSNatEntry),
	}
	// Start cleanup goroutine
	go nat.cleanup()
	return nat
}

func (nat *DNSNatTable) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		nat.mu.Lock()
		now := time.Now()
		for key, entry := range nat.entries {
			if now.Sub(entry.LastUsed) > 1*time.Minute {
				delete(nat.entries, key)
			}
		}
		nat.mu.Unlock()
	}
}

func (nat *DNSNatTable) Add(srcIP net.IP, srcPort uint16, dstIP net.IP, queryID uint16) {
	key := fmt.Sprintf("%s:%d:%d", srcIP.String(), srcPort, queryID)
	if debug {
		debugLog("Adding NAT entry with key: %s, original DNS: %v", key, dstIP)
	}
	nat.mu.Lock()
	nat.entries[key] = &DNSNatEntry{
		OriginalDst: dstIP,
		OriginalSrc: srcIP,
		QueryID:     queryID,
		LastUsed:    time.Now(),
	}
	nat.mu.Unlock()
}

func (nat *DNSNatTable) Lookup(clientIP net.IP, clientPort uint16, queryID uint16) *DNSNatEntry {
	key := fmt.Sprintf("%s:%d:%d", clientIP.String(), clientPort, queryID)
	if debug {
		debugLog("Looking up NAT entry with key: %s", key)
	}
	nat.mu.RLock()
	entry, exists := nat.entries[key]
	nat.mu.RUnlock()
	if exists {
		nat.mu.Lock()
		entry.LastUsed = time.Now()
		nat.mu.Unlock()
		if debug {
			debugLog("Found NAT entry for key %s: original DNS was %v", key, entry.OriginalDst)
		}
		return entry
	}
	if debug {
		debugLog("No NAT entry found for key: %s", key)
	}
	return nil
}

// Add to main VPN struct or where appropriate
type VPNConfig struct {
	// ... existing fields ...
	snarfDNS    bool
	dnsNatTable *DNSNatTable
}

// Function to handle DNS packet rewriting
func rewriteDNSPacket(packet []byte, serverIP net.IP, natTable *DNSNatTable) []byte {
	// Ensure it's an IPv4 packet
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return packet
	}

	// Check if UDP and port 53
	if packet[9] != 17 { // UDP protocol
		return packet
	}

	// Extract ports and query ID
	srcPort := uint16(packet[20])<<8 | uint16(packet[21])
	dstPort := uint16(packet[22])<<8 | uint16(packet[23])
	queryID := uint16(packet[28])<<8 | uint16(packet[29])

	srcIP := net.IP(packet[12:16])
	dstIP := net.IP(packet[16:20])

	if debug {
		debugLog("Processing packet - src=%v:%d dst=%v:%d queryID=%d",
			srcIP, srcPort, dstIP, dstPort, queryID)
	}

	// Handle DNS response (source port must be 53)
	if srcPort == DNS_PORT && bytes.Equal(srcIP.To4(), serverIP.To4()) {
		if debug {
			debugLog("Detected DNS response from VPN server %v:%d to %v with queryID %d",
				srcIP, srcPort, dstIP, queryID)
		}

		// Iterate through NAT entries to find matching query
		natTable.mu.RLock()
		for key, entry := range natTable.entries {
			if entry.QueryID == queryID {
				if debug {
					debugLog("Found matching NAT entry: %s (queryID=%d)", key, queryID)
					debugLog("Rewriting source IP from %v to %v", srcIP, entry.OriginalDst)
				}
				// Rewrite source IP to original DNS server
				copy(packet[12:16], entry.OriginalDst.To4())
				updateIPChecksum(packet)
				if packet[26:28][0] != 0 || packet[26:28][1] != 0 {
					updateUDPChecksum(packet)
				}
				natTable.mu.RUnlock()
				return packet
			}
		}
		natTable.mu.RUnlock()
		if debug {
			debugLog("No matching NAT entry found for DNS response (queryID=%d)", queryID)
		}
		return packet
	}

	// Handle outbound DNS query (destination port must be 53)
	if dstPort == DNS_PORT {
		originalDst := make(net.IP, 4)

		copy(originalDst, packet[16:20])
		clientIP := make(net.IP, 4)
		copy(clientIP, packet[12:16])

		if debug {
			debugLog("DNS Query from %v:%d to %v with queryID %d",
				clientIP, srcPort, originalDst, queryID)
		}

		// Add NAT entry
		natTable.Add(clientIP, srcPort, originalDst, queryID)

		// Rewrite destination IP to VPN server
		copy(packet[16:20], serverIP.To4())
		updateIPChecksum(packet)
		if packet[26:28][0] != 0 || packet[26:28][1] != 0 {
			updateUDPChecksum(packet)
		}
	}

	return packet
}

// Helper function to update IP header checksum
func updateIPChecksum(packet []byte) {
	// Clear existing checksum
	packet[10] = 0
	packet[11] = 0

	// Calculate new checksum
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(packet[i])<<8 | uint32(packet[i+1])
	}

	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)

	// Store new checksum
	packet[10] = byte(^sum >> 8)
	packet[11] = byte(^sum)
}

// Helper function to update UDP checksum
func updateUDPChecksum(packet []byte) {
	// Clear existing UDP checksum
	packet[26] = 0
	packet[27] = 0

	ipHeaderLen := int(packet[0]&0x0F) * 4
	udpLen := len(packet) - ipHeaderLen

	// Calculate pseudo-header checksum
	var sum uint32

	// Add source IP address
	for i := 12; i < 16; i += 2 {
		sum += uint32(packet[i])<<8 | uint32(packet[i+1])
	}

	// Add destination IP address
	for i := 16; i < 20; i += 2 {
		sum += uint32(packet[i])<<8 | uint32(packet[i+1])
	}

	// Add protocol
	sum += uint32(packet[9])

	// Add UDP length
	sum += uint32(udpLen)

	// Add UDP header and data
	for i := ipHeaderLen; i < len(packet)-1; i += 2 {
		sum += uint32(packet[i])<<8 | uint32(packet[i+1])
	}

	// If packet length is odd, pad with zero
	if (len(packet)-ipHeaderLen)%2 == 1 {
		sum += uint32(packet[len(packet)-1]) << 8
	}

	// Fold 32-bit sum into 16 bits
	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}

	// One's complement
	checksum := ^uint16(sum)

	// If checksum is 0, make it 0xFFFF (RFC 768)
	if checksum == 0 {
		checksum = 0xFFFF
	}

	// Store new UDP checksum
	packet[26] = byte(checksum >> 8)
	packet[27] = byte(checksum)
}

func checkCAandDNSConfig() (bool, map[string]bool) {
	status := make(map[string]bool)

	fmt.Println("\nChecking Doxx.net configuration...")
	fmt.Println("────────────────────────────")

	// Check CA certificate installation
	switch runtime.GOOS {
	case "darwin":
		// Check system trust store
		cmd := exec.Command("security", "find-certificate", "-c", "Doxx.net Root CA", "/Library/Keychains/System.keychain")
		status["ca_system"] = cmd.Run() == nil

		// Check curl certificates
		_, err := os.Stat("/etc/ssl/certs/doxx-root-ca.crt")
		status["ca_curl"] = err == nil

		// Check .doxx resolver configuration
		content, err := os.ReadFile("/etc/resolver/doxx")
		if err == nil {
			expected := "nameserver 8.8.8.8\ndomain doxx\nsearch doxx\noptions ndots:0"
			status["resolver"] = string(content) == expected
		}

	case "linux":
		// Check system certificates
		_, err := os.Stat("/etc/ssl/certs/doxx-root-ca.crt")
		status["ca_system"] = err == nil

		// Check if cert is in the hash directory
		hashCmd := exec.Command("sh", "-c", "ls /etc/ssl/certs | grep -i doxx")
		status["ca_hash"] = hashCmd.Run() == nil

	case "windows":
		// Check Windows certificate store
		cmd := exec.Command("certutil", "-store", "root", "Doxx.net Root CA")
		status["ca_system"] = cmd.Run() == nil
	}

	// Print status
	fmt.Println("Configuration Status:")
	allConfigured := true

	switch runtime.GOOS {
	case "darwin":
		if status["ca_system"] {
			fmt.Println("✓ Root CA installed in system trust store")
		} else {
			fmt.Println("✗ Root CA not found in system trust store")
			allConfigured = false
		}

		if status["ca_curl"] {
			fmt.Println("✓ Root CA installed for curl")
		} else {
			fmt.Println("✗ Root CA not configured for curl")
			allConfigured = false
		}

		if status["resolver"] {
			fmt.Println("✓ .doxx domain resolver configured")
		} else {
			fmt.Println("✗ .doxx domain resolver not configured")
			allConfigured = false
		}

	case "linux":
		if status["ca_system"] {
			fmt.Println("✓ Root CA installed in system certificates")
		} else {
			fmt.Println("✗ Root CA not found in system certificates")
			allConfigured = false
		}

		if status["ca_hash"] {
			fmt.Println("✓ Root CA hash links created")
		} else {
			fmt.Println("✗ Root CA hash links not found")
			allConfigured = false
		}

	case "windows":
		if status["ca_system"] {
			fmt.Println("✓ Root CA installed in Windows certificate store")
		} else {
			fmt.Println("✗ Root CA not found in Windows certificate store")
			allConfigured = false
		}
	}

	return allConfigured, status
}

func setupCAandDNS() error {
	// First check current configuration
	allConfigured, status := checkCAandDNSConfig()

	if allConfigured {
		fmt.Println("\n✓ All Doxx.net components are properly configured!")
		fmt.Println("No additional setup needed.")
		return nil
	}

	fmt.Println("\nDoxx.net Root CA Installation")
	fmt.Println("────────────────────────────")
	fmt.Println("The Doxx.net Root CA enables secure communication with .doxx domains and")
	fmt.Println("allows users to register their own domains without relying on the public PKI system.")
	fmt.Println("This is essential for maintaining privacy and security within the Doxx.net network.")
	fmt.Println("\nDNS Configuration:")
	fmt.Println("When connected to Doxx.net, DNS queries are automatically secured through our network.")
	fmt.Println("We recommend using 1.1.1.1 and 8.8.8.8 as your default DNS servers.")
	fmt.Println("The Doxx client will automatically redirect DNS traffic to secure Doxx.net servers")
	fmt.Println("while connected, and restore your original DNS settings when disconnected.")

	fmt.Print("\nWould you like to proceed with installation of missing components? (y/n): ")
	var response string
	fmt.Scanln(&response)
	if strings.ToLower(response) != "y" {
		return fmt.Errorf("installation cancelled by user")
	}

	switch runtime.GOOS {
	case "darwin":
		if !status["ca_system"] || !status["ca_curl"] {
			// Install CA certificate for curl if needed
			if !status["ca_curl"] {
				fmt.Println("Installing Root CA for curl...")
				if err := exec.Command("sudo", "mkdir", "-p", "/etc/ssl/certs").Run(); err != nil {
					return fmt.Errorf("failed to create cert directory: %v", err)
				}
				if err := exec.Command("sudo", "cp", "assets/doxx-root-ca.crt", "/etc/ssl/certs/").Run(); err != nil {
					return fmt.Errorf("failed to copy CA cert: %v", err)
				}
			}

			// Install CA certificate to system trust if needed
			if !status["ca_system"] {
				fmt.Println("Adding Root CA to system trust store...")
				if err := exec.Command("sudo", "security", "add-trusted-cert", "-d", "-r", "trustRoot",
					"-k", "/Library/Keychains/System.keychain", "assets/doxx-root-ca.crt").Run(); err != nil {
					return fmt.Errorf("failed to add CA cert to system trust: %v", err)
				}
			}
		}

		// Configure .doxx resolver if needed
		if !status["resolver"] {
			fmt.Println("Configuring .doxx domain resolver...")
			if err := os.MkdirAll("/etc/resolver", 0755); err != nil {
				return fmt.Errorf("failed to create resolver directory: %v", err)
			}

			resolverContent := []byte("nameserver 8.8.8.8\ndomain doxx\nsearch doxx\noptions ndots:0")
			if err := os.WriteFile("/etc/resolver/doxx", resolverContent, 0644); err != nil {
				return fmt.Errorf("failed to create resolver configuration: %v", err)
			}

			// Restart mDNSResponder
			if err := exec.Command("sudo", "killall", "-HUP", "mDNSResponder").Run(); err != nil {
				fmt.Println("Warning: Failed to restart mDNSResponder. You may need to restart your system.")
			}
		}

	case "linux":
		if !status["ca_system"] {
			fmt.Println("Installing Root CA...")
			if err := exec.Command("sudo", "mkdir", "-p", "/etc/ssl/certs").Run(); err != nil {
				return fmt.Errorf("failed to create cert directory: %v", err)
			}
			if err := exec.Command("sudo", "cp", "assets/doxx-root-ca.crt", "/etc/ssl/certs/").Run(); err != nil {
				return fmt.Errorf("failed to copy CA cert: %v", err)
			}
			if err := exec.Command("sudo", "update-ca-certificates").Run(); err != nil {
				return fmt.Errorf("failed to update CA certificates: %v", err)
			}
		}

	case "windows":
		if !status["ca_system"] {
			fmt.Println("\nTo install the Doxx.net Root CA on Windows:")
			fmt.Println("1. Double-click the 'assets/doxx-root-ca.crt' file")
			fmt.Println("2. Click 'Install Certificate'")
			fmt.Println("3. Select 'Local Machine' and click 'Next'")
			fmt.Println("4. Select 'Place all certificates in the following store'")
			fmt.Println("5. Click 'Browse' and select 'Trusted Root Certification Authorities'")
			fmt.Println("6. Click 'Next' and then 'Finish'")
			fmt.Println("\nAlternatively, run this command as Administrator:")
			fmt.Println("certutil -addstore root assets\\doxx-root-ca.crt")
		}
	}

	// Verify configuration after installation
	allConfigured, _ = checkCAandDNSConfig()
	if allConfigured {
		fmt.Println("\n✓ Installation completed successfully!")
		fmt.Println("Your system is now configured to use Doxx.net secure DNS services.")
		fmt.Println("Default DNS servers (recommended):")
		fmt.Println("  Primary:   1.1.1.1    (Cloudflare)")
		fmt.Println("  Secondary: 8.8.8.8    (Google)")
	} else {
		fmt.Println("\n⚠ Some components may not have installed correctly.")
		fmt.Println("Please check the status messages above.")
	}

	return nil
}
