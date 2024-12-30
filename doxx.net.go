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
	"github.com/songgao/water"
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
            \/            \/          \/               
                        
     [ Copyright (c) Barrett Lyon 2024 - https://doxx.net ]
     [ Secure Networking for Humans                       ]
`
)

var (
	debug                 bool
	snarfDNS              bool
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

func main() {
	var (
		serverAddr string
		token      string
		vpnType    string
		noRouting  bool
		killRoute  bool
		proxyURL   string
		keepSSH    bool
		bandwidth  bool
	)

	// Print ASCII logo before flag parsing
	fmt.Print(ASCII_LOGO)

	flag.StringVar(&serverAddr, "server", "", "VPN server address (host:port)")
	flag.StringVar(&token, "token", "", "Authentication token")
	flag.StringVar(&vpnType, "type", "tcp", "Transport type (tcp, tcp-encrypted, or https)")
	flag.BoolVar(&noRouting, "no-routing", false, "Disable automatic routing")
	flag.BoolVar(&killRoute, "kill", false, "Remove default route instead of saving it")
	flag.StringVar(&proxyURL, "proxy", "", "Proxy URL (e.g., http://user:pass@host:port)")
	flag.BoolVar(&keepSSH, "keep-established-ssh", false, "Maintain existing SSH connections")
	flag.BoolVar(&bandwidth, "bandwidth", false, "Show bandwidth statistics")
	flag.BoolVar(&snarfDNS, "snarf-dns", false, "Snarf DNS traffic")
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

	// Create TUN interface
	iface, err := water.New(water.Config{
		DeviceType: water.TUN,
	})
	if err != nil {
		log.Printf("Failed to create TUN interface: %v", err)
		cleanup(nil, nil, ctx)
		os.Exit(1)
	}

	// Create route manager only if routing is enabled
	var routeManager *RouteManager
	if !noRouting {
		routeManager = NewRouteManager(iface.Name(), killRoute, keepSSH)
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
	if err := setupTUN(iface.Name(), response.AssignedIP, response.ServerIP, response.PrefixLen); err != nil {
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

	// Create WaitGroup for goroutines
	var wg sync.WaitGroup

	// Create channels for error handling
	errChan := make(chan error, 2)

	// Create packet buffer
	packet := make([]byte, MTU)

	// Create bandwidth stats if enabled
	var bandwidthStats *BandwidthStats
	if bandwidth {
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
						stats, err := getInterfaceStats(iface.Name())
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
	if snarfDNS {
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
				n, err := iface.Read(packet)
				if err != nil {
					errChan <- fmt.Errorf("error reading from TUN: %v", err)
					return
				}

				if !isValidIPPacket(packet[:n]) {
					debugLog("Skipping invalid IP packet from TUN")
					continue
				}

				//if debug {
				// Log basic info about every packet
				//proto := packet[9]
				//srcIP := net.IP(packet[12:16])
				//dstIP := net.IP(packet[16:20])
				//debugLog("Packet: proto=%d src=%v dst=%v len=%d", proto, srcIP, dstIP, n)
				//}

				// Create a copy of the packet before modification
				packetCopy := make([]byte, n)
				copy(packetCopy, packet[:n])

				if snarfDNS && isDNSPacket(packetCopy, net.ParseIP(response.ServerIP)) {
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

				if !isValidIPPacket(packet) {
					debugLog("Skipping invalid IP packet from transport")
					continue
				}

				// Create a copy of the packet before modification
				packetCopy := make([]byte, len(packet))
				copy(packetCopy, packet)

				if snarfDNS && isDNSPacket(packetCopy, net.ParseIP(response.ServerIP)) {
					if debug {
						debugLog("Processing DNS packet from transport")
					}
					packetCopy = rewriteDNSPacket(packetCopy, net.ParseIP(response.ServerIP), dnsNatTable)
				}

				if _, err := iface.Write(packetCopy); err != nil {
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
		// Debug: Show current interface state
		debugCmd := exec.Command("ipconfig", "/all")
		if out, err := debugCmd.CombinedOutput(); err == nil {
			debugLog("Current interface config:\n%s", string(out))
		}

		// Add route to server
		routeCmd := exec.Command("route", "add",
			serverIP,
			"mask", "255.255.255.255",
			clientIP)
		debugLog("Running command: route add %s mask 255.255.255.255 %s",
			serverIP, clientIP)
		if out, err := routeCmd.CombinedOutput(); err != nil {
			debugLog("Warning: failed to add server route: %v\nOutput: %s", err, string(out))
		}

		debugLog("Basic Windows TAP setup completed")
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
	return version == 4 || version == 6
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
	srcPort := (uint16(packet[20]) << 8) | uint16(packet[21])
	dstPort := (uint16(packet[22]) << 8) | uint16(packet[23])

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
		// First try to remove any existing route
		delCmd := exec.Command("route", "delete", dst)
		if out, err := delCmd.CombinedOutput(); err != nil {
			debugLog("Note: Could not delete existing route for %s: %v\nOutput: %s", dst, err, string(out))
			// Continue anyway as the route might not exist
		}

		// Add the new route
		addCmd := exec.Command("route", "-p", "add",
			dst, "mask", "255.255.255.255",
			gw)
		debugLog("Running command: route -p add %s mask 255.255.255.255 %s", dst, gw)
		if out, err := addCmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to add route (exit code %d): %v\nOutput: %s",
				addCmd.ProcessState.ExitCode(), err, string(out))
		}

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
		cmd := exec.Command("route", "delete", dst)
		debugLog("Running command: route delete %s", dst)
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
