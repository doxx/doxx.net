/*
 * Copyright (c) 2024-2025 doxx.net
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
	"bufio"
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
                        
     [ Copyright (c) Barrett Lyon 2024-2025 - https://doxx.net ]
     [ Secure Networking for Humans                            ]
`
)

// At package level, declare the variables
var (
	debug                 bool
	snarfDNS              = true
	bandwidthDisplayReady = make(chan struct{})
	bandwidthDisplayInit  sync.Once
	dnsNatTable           *DNSNatTable
	dnsBlocker            *DNSBlocker
	blockBadDNS           bool
	noAutoReconnect       bool
	bandwidthStats        *BandwidthStats
	displayManager        *DisplayManager
	firstConnect          = true
	lastResolvedServerIP  string
	originalServerHost    string
)

// Add a channel to control bandwidth monitoring
var (
	bandwidthMonitorStop = make(chan struct{})
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
	host, port, err := net.SplitHostPort(serverAddr)
	if err != nil {
		return fmt.Errorf("invalid server address format: %v", err)
	}

	// Store original hostname for display
	originalServerHost = host

	// If we have a cached IP and this isn't our first connection, use it
	if lastResolvedServerIP != "" && !firstConnect {
		debugLog("Using cached server IP: %s (original host: %s)", lastResolvedServerIP, originalServerHost)
		serverAddr = net.JoinHostPort(lastResolvedServerIP, port)
	}

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
		// For direct connections, resolve the IP address first
		ips, err := net.LookupIP(host)
		if err != nil {
			return fmt.Errorf("failed to resolve server address %s: %v", host, err)
		}
		if len(ips) == 0 {
			return fmt.Errorf("no IP addresses found for %s", host)
		}

		// Store the first resolved IP for future reconnects
		lastResolvedServerIP = ips[0].String()
		debugLog("Resolved and cached server IP: %s for host: %s", lastResolvedServerIP, originalServerHost)

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
				debugLog("Adding static route for VPN server %s (host: %s)", ipStr, originalServerHost)
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

	return fmt.Sprintf("↓ %-12s  ↑ %-12s    ↓ %-10s  ↑ %-10s",
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
		// Remove resolver file on macOS
		if runtime.GOOS == "darwin" {
			debugLog("Removing .doxx resolver configuration...")
			if err := exec.Command("sudo", "rm", "-f", "/etc/resolver/doxx").Run(); err != nil {
				debugLog("Warning: Failed to remove resolver configuration: %v", err)
			} else {
				// Flush DNS cache and restart mDNSResponder after removal
				if err := exec.Command("sudo", "dscacheutil", "-flushcache").Run(); err != nil {
					debugLog("Warning: Failed to flush DNS cache: %v", err)
				}
				if err := exec.Command("sudo", "killall", "-HUP", "mDNSResponder").Run(); err != nil {
					debugLog("Warning: Failed to restart mDNSResponder: %v", err)
				}
				debugLog("Successfully removed .doxx resolver configuration")
			}
		}

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

// Add new display manager type and global variable
type DisplayManager struct {
	mu            sync.Mutex
	lastBandwidth string
	lastBlocked   string
	enabled       bool
}

// Remove any other declarations of bandwidthDisplayInit since it's now global

func NewDisplayManager() *DisplayManager {
	return &DisplayManager{}
}

func (dm *DisplayManager) Update(bandwidth, blocked string) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	if !dm.enabled {
		return
	}

	// Don't update if both values are empty
	if bandwidth == "" && blocked == "" {
		return
	}

	// Don't overwrite bandwidth with empty value
	if bandwidth == "" {
		bandwidth = dm.lastBandwidth
	}

	// Clear the current line
	fmt.Print("\r\033[K")

	// If we have both bandwidth and blocked info
	if bandwidth != "" && blocked != "" {
		fmt.Printf("\r%s | 🛡️  %s", bandwidth, blocked)
	} else if bandwidth != "" {
		fmt.Printf("\r%s", bandwidth)
	} else if blocked != "" {
		fmt.Printf("\r🛡️  %s", blocked)
	}

	// Store last known good values
	if bandwidth != "" {
		dm.lastBandwidth = bandwidth
	}
	if blocked != "" {
		dm.lastBlocked = blocked
	}
}

// Add a function to control bandwidth display
func toggleBandwidthDisplay(enabled bool) {
	if displayManager != nil {
		if !enabled {
			// Clear the current line
			fmt.Print("\r\033[K")
		}
		displayManager.enabled = enabled
	}
}

// Create a separate function for bandwidth monitoring
func startBandwidthMonitoring(ctx context.Context, tunName string) {
	// Stop any existing monitoring
	select {
	case bandwidthMonitorStop <- struct{}{}:
	default:
	}

	go func() {
		// Use a consistent 2-second interval for smoother updates
		ticker := time.NewTicker(4 * time.Second)
		defer ticker.Stop()

		// Get initial stats
		initialStats, err := getInterfaceStats(tunName)
		if err != nil {
			debugLog("Failed to get initial interface stats: %v", err)
			return
		}

		if bandwidthStats != nil {
			bandwidthStats.mu.Lock()
			bandwidthStats.lastRx = initialStats.rx
			bandwidthStats.lastTx = initialStats.tx
			bandwidthStats.lastUpdate = time.Now()
			bandwidthStats.mu.Unlock()
		}

		for {
			select {
			case <-ticker.C:
				if displayManager != nil && bandwidthStats != nil {
					stats, err := getInterfaceStats(tunName)
					if err != nil {
						debugLog("Failed to get interface stats: %v", err)
						continue
					}
					bandwidthStats.Update(stats.rx, stats.tx)
					displayManager.Update(bandwidthStats.GetReadable(), "")
				}
			case <-bandwidthMonitorStop:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
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
	flag.BoolVar(&blockBadDNS, "block-bad-dns", false, "Block bad DNS traffic")
	flag.BoolVar(&noAutoReconnect, "no-auto-reconnect", false, "Disable automatic reconnection on failure")
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

	// Initialize DNS blocker right here, before "Setting up tunnel device..."
	if blockBadDNS {
		log.Printf("Initializing DNS blocking...")
		fmt.Print("\n\n")
		fmt.Printf("🛡️  DNS Protection\n")
		fmt.Println("────────────────────────────")
		fmt.Printf("Downloading blocklist from hagezi/dns-blocklists...\n")

		// Create DNS blocker with retry logic
		var err error
		for attempt := 1; attempt <= 3; attempt++ {
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(attempt*30)*time.Second)

			if dnsBlocker == nil {
				dnsBlocker = NewDNSBlocker()
			}

			// Try pro list first, fall back to basic
			urls := []string{
				"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt",
				"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/basic.txt",
			}

			for _, url := range urls {
				err = dnsBlocker.UpdateBlocklist(ctx, url)
				if err == nil {
					log.Printf("✓ Successfully downloaded blocklist from %s", url)
					break
				}
			}
			cancel()

			if err == nil {
				// Start background updater
				go func() {
					ticker := time.NewTicker(24 * time.Hour)
					defer ticker.Stop()

					for range ticker.C {
						ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
						if err := dnsBlocker.UpdateBlocklist(ctx, urls[0]); err != nil {
							log.Printf("Warning: Failed to update blocklist: %v", err)
						}
						cancel()
					}
				}()
				break
			}

			if attempt < 3 {
				log.Printf("Attempt %d failed, retrying in %d seconds...", attempt, attempt*2)
				time.Sleep(time.Duration(attempt*2) * time.Second)
			}
		}

		if err != nil {
			log.Printf("❌ Failed to initialize DNS blocklist after 3 attempts: %v", err)
			log.Printf("Continuing without DNS blocking...")
			blockBadDNS = false
			dnsBlocker = nil
		} else {
			fmt.Printf("✓ DNS Protection initialized successfully\n")
		}

		fmt.Println("────────────────────────────")
		time.Sleep(1 * time.Second)
	}

	log.Printf("Setting up tunnel device...")
	tunDevice, err := createTunDevice("doxx")
	if err != nil {
		log.Printf("Failed to create TUN device: %v", err)
		cleanup(nil, nil, ctx)
		os.Exit(1)
	}
	defer tunDevice.Close()

	// Create route manager ONCE, outside the connection loop
	var routeManager *RouteManager
	if !noRouting {
		routeManager = NewRouteManager(tunDevice.Name(), killRoute, keepSSH)
	}

	// Connection loop
	retryDelay := time.Second
	for {
		// Create transport
		var client transport.TransportType
		switch vpnType {
		case "tcp":
			client = transport.NewSingleTCPClient()
			// Use cached IP if available, otherwise use original address
			connectAddr := serverAddr
			if lastResolvedServerIP != "" && !firstConnect {
				host, port, _ := net.SplitHostPort(serverAddr)
				connectAddr = net.JoinHostPort(lastResolvedServerIP, port)
				debugLog("Reconnecting using cached IP %s (original host: %s)", lastResolvedServerIP, host)
			}

			if err := client.Connect(connectAddr); err != nil {
				if noAutoReconnect {
					log.Printf("Connection failed: %v", err)
					cleanup(routeManager, nil, ctx)
					os.Exit(1)
				}
				// Temporarily disable bandwidth display during reconnection
				toggleBandwidthDisplay(false)
				log.Printf("Connection failed: %v, retrying in %v...", err, retryDelay)

				// Use timer for retry delay with interrupt handling
				timer := time.NewTimer(retryDelay)
				select {
				case <-timer.C:
					retryDelay *= 2
					if retryDelay > time.Minute {
						retryDelay = time.Minute
					}
					continue
				case <-sigChan:
					timer.Stop()
					log.Println("Received interrupt signal")
					cleanup(routeManager, client, ctx)
					os.Exit(0)
				}
			}
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

		// Connect and handle session
		log.Printf("Connecting to %s...", serverAddr)

		// Add signal handling for connection attempt
		connErrChan := make(chan error, 1)
		go func() {
			connErrChan <- client.Connect(serverAddr)
		}()

		select {
		case err := <-connErrChan:
			if err != nil {
				if noAutoReconnect {
					log.Printf("Connection failed: %v", err)
					cleanup(routeManager, client, ctx)
					os.Exit(1)
				}
				// Temporarily disable bandwidth display during reconnection
				toggleBandwidthDisplay(false)
				log.Printf("Connection failed: %v, retrying in %v...", err, retryDelay)

				// Use timer for retry delay with interrupt handling
				timer := time.NewTimer(retryDelay)
				select {
				case <-timer.C:
					retryDelay *= 2
					if retryDelay > time.Minute {
						retryDelay = time.Minute
					}
					continue
				case <-sigChan:
					timer.Stop()
					log.Println("Received interrupt signal")
					cleanup(routeManager, client, ctx)
					os.Exit(0)
				}
			}
		case <-sigChan:
			log.Println("Received interrupt signal")
			cleanup(routeManager, client, ctx)
			os.Exit(0)
		}

		// Reset delay on successful connection
		retryDelay = time.Second

		// Send authentication token
		if err := client.SendAuth(token); err != nil {
			log.Printf("Failed to send authentication token: %v, retrying in %v...", err, retryDelay)
			client.Close()
			timer := time.NewTimer(retryDelay)
			select {
			case <-timer.C:
				retryDelay *= 2
				if retryDelay > time.Minute {
					retryDelay = time.Minute
				}
				continue
			case <-sigChan:
				timer.Stop()
				log.Println("Received interrupt signal")
				cleanup(routeManager, client, ctx)
				os.Exit(0)
			}
		}

		// Handle authentication response
		response, err := client.HandleAuth()
		if err != nil {
			log.Printf("Authentication failed: %v, retrying in %v...", err, retryDelay)
			client.Close()
			timer := time.NewTimer(retryDelay)
			select {
			case <-timer.C:
				retryDelay *= 2
				if retryDelay > time.Minute {
					retryDelay = time.Minute
				}
				continue
			case <-sigChan:
				timer.Stop()
				log.Println("Received interrupt signal")
				cleanup(routeManager, client, ctx)
				os.Exit(0)
			}
		}

		// Validate response
		if response == nil || response.AssignedIP == "" || response.ServerIP == "" {
			log.Printf("Invalid response from server: missing IP information, retrying in %v...", retryDelay)
			client.Close()
			timer := time.NewTimer(retryDelay)
			select {
			case <-timer.C:
				retryDelay *= 2
				if retryDelay > time.Minute {
					retryDelay = time.Minute
				}
				continue
			case <-sigChan:
				timer.Stop()
				log.Println("Received interrupt signal")
				cleanup(routeManager, client, ctx)
				os.Exit(0)
			}
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

		// IMPORTANT: Only store the default gateway on first connection
		if routeManager != nil && firstConnect {
			if err := routeManager.Setup(serverAddr); err != nil {
				log.Printf("Failed to setup routing: %v", err)
				cleanup(routeManager, client, ctx)
				os.Exit(1)
			}
			firstConnect = false
		} else if routeManager != nil {
			// On reconnect, only update the server routes
			if err := routeManager.updateServerRoutes(serverAddr); err != nil {
				log.Printf("Failed to update server routes: %v", err)
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
		performGeoLookup(func() {
			// Initialize bandwidth display after geo lookup completes
			bandwidthDisplayInit.Do(func() {
				close(bandwidthDisplayReady)
			})

			toggleBandwidthDisplay(true)
		})

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

		// In main(), before starting the connection loop, add:
		if !noBandwidth {
			bandwidthStats = NewBandwidthStats()
			displayManager = NewDisplayManager()
		}

		// Then in the connection handling section:
		if !noBandwidth {
			// Create bandwidth stats if enabled
			if bandwidthStats == nil {
				bandwidthStats = NewBandwidthStats()
			}
			if displayManager == nil {
				displayManager = NewDisplayManager()
			}

			// Start the single bandwidth monitoring routine
			startBandwidthMonitoring(ctx, tunDevice.Name())
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
						packetCopy = rewriteDNSPacket(packetCopy, net.ParseIP(response.ServerIP), dnsNatTable, tunDevice)
						// Skip if packet was handled internally (nil return)
						if packetCopy == nil {
							continue
						}
					}

					if err := client.WritePacket(packetCopy); err != nil {
						errChan <- fmt.Errorf("error writing to transport: %v", err)
						return
					}

					debugICMPPacket("TUN->Transport", packet[:n])
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

					var packetToWrite []byte
					if !noSnarfDNS && isDNSPacket(packet, net.ParseIP(response.ServerIP)) {
						if debug {
							debugLog("Processing DNS packet from transport")
						}
						// Create copy only for DNS packets that need modification
						packetCopy := make([]byte, len(packet))
						copy(packetCopy, packet)
						packetToWrite = rewriteDNSPacket(packetCopy, net.ParseIP(response.ServerIP), dnsNatTable, tunDevice)
					} else {
						// Use original packet for non-DNS traffic
						packetToWrite = packet
					}

					// Write ONLY ONCE, using either the modified copy or original
					if _, err := tunDevice.Write(packetToWrite); err != nil {
						errChan <- fmt.Errorf("error writing to TUN: %v", err)
						return
					}

					debugICMPPacket("Transport->TUN", packet)
				}
			}
		}()

		// Error and signal handling
		go func() {
			for {
				select {
				case err := <-errChan:
					if noAutoReconnect {
						log.Printf("Connection error: %v", err)
						cleanup(routeManager, client, ctx)
						os.Exit(1)
					}

					// Check for specific connection errors
					if err != nil {
						if strings.Contains(err.Error(), "connection reset by peer") ||
							strings.Contains(err.Error(), "EOF") ||
							strings.Contains(err.Error(), "broken pipe") {
							log.Printf("Connection lost: %v, reconnecting in %v...", err, retryDelay)
						} else {
							log.Printf("Connection error: %v, reconnecting in %v...", err, retryDelay)
						}
					}

					// Close only the client connection, preserve routes
					if client != nil {
						client.Close()
					}

					// Use timer instead of sleep to allow interrupt handling
					timer := time.NewTimer(retryDelay)
					select {
					case <-timer.C:
						// Timer completed, continue with reconnect
					case <-sigChan:
						timer.Stop()
						log.Println("Received interrupt signal")
						cleanup(routeManager, client, ctx)
						os.Exit(0)
					}

					retryDelay *= 2

					// Maximum retry delay of 1 minute
					if retryDelay > time.Minute {
						retryDelay = time.Minute
					}

					// Create new context for the next connection attempt
					ctx, cancel = context.WithCancel(context.Background())
					return

				case <-sigChan:
					log.Println("Received interrupt signal")
					cleanup(routeManager, client, ctx)
					os.Exit(0)

				case <-ctx.Done():
					// Only do full cleanup if we're not in a reconnection scenario
					select {
					case <-errChan:
						// We're reconnecting, just close the client
						if client != nil {
							client.Close()
						}
					default:
						// Normal shutdown
						log.Println("Context cancelled")
						cleanup(routeManager, client, ctx)
						os.Exit(0)
					}
				}
			}
		}()

		// Wait for goroutines
		wg.Wait()
		debugLog("All goroutines completed")

		// Only show connection details on first connect
		if firstConnect {
			log.Printf("To test connectivity:")
			log.Printf("  - Ping remote endpoint: ping %s", response.ServerIP)
			log.Printf("  - DNS servers available: %s (doxx.net), 1.1.1.1, 8.8.8.8", response.ServerIP)
			log.Printf("  - Test DNS resolution: dig @%s doxx.net", response.ServerIP)

			// Now perform the geo lookup after routes are established
			performGeoLookup(func() {
				// Initialize bandwidth display after geo lookup completes
				bandwidthDisplayInit.Do(func() {
					close(bandwidthDisplayReady)
				})

				toggleBandwidthDisplay(true)
			})

			firstConnect = false
		} else {
			// For reconnects, just enable bandwidth display immediately
			toggleBandwidthDisplay(true)
		}
	}
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

		// Get current DNS servers from primary interface
		primaryDNS := []string{}

		// Use ipconfig /all to get more reliable DNS information
		dnsListCmd := exec.Command("ipconfig", "/all")
		if out, err := dnsListCmd.CombinedOutput(); err == nil {
			lines := strings.Split(string(out), "\n")
			currentAdapter := ""
			foundPrimaryAdapter := false

			for _, line := range lines {
				line = strings.TrimSpace(line)

				// Look for adapter sections
				if strings.Contains(line, "Ethernet adapter") || strings.Contains(line, "Wireless LAN adapter") {
					currentAdapter = line
					// Skip the doxx adapter
					if strings.Contains(strings.ToLower(line), "doxx") {
						currentAdapter = ""
					}
					continue
				}

				// Only process if we're in a valid adapter section
				if currentAdapter == "" {
					continue
				}

				// Look for default gateway to identify primary adapter
				if strings.Contains(line, "Default Gateway") && !strings.HasSuffix(line, ":") {
					foundPrimaryAdapter = true
				}

				// If we found the primary adapter, look for its DNS servers
				if foundPrimaryAdapter && strings.Contains(line, "DNS Servers") {
					parts := strings.Split(line, ":")
					if len(parts) == 2 {
						server := strings.TrimSpace(parts[1])
						if net.ParseIP(server) != nil && server != "" {
							primaryDNS = append(primaryDNS, server)
						}
					}
				}
			}

			if len(primaryDNS) > 0 {
				debugLog("Found existing DNS servers on primary interface: %v", primaryDNS)
			}
		}

		// Only use defaults if we couldn't find any DNS servers
		if len(primaryDNS) == 0 {
			primaryDNS = []string{"1.1.1.1"}
			debugLog("No existing DNS servers found, using default: %v", primaryDNS)
		}

		// First, remove any existing DNS servers
		clearDNSCmd := exec.Command("netsh", "interface", "ipv4", "delete", "dnsservers", ifName, "all")
		if out, err := clearDNSCmd.CombinedOutput(); err != nil {
			debugLog("Warning: Failed to clear existing DNS servers: %v\nOutput: %s", err, string(out))
		}

		// Configure DNS servers
		for i, dns := range primaryDNS {
			dnsCmd := exec.Command("netsh", "interface", "ipv4", "add", "dnsservers",
				ifName, dns, fmt.Sprintf("index=%d", i+1))
			if out, err := dnsCmd.CombinedOutput(); err != nil {
				debugLog("Warning: Failed to set DNS server %s: %v\nOutput: %s", dns, err, string(out))
			} else {
				debugLog("Successfully configured DNS server %s for interface %s", dns, ifName)
			}
		}

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
			// For download (rx), only count packets coming from the transport
			// For upload (tx), only count packets going to the transport
			return &interfaceStats{
				rx: counter.BytesRecv / 2, // Divide by 2 to correct double counting
				tx: counter.BytesSent,     // Upload path is correct
			}, nil
		}
	}

	return nil, fmt.Errorf("interface %s not found", ifName)
}

// Modify performGeoLookup to take a callback
func performGeoLookup(onComplete func()) {
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

		// Call the completion callback
		if onComplete != nil {
			onComplete()
		}
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
func rewriteDNSPacket(packet []byte, serverIP net.IP, natTable *DNSNatTable, tun io.Writer) []byte {
	// Ensure it's an IPv4 packet
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return packet
	}

	// Check if UDP and port 53
	if packet[9] != 17 { // UDP protocol
		return packet
	}

	// Extract ports and query ID
	srcIP := net.IP(packet[12:16])
	dstIP := net.IP(packet[16:20])
	srcPort := uint16(packet[20])<<8 | uint16(packet[21])
	dstPort := uint16(packet[22])<<8 | uint16(packet[23])
	queryID := uint16(packet[28])<<8 | uint16(packet[29])

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

	if dstPort == DNS_PORT && dnsBlocker != nil {
		dnsPayload := packet[28:] // Skip IP + UDP headers
		if len(dnsPayload) < 12 {
			return packet
		}

		queryID := uint16(packet[28])<<8 | uint16(packet[29])
		key := fmt.Sprintf("%s:%d:%d", srcIP.String(), srcPort, queryID)

		// Only add NAT entry if it doesn't exist and dstIP is a public DNS server
		existingEntry := natTable.Lookup(srcIP, srcPort, queryID)
		if existingEntry == nil && !dstIP.Equal(serverIP) {
			if debug {
				debugLog("Adding NAT entry with key: %s, original DNS: %s", key, dstIP)
			}
			natTable.Add(srcIP, srcPort, dstIP, queryID)
		}

		// Extract domain from DNS query
		offset := 12
		var domain strings.Builder
		for offset < len(dnsPayload) {

			length := int(dnsPayload[offset])
			if length == 0 {
				break
			}
			if offset+length+1 > len(dnsPayload) {
				break
			}
			if domain.Len() > 0 {
				domain.WriteString(".")
			}
			domain.Write(dnsPayload[offset+1 : offset+1+length])
			offset += length + 1
		}

		domainStr := domain.String()
		if domainStr != "" && dnsBlocker.ShouldBlock(domainStr) {
			// Pad domain string to typical FQDN length
			if len(domainStr) > 40 {
				domainStr = domainStr[:37] + "..."
			}
			paddedDomain := fmt.Sprintf("%-40s", domainStr)

			// Update display with blocked domain
			if displayManager != nil {
				var bandwidth string
				if bandwidthStats != nil {
					bandwidth = bandwidthStats.GetReadable()
				}
				displayManager.Update(bandwidth, fmt.Sprintf("Blocked: %s\n", paddedDomain))
			}

			// Look up the original DNS server from NAT table
			natEntry := natTable.Lookup(srcIP, srcPort, queryID)

			originalDNS := dstIP
			if natEntry != nil {
				originalDNS = natEntry.OriginalDst
				if debug {
					debugLog("Using NAT entry original DNS: %v", originalDNS)
				}
			} else if debug {
				debugLog("No NAT entry found, using packet destination: %v", originalDNS)
			}

			// Create NXDOMAIN response using the original DNS server IP
			response := createBlockedDNSResponse(packet, originalDNS)

			if debug {
				debugLog("Original query packet:")
				debugLog("Src IP:Port = %v:%d", srcIP, srcPort)
				debugLog("Dst IP:Port = %v:%d (Original DNS server)", originalDNS, dstPort)
				debugLog("NXDOMAIN response packet:")
				debugLog("Src IP:Port = %v:%d (Original DNS server)", net.IP(response[12:16]),
					uint16(response[20])<<8|uint16(response[21]))
				debugLog("Dst IP:Port = %v:%d (Client)", net.IP(response[16:20]),
					uint16(response[22])<<8|uint16(response[23]))
			}

			// Write the NXDOMAIN response
			n, err := tun.Write(response)
			if err != nil {
				debugLog("Failed to write NXDOMAIN response to TUN: %v", err)
			} else if n != len(response) {
				debugLog("Incomplete write to TUN device: wrote %d of %d bytes", n, len(response))
				// On Windows with WinTUN, partial writes can occur
				if runtime.GOOS == "windows" && n > 0 {
					// Attempt to write remaining bytes
					remaining := response[n:]
					if _, err := tun.Write(remaining); err != nil {
						debugLog("Failed to write remaining bytes: %v", err)
					}
				}
			} else {
				debugLog("Successfully wrote %d byte NXDOMAIN response to TUN device", n)
			}

			return nil
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

	fmt.Println("\nChecking doxx.net configuration...")
	fmt.Println("────────────────────────────")

	// Check CA certificate installation
	switch runtime.GOOS {
	case "darwin":
		// Check system trust store
		cmd := exec.Command("security", "find-certificate", "-c", "doxx.net Root CA", "/Library/Keychains/System.keychain")
		status["ca_system"] = cmd.Run() == nil

		// Check curl certificates
		_, err := os.Stat("/etc/ssl/certs/doxx-root-ca.crt")
		status["ca_curl"] = err == nil

		// Always write the resolver configuration
		resolverContent := []byte("domain doxx\nnameserver 1.1.1.1\nnameserver 8.8.8.8\nsearch_order 1\ntimeout 5\noptions private")

		// Create resolver directory if it doesn't exist
		if err := exec.Command("sudo", "mkdir", "-p", "/etc/resolver").Run(); err == nil {
			// Create temporary file with resolver content
			if tmpfile, err := os.CreateTemp("", "resolver"); err == nil {
				defer os.Remove(tmpfile.Name())

				if _, err := tmpfile.Write(resolverContent); err == nil {
					tmpfile.Close()

					// Copy file to destination using sudo
					if err := exec.Command("sudo", "cp", tmpfile.Name(), "/etc/resolver/doxx").Run(); err == nil {
						// Set proper permissions
						exec.Command("sudo", "chmod", "644", "/etc/resolver/doxx").Run()

						// Flush DNS cache and restart mDNSResponder
						exec.Command("sudo", "dscacheutil", "-flushcache").Run()
						exec.Command("sudo", "killall", "-HUP", "mDNSResponder").Run()
					}
				}
			}
		}

		// Check if the file exists now (for status reporting)
		content, _ := os.ReadFile("/etc/resolver/doxx")
		status["resolver"] = string(content) == string(resolverContent)

	case "linux":
		// Check system certificates
		_, err := os.Stat("/etc/ssl/certs/doxx-root-ca.crt")
		status["ca_system"] = err == nil

		// Check if cert is in the hash directory
		hashCmd := exec.Command("sh", "-c", "ls /etc/ssl/certs | grep -i doxx")
		status["ca_hash"] = hashCmd.Run() == nil

	case "windows":
		// Check Windows certificate store
		cmd := exec.Command("certutil", "-store", "root", "doxx.net Root CA")
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
	// Get the status without printing it again
	allConfigured, status := checkCAandDNSConfig()

	if allConfigured {
		fmt.Println("\n✓ All doxx.net components are properly configured!")
		fmt.Println("No additional setup needed.")
		return nil
	}

	fmt.Println("\ndoxx.net Root CA Installation")
	fmt.Println("────────────────────────────")
	fmt.Println("The doxx.net Root CA enables secure communication with .doxx domains and")
	fmt.Println("allows users to register their own domains without relying on the public PKI system.")
	fmt.Println("This is essential for maintaining privacy and security within the doxx.net network.")
	fmt.Println("\nDNS Configuration:")
	fmt.Println("When connected to doxx.net, DNS queries are automatically secured through our network.")
	fmt.Println("We recommend using 1.1.1.1 and 8.8.8.8 as your default DNS servers.")
	fmt.Println("The doxx client will automatically redirect DNS traffic to secure doxx.net servers")
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
			fmt.Println("\nTo install the doxx.net Root CA on Windows:")
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
		fmt.Println("Your system is now configured to use doxx.net secure DNS services.")
		fmt.Println("Default DNS servers (recommended):")
		fmt.Println("  Primary:   1.1.1.1    (Cloudflare)")
		fmt.Println("  Secondary: 8.8.8.8    (Google)")
	} else {
		fmt.Println("\n⚠ Some components may not have installed correctly.")
		fmt.Println("Please check the status messages above.")
	}

	return nil
}

func installCertificate(certPath string) error {
	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("certutil", "-addstore", "root", certPath)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to install certificate: %v\nOutput: %s", err, out)
		}
		debugLog("Certificate installed successfully using certutil")
		return nil

	case "darwin":
		// Install in system keychain
		cmd := exec.Command("security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", certPath)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to install certificate in system keychain: %v\nOutput: %s", err, out)
		}

		// Create directory for Unix-style cert location if it doesn't exist
		if err := exec.Command("sudo", "mkdir", "-p", "/etc/ssl/certs").Run(); err != nil {
			return fmt.Errorf("failed to create Unix-style cert directory: %v", err)
		}

		// Copy certificate to Unix-style location for curl and other tools
		if err := exec.Command("sudo", "cp", certPath, "/etc/ssl/certs/doxx-root-ca.crt").Run(); err != nil {
			return fmt.Errorf("failed to install certificate for Unix-style tools: %v", err)
		}

		debugLog("Certificate installed successfully in both system keychain and Unix-style location")
		return nil

	case "linux":
		// Create necessary directories
		if err := exec.Command("sudo", "mkdir", "-p", "/usr/local/share/ca-certificates").Run(); err != nil {
			return fmt.Errorf("failed to create certificate directory: %v", err)
		}

		// Copy certificate to the CA directory
		if err := exec.Command("sudo", "cp", certPath, "/usr/local/share/ca-certificates/doxx-root-ca.crt").Run(); err != nil {
			return fmt.Errorf("failed to copy certificate: %v", err)
		}

		// Update CA certificates
		if err := exec.Command("sudo", "update-ca-certificates").Run(); err != nil {
			return fmt.Errorf("failed to update CA certificates: %v", err)
		}

		// Create symlink in /etc/ssl/certs for compatibility
		if err := exec.Command("sudo", "ln", "-sf",
			"/usr/local/share/ca-certificates/doxx-root-ca.crt",
			"/etc/ssl/certs/doxx-root-ca.pem").Run(); err != nil {
			debugLog("Warning: Failed to create symlink in /etc/ssl/certs: %v", err)
			// Don't return error as this is not critical
		}

		debugLog("Certificate installed successfully on Linux")
		return nil

	}

	return fmt.Errorf("unsupported platform for certificate installation")
}

func debugICMPPacket(prefix string, packet []byte) {
	if !debug || len(packet) < 28 || packet[9] != 1 { // Not ICMP
		return
	}

	srcIP := net.IP(packet[12:16])
	dstIP := net.IP(packet[16:20])
	icmpType := packet[20]
	icmpCode := packet[21]
	icmpID := uint16(packet[24])<<8 | uint16(packet[25])
	icmpSeq := uint16(packet[26])<<8 | uint16(packet[27])

	debugLog("%s ICMP packet: %s -> %s (Type: %d, Code: %d, ID: %d, Seq: %d)",
		prefix, srcIP, dstIP, icmpType, icmpCode, icmpID, icmpSeq)
}

// DNSBlocker manages the DNS blocking functionality
type DNSBlocker struct {
	blocklist map[string]struct{}
	mu        sync.RWMutex
}

// NewDNSBlocker creates a new DNS blocker instance
func NewDNSBlocker() *DNSBlocker {
	return &DNSBlocker{
		blocklist: make(map[string]struct{}),
	}
}

// UpdateBlocklist downloads and updates the DNS blocklist
func (db *DNSBlocker) UpdateBlocklist(ctx context.Context, url string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download blocklist: %v", err)
	}
	defer resp.Body.Close()

	newBlocklist := make(map[string]struct{})
	scanner := bufio.NewScanner(resp.Body)
	count := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			newBlocklist[line] = struct{}{}
			count++
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading blocklist: %v", err)
	}

	db.mu.Lock()
	db.blocklist = newBlocklist
	db.mu.Unlock()

	// Add this debug logging
	log.Printf("DNS Blocklist loaded with %d domains", count)
	// Log a few example domains
	i := 0
	for domain := range newBlocklist {
		if i < 5 {
			log.Printf("Sample blocked domain: %s", domain)
			i++
		} else {
			break
		}
	}
	return nil
}

// ShouldBlock checks if a domain should be blocked
func (db *DNSBlocker) ShouldBlock(domain string) bool {
	db.mu.RLock()
	defer db.mu.RUnlock()

	// Ignore system domains
	if strings.HasSuffix(domain, ".local") ||
		strings.HasSuffix(domain, ".doxx") ||
		strings.HasSuffix(domain, ".arpa") ||
		strings.Contains(domain, "_tcp.") ||
		strings.Contains(domain, "_udp.") {
		return false
	}

	// Check exact match
	if _, exists := db.blocklist[domain]; exists {
		debugLog("Blocked domain: %s (exact match)", domain)
		return true
	}

	// Check parent domains
	parts := strings.Split(domain, ".")
	for i := 0; i < len(parts)-1; i++ {
		parentDomain := strings.Join(parts[i:], ".")
		if _, exists := db.blocklist[parentDomain]; exists {
			debugLog("Blocked domain: %s (parent domain match: %s)", domain, parentDomain)
			return true
		}
	}
	return false
}

// Update createBlockedDNSResponse to accept the original DNS server IP
func createBlockedDNSResponse(originalPacket []byte, dnsServerIP net.IP) []byte {
	response := make([]byte, len(originalPacket))
	copy(response, originalPacket)

	// Use original DNS server IP as source
	copy(response[12:16], dnsServerIP.To4())     // Source IP is DNS server
	copy(response[16:20], originalPacket[12:16]) // Destination IP is original client

	// Swap source and destination ports
	copy(response[20:22], originalPacket[22:24]) // Source port (DNS port 53)
	copy(response[22:24], originalPacket[20:22]) // Destination port (client port)

	// Update UDP length (offset 24, 2 bytes)
	udpLen := len(response) - 20 // Total length minus IP header
	response[24] = byte(udpLen >> 8)
	response[25] = byte(udpLen)

	// DNS header starts at offset 28
	response[28+2] = 0x81 // Set QR bit (response) and keep original opcode
	response[28+3] = 0x83 // Set RCODE to NXDOMAIN (3)

	// Keep the QDCOUNT but zero out other counts
	response[28+4] = originalPacket[28+4] // QDCOUNT high byte
	response[28+5] = originalPacket[28+5] // QDCOUNT low byte
	response[28+6] = 0x00                 // ANCOUNT = 0
	response[28+7] = 0x00
	response[28+8] = 0x00 // NSCOUNT = 0
	response[28+9] = 0x00
	response[28+10] = 0x00 // ARCOUNT = 0
	response[28+11] = 0x00

	// Update IP total length field (offset 2, 2 bytes)
	totalLen := len(response)
	response[2] = byte(totalLen >> 8)
	response[3] = byte(totalLen)

	// Update checksums
	updateIPChecksum(response)
	updateUDPChecksum(response)

	return response
}

// Add this new method to RouteManager
func (rm *RouteManager) updateServerRoutes(serverAddr string) error {
	// Extract hostname/IP from server address
	host := strings.Split(serverAddr, ":")[0]

	// For Cloudflare-proxied domains, routes are already set up
	if strings.Contains(serverAddr, "cdn.") && strings.Contains(serverAddr, ".doxx.net") {
		return nil
	}

	// Resolve the IP address
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("failed to resolve server address %s: %v", host, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("no IP addresses found for %s", host)
	}

	// Add static route for each resolved IP
	for _, ip := range ips {
		if ip.To4() != nil { // Only handle IPv4 addresses
			ipStr := ip.String()
			debugLog("Adding static route for VPN server %s", ipStr)
			if err := rm.addStaticRoute(ipStr+"/32", rm.defaultGW, rm.defaultIface); err != nil {
				return fmt.Errorf("failed to add static route for VPN server IP %s: %v", ipStr, err)
			}
			rm.mu.Lock()
			rm.staticRoutes = append(rm.staticRoutes, ipStr+"/32")
			rm.serverIPs = append(rm.serverIPs, ip)
			rm.mu.Unlock()
		}
	}

	return nil
}
