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
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"doxx.net/transport"
	"github.com/songgao/water"
)

const (
	MTU         = 1500
	HEADER_SIZE = 4
	ASCII_LOGO  = `
    ________                                         __   
    \____  \  ____  ___  ___  ___    ____   ____   _/  |_ 
     |  |\  \/  _ \ \  \/  / /  _\  /    \ /  _ \  \   __\
     |  |/   ( <_> ) >    <  \_  \ |   |  ( <_> )   |  |  
    /_______  \____/ /__/\_ \ \___/ |___|  /\____/  |__|  
            \/            \/            \/               
                        
     [ Copyright (c) Barrett Lyon 2024 - https://doxx.net ]
     [ Secure Networking for Humans                       ]
`
)

var debug bool

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
	mu           sync.Mutex
}

type AuthResponse struct {
	Success    bool   `json:"success"`
	AssignedIP string `json:"assigned_ip"`
	PrefixLen  int    `json:"prefix_len"`
	Status     string `json:"status"`
	Message    string `json:"message"`
}

func NewRouteManager(tunIface string, killRoute bool) *RouteManager {
	return &RouteManager{
		tunInterface: tunIface,
		staticRoutes: make([]string, 0),
		killRoute:    killRoute,
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

	// Set new default route via TUN using VPN server IP from auth response
	if err := rm.setDefaultRoute(rm.tunInterface, rm.serverIP); err != nil {
		return fmt.Errorf("failed to set default route: %v", err)
	}

	return nil
}

func (rm *RouteManager) Cleanup() error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

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
	}

	debugLog("Successfully restored default route")
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
	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		return err
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
	return readPacket(t.conn)
}

func (t *SingleTCPTransport) WritePacket(packet []byte) error {
	return writePacket(t.conn, packet)
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

func main() {
	var (
		serverAddr string
		token      string
		vpnType    string
		noRouting  bool
		killRoute  bool
	)

	// Print ASCII logo before flag parsing
	fmt.Print(ASCII_LOGO)

	flag.StringVar(&serverAddr, "server", "", "VPN server address (host:port)")
	flag.StringVar(&token, "token", "", "Authentication token")
	flag.StringVar(&vpnType, "type", "tcp", "Transport type (tcp, tcp-encrypted, or https)")
	flag.BoolVar(&noRouting, "no-routing", false, "Disable automatic routing")
	flag.BoolVar(&killRoute, "kill", false, "Remove default route instead of saving it")
	flag.Parse()

	if debug {
		log.Printf("Debug logging enabled")
	}

	if serverAddr == "" || token == "" {
		log.Println("Error: Server address and token are required")
		flag.Usage()
		os.Exit(1)
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Create TUN interface
	config := water.Config{
		DeviceType: water.TUN,
	}
	iface, err := water.New(config)
	if err != nil {
		log.Fatal(err)
	}

	// Create route manager only if routing is enabled
	var routeManager *RouteManager
	if !noRouting {
		routeManager = NewRouteManager(iface.Name(), killRoute)
	}

	// Create transport based on type
	var client transport.TransportType
	switch vpnType {
	case "tcp":
		client = transport.NewSingleTCPClient()
	case "tcp-encrypted":
		var initErr error
		client, initErr = transport.NewSingleTCPEncryptedClient()
		if initErr != nil {
			log.Fatalf("Failed to create encrypted transport: %v", initErr)
		}
	case "https":
		client = transport.NewHTTPSTransportClient()
	default:
		log.Fatalf("Unsupported transport type: %s", vpnType)
	}

	// Connect using the transport
	if err := client.Connect(serverAddr); err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	log.Printf("Connected to VPN server at %s using %s transport", serverAddr, vpnType)

	// Send authentication token
	if err := client.SendAuth(token); err != nil {
		log.Fatal("Failed to send authentication token:", err)
	}

	// Handle authentication response
	response, err := client.HandleAuth()
	if err != nil {
		log.Printf("Authentication failed: %v", err)

		// Clean shutdown on auth failure
		if routeManager != nil && !noRouting {
			if cleanupErr := routeManager.Cleanup(); cleanupErr != nil {
				log.Printf("Failed to cleanup routes: %v", cleanupErr)
			}
		}
		client.Close()
		os.Exit(1)
	}

	// Only proceed with interface setup if we have a valid IP
	if response.AssignedIP == "" {
		log.Fatal("No IP address assigned by server")
	}

	log.Printf("Successfully authenticated. Assigned IP: %s", response.AssignedIP)

	// Use the assigned IP and prefix length from server
	if err := setupTUN(iface.Name(), response.AssignedIP, response.ServerIP, response.PrefixLen); err != nil {
		log.Fatal(err)
	}

	// Set the client IP and server IP in the route manager before setup
	if routeManager != nil {
		routeManager.SetClientIP(response.AssignedIP)
		routeManager.SetServerIP(response.ServerIP)
	}

	// Setup routing if enabled
	if !noRouting {
		if err := routeManager.Setup(serverAddr); err != nil {
			// Print the error but continue
			log.Printf("Failed to setup routing: %v", err)
		}
	}

	// Add the helpful information with actual gateway - OS specific only
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

	// Add debugging/testing information
	log.Printf("To test connectivity:")
	log.Printf("  - Ping remote endpoint: ping %s", response.ServerIP)
	log.Printf("  - DNS servers available: %s (doxx.net), 1.1.1.1, 8.8.8.8", response.ServerIP)
	log.Printf("  - Test DNS resolution: dig @%s doxx.net", response.ServerIP)

	// Create WaitGroup for goroutines
	var wg sync.WaitGroup

	// Create channels for error handling
	errChan := make(chan error, 2)

	// Create packet buffer
	packet := make([]byte, MTU)

	// TUN to Transport
	wg.Add(1)
	go func() {
		defer func() {
			debugLog("TUN to Transport goroutine exiting")
			wg.Done()
		}()

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

				if err := client.WritePacket(packet[:n]); err != nil {
					errChan <- fmt.Errorf("error writing to transport: %v", err)
					return
				}
			}
		}
	}()

	// Transport to TUN
	wg.Add(1)
	go func() {
		defer func() {
			debugLog("Transport to TUN goroutine exiting")
			wg.Done()
		}()

		for {
			select {
			case <-ctx.Done():
				return
			default:
				pkt, err := client.ReadPacket()
				if err != nil {
					if !strings.Contains(err.Error(), "use of closed network connection") {
						errChan <- fmt.Errorf("error reading from transport: %v", err)
					}
					return
				}

				if !isValidIPPacket(pkt) {
					debugLog("Received invalid IP packet, skipping")
					continue
				}

				if _, err := iface.Write(pkt); err != nil {
					errChan <- fmt.Errorf("error writing to TUN: %v", err)
					return
				}
			}
		}
	}()

	// Error and signal handling
	go func() {
		select {
		case err := <-errChan:
			debugLog("Error occurred: %v", err)
			if strings.Contains(err.Error(), "error reading from transport") {
				log.Printf("Server connection lost: %v", err)
			}
			cancel() // Trigger shutdown
		case <-sigChan:
			debugLog("Received shutdown signal")
			cancel() // Trigger shutdown
		case <-ctx.Done():
			debugLog("Context cancelled")
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

	// Handle signals in a goroutine
	go func() {
		<-sigChan
		log.Println("Received interrupt signal, cleaning up...")
		cancel()
		// Give a moment for cleanup
		time.Sleep(100 * time.Millisecond)
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
		// Convert prefix length to netmask
		mask := net.CIDRMask(prefixLen, 32)
		maskStr := fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])

		// Set IP address using netsh
		addCmd := exec.Command("netsh", "interface", "ip", "set", "address",
			fmt.Sprintf("name=%s", ifName),
			"static",
			clientIP,
			maskStr)
		if out, err := addCmd.CombinedOutput(); err != nil {
			return fmt.Errorf("error setting IP address: %v\nOutput: %s", err, string(out))
		}

		// Add route to server
		routeCmd := exec.Command("netsh", "interface", "ip", "add", "route",
			fmt.Sprintf("%s/32", serverIP),
			ifName,
			clientIP)
		if out, err := routeCmd.CombinedOutput(); err != nil {
			return fmt.Errorf("error adding route: %v\nOutput: %s", err, string(out))
		}

		// Enable the interface
		enableCmd := exec.Command("netsh", "interface", "set", "interface",
			ifName, "enable")
		if out, err := enableCmd.CombinedOutput(); err != nil {
			return fmt.Errorf("error enabling interface: %v\nOutput: %s", err, string(out))
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
	return version == 4 || version == 6
}

func isDNSPacket(packet []byte) bool {
	if len(packet) < 28 { // Minimum DNS packet size (IP + UDP + DNS header)
		return false
	}

	// Check if it's UDP
	if packet[9] != 17 { // Protocol field in IP header
		return false
	}

	// Extract UDP destination port (typically 53 for DNS)
	dstPort := (uint16(packet[22]) << 8) | uint16(packet[23])
	return dstPort == 53
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
	switch runtime.GOOS {
	case "darwin":
		cmd := exec.Command("netstat", "-rn")
		output, err := cmd.Output()
		if err != nil {
			return "", "", err
		}
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "default") {
				fields := strings.Fields(line)
				if len(fields) >= 4 {
					return fields[1], fields[3], nil
				}
			}
		}
		return "", "", fmt.Errorf("default route not found")
	case "linux":
		cmd := exec.Command("ip", "route", "show", "default")
		output, err := cmd.Output()
		if err != nil {
			return "", "", err
		}
		fields := strings.Fields(string(output))
		if len(fields) >= 5 {
			return fields[2], fields[4], nil
		}
		return "", "", fmt.Errorf("default route not found")
	default:
		return "", "", fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

func (rm *RouteManager) addStaticRoute(dst, gw, iface string) error {
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
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

func handleAuthResponse(conn net.Conn) (*AuthResponse, error) {
	packet, err := readPacket(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to read auth response: %v", err)
	}

	var response AuthResponse
	if err := json.Unmarshal(packet, &response); err != nil {
		return nil, fmt.Errorf("failed to parse auth response: %v", err)
	}

	if !response.Success {
		return nil, fmt.Errorf("authentication failed")
	}

	return &response, nil
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
