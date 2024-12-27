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
	"math"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"doxx.net/transport"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/songgao/water"
)

const (
	MTU         = 1500
	HEADER_SIZE = 4
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

	return fmt.Sprintf("\r↓ %s/s  ↑ %s/s    ↓ %s  ↑ %s    ",
		formatBytes(bs.rxBytes),
		formatBytes(bs.txBytes),
		formatBits(bs.rxBytes),
		formatBits(bs.txBytes))
}

func formatBytes(bitsPerSec uint64) string {
	switch {
	case bitsPerSec >= 1_000_000_000: // 1 Gbps
		return fmt.Sprintf("%.1f Gbps", float64(bitsPerSec)/1_000_000_000)
	case bitsPerSec >= 1_000_000: // 1 Mbps
		return fmt.Sprintf("%.1f Mbps", float64(bitsPerSec)/1_000_000)
	case bitsPerSec >= 1_000: // 1 Kbps
		return fmt.Sprintf("%.1f Kbps", float64(bitsPerSec)/1_000)
	default:
		if bitsPerSec < 1 {
			return "0 bps"
		}
		return fmt.Sprintf("%.0f bps", float64(bitsPerSec))
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
		return fmt.Sprintf("%.1f Kbps", float64(bits)/1000)
	default:
		return fmt.Sprintf("%d bps", bits)
	}
}

// Add after the existing types
type Connection struct {
	SourceIP     string
	DestIP       string
	SourcePort   int
	DestPort     int
	Protocol     string
	ServiceName  string
	BytesIn      uint64
	BytesOut     uint64
	LastActive   time.Time
	lastBytesIn  uint64
	lastBytesOut uint64
	rateIn       float64
	rateOut      float64
	lastUpdate   time.Time
	firstUpdate  bool
}

type ConnectionMonitor struct {
	app         *tview.Application
	flex        *tview.Flex
	statsView   *tview.TextView
	table       *tview.Table
	connections map[string]*Connection
	mu          sync.RWMutex
	lastUpdate  time.Time
	assignedIP  string
	// Stats
	totalRateIn  float64
	totalRateOut float64
	maxRate      float64
	totalConns   int
}

func NewConnectionMonitor() (*ConnectionMonitor, error) {
	cm := &ConnectionMonitor{
		app:         tview.NewApplication(),
		flex:        tview.NewFlex().SetDirection(tview.FlexRow),
		statsView:   tview.NewTextView().SetTextAlign(tview.AlignLeft),
		connections: make(map[string]*Connection),
		lastUpdate:  time.Now(),
	}

	// Create and style the table
	cm.table = tview.NewTable().
		SetBorders(true).
		SetBordersColor(tcell.ColorDarkGray)

	// Style the stats view
	cm.statsView.
		SetTextColor(tcell.ColorGreen).
		SetDynamicColors(true)

	// Add components to flex layout
	cm.flex.
		AddItem(cm.statsView, 1, 1, false).
		AddItem(cm.table, 0, 1, true)

	// Set up the layout
	cm.app.SetRoot(cm.flex, true)

	// Handle keyboard input
	cm.app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEscape || event.Rune() == 'q' {
			cm.app.Stop()
		}
		return event
	})

	return cm, nil
}

func (cm *ConnectionMonitor) SetAssignedIP(ip string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.assignedIP = ip
}

func (cm *ConnectionMonitor) UpdateConnection(packet []byte) {
	ipHeader, err := parseIPHeader(packet)
	if err != nil {
		return
	}

	// Create unique connection ID
	connID := fmt.Sprintf("%s:%d-%s:%d",
		ipHeader.SrcIP, ipHeader.SrcPort,
		ipHeader.DstIP, ipHeader.DstPort)

	cm.mu.Lock()
	defer cm.mu.Unlock()

	conn, exists := cm.connections[connID]
	if !exists {
		// Look up service name for the destination port
		serviceName := lookupServiceName(ipHeader.DstPort)

		conn = &Connection{
			SourceIP:    ipHeader.SrcIP,
			DestIP:      ipHeader.DstIP,
			SourcePort:  ipHeader.SrcPort,
			DestPort:    ipHeader.DstPort,
			Protocol:    ipHeader.Protocol,
			ServiceName: serviceName,
			LastActive:  time.Now(),
			lastUpdate:  time.Now(),
			firstUpdate: true,
		}
		cm.connections[connID] = conn
	}

	now := time.Now()
	duration := now.Sub(conn.lastUpdate).Seconds()
	packetLen := uint64(len(packet))

	// Only update rates if enough time has passed
	if duration >= 2.0 { // Update every 2 seconds
		// Determine direction based on our assigned IP
		if ipHeader.SrcIP == cm.assignedIP {
			// This is upload (from us to remote)
			byteDiff := conn.BytesOut - conn.lastBytesOut
			if !conn.firstUpdate {
				// Store raw bytes per second (not bits yet)
				conn.rateOut = float64(byteDiff) / duration
			}
			conn.BytesOut += packetLen
			conn.lastBytesOut = conn.BytesOut
		} else if ipHeader.DstIP == cm.assignedIP {
			// This is download (from remote to us)
			byteDiff := conn.BytesIn - conn.lastBytesIn
			if !conn.firstUpdate {
				// Store raw bytes per second (not bits yet)
				conn.rateIn = float64(byteDiff) / duration
			}
			conn.BytesIn += packetLen
			conn.lastBytesIn = conn.BytesIn
		}

		if conn.firstUpdate {
			conn.firstUpdate = false
		}
		conn.lastUpdate = now
	} else {
		// Just accumulate bytes without updating rates
		if ipHeader.SrcIP == cm.assignedIP {
			conn.BytesOut += packetLen
		} else if ipHeader.DstIP == cm.assignedIP {
			conn.BytesIn += packetLen
		}
	}

	conn.LastActive = now
}

func (cm *ConnectionMonitor) Render() {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	// Clear existing rows
	cm.table.Clear()

	// Get terminal size
	_, _, width, height := cm.table.GetRect()
	maxRows := (height - 2) / 2 // Adjust for table headers

	// Calculate total bytes for this interval
	var totalBytesIn, totalBytesOut uint64
	for _, conn := range cm.connections {
		if time.Since(conn.LastActive) <= 2*time.Second {
			if conn.BytesIn > conn.lastBytesIn {
				totalBytesIn += conn.BytesIn - conn.lastBytesIn
			}
			if conn.BytesOut > conn.lastBytesOut {
				totalBytesOut += conn.BytesOut - conn.lastBytesOut
			}
		}
	}

	// Calculate rates in bits per second (multiply by 8 here only)
	duration := 2.0 // our update interval
	currentRateIn := (float64(totalBytesIn) / duration) * 8
	currentRateOut := (float64(totalBytesOut) / duration) * 8

	// Update max rate only if we see a higher value
	currentMaxRate := math.Max(currentRateIn, currentRateOut)
	if currentMaxRate > cm.maxRate {
		cm.maxRate = currentMaxRate
	}

	// Update stats view with left padding
	statsText := fmt.Sprintf(" Download: %s  Upload: %s  Peak: %s  Connections: %d",
		formatBytes(uint64(currentRateIn)),
		formatBytes(uint64(currentRateOut)),
		formatBytes(uint64(cm.maxRate)),
		cm.totalConns)
	cm.statsView.SetText(statsText)

	// Define column widths
	columnWidths := []int{
		width * 15 / 100, // Rate (15%)
		width * 25 / 100, // Source IP (25%)
		width * 15 / 100, // Source Port (15%)
		width * 5 / 100,  // Arrow (5%)
		width * 25 / 100, // Dest IP (25%)
		width * 15 / 100, // Dest Port (15%)
	}

	// Set headers
	headers := []string{
		"Rate", "Source IP", "Source Port", "→",
		"Dest IP", "Dest Port (Service)",
	}
	for i, header := range headers {
		cell := tview.NewTableCell(header).
			SetTextColor(tcell.ColorYellow).
			SetAlign(tview.AlignCenter).
			SetSelectable(false).
			SetMaxWidth(columnWidths[i])
		cm.table.SetCell(0, i, cell)
	}

	// Reset total rates for this render
	cm.totalRateIn = 0
	cm.totalRateOut = 0
	cm.totalConns = 0

	// Create a map to store paired connections
	type sessionKey struct {
		ip1, ip2     string
		port1, port2 int
	}
	type sessionInfo struct {
		sourceIP   string
		destIP     string
		sourcePort int
		destPort   string // Include service name
		rate       float64
	}
	sessions := make(map[sessionKey]*sessionInfo)

	// Group connections into sessions
	for _, conn := range cm.connections {
		if time.Since(conn.LastActive) > 30*time.Second {
			continue
		}

		// Create session keys for both directions
		key1 := sessionKey{
			ip1: conn.SourceIP, ip2: conn.DestIP,
			port1: conn.SourcePort, port2: conn.DestPort,
		}
		key2 := sessionKey{
			ip1: conn.DestIP, ip2: conn.SourceIP,
			port1: conn.DestPort, port2: conn.SourcePort,
		}

		// Calculate bytes transferred in this interval
		var bytesTransferred uint64
		if conn.BytesIn > conn.lastBytesIn {
			bytesTransferred += conn.BytesIn - conn.lastBytesIn
		}
		if conn.BytesOut > conn.lastBytesOut {
			bytesTransferred += conn.BytesOut - conn.lastBytesOut
		}

		// Calculate rate in bits per second
		rate := (float64(bytesTransferred) / 2.0) * 8 // Convert to bits/sec using same 2-second interval

		// Update session info
		if existing, exists := sessions[key1]; exists {
			existing.rate += rate
		} else if existing, exists := sessions[key2]; exists {
			existing.rate += rate
		} else {
			// Create new session
			sessions[key1] = &sessionInfo{
				sourceIP:   conn.SourceIP,
				destIP:     conn.DestIP,
				sourcePort: conn.SourcePort,
				destPort:   fmt.Sprintf("%d (%s)", conn.DestPort, conn.ServiceName),
				rate:       rate,
			}
		}

		// Update totals
		cm.totalRateIn += conn.rateIn
		cm.totalRateOut += conn.rateOut
		if rate > cm.maxRate {
			cm.maxRate = rate
		}
	}
	cm.totalConns = len(sessions)

	// Convert sessions to sorted slice
	var sortedSessions []sessionInfo
	for _, session := range sessions {
		sortedSessions = append(sortedSessions, *session)
	}

	// Sort by rate
	sort.Slice(sortedSessions, func(i, j int) bool {
		return sortedSessions[i].rate > sortedSessions[j].rate
	})

	// Add rows
	row := 1 // Start after header
	for _, session := range sortedSessions {
		if row >= maxRows {
			break
		}

		cells := []string{
			formatBytes(uint64(session.rate)),
			session.sourceIP,
			fmt.Sprintf("%d (%s)", session.sourcePort, lookupServiceName(session.sourcePort)),
			"⇄",
			session.destIP,
			session.destPort,
		}

		for col, cell := range cells {
			cm.table.SetCell(row, col,
				tview.NewTableCell(cell).
					SetTextColor(tcell.ColorWhite).
					SetAlign(tview.AlignCenter).
					SetMaxWidth(columnWidths[col]))
		}
		row++
	}
}

func (cm *ConnectionMonitor) Start() {
	go func() {
		// Update UI every 2 seconds
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				cm.app.QueueUpdateDraw(func() {
					cm.Render()
				})
			}
		}
	}()

	if err := cm.app.Run(); err != nil {
		log.Printf("Error running UI: %v", err)
	}
}

func lookupServiceName(port int) string {
	services := map[int]string{
		// Common Web Services
		80:   "HTTP",
		443:  "HTTPS",
		8080: "HTTP-ALT",
		8443: "HTTPS-ALT",

		// Email Services
		25:  "SMTP",
		465: "SMTPS",
		587: "SUBMISSION",
		110: "POP3",
		995: "POP3S",
		143: "IMAP",
		993: "IMAPS",

		// Remote Access
		22:   "SSH",
		23:   "TELNET",
		3389: "RDP",
		5900: "VNC",

		// File Transfer
		20:  "FTP-DATA",
		21:  "FTP",
		69:  "TFTP",
		115: "SFTP",
		989: "FTPS-DATA",
		990: "FTPS",

		// Name Services
		53:  "DNS",
		88:  "KERBEROS",
		137: "NETBIOS-NS",
		138: "NETBIOS-DGM",
		139: "NETBIOS-SSN",
		389: "LDAP",
		636: "LDAPS",

		// Database Services
		1433:  "MSSQL",
		1521:  "ORACLE",
		3306:  "MYSQL",
		5432:  "POSTGRES",
		27017: "MONGODB",
		6379:  "REDIS",

		// Messaging & Collaboration
		5222: "XMPP",
		5269: "XMPP-SERVER",
		1935: "RTMP",
		5060: "SIP",
		5061: "SIPS",

		// System Services
		67:  "DHCP-SERVER",
		68:  "DHCP-CLIENT",
		123: "NTP",
		161: "SNMP",
		162: "SNMP-TRAP",
		514: "SYSLOG",

		// Gaming
		27015: "SRCDS",
		25565: "MINECRAFT",

		// Media Streaming
		554:  "RTSP",
		1755: "MMS",
		8000: "ICECAST",

		// VPN/Tunneling
		500:  "ISAKMP",
		1701: "L2TP",
		1723: "PPTP",
		1194: "OPENVPN",
		4500: "IPSEC-NAT",

		// Monitoring
		8472: "VXLAN",
		9100: "PROMETHEUS",
		9090: "PROMETHEUS-API",

		// Cloud Services
		2379:  "ETCD",
		6443:  "KUBERNETES-API",
		10250: "KUBELET",
	}

	if service, ok := services[port]; ok {
		return service
	}
	return "Unknown"
}

// Add this helper function to parse IP packets
func parseIPHeader(packet []byte) (*struct {
	SrcIP    string
	DstIP    string
	SrcPort  int
	DstPort  int
	Protocol string
}, error) {
	if len(packet) < 20 {
		return nil, fmt.Errorf("packet too short")
	}

	version := packet[0] >> 4
	if version != 4 {
		return nil, fmt.Errorf("only IPv4 supported")
	}

	ihl := (packet[0] & 0x0F) * 4
	protocol := packet[9]

	srcIP := net.IP(packet[12:16]).String()
	dstIP := net.IP(packet[16:20]).String()

	// Parse ports for TCP/UDP
	var srcPort, dstPort int
	if protocol == 6 || protocol == 17 { // TCP or UDP
		if len(packet) < int(ihl)+4 {
			return nil, fmt.Errorf("packet too short for ports")
		}
		srcPort = int(binary.BigEndian.Uint16(packet[ihl : ihl+2]))
		dstPort = int(binary.BigEndian.Uint16(packet[ihl+2 : ihl+4]))
	}

	protocolName := "Unknown"
	switch protocol {
	case 1:
		protocolName = "ICMP"
	case 6:
		protocolName = "TCP"
	case 17:
		protocolName = "UDP"
	}

	return &struct {
		SrcIP    string
		DstIP    string
		SrcPort  int
		DstPort  int
		Protocol string
	}{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Protocol: protocolName,
	}, nil
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
		uber       bool
	)

	// Print ASCII logo before flag parsing
	fmt.Print(ASCII_LOGO)

	flag.StringVar(&serverAddr, "server", "", "VPN server address (host:port)")
	flag.StringVar(&token, "token", "", "Authentication token")
	flag.StringVar(&vpnType, "type", "tcp", "Transport type (tcp, tcp-encrypted, or https)")
	flag.BoolVar(&noRouting, "no-routing", false, "Disable automatic routing")
	flag.BoolVar(&killRoute, "kill", false, "Remove default route instead of saving it")
	flag.StringVar(&proxyURL, "proxy", "", "Proxy URL (e.g., http://user:pass@host:port, https://user:pass@host:port, or socks5://user:pass@host:port)")
	flag.BoolVar(&keepSSH, "keep-established-ssh", false, "Maintain existing SSH connections through original default route")
	flag.BoolVar(&bandwidth, "bandwidth", false, "Show bandwidth statistics")
	flag.BoolVar(&uber, "uber", false, "Enable interactive connection monitoring UI")
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
		routeManager = NewRouteManager(iface.Name(), killRoute, keepSSH)
	} else if keepSSH {
		log.Printf("Warning: -keep-established-ssh is ignored when -no-routing is set")
		keepSSH = false
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
		var proxyConfig *transport.ProxyConfig
		if proxyURL != "" {
			var err error
			proxyConfig, err = transport.ParseProxyURL(proxyURL)
			if err != nil {
				log.Fatalf("Invalid proxy URL: %v", err)
			}
		}
		client = transport.NewHTTPSTransportClient(proxyConfig)
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

	// Only proceed with interface setup if we have a valid IP and server IP
	if response == nil || response.AssignedIP == "" || response.ServerIP == "" {
		log.Fatal("Invalid response from server: missing IP information")
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
	if routeManager != nil {
		if err := routeManager.Setup(serverAddr); err != nil {
			// Print the error but continue
			log.Printf("Failed to setup routing: %v", err)
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

	// Create WaitGroup for goroutines
	var wg sync.WaitGroup

	// Create channels for error handling
	errChan := make(chan error, 2)

	// Create packet buffer
	packet := make([]byte, MTU)

	// Initialize connection monitor if uber mode is enabled
	var connectionMonitor *ConnectionMonitor
	if uber {
		monitor, err := NewConnectionMonitor()
		if err != nil {
			log.Printf("Warning: Failed to create connection monitor: %v", err)
		} else {
			connectionMonitor = monitor
			// Set our assigned IP after we get it from the server
			connectionMonitor.SetAssignedIP(strings.Split(response.AssignedIP, "/")[0])
			go connectionMonitor.Start()
		}
	}

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

				if connectionMonitor != nil {
					connectionMonitor.UpdateConnection(packet[:n])
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

				if connectionMonitor != nil {
					connectionMonitor.UpdateConnection(pkt)
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

	// Create bandwidth stats if enabled
	var bandwidthStats *BandwidthStats
	if bandwidth {
		bandwidthStats = NewBandwidthStats()

		// Start bandwidth display goroutine
		go func() {
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
		}()
	}

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

	switch runtime.GOOS {
	case "darwin":
		// Use netstat to find established SSH connections
		cmd := exec.Command("netstat", "-n", "-p", "tcp")
		output, err := cmd.Output()
		if err != nil {
			return fmt.Errorf("failed to get netstat output: %v", err)
		}

		debugLog("Parsing netstat output:\n%s", string(output))

		// Updated regex to better match macOS netstat output
		// Looking for connections to remote port 22
		re := regexp.MustCompile(`(?m)^tcp\d*\s+\d+\s+\d+\s+\S+\s+(\d+\.\d+\.\d+\.\d+)\.22\s+.*?ESTABLISHED`)
		matches := re.FindAllStringSubmatch(string(output), -1)

		debugLog("Found %d SSH connections", len(matches))

		for _, match := range matches {
			remoteIP := match[1]
			debugLog("Found established SSH connection to %s", remoteIP)
			if err := rm.addStaticRoute(remoteIP+"/32", rm.defaultGW, rm.defaultIface); err != nil {
				log.Printf("Warning: Failed to preserve SSH route to %s: %v", remoteIP, err)
				continue
			}
			rm.mu.Lock()
			rm.sshRoutes = append(rm.sshRoutes, remoteIP+"/32")
			rm.mu.Unlock()
			debugLog("Successfully preserved route to SSH host %s", remoteIP)
		}

		// Also look for local SSH server connections (connections to our port 22)
		reLocal := regexp.MustCompile(`(?m)^tcp\d*\s+\d+\s+\d+\s+(\d+\.\d+\.\d+\.\d+)\.22\s+\S+\s+.*?ESTABLISHED`)
		localMatches := reLocal.FindAllStringSubmatch(string(output), -1)

		debugLog("Found %d incoming SSH connections", len(localMatches))

		for _, match := range localMatches {
			remoteIP := match[1]
			debugLog("Found established incoming SSH connection from %s", remoteIP)
			if err := rm.addStaticRoute(remoteIP+"/32", rm.defaultGW, rm.defaultIface); err != nil {
				log.Printf("Warning: Failed to preserve SSH route to %s: %v", remoteIP, err)
				continue
			}
			rm.mu.Lock()
			rm.sshRoutes = append(rm.sshRoutes, remoteIP+"/32")
			rm.mu.Unlock()
			debugLog("Successfully preserved route to SSH client %s", remoteIP)
		}

		if len(matches) == 0 && len(localMatches) == 0 {
			debugLog("No established SSH connections found")
		}

	case "linux":
		// Use ss command to find established SSH connections
		cmd := exec.Command("ss", "-n", "-t", "state", "established", "sport", ":22")
		output, err := cmd.Output()
		if err != nil {
			return fmt.Errorf("failed to get ss output: %v", err)
		}

		// Parse ss output for remote IPs
		re := regexp.MustCompile(`(?m)\d+\.\d+\.\d+\.\d+:\d+`)
		matches := re.FindAllString(string(output), -1)

		for _, match := range matches {
			remoteIP := strings.Split(match, ":")[0]
			debugLog("Found established SSH connection to %s", remoteIP)
			if err := rm.addStaticRoute(remoteIP+"/32", rm.defaultGW, rm.defaultIface); err != nil {
				log.Printf("Warning: Failed to preserve SSH route to %s: %v", remoteIP, err)
				continue
			}
			rm.mu.Lock()
			rm.sshRoutes = append(rm.sshRoutes, remoteIP+"/32")
			rm.mu.Unlock()
		}

	case "windows":
		// Use netstat to find established SSH connections
		cmd := exec.Command("netstat", "-n", "-p", "TCP")
		output, err := cmd.Output()
		if err != nil {
			return fmt.Errorf("failed to get netstat output: %v", err)
		}

		// Parse netstat output for SSH connections (port 22)
		re := regexp.MustCompile(`(?m)TCP\s+\d+\.\d+\.\d+\.\d+:\d+\s+(\d+\.\d+\.\d+\.\d+):22\s+ESTABLISHED`)
		matches := re.FindAllStringSubmatch(string(output), -1)

		for _, match := range matches {
			remoteIP := match[1]
			debugLog("Found established SSH connection to %s", remoteIP)
			if err := rm.addStaticRoute(remoteIP+"/32", rm.defaultGW, rm.defaultIface); err != nil {
				log.Printf("Warning: Failed to preserve SSH route to %s: %v", remoteIP, err)
				continue
			}
			rm.mu.Lock()
			rm.sshRoutes = append(rm.sshRoutes, remoteIP+"/32")
			rm.mu.Unlock()
		}
	}

	return nil
}

// Add platform-specific interface statistics gathering
type interfaceStats struct {
	rx uint64
	tx uint64
}

func getInterfaceStats(ifName string) (*interfaceStats, error) {
	switch runtime.GOOS {
	case "linux":
		// Read from /sys/class/net/<interface>/statistics/
		rxBytes, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/statistics/rx_bytes", ifName))
		if err != nil {
			return nil, err
		}
		txBytes, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/statistics/tx_bytes", ifName))
		if err != nil {
			return nil, err
		}

		rx, _ := strconv.ParseUint(strings.TrimSpace(string(rxBytes)), 10, 64)
		tx, _ := strconv.ParseUint(strings.TrimSpace(string(txBytes)), 10, 64)

		return &interfaceStats{rx: rx, tx: tx}, nil

	case "darwin":
		// Use netstat for macOS
		cmd := exec.Command("netstat", "-I", ifName, "-b")
		output, err := cmd.Output()
		if err != nil {
			return nil, err
		}

		lines := strings.Split(string(output), "\n")
		if len(lines) < 3 {
			return nil, fmt.Errorf("unexpected netstat output")
		}

		fields := strings.Fields(lines[2])
		if len(fields) < 7 {
			return nil, fmt.Errorf("invalid netstat output format")
		}

		rx, _ := strconv.ParseUint(fields[6], 10, 64)
		tx, _ := strconv.ParseUint(fields[9], 10, 64)

		return &interfaceStats{rx: rx, tx: tx}, nil

	case "windows":
		// Use PowerShell for Windows
		cmd := exec.Command("powershell", "-Command",
			fmt.Sprintf("Get-NetAdapter | Where-Object Name -eq '%s' | Get-NetAdapterStatistics | Select BytesReceived,BytesSent | ConvertTo-Json", ifName))
		output, err := cmd.Output()
		if err != nil {
			return nil, err
		}

		var stats struct {
			BytesReceived int64 `json:"BytesReceived"`
			BytesSent     int64 `json:"BytesSent"`
		}

		if err := json.Unmarshal(output, &stats); err != nil {
			return nil, err
		}

		return &interfaceStats{
			rx: uint64(stats.BytesReceived),
			tx: uint64(stats.BytesSent),
		}, nil
	}

	return nil, fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
}
