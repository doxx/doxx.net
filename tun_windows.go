//go:build windows

package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

type TunDevice struct {
	adapter *wintun.Adapter
	session wintun.Session
	name    string
}

const (
	WINTUN_DLL          = "wintun.dll"
	WINTUN_DOWNLOAD_URL = "https://www.wintun.net/"
)

func createTunDevice(name string) (*TunDevice, error) {
	debugLog("Checking for existing adapter named: %s", name)

	// Force cleanup of any existing adapters with our name
	cleanupCmd := exec.Command("netsh", "interface", "delete", "interface", name)
	if output, err := cleanupCmd.CombinedOutput(); err != nil {
		debugLog("Cleanup attempt (non-critical): %v\nOutput: %s", err, output)
	}

	// Wait for cleanup
	time.Sleep(2 * time.Second)

	// First try to extract embedded DLL
	dllPath, err := extractEmbeddedWintun()
	if err != nil {
		debugLog("Failed to extract embedded Wintun DLL: %v", err)
	} else {
		debugLog("Successfully extracted Wintun DLL to: %s", dllPath)
	}

	// Try both System32, embedded/extracted, and local paths
	dllPaths := []string{
		`C:\Windows\System32\wintun.dll`,
		dllPath, // Our extracted path
		filepath.Join(filepath.Dir(dllPath), "wintun.dll"),
	}

	var handle windows.Handle
	var loadError error

	for _, path := range dllPaths {
		if path == "" {
			continue
		}

		debugLog("Trying to load: %s", path)

		// Check if file exists and is readable
		if _, err := os.Stat(path); err != nil {
			debugLog("File check failed: %v", err)
			continue
		}

		// Try to load using direct Windows API
		handle, loadError = windows.LoadLibraryEx(path, 0, windows.LOAD_WITH_ALTERED_SEARCH_PATH)
		if handle != 0 {
			debugLog("Successfully loaded DLL from: %s", path)
			break
		}
		debugLog("LoadLibrary failed: %v (error code: %d)", loadError, windows.GetLastError())
	}

	if handle == 0 {
		return nil, fmt.Errorf("failed to load wintun.dll: %v", loadError)
	}
	defer windows.FreeLibrary(handle)

	// Try to initialize Wintun with more detailed logging
	guid, err := windows.GUIDFromString("{56B4895A-C9E8-45B4-9C72-4EAAF6B6D65B}")
	if err != nil {
		return nil, fmt.Errorf("error creating GUID: %v", err)
	}

	debugLog("Creating new adapter named: %s", name)
	adapter, err := wintun.CreateAdapter(name, "doxx.net", &guid)
	if err != nil {
		return nil, fmt.Errorf("error creating Wintun adapter: %v", err)
	}

	debugLog("Starting adapter session")
	session, err := adapter.StartSession(0x2000000) // 32MB ring buffer (increased from 8MB)
	if err != nil {
		debugLog("Session start failed: %v", err)
		adapter.Close()
		return nil, fmt.Errorf("error starting Wintun session: %v", err)
	}
	debugLog("Session started successfully")

	// Verify adapter exists in Windows
	debugLog("Verifying adapter in network interfaces")
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			debugLog("Found interface: %s", iface.Name)
		}
	}

	return &TunDevice{
		adapter: adapter,
		session: session,
		name:    name,
	}, nil
}

func (tun *TunDevice) Read(packet []byte) (int, error) {
	// Add retry logic for packet receiving
	var data []byte
	var err error

	for retries := 0; retries < 3; retries++ {
		data, err = tun.session.ReceivePacket()
		if err == nil {
			break
		}

		if err == windows.ERROR_NO_MORE_ITEMS {
			return 0, nil
		}

		// If receive fails, wait briefly before retry
		debugLog("[TUN→Transport] Receive attempt %d failed: %v", retries+1, err)
		time.Sleep(time.Millisecond * 10)
	}

	if err != nil {
		return 0, fmt.Errorf("error receiving from Wintun after retries: %v", err)
	}

	// Validate packet
	if len(data) < 20 { // Minimum IP header size
		debugLog("Received undersized packet: %d bytes", len(data))
		return 0, nil
	}

	// Check IP version
	version := data[0] >> 4
	if version != 4 {
		debugLog("Skipping IPv6 packet (not supported)")
		return 0, nil
	}

	// Only log packet details if it's an IPv4 packet we're going to process
	debugLog("[TUN→Transport] Packet Details:\n"+
		"Protocol: %d\n"+
		"Source: %s\n"+
		"Destination: %s\n"+
		"Length: %d bytes\n"+
		"Hex dump:\n%s",
		data[9],
		net.IP(data[12:16]).String(),
		net.IP(data[16:20]).String(),
		len(data),
		hex.Dump(data))

	copy(packet, data)
	return len(data), nil
}

func (tun *TunDevice) Write(packet []byte) (int, error) {
	size := len(packet)

	// Basic validation
	if size == 0 {
		debugLog("[Transport→TUN] Skipping zero-length packet")
		return 0, nil
	}

	// Detailed logging for large packets
	if size > 1500 {
		debugLog("[Transport→TUN] Large packet detected: %d bytes", size)
	}

	// Implement exponential backoff for buffer allocation
	var buf []byte
	var err error
	maxRetries := 5
	baseDelay := time.Millisecond * 20

	for retry := 0; retry < maxRetries; retry++ {
		buf, err = tun.session.AllocateSendPacket(size)
		if err == nil {
			break
		}

		// Calculate backoff delay
		delay := baseDelay * time.Duration(1<<uint(retry))
		debugLog("[Transport→TUN] Buffer allocation attempt %d failed: %v, waiting %v",
			retry+1, err, delay)

		// Check for specific error conditions
		if err == windows.ERROR_BUFFER_OVERFLOW {
			debugLog("[Transport→TUN] Buffer overflow detected, possible bandwidth issue")
		}

		time.Sleep(delay)
	}

	if err != nil {
		return 0, fmt.Errorf("failed to allocate send buffer after %d retries: %v", maxRetries, err)
	}

	// Copy packet data to the allocated buffer
	copy(buf, packet)

	// Send with recovery for panic conditions
	success := false
	for retry := 0; retry < 3 && !success; retry++ {
		func() {
			defer func() {
				if r := recover(); r != nil {
					debugLog("[Transport→TUN] Recovered from panic in SendPacket: %v", r)
					err = fmt.Errorf("panic in SendPacket: %v", r)
				}
			}()

			tun.session.SendPacket(buf)
			success = true
			err = nil
		}()

		if !success {
			time.Sleep(time.Millisecond * 10)
		}
	}

	if err != nil {
		return 0, fmt.Errorf("failed to send packet after retries: %v", err)
	}

	return size, nil
}

func (tun *TunDevice) Close() error {
	if tun.adapter != nil {
		tun.session.End()
		tun.adapter.Close()
	}
	return nil
}

func (tun *TunDevice) Name() string {
	return tun.name
}
