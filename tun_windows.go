//go:build windows

package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
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
	// Get absolute path to executable's directory
	exe, err := os.Executable()
	if err != nil {
		debugLog("Failed to get executable path: %v", err)
		return nil, err
	}
	exePath := filepath.Dir(exe)
	debugLog("Executable path: %s", exePath)

	// Try both System32 and local paths
	dllPaths := []string{
		`C:\Windows\System32\wintun.dll`,
		filepath.Join(exePath, "wintun.dll"),
	}

	var handle windows.Handle
	var loadError error

	for _, dllPath := range dllPaths {
		debugLog("Trying to load: %s", dllPath)

		// Check if file exists and is readable
		if _, err := os.Stat(dllPath); err != nil {
			debugLog("File check failed: %v", err)
			continue
		}

		// Try to load using direct Windows API
		handle, loadError = windows.LoadLibraryEx(dllPath, 0, windows.LOAD_WITH_ALTERED_SEARCH_PATH)
		if handle != 0 {
			debugLog("Successfully loaded DLL from: %s", dllPath)
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

	debugLog("Creating adapter with name: %s", name)
	adapter, err := wintun.CreateAdapter(name, "Doxx", &guid)
	if err != nil {
		debugLog("Failed to create adapter: %v (error code: %d)", err, windows.GetLastError())
		return nil, fmt.Errorf("error creating Wintun adapter: %v", err)
	}
	debugLog("Adapter created successfully")

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

	// Add basic packet validation
	if size == 0 {
		debugLog("[Transport→TUN] Received zero-length packet")
		return 0, nil
	}

	// Add retry logic for buffer allocation with increased timeout
	var buf []byte
	var err error
	for retries := 0; retries < 5; retries++ { // Increased retries from 3 to 5
		buf, err = tun.session.AllocateSendPacket(size)
		if err == nil {
			break
		}
		// Exponential backoff: 10ms, 20ms, 40ms, 80ms, 160ms
		waitTime := time.Duration(10*(1<<retries)) * time.Millisecond
		debugLog("[Transport→TUN] Allocation attempt %d failed: %v, waiting %v", retries+1, err, waitTime)
		time.Sleep(waitTime)
	}

	if err != nil {
		debugLog("[Transport→TUN] Failed to allocate send packet after retries: %v", err)
		return 0, fmt.Errorf("failed to allocate packet buffer: %v", err)
	}

	copy(buf, packet)

	// Add error handling around SendPacket
	defer func() {
		if r := recover(); r != nil {
			debugLog("[Transport→TUN] Panic recovered in SendPacket: %v", r)
		}
	}()

	tun.session.SendPacket(buf)
	debugLog("[Transport→TUN] Wrote packet of length %d", size)
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
