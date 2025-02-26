//go:build windows

package main

import (
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
	adapter  *wintun.Adapter
	session  wintun.Session
	name     string
	readBuf  chan []byte   // Buffer channel for reads
	writeBuf chan []byte   // Buffer channel for writes
	done     chan struct{} // Channel to signal shutdown
}

const (
	WINTUN_DLL          = "wintun.dll"
	WINTUN_DOWNLOAD_URL = "https://www.wintun.net/"
	WINTUN_LOG_INFO     = 0
	WINTUN_LOG_WARN     = 1
	WINTUN_LOG_ERR      = 2
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
	session, err := adapter.StartSession(0x4000000) // 64MB ring buffer
	if err != nil {
		debugLog("Session start failed: %v", err)
		adapter.Close()
		return nil, fmt.Errorf("error starting Wintun session: %v", err)
	}
	debugLog("Session started successfully with 64MB buffer")

	// Verify adapter exists in Windows
	debugLog("Verifying adapter in network interfaces")
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			debugLog("Found interface: %s", iface.Name)
		}
	}

	tun := &TunDevice{
		adapter:  adapter,
		session:  session,
		name:     name,
		readBuf:  make(chan []byte, 4096), // Increased from 1024
		writeBuf: make(chan []byte, 4096), // Increased from 1024
		done:     make(chan struct{}),
	}

	// Start background workers
	go tun.readWorker()
	go tun.writeWorker()

	return tun, nil
}

func (tun *TunDevice) readWorker() {
	waitEvent := tun.session.ReadWaitEvent()
	if waitEvent == 0 {
		debugLog("[ERROR] Failed to get read wait event")
		return
	}

	var stats struct {
		packets    uint64
		drops      uint64
		errors     uint64
		lastReport time.Time
	}
	stats.lastReport = time.Now()

	for {
		select {
		case <-tun.done:
			return
		default:
			// Wait for data to be available
			result, _ := windows.WaitForSingleObject(windows.Handle(waitEvent), windows.INFINITE)
			if result != windows.WAIT_OBJECT_0 {
				debugLog("[ERROR] Wait failed with result: %d (Windows error: %d)",
					result, windows.GetLastError())
				stats.errors++
				continue
			}

			// Process all available packets
			for {
				data, err := tun.session.ReceivePacket()
				if err == windows.ERROR_NO_MORE_ITEMS {
					break // No more packets, go back to waiting
				}
				if err != nil {
					debugLog("[ERROR] Read error: %v (Windows error: %d)",
						err, windows.GetLastError())
					stats.errors++
					break
				}
				if len(data) > 0 {
					stats.packets++
					packet := make([]byte, len(data))
					copy(packet, data)

					// Release the packet BEFORE trying to send it
					tun.session.ReleaseReceivePacket(data)

					select {
					case tun.readBuf <- packet:
						// Successfully buffered
					default:
						stats.drops++
						debugLog("[WARN] Read buffer full, dropping packet")
					}
				}
			}

			// Print stats every second
			if time.Since(stats.lastReport) >= time.Second {
				debugLog("[Stats] Packets: %d/s, Drops: %d/s, Errors: %d/s, Buffer: %d",
					stats.packets, stats.drops, stats.errors, len(tun.readBuf))
				stats.packets = 0
				stats.drops = 0
				stats.errors = 0
				stats.lastReport = time.Now()
			}
		}
	}
}

func (tun *TunDevice) writeWorker() {
	for {
		select {
		case <-tun.done:
			return
		case packet := <-tun.writeBuf:
			for retries := 0; retries < 5; retries++ {
				buf, err := tun.session.AllocateSendPacket(len(packet))
				if err == nil {
					copy(buf, packet)
					tun.session.SendPacket(buf)
					break
				}
				debugLog("[Transport→TUN] Write error: %v", err)
				time.Sleep(time.Millisecond * 5)
			}
		}
	}
}

func (tun *TunDevice) Read(packet []byte) (int, error) {
	select {
	case data := <-tun.readBuf:
		return copy(packet, data), nil
	case <-time.After(time.Millisecond * 100):
		return 0, nil
	}
}

func (tun *TunDevice) Write(packet []byte) (int, error) {
	if len(packet) == 0 {
		return 0, nil
	}

	// Make a copy of the packet
	buf := make([]byte, len(packet))
	copy(buf, packet)

	select {
	case tun.writeBuf <- buf:
		return len(packet), nil
	case <-time.After(time.Millisecond * 100):
		debugLog("[Transport→TUN] Write buffer full")
		return 0, fmt.Errorf("write buffer full")
	}
}

func (tun *TunDevice) Close() error {
	close(tun.done)
	if tun.adapter != nil {
		tun.session.End()
		tun.adapter.Close()
	}
	return nil
}

func (tun *TunDevice) Name() string {
	return tun.name
}
