package transport

import (
	"fmt"
	"sync"
	"time"
)

type BandwidthMonitor struct {
	bytesIn     uint64
	bytesOut    uint64
	lastCheck   time.Time
	mu          sync.Mutex
	sourceIP    string
	sessionID   string
	token       string
	transportID string
}

func NewBandwidthMonitor(transportID string) *BandwidthMonitor {
	bw := &BandwidthMonitor{
		lastCheck:   time.Now(),
		transportID: transportID,
	}
	// Start the monitoring goroutine
	go bw.monitor()
	return bw
}

func (bw *BandwidthMonitor) SetSessionInfo(ip, sessionID, token string) {
	bw.mu.Lock()
	bw.sourceIP = ip
	bw.sessionID = sessionID
	bw.token = token
	bw.mu.Unlock()
}

func (bw *BandwidthMonitor) monitor() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		bw.mu.Lock()
		duration := time.Since(bw.lastCheck).Seconds()
		bpsIn := float64(bw.bytesIn) * 8 / duration / 1024 / 1024
		bpsOut := float64(bw.bytesOut) * 8 / duration / 1024 / 1024
		bw.lastCheck = time.Now()
		if bpsIn > 0 || bpsOut > 0 {
			fmt.Printf("[%s] %s %s %s Bandwidth: IN: %.2f Mbps, OUT: %.2f Mbps\n",
				bw.transportID,
				bw.sourceIP,
				bw.sessionID,
				bw.token,
				bpsIn,
				bpsOut)
		}

		// Reset counters
		bw.bytesIn = 0
		bw.bytesOut = 0
		bw.lastCheck = time.Now()
		bw.mu.Unlock()
	}
}

func (bw *BandwidthMonitor) AddBytesIn(n uint64) {
	bw.mu.Lock()
	bw.bytesIn += n
	bw.mu.Unlock()
}

func (bw *BandwidthMonitor) AddBytesOut(n uint64) {
	bw.mu.Lock()
	bw.bytesOut += n
	bw.mu.Unlock()
}
