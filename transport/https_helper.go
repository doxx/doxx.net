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
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/songgao/water"
)

type HTTPSTransportServer struct {
	cert       tls.Certificate
	server     *http.Server
	sessions   map[string]*HTTPSSession
	sessionsmu sync.RWMutex
	connChan   chan net.Conn
	running    bool
	hostname   string
	tun        *water.Interface
	shutdown   chan struct{}
	bwMonitor  *BandwidthMonitor
}

type HTTPSSession struct {
	ID           string
	Token        string
	LastAccessed time.Time
	ReadChan     chan []byte
	WriteChan    chan []byte
	Conn         *HTTPSVirtualConn
	closed       chan struct{}
	LastDataRead time.Time
	tun          *water.Interface
	ConnAddr     string
	UserAgent    string
	AssignedIP   string
}

type HTTPSVirtualConn struct {
	session    *HTTPSSession
	localAddr  net.Addr
	remoteAddr net.Addr
	readChan   chan []byte
	writeChan  chan []byte
	closed     chan struct{}
	iface      *water.Interface
}

// Implement net.Conn interface
func (c *HTTPSVirtualConn) Read(b []byte) (n int, err error) {
	packet, err := c.ReadPacket()
	if err != nil {
		return 0, err
	}
	return copy(b, packet), nil
}

func (c *HTTPSVirtualConn) Write(b []byte) (n int, err error) {
	err = c.WritePacket(b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *HTTPSVirtualConn) Close() error {
	select {
	case <-c.closed:
		return nil
	default:
		close(c.closed)
	}
	return nil
}

func (c *HTTPSVirtualConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *HTTPSVirtualConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *HTTPSVirtualConn) SetDeadline(t time.Time) error {
	return nil // Optional implementation
}

func (c *HTTPSVirtualConn) SetReadDeadline(t time.Time) error {
	return nil // Optional implementation
}

func (c *HTTPSVirtualConn) SetWriteDeadline(t time.Time) error {
	return nil // Optional implementation
}

// Implement TransportConn interface
func (c *HTTPSVirtualConn) ReadPacket() ([]byte, error) {
	select {
	case <-c.closed:
		return nil, io.EOF
	case packet := <-c.readChan:
		return packet, nil
	}
}

func (c *HTTPSVirtualConn) WritePacket(packet []byte) error {
	select {
	case <-c.closed:
		return io.EOF
	case c.writeChan <- packet:
		return nil
	}
}

// Helper function to get the main interface name
func getMainInterface() (string, error) {
	// Get the default route interface
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return "", fmt.Errorf("failed to get default route: %v", err)
	}

	// Parse the output to get interface name
	fields := strings.Fields(string(out))
	for i, field := range fields {
		if field == "dev" && i+1 < len(fields) {
			return fields[i+1], nil
		}
	}

	return "", fmt.Errorf("no default interface found")
}

func isValidIPPacket(packet []byte) bool {
	if len(packet) < 1 {
		return false
	}

	// Check IP version (first 4 bits)
	version := packet[0] >> 4
	return version == 4 || version == 6
}
