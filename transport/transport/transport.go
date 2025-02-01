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
	"encoding/json"
	"fmt"
	"io"
	"net"
)

const (
	HEADER_SIZE     = 4
	MTU             = 1500
	MAX_PACKET_SIZE = MTU - 20
	MAX_BATCH_SIZE  = 1024 * 1024
	ServerAuthToken = "doxx_server_auth_token_2024"
)

// TransportType represents a VPN transport layer type
type TransportType interface {
	Connect(serverAddr string) error
	Close() error
	ReadPacket() ([]byte, error)
	WritePacket([]byte) error
	SendAuth(token string) error
	HandleAuth() (*AuthResponse, error)
}

// TransportServer interface for server implementations
type TransportServer interface {
	Listen(addr string) error
	Accept() (TransportConn, error)
	Close() error
}

// TransportConn interface for individual connections
type TransportConn interface {
	ReadPacket() ([]byte, error)
	WritePacket([]byte) error
	Close() error
	RemoteAddr() net.Addr
}

// AuthResponse represents the server's authentication response
type AuthResponse struct {
	Status     string  `json:"status"`
	Message    string  `json:"message"`
	User       VPNUser `json:"user"`
	ServerIP   string  `json:"server_ip,omitempty"`
	ClientIP   string  `json:"client_ip,omitempty"`
	PrefixLen  int     `json:"prefix_len,omitempty"`
	AssignedIP string  `json:"assigned_ip,omitempty"`
}

// Common utility functions
func readPacket(conn net.Conn) ([]byte, error) {
	header := make([]byte, HEADER_SIZE)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	length := int(header[0])<<24 | int(header[1])<<16 | int(header[2])<<8 | int(header[3])
	if length > MTU {
		return nil, fmt.Errorf("packet too large: %d", length)
	}

	packet := make([]byte, length)
	if _, err := io.ReadFull(conn, packet); err != nil {
		return nil, err
	}
	return packet, nil
}

func writePacket(conn net.Conn, packet []byte) error {
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

func handleAuthResponse(conn net.Conn) (*AuthResponse, error) {
	responseBytes, err := readPacket(conn)
	if err != nil {
		return nil, err
	}

	var response AuthResponse
	if err := json.Unmarshal(responseBytes, &response); err != nil {
		return nil, err
	}

	return &response, nil
}

type VPNUser struct {
	EmailAddress string `json:"email_address"`
	AssignedIP   string `json:"assigned_ip"`
	Active       bool   `json:"active"`
	Server       string `json:"server"`
	PrefixLen    int    // This is parsed from AssignedIP
}
