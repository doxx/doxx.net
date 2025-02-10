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
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
)

// SingleTCPEncryptedClient implements the TransportType interface
type SingleTCPEncryptedClient struct {
	conn         *tls.Conn
	cert         tls.Certificate
	config       *tls.Config
	originalHost string
}

// NewSingleTCPEncryptedClient creates a new encrypted TCP client
func NewSingleTCPEncryptedClient() (TransportType, error) {
	// Generate a new certificate for this session
	cert, err := generateCert()
	if err != nil {
		return nil, fmt.Errorf("failed to generate client certificate: %v", err)
	}

	config := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true, // We'll verify manually using stored fingerprint
		MinVersion:         tls.VersionTLS12,
	}

	return &SingleTCPEncryptedClient{
		cert:   cert,
		config: config,
	}, nil
}

// tcpDebugLog handles debug logging for the TCP client
func (t *SingleTCPEncryptedClient) tcpDebugLog(format string, args ...interface{}) {
	debugLogc(format, args...)
}

func (t *SingleTCPEncryptedClient) Connect(addr string) error {
	// Split IP and port from addr
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid address format '%s': %v", addr, err)
	}

	// If we have an original hostname stored, use it for cert verification
	verifyHost := host
	if t.originalHost != "" {
		verifyHost = t.originalHost
	}

	// Update TLS config with ServerName for proper certificate verification
	t.config.ServerName = verifyHost

	// Connect using the IP:port directly
	conn, err := tls.Dial("tcp", addr, t.config)
	if err != nil {
		return err
	}

	// Get server certificate fingerprint
	if len(conn.ConnectionState().PeerCertificates) == 0 {
		conn.Close()
		return fmt.Errorf("no server certificate received")
	}

	serverCert := conn.ConnectionState().PeerCertificates[0]
	fingerprint := GetCertificateFingerprint(serverCert)

	// Use original hostname for known_hosts checks
	knownHostKey := verifyHost

	// Load known hosts
	knownHosts, err := loadKnownHosts()
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to load known hosts: %v", err)
	}

	// Check if we know this host
	if storedFingerprint, exists := knownHosts[knownHostKey]; exists {
		if fingerprint != storedFingerprint {
			conn.Close()
			return fmt.Errorf("WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!\nThe fingerprint for host '%s' has changed from:\n%s\nto:\n%s\nIf you trust this change, please remove %s/.doxx.net/known_hosts",
				knownHostKey, storedFingerprint, fingerprint, os.Getenv("HOME"))
		}
	} else {
		// New host, ask for confirmation
		fmt.Printf("\nThe authenticity of host '%s' can't be established.\n", knownHostKey)
		fmt.Printf("Fingerprint: %s\n", fingerprint)
		fmt.Print("Are you sure you want to continue connecting (yes/no)? ")

		var response string
		fmt.Scanln(&response)
		if strings.ToLower(response) != "yes" {
			conn.Close()
			return fmt.Errorf("connection rejected by user")
		}

		// Save the new fingerprint
		if err := saveKnownHost(knownHostKey, fingerprint); err != nil {
			conn.Close()
			return fmt.Errorf("failed to save host fingerprint: %v", err)
		}
		fmt.Printf("Warning: Permanently added '%s' (%s) to the list of known hosts.\n", knownHostKey, fingerprint)
	}

	t.conn = conn
	return nil
}

func (t *SingleTCPEncryptedClient) ReadPacket() ([]byte, error) {
	data, err := readPacket(t.conn)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (t *SingleTCPEncryptedClient) WritePacket(packet []byte) error {
	err := writePacket(t.conn, packet)
	if err != nil {
		return err
	}
	return nil
}

func (t *SingleTCPEncryptedClient) SendAuth(token string) error {
	return writePacket(t.conn, []byte(token))
}

type RuntimeConfig struct {
	KeepEstablishedSSH bool
	KillDefaultRoute   bool
	AutoReconnect      bool
	EnableRouting      bool
	SnarfDNS           bool
	AssignedIP         string
	ServerIP           string
	ClientIP           string
	PrefixLen          int
}

func (t *SingleTCPEncryptedClient) HandleAuth() (*AuthResponse, error) {
	t.tcpDebugLog("Waiting for auth response from server...")

	// Read the response
	responseBytes, err := readPacket(t.conn)
	if err != nil {
		t.tcpDebugLog("Failed to read auth response: %v", err)
		return nil, fmt.Errorf("failed to read auth response: %v", err)
	}

	t.tcpDebugLog("Raw auth response from server: %s", string(responseBytes))

	// Parse the response
	var response AuthResponse
	if err := json.Unmarshal(responseBytes, &response); err != nil {
		t.tcpDebugLog("Failed to parse auth response: %v", err)
		return nil, fmt.Errorf("failed to parse auth response: %v", err)
	}

	t.tcpDebugLog("Parsed auth response: %+v", response)

	// Check status
	if response.Status != "success" {
		t.tcpDebugLog("Auth failed: %s", response.Message)
		return nil, fmt.Errorf("authentication failed: %s", response.Message)
	}

	t.tcpDebugLog("Authentication successful")
	return &response, nil
}

func (t *SingleTCPEncryptedClient) Close() error {
	if t.conn != nil {
		return t.conn.Close()
	}
	return nil
}

func (t *SingleTCPEncryptedClient) SetOriginalHost(host string) {
	t.originalHost = host
}
