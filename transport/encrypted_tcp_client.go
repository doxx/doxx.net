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
	"os"
	"strings"
)

// SingleTCPEncryptedClient implements the TransportType interface
type SingleTCPEncryptedClient struct {
	conn   *tls.Conn
	cert   tls.Certificate
	config *tls.Config
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

func (t *SingleTCPEncryptedClient) Connect(addr string) error {
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
	host := strings.Split(addr, ":")[0]

	// Load known hosts
	knownHosts, err := loadKnownHosts()
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to load known hosts: %v", err)
	}

	// Check if we know this host
	if storedFingerprint, exists := knownHosts[host]; exists {
		if fingerprint != storedFingerprint {
			conn.Close()
			return fmt.Errorf("WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!\nThe fingerprint for host '%s' has changed from:\n%s\nto:\n%s\nIf you trust this change, please remove %s/.doxx.net/known_hosts",
				host, storedFingerprint, fingerprint, os.Getenv("HOME"))
		}
	} else {
		// New host, ask for confirmation
		fmt.Printf("\nThe authenticity of host '%s' can't be established.\n", host)
		fmt.Printf("Fingerprint: %s\n", fingerprint)
		fmt.Print("Are you sure you want to continue connecting (yes/no)? ")

		var response string
		fmt.Scanln(&response)
		if strings.ToLower(response) != "yes" {
			conn.Close()
			return fmt.Errorf("connection rejected by user")
		}

		// Save the new fingerprint
		if err := saveKnownHost(host, fingerprint); err != nil {
			conn.Close()
			return fmt.Errorf("failed to save host fingerprint: %v", err)
		}
		fmt.Printf("Warning: Permanently added '%s' (%s) to the list of known hosts.\n", host, fingerprint)
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

func (t *SingleTCPEncryptedClient) HandleAuth() (*AuthResponse, error) {
	return handleAuthResponse(t.conn)
}

func (t *SingleTCPEncryptedClient) Close() error {
	if t.conn != nil {
		return t.conn.Close()
	}
	return nil
}
