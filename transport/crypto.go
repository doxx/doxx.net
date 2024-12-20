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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

func generateOrLoadCert(certPath, keyPath string) (tls.Certificate, error) {
	// Try to load existing cert/key pair
	if certExists(certPath) && certExists(keyPath) {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err == nil {
			return cert, nil
		}
		// If loading fails, generate new ones
	}

	// Generate new cert/key pair
	cert, err := generateCert()
	if err != nil {
		return tls.Certificate{}, err
	}

	// Save to files
	if err := saveCert(cert, certPath, keyPath); err != nil {
		return tls.Certificate{}, err
	}

	return cert, nil
}

func generateCert() (tls.Certificate, error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"VPN Internal"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365), // 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Create PEM blocks
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Parse into tls.Certificate
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, err
	}

	return cert, nil
}

func saveCert(cert tls.Certificate, certPath, keyPath string) error {
	// Create directories if they don't exist
	if err := os.MkdirAll(filepath.Dir(certPath), 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0755); err != nil {
		return err
	}

	// Save certificate
	certFile, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer certFile.Close()

	if err := pem.Encode(certFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Certificate[0],
	}); err != nil {
		return err
	}

	// Save private key
	keyFile, err := os.Create(keyPath)
	if err != nil {
		return err
	}
	defer keyFile.Close()

	privKey, ok := cert.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("private key type is not RSA")
	}

	return pem.Encode(keyFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})
}

func certExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func GetCertificateFingerprint(cert *x509.Certificate) string {
	fingerprint := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(fingerprint[:])
}

// Helper function to verify certificate against pinned fingerprint
func verifyPinnedCertificate(conn *tls.Conn, expectedFingerprint string) error {
	if len(conn.ConnectionState().PeerCertificates) == 0 {
		return fmt.Errorf("no server certificate received")
	}

	serverCert := conn.ConnectionState().PeerCertificates[0]
	fingerprint := GetCertificateFingerprint(serverCert)

	if fingerprint != expectedFingerprint {
		return fmt.Errorf("server certificate fingerprint mismatch: got %s, want %s",
			fingerprint, expectedFingerprint)
	}

	return nil
}

func getDoxxNetDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	doxxDir := filepath.Join(homeDir, ".doxx.net")
	if err := os.MkdirAll(doxxDir, 0700); err != nil {
		return "", err
	}
	return doxxDir, nil
}

func loadKnownHosts() (map[string]string, error) {
	doxxDir, err := getDoxxNetDir()
	if err != nil {
		return nil, err
	}

	knownHostsFile := filepath.Join(doxxDir, "known_hosts")
	data, err := os.ReadFile(knownHostsFile)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	knownHosts := make(map[string]string)
	if len(data) > 0 {
		if err := json.Unmarshal(data, &knownHosts); err != nil {
			return nil, err
		}
	}
	return knownHosts, nil
}

func saveKnownHost(host, fingerprint string) error {
	knownHosts, err := loadKnownHosts()
	if err != nil {
		return err
	}

	knownHosts[host] = fingerprint
	doxxDir, err := getDoxxNetDir()
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(knownHosts, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(doxxDir, "known_hosts"), data, 0600)
}
