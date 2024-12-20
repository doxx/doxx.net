package transport

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
)

// SingleTCPClient implements the TransportType interface
type SingleTCPClient struct {
	conn net.Conn
}

func NewSingleTCPClient() TransportType {
	return &SingleTCPClient{}
}

func (t *SingleTCPClient) Connect(serverAddr string) error {
	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		return err
	}
	t.conn = conn
	return nil
}

func (t *SingleTCPClient) Close() error {
	if t.conn != nil {
		return t.conn.Close()
	}
	return nil
}

func (t *SingleTCPClient) ReadPacket() ([]byte, error) {
	// Read 4-byte header first
	header := make([]byte, HEADER_SIZE)
	if _, err := io.ReadFull(t.conn, header); err != nil {
		return nil, err
	}

	// Extract length
	length := int(header[0])<<24 | int(header[1])<<16 | int(header[2])<<8 | int(header[3])
	if length > MTU {
		return nil, fmt.Errorf("packet too large: %d", length)
	}

	// Read packet data
	packet := make([]byte, length)
	if _, err := io.ReadFull(t.conn, packet); err != nil {
		return nil, err
	}

	return packet, nil
}

func (t *SingleTCPClient) WritePacket(packet []byte) error {
	// Write 4-byte header
	header := make([]byte, HEADER_SIZE)
	header[0] = byte(len(packet) >> 24)
	header[1] = byte(len(packet) >> 16)
	header[2] = byte(len(packet) >> 8)
	header[3] = byte(len(packet))

	// Write header and packet in one call to avoid fragmentation
	fullPacket := append(header, packet...)
	_, err := t.conn.Write(fullPacket)
	return err
}

func (t *SingleTCPClient) SendAuth(token string) error {
	return t.WritePacket([]byte(token))
}

func (t *SingleTCPClient) HandleAuth() (*AuthResponse, error) {
	packet, err := t.ReadPacket()
	if err != nil {
		return nil, err
	}

	var response AuthResponse
	if err := json.Unmarshal(packet, &response); err != nil {
		return nil, err
	}

	return &response, nil
}
