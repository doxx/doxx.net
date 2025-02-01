package main

// TunInterface defines the common interface for TUN devices
type TunInterface interface {
	Read(packet []byte) (int, error)
	Write(packet []byte) (int, error)
	Close() error
	Name() string
}
