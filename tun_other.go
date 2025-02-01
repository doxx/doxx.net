//go:build !windows

package main

import (
	"github.com/songgao/water"
)

type TunDevice struct {
	iface *water.Interface
	name  string
}

func createTunDevice(name string) (*TunDevice, error) {
	iface, err := water.New(water.Config{
		DeviceType: water.TUN,
	})
	if err != nil {
		return nil, err
	}

	return &TunDevice{
		iface: iface,
		name:  name,
	}, nil
}

func (tun *TunDevice) Read(packet []byte) (int, error) {
	return tun.iface.Read(packet)
}

func (tun *TunDevice) Write(packet []byte) (int, error) {
	return tun.iface.Write(packet)
}

func (tun *TunDevice) Close() error {
	if tun.iface != nil {
		return tun.iface.Close()
	}
	return nil
}

func (tun *TunDevice) Name() string {
	if tun.iface != nil {
		return tun.iface.Name()
	}
	return tun.name
}
