package transport

import (
	"fmt"
	"net"
)

// CalculateIPs determines server and client IPs from a CIDR
func CalculateIPs(cidr string) (serverIP, clientIP string, prefixLen int, err error) {
	// Parse the CIDR
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", "", 0, fmt.Errorf("invalid CIDR format: %v", err)
	}

	// Get the prefix length
	prefixLen, _ = ipnet.Mask.Size()

	// For /31 networks, use the exact IP from the CIDR as server IP
	// and the next IP as client IP
	// Example: 10.0.0.3/31 -> server: 10.0.0.3, client: 10.0.0.4
	serverIP = ip.String()
	clientIP = nextIP(ip).String()

	return serverIP, clientIP, prefixLen, nil
}

// Helper function to get next IP address
func nextIP(ip net.IP) net.IP {
	next := make(net.IP, len(ip))
	copy(next, ip)
	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] != 0 {
			break
		}
	}
	return next
}
