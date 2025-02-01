package transport

// isLatencySensitivePacket checks if a packet needs fast-path processing (like ICMP)
func isLatencySensitivePacket(packet []byte) bool {
	if len(packet) < 1 {
		return false
	}

	// Check if it's an IPv4 packet
	if packet[0]>>4 == 4 {
		if len(packet) < 20 {
			return false
		}
		// Check if it's ICMP (protocol 1)
		return packet[9] == 1
	}

	// Check if it's an IPv6 packet
	if packet[0]>>4 == 6 {
		if len(packet) < 40 {
			return false
		}
		// Check if it's ICMPv6 (next header 58)
		return packet[6] == 58
	}

	return false
}
