package fingerprint

import "TCP_IP_FingerPrinter/models"

// fingerprintTCP performs simple matching based on the IPv4 TTL and TCP window size.
// In reality, this function should perform a lot more checks
// Please add more rules here if you have nothing better to do
func FingerprintTCP(ipHeader *models.IPv4Header, tcpHeader *models.TCPHeader) string {
	// For demonstration, use TTL and window size heuristics:
	// - Linux often uses TTL=64 and a specific window size (e.g., 5840)
	// - Windows typically uses TTL=128.
	// - macOS/iOS/Android may also use TTL=64 with different window sizes.
	if ipHeader.TTL == 64 {
		if tcpHeader.WindowSize == 5840 {
			return "Linux"
		} else if tcpHeader.WindowSize == 65535 {
			return "macOS"
		} else {
			// This is a not really correct.
			return "OS Still Not Mapped"
		}
	} else if ipHeader.TTL == 128 {
		return "Windows"
	}
	return "Unknown"
}
