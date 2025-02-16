package main

import (
	"TCP_IP_FingerPrinter/fingerprint"
	"TCP_IP_FingerPrinter/ipv4"
	"TCP_IP_FingerPrinter/models"
	"TCP_IP_FingerPrinter/tcp"
	"log"
	"syscall"
)

func main() {

	// Requires root privileges.
	sock, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		log.Fatalf("Error creating raw socket: %v", err)
	}
	defer syscall.Close(sock)

	buffer := make([]byte, 65535)
	log.Println("Listening for TCP packets...")

	// Main loop to receive packets asynchronously.
	for {
		n, _, err := syscall.Recvfrom(sock, buffer, 0)
		if err != nil {
			log.Printf("Recvfrom error: %v", err)
			continue
		}

		// Handle each packet in its own goroutine.
		go handlePacket(buffer[:n])
	}
}

// handlePacket processes a captured packet.
func handlePacket(packet []byte) {
	// Parse the IPv4 header.
	ipHeader, ipHeaderLength, err := ipv4.ParseIPv4Header(packet)
	if err != nil {
		log.Printf("Error parsing IPv4 header: %v", err)
		return
	}

	// Only Protocol 6
	if ipHeader.Protocol != syscall.IPPROTO_TCP {
		return
	}

	// Parse the TCP header.
	tcpPacket := packet[ipHeaderLength:]
	tcpHeader, err := tcp.ParseTCPHeader(tcpPacket)
	if err != nil {
		log.Printf("Error parsing TCP header: %v", err)
		return
	}

	// Fingerprint the packet.
	// Currently, we use some very basic heuristics and in no sense is this function final
	//	osPredicted := fingerprint.FingerprintTCP(ipHeader, tcpHeader)
	osPredicted := fingerprint.FingerprintTCP(ipHeader, tcpHeader)

	// Log the details for debugging.
	log.Printf("Packet from %v:%d -> %v:%d | TTL: %d | Window: %d | OS Predicted: %s",
		ipHeader.SrcIP, tcpHeader.SrcPort, ipHeader.DstIP, tcpHeader.DstPort, ipHeader.TTL, tcpHeader.WindowSize, osPredicted)

	// Send a response with the OS information.
	responseHandler(ipHeader, tcpHeader, osPredicted)
}

// responseHandler is a placeholder
// Use this to do something else or return something back
func responseHandler(ipHeader *models.IPv4Header, tcpHeader *models.TCPHeader, osPredicted string) {
	// For demonstration, we just log that a response would be sent.
	log.Printf("Responding to %v:%d with predicted OS: %s",
		ipHeader.SrcIP, tcpHeader.SrcPort, osPredicted)
	// TODO: Next time
}
