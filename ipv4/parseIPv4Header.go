package ipv4

import (
	"TCP_IP_FingerPrinter/models"
	"encoding/binary"
	"fmt"
	"net"
)

// parseIPv4Header extracts the IPv4 header from a raw packet.
func ParseIPv4Header(packet []byte) (*models.IPv4Header, int, error) {
	if len(packet) < 20 {
		return nil, 0, fmt.Errorf("packet too short for IPv4 header")
	}

	verIHL := packet[0]
	version := verIHL >> 4
	ihl := verIHL & 0x0F
	ipHeaderLength := int(ihl) * 4
	if len(packet) < ipHeaderLength {
		return nil, 0, fmt.Errorf("packet length less than IPv4 header length")
	}

	header := &models.IPv4Header{
		Version:        version,
		IHL:            ihl,
		TOS:            packet[1],
		TotalLength:    binary.BigEndian.Uint16(packet[2:4]),
		Identification: binary.BigEndian.Uint16(packet[4:6]),
		FlagsFragment:  binary.BigEndian.Uint16(packet[6:8]),
		TTL:            packet[8],
		Protocol:       packet[9],
		Checksum:       binary.BigEndian.Uint16(packet[10:12]),
		SrcIP:          net.IP(packet[12:16]),
		DstIP:          net.IP(packet[16:20]),
	}
	return header, ipHeaderLength, nil
}
