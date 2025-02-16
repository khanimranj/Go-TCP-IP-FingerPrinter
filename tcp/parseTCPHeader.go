package tcp

import (
	"TCP_IP_FingerPrinter/models"
	"encoding/binary"
	"fmt"
)

// parseTCPHeader extracts the TCP header (and options if present) from a packet.
func ParseTCPHeader(packet []byte) (*models.TCPHeader, error) {
	if len(packet) < 20 {
		return nil, fmt.Errorf("packet too short for TCP header")
	}

	tcpHeader := &models.TCPHeader{
		SrcPort: binary.BigEndian.Uint16(packet[0:2]),
		DstPort: binary.BigEndian.Uint16(packet[2:4]),
		SeqNum:  binary.BigEndian.Uint32(packet[4:8]),
		AckNum:  binary.BigEndian.Uint32(packet[8:12]),
	}

	// The Data Offset is in the high 4 bits of byte 12.
	dataOffset := packet[12] >> 4
	tcpHeader.DataOffset = dataOffset
	headerLength := int(dataOffset) * 4
	if len(packet) < headerLength {
		return nil, fmt.Errorf("packet too short for full TCP header")
	}

	// Byte 13 holds the TCP flags (we use all 8 bits here).
	tcpHeader.Flags = packet[13]
	tcpHeader.WindowSize = binary.BigEndian.Uint16(packet[14:16])
	tcpHeader.Checksum = binary.BigEndian.Uint16(packet[16:18])
	tcpHeader.Urgent = binary.BigEndian.Uint16(packet[18:20])

	// If there are options, capture them.
	if headerLength > 20 {
		tcpHeader.Options = packet[20:headerLength]
	}
	return tcpHeader, nil
}
