package models

import "net"

type IPv4Header struct {
	Version        uint8
	IHL            uint8
	TOS            uint8
	TotalLength    uint16
	Identification uint16
	FlagsFragment  uint16
	TTL            uint8
	Protocol       uint8
	Checksum       uint16
	SrcIP          net.IP
	DstIP          net.IP
}
