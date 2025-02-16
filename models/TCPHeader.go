package models

type TCPHeader struct {
	SrcPort    uint16
	DstPort    uint16
	SeqNum     uint32
	AckNum     uint32
	DataOffset uint8
	Flags      uint8
	WindowSize uint16
	Checksum   uint16
	Urgent     uint16
	Options    []byte
}
