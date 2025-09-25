package m2pa

import (
	"encoding/binary"
	"fmt"
)

// M2PA Message Header (RFC 4165)
type Header struct {
	Version       uint8  `json:"version"`
	Spare         uint8  `json:"spare"`
	MessageClass  uint8  `json:"message_class"`
	MessageType   uint8  `json:"message_type"`
	MessageLength uint32 `json:"message_length"`
}

// M2PA Data Message
type Data struct {
	Header   Header `json:"header"`
	Ununsed1 uint8  `json:"unused1"`
	BSN      uint32 `json:"bsn"` // Backward Sequence Number
	Ununsed2 uint8  `json:"unused2"`
	FSN      uint32 `json:"fsn"` // Forward Sequence Number
	Priority uint8  `json:"priority"`
	Data     []byte `json:"data"` // Contains MTP3 + ISUP message
}

// Message type constants
const (
	MessageClassTransfer = 11
	MessageTypeUserData  = 1
)

// Parse M2PA message from bytes
func ParseM2PA(data []byte) (*Data, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("M2PA message too short (%d bytes)", len(data))
	}

	header := Header{
		Version:       data[0],
		Spare:         data[1],
		MessageClass:  data[2],
		MessageType:   data[3],
		MessageLength: binary.BigEndian.Uint32(data[4:8]),
	}

	msg := &Data{
		Header: header,
	}

	offset := 8

	// Parse fields sequentially
	if offset < len(data) {
		msg.Ununsed1 = data[offset]
		offset += 1
	}

	// Parse BSN (3 bytes)
	if offset+3 <= len(data) {
		bsnBytes := make([]byte, 4)
		copy(bsnBytes[1:], data[offset:offset+3])
		msg.BSN = binary.BigEndian.Uint32(bsnBytes)
		offset += 3
	}

	// Parse Unused2 (1 byte)
	if offset < len(data) {
		msg.Ununsed2 = data[offset]
		offset += 1
	}

	// Parse FSN (3 bytes)
	if offset+3 <= len(data) {
		fsnBytes := make([]byte, 4)
		copy(fsnBytes[1:], data[offset:offset+3])
		msg.FSN = binary.BigEndian.Uint32(fsnBytes)
		offset += 3
	}

	// Parse Priority (1 byte)
	if offset < len(data) {
		msg.Priority = data[offset]
		offset += 1
	}

	// Remaining data contains MTP3 + ISUP
	if offset < len(data) {
		msg.Data = data[offset:]
	}

	return msg, nil
}

// IsUserData checks if this is a user data message
func (d *Data) IsUserData() bool {
	return d.Header.MessageClass == MessageClassTransfer &&
		d.Header.MessageType == MessageTypeUserData
}
