package m3ua

import (
	"encoding/binary"
	"fmt"
)

// M3UA Header
type Header struct {
	Version       uint8  `json:"version"`
	Reserved      uint8  `json:"reserved"`
	MessageClass  uint8  `json:"message_class"`
	MessageType   uint8  `json:"message_type"`
	MessageLength uint32 `json:"message_length"`
}

// M3UA Protocol Data
type ProtocolData struct {
	OriginPointCode      uint32 `json:"origin_point_code"`
	DestinationPointCode uint32 `json:"destination_point_code"`
	ServiceIndicator     uint8  `json:"service_indicator"`
	NetworkIndicator     uint8  `json:"network_indicator"`
	MessagePriority      uint8  `json:"message_priority"`
	SignalingLink        uint8  `json:"signaling_link"`
	Data                 []byte `json:"-"` // Contains ISUP message
}

// M3UA Message
type Message struct {
	Header Header        `json:"header"`
	Data   *ProtocolData `json:"-"`
}

// Message type constants
const (
	MessageClassASPSM    = 1 // ASP State Maintenance
	MessageClassASPTM    = 2 // ASP Traffic Maintenance
	MessageClassTransfer = 3 // Transfer Messages
	MessageTypeData      = 1 // Payload Data
)

// Parse M3UA message from bytes
func ParseM3UA(data []byte) (*Message, error) {

	Len := uint32(len(data))

	if Len < 8 {
		return nil, fmt.Errorf("M3UA message too short (%d bytes)", Len)
	}

	header := Header{
		Version:       data[0],
		Reserved:      data[1],
		MessageClass:  data[2],
		MessageType:   data[3],
		MessageLength: binary.BigEndian.Uint32(data[4:8]),
	}

	msg := &Message{
		Header: header,
	}

	// Parse Protocol Data for Data messages
	if header.MessageClass == MessageClassTransfer &&
		header.MessageType == MessageTypeData &&
		Len >= 20 {

		protocolData := &ProtocolData{
			OriginPointCode:      binary.BigEndian.Uint32(data[8:12]) & 0x00FFFFFF,
			DestinationPointCode: binary.BigEndian.Uint32(data[12:16]) & 0x00FFFFFF,
			ServiceIndicator:     data[16] & 0x0F,
			NetworkIndicator:     data[17] & 0x0F,
			MessagePriority:      data[18] & 0x0F,
			SignalingLink:        data[19],
		}

		if Len > 20 {
			protocolData.Data = data[20:]
		}

		msg.Data = protocolData
	}

	Len += 8 // Including header length

	return msg, nil
}
