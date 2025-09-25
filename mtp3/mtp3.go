package mtp3

import (
	"fmt"
)

// MTP3 Routing Label
type RoutingLabel struct {
	DPC                   uint32 `json:"dpc"`
	OPC                   uint32 `json:"opc"`
	SignalingLinkSelector uint8  `json:"signaling_link_selector"`
}

// MTP3 Message
type Message struct {
	ServiceIndicator uint8        `json:"service_indicator"`
	NetworkIndicator uint8        `json:"network_indicator"`
	RoutingLabel     RoutingLabel `json:"routing_label"`
	Data             []byte       `json:"data"` // Contains ISUP message
}

// ISUP types
const (
	ITU  = 5
	ANSI = 2
)

// Parse MTP3 message from bytes
func ParseMTP3(data []byte) (*Message, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("MTP3 message too short (%d bytes)", len(data))
	}

	// Service Information Octet
	sio := data[0]
	mtp3 := &Message{
		NetworkIndicator: (sio >> 6) & 0x03,
		ServiceIndicator: sio & 0x0F,
	}

	// Routing Label parsing
	if len(data) >= 5 {
		// Convert the 4 bytes to a 32-bit value
		rl := uint32(data[1]) | uint32(data[2])<<8 | uint32(data[3])<<16 | uint32(data[4])<<24

		// DPC: 14 bits (bits 0-13)
		dpc := rl & 0x3FFF
		// OPC: 14 bits (bits 14-27)
		opc := (rl >> 14) & 0x3FFF
		// SLS: 4 bits (bits 28-31)
		sls := uint8((rl >> 28) & 0x0F)

		mtp3.RoutingLabel = RoutingLabel{
			DPC:                   dpc,
			OPC:                   opc,
			SignalingLinkSelector: sls,
		}
	}

	// ISUP payload
	if len(data) > 5 {
		mtp3.Data = data[5:]
	}

	return mtp3, nil
}

// GetISUPFormat returns the ISUP format based on Service Indicator
func (m *Message) GetISUPFormat() uint8 {
	switch m.ServiceIndicator {
	case 5:
		return ITU
	case 2:
		return ANSI
	default:
		return 0 // Unknown
	}
}
