package mtp3

import (
	"fmt"
)

// ANSI Point Code decomposition
type ANSIPointCode struct {
	Network uint8  `json:"network"`
	Cluster uint8  `json:"cluster"`
	Member  uint8  `json:"member"`
	String  string `json:"string"` // x-y-z format
}

// MTP3 Routing Label
type RoutingLabel struct {
	DPC                   uint32         `json:"dpc"`
	OPC                   uint32         `json:"opc"`
	SignalingLinkSelector uint8          `json:"signaling_link_selector"`
	DPC_ANSI              *ANSIPointCode `json:"pcs_dpc,omitempty"`
	OPC_ANSI              *ANSIPointCode `json:"pcs_opc,omitempty"`
}

// MTP3 Message
type Message struct {
	ServiceIndicator uint8        `json:"service_indicator"`
	NetworkIndicator uint8        `json:"network_indicator"`
	RoutingLabel     RoutingLabel `json:"routing_label"`
	Data             []byte       `json:"-"` // Contains ISUP message
}

// Decompose ANSI 24-bit point code into network-cluster-member format
func DecomposeANSIPointCode(pointCode uint32) *ANSIPointCode {
	if pointCode == 0 {
		return nil
	}

	// ANSI 24-bit point code format:
	// [23..16] = Network (8 bits), [15..8] = Cluster (8 bits), [7..0] = Member (8 bits)
	network := uint8((pointCode >> 16) & 0xFF) // Bits 23-16
	cluster := uint8((pointCode >> 8) & 0xFF)  // Bits 15-8
	member := uint8(pointCode & 0xFF)          // Bits 7-0

	return &ANSIPointCode{
		Network: network,
		Cluster: cluster,
		Member:  member,
		String:  fmt.Sprintf("%d-%d-%d", network, cluster, member),
	}
}

// Compose ANSI point code from network-cluster-member
func ComposeANSIPointCode(network, cluster, member uint8) uint32 {
	return (uint32(network) << 18) | (uint32(cluster) << 8) | uint32(member)
}

// Parse MTP3 ITU message
func ParseMTP3_ITU(data []byte) (*Message, error) {

	Len := uint32(len(data))

	if Len < 5 {
		return nil, fmt.Errorf("MTP3 message too short (%d bytes)", Len)
	}

	// Service Information Octet
	sio := data[0]
	mtp3 := &Message{
		NetworkIndicator: (sio >> 6) & 0x03,
		ServiceIndicator: sio & 0x0F,
	}

	// Routing Label parsing
	if Len >= 5 {
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
	if Len > 5 {
		mtp3.Data = data[5:]
	}

	return mtp3, nil
}

// Parse MTP3 ANSI message
func ParseMTP3_ANSI(data []byte) (*Message, error) {
	Len := uint32(len(data))

	if Len < 8 {
		return nil, fmt.Errorf("MTP3 ANSI message too short (%d bytes)", Len)
	}

	// Byte 0: Service Information Octet
	sio := data[0]
	mtp3 := &Message{
		NetworkIndicator: (sio >> 6) & 0x03,
		ServiceIndicator: sio & 0x0F,
	}

	// Bytes 1-3: Destination Point Code (little-endian 3-byte value)
	dpc := uint32(data[3])<<16 | uint32(data[2])<<8 | uint32(data[1])

	// Bytes 4-6: Originating Point Code (little-endian 3-byte value)
	opc := uint32(data[6])<<16 | uint32(data[5])<<8 | uint32(data[4])

	// Byte 7: Signaling Link Selector (lower 5 bits)
	sls := data[7] & 0x1F

	// Create ANSI point code decompositions
	dpcANSI := DecomposeANSIPointCode(dpc)
	opcANSI := DecomposeANSIPointCode(opc)

	mtp3.RoutingLabel = RoutingLabel{
		DPC:                   dpc,
		OPC:                   opc,
		SignalingLinkSelector: sls,
		DPC_ANSI:              dpcANSI,
		OPC_ANSI:              opcANSI,
	}

	// Debug output
	fmt.Printf("ANSI MTP3 Debug:\n")
	fmt.Printf("  DPC: %d -> Network=%d, Cluster=%d, Member=%d -> %s\n",
		dpc, dpcANSI.Network, dpcANSI.Cluster, dpcANSI.Member, dpcANSI.String)
	fmt.Printf("  OPC: %d -> Network=%d, Cluster=%d, Member=%d -> %s\n",
		opc, opcANSI.Network, opcANSI.Cluster, opcANSI.Member, opcANSI.String)
	fmt.Printf("  SLS: %d\n", sls)

	// ISUP payload starts at byte 8
	if Len > 8 {
		mtp3.Data = data[8:]
		fmt.Printf("  Payload: %d bytes\n", len(mtp3.Data))
	}

	return mtp3, nil
}
