package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"isup-parser/isup"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Protocol types
const (
	ProtocolUnknown = "unknown"
	ProtocolM2PA    = "m2pa"
	ProtocolM3UA    = "m3ua"
)

// M2PA Message Header (RFC 4165)
type M2PAHeader struct {
	Version       uint8  `json:"version"`
	Spare         uint8  `json:"spare"`
	MessageClass  uint8  `json:"message_class"`
	MessageType   uint8  `json:"message_type"`
	MessageLength uint32 `json:"message_length"`
}

// M2PA User Data Message
type M2PAUserData struct {
	Header   M2PAHeader `json:"header"`
	Ununsed1 uint8      `json:"unused1"`
	BSN      uint32     `json:"bsn"` // Backward Sequence Number
	Ununsed2 uint8      `json:"unused2"`
	FSN      uint32     `json:"fsn"`  // Forward Sequence Number
	Data     []byte     `json:"data"` // Contains MTP3 + ISUP message
}

// M3UA Common Header
type M3UACommonHeader struct {
	Version       uint8  `json:"version"`
	Reserved      uint8  `json:"reserved"`
	MessageClass  uint8  `json:"message_class"`
	MessageType   uint8  `json:"message_type"`
	MessageLength uint32 `json:"message_length"`
}

// M3UA Protocol Data
type M3UAProtocolData struct {
	OriginPointCode      uint32 `json:"origin_point_code"`
	DestinationPointCode uint32 `json:"destination_point_code"`
	ServiceIndicator     uint8  `json:"service_indicator"`
	NetworkIndicator     uint8  `json:"network_indicator"`
	MessagePriority      uint8  `json:"message_priority"`
	SignalingLink        uint8  `json:"signaling_link"`
	Data                 []byte `json:"data"` // Contains ISUP message
}

// M3UA Message
type M3UAMessage struct {
	Header M3UACommonHeader `json:"header"`
	Data   M3UAProtocolData `json:"protocol_data,omitempty"`
}

// MTP3 Routing Label
type MTP3RoutingLabel struct {
	DPC                   uint32 `json:"dpc"`
	OPC                   uint32 `json:"opc"`
	SignalingLinkSelector uint8  `json:"signaling_link_selector"`
}

// MTP3 Message
type MTP3Message struct {
	ServiceIndicator uint8            `json:"service_indicator"`
	NetworkIndicator uint8            `json:"network_indicator"`
	RoutingLabel     MTP3RoutingLabel `json:"routing_label"`
	Data             []byte           `json:"data"` // Contains ISUP message
}

// Complete parsed message structure
type ParsedMessage struct {
	Timestamp       time.Time         `json:"timestamp"`
	PacketNumber    int               `json:"packet_number"`
	Protocol        string            `json:"protocol"`
	SourceIP        string            `json:"source_ip"`
	DestinationIP   string            `json:"destination_ip"`
	SourcePort      uint16            `json:"source_port"`
	DestinationPort uint16            `json:"destination_port"`
	SCTPTSN         uint32            `json:"sctp_tsn,omitempty"`
	SCTPPPID        uint32            `json:"sctp_ppid,omitempty"`
	M2PA            *M2PAUserData     `json:"m2pa,omitempty"`
	M3UA            *M3UAMessage      `json:"m3ua,omitempty"`
	MTP3            *MTP3Message      `json:"mtp3,omitempty"`
	ISUP            *isup.ISUPMessage `json:"isup,omitempty"`
	RawPayload      []byte            `json:"raw_payload,omitempty"`
	Error           string            `json:"error,omitempty"`
}

// Parse M2PA message from bytes with correct field sizes
func parseM2PA(data []byte) (*M2PAUserData, error) {
	fmt.Printf("M2PA data length: %d bytes\n", len(data))
	if len(data) < 8 {
		return nil, fmt.Errorf("M2PA message too short (%d bytes)", len(data))
	}

	// Print first few bytes for debugging
	fmt.Printf("M2PA header bytes: %v\n", data[:min(20, len(data))])

	header := M2PAHeader{
		Version:       data[0],
		Spare:         data[1],
		MessageClass:  data[2],
		MessageType:   data[3],
		MessageLength: binary.BigEndian.Uint32(data[4:8]),
	}

	fmt.Printf("M2PA Header: Version=%d, Class=%d, Type=%d, Length=%d\n",
		header.Version, header.MessageClass, header.MessageType, header.MessageLength)

	msg := &M2PAUserData{
		Header: header,
	}

	offset := 8

	// Parse Unused1 (1 byte)
	if offset < len(data) {
		msg.Ununsed1 = data[offset]
		fmt.Printf("Unused1: %d (0x%02X)\n", msg.Ununsed1, msg.Ununsed1)
		offset += 1
	}

	// Parse BSN (3 bytes)
	if offset+3 <= len(data) {
		bsnBytes := make([]byte, 4)
		copy(bsnBytes[1:], data[offset:offset+3]) // Pad with 0 at beginning
		msg.BSN = binary.BigEndian.Uint32(bsnBytes)
		fmt.Printf("BSN (3 bytes): %d (bytes: %v)\n", msg.BSN, data[offset:offset+3])
		offset += 3
	}

	// Parse Unused2 (1 byte)
	if offset < len(data) {
		msg.Ununsed2 = data[offset]
		fmt.Printf("Unused2: %d (0x%02X)\n", msg.Ununsed2, msg.Ununsed2)
		offset += 1
	}

	// Parse FSN (3 bytes)
	if offset+3 <= len(data) {
		fsnBytes := make([]byte, 4)
		copy(fsnBytes[1:], data[offset:offset+3]) // Pad with 0 at beginning
		msg.FSN = binary.BigEndian.Uint32(fsnBytes)
		fmt.Printf("FSN (3 bytes): %d (bytes: %v)\n", msg.FSN, data[offset:offset+3])
		offset += 3
	}

	// Remaining data contains MTP3 + ISUP
	if offset < len(data) {
		msg.Data = data[offset:]
		fmt.Printf("M2PA payload: %d bytes (starts with: %v)\n", len(msg.Data), msg.Data[:min(10, len(msg.Data))])
	} else {
		fmt.Println("No M2PA payload data")
	}

	return msg, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Parse M3UA message from bytes
func parseM3UA(data []byte) (*M3UAMessage, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("M3UA message too short (%d bytes)", len(data))
	}

	header := M3UACommonHeader{
		Version:       data[0],
		Reserved:      data[1],
		MessageClass:  data[2],
		MessageType:   data[3],
		MessageLength: binary.BigEndian.Uint32(data[4:8]),
	}

	msg := &M3UAMessage{
		Header: header,
	}

	// Parse Protocol Data for Data messages
	if header.MessageClass == 3 && header.MessageType == 1 && len(data) >= 20 {
		protocolData := M3UAProtocolData{
			OriginPointCode:      binary.BigEndian.Uint32(data[8:12]) & 0x00FFFFFF,
			DestinationPointCode: binary.BigEndian.Uint32(data[12:16]) & 0x00FFFFFF,
			ServiceIndicator:     data[16] & 0x0F,
			NetworkIndicator:     data[17] & 0x0F,
			MessagePriority:      data[18] & 0x0F,
			SignalingLink:        data[19],
		}

		if len(data) > 20 {
			protocolData.Data = data[20:]
		}

		msg.Data = protocolData
	}

	return msg, nil
}

// Parse MTP3 message from bytes
func parseMTP3(data []byte) (*MTP3Message, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("MTP3 message too short (%d bytes)", len(data))
	}

	// Service Information Octet
	sio := data[0]
	mtp3 := &MTP3Message{
		NetworkIndicator: (sio >> 6) & 0x03,
		ServiceIndicator: sio & 0x0F,
	}

	// Routing Label (4 bytes)
	// DPC: bits 14-1 of bytes 1-2
	dpc := (uint32(data[1]) << 8) | uint32(data[2])
	dpc &= 0x3FFF // Keep only 14 bits

	// OPC: bits 14-1 of bytes 3-4
	opc := (uint32(data[2]) << 14) | (uint32(data[3]) << 6) | (uint32(data[4]) >> 2)
	opc &= 0x3FFF // Keep only 14 bits

	// SLS: last 4 bits of byte 4
	sls := data[4] & 0x0F

	mtp3.RoutingLabel = MTP3RoutingLabel{
		DPC:                   dpc,
		OPC:                   opc,
		SignalingLinkSelector: sls,
	}

	if len(data) > 5 {
		mtp3.Data = data[5:]
	}

	return mtp3, nil
}

// Manual SCTP chunk parsing to extract PPID and TSN
func parseSCTPChunks(sctpPayload []byte) ([]byte, uint32, uint32, error) {
	offset := 0
	for offset < len(sctpPayload) {

		if offset+4 > len(sctpPayload) {
			fmt.Println("Incomplete chunk header, stopping parse")
			break
		}

		chunkType := uint16(sctpPayload[offset])
		chunkFlags := sctpPayload[offset+1]
		chunkLength := uint32(binary.BigEndian.Uint16(sctpPayload[offset+2 : offset+4]))

		fmt.Printf("Chunk Type: %d, Flags: %x, Length: %d\n", chunkType, chunkFlags, chunkLength)

		if chunkLength < 4 {
			break
		}

		if chunkType == 0 { // DATA chunk
			if offset+16 > len(sctpPayload) {
				break
			}

			tsn := binary.BigEndian.Uint32(sctpPayload[offset+4 : offset+8])
			ppid := binary.BigEndian.Uint32(sctpPayload[offset+12 : offset+16])

			fmt.Println("DATA Chunk found --> TSN:", tsn, "PPID:", ppid)

			// Extract user data
			dataStart := offset + 16
			dataEnd := offset + int(chunkLength)
			if dataEnd > len(sctpPayload) {
				dataEnd = len(sctpPayload)
			}

			if dataStart < dataEnd {
				userData := sctpPayload[dataStart:dataEnd]
				return userData, ppid, tsn, nil
			}
		}

		// Move to next chunk
		offset += int(chunkLength)
		// Padding to 4 bytes
		if offset%4 != 0 {
			offset += 4 - (offset % 4)
		}
	}

	return nil, 0, 0, fmt.Errorf("no DATA chunk found")
}

// Extract SCTP payload from packet
func extractSCTPPayload(packet gopacket.Packet) ([]byte, uint32, uint32, error) {
	// Get SCTP layer
	sctpLayer := packet.Layer(layers.LayerTypeSCTP)
	if sctpLayer == nil {
		return nil, 0, 0, fmt.Errorf("not SCTP packet")
	}

	// Check the header length
	sctpHeader := sctpLayer.LayerContents()
	if len(sctpHeader) < 12 {
		return nil, 0, 0, fmt.Errorf("SCTP header too short (%d bytes)", len(sctpHeader))
	}

	sctpPayload := sctpLayer.LayerPayload()

	// parse SCTP chunks
	userData, ppid, tsn, err := parseSCTPChunks(sctpPayload)
	if err != nil {
		return nil, 0, 0, err
	}

	return userData, ppid, tsn, nil
}

// Detect protocol based on PPID and payload content
func detectProtocol(ppid uint32, payload []byte) string {

	if len(payload) < 4 {
		return ProtocolUnknown
	}

	switch ppid {
	case 5: // M2PA PPID
		// M2PA: version = 1, message class often = 11 (Transfer) or 1 (Management)
		if payload[0] == 1 && payload[1] == 0 && (payload[2] == 11 || payload[2] == 1) {
			return ProtocolM2PA
		}
	case 3: // M3UA PPID
		// M3UA: version = 1, reserved = 0
		if payload[0] == 1 && payload[1] == 0 {
			return ProtocolM3UA
		}
	}

	return ProtocolUnknown
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s <pcap_file>\n", os.Args[0])
		return
	}

	pcapFile := os.Args[1]

	// Open the pcap file
	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		fmt.Printf("Error opening pcap file: %v\n", err)
		return
	}
	defer handle.Close()

	// Create a packet source
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	var allMessages []ParsedMessage
	packetCount := 0
	successfulParses := 0
	m2paCount := 0
	m3uaCount := 0

	// Iterate through packets
	for packet := range packetSource.Packets() {
		packetCount++

		// Get network layer information
		var srcIP, dstIP string
		var srcPort, dstPort uint16

		if netLayer := packet.NetworkLayer(); netLayer != nil {
			srcIP = netLayer.NetworkFlow().Src().String()
			dstIP = netLayer.NetworkFlow().Dst().String()
		}

		// Fixed port extraction
		if transLayer := packet.TransportLayer(); transLayer != nil {
			srcRaw := transLayer.TransportFlow().Src().Raw()
			dstRaw := transLayer.TransportFlow().Dst().Raw()
			if len(srcRaw) >= 2 {
				srcPort = binary.BigEndian.Uint16(srcRaw)
			}
			if len(dstRaw) >= 2 {
				dstPort = binary.BigEndian.Uint16(dstRaw)
			}
		}

		// Extract SCTP payload
		payload, ppid, tsn, err := extractSCTPPayload(packet)
		if err != nil {
			// Skip non-SCTP or malformed SCTP packets
			continue
		}

		// Detect protocol
		protocol := detectProtocol(ppid, payload)
		if protocol == ProtocolUnknown {
			continue
		}

		parsedMessage := ParsedMessage{
			Timestamp:       packet.Metadata().Timestamp,
			PacketNumber:    packetCount,
			Protocol:        protocol,
			SourceIP:        srcIP,
			DestinationIP:   dstIP,
			SourcePort:      srcPort,
			DestinationPort: dstPort,
			SCTPTSN:         tsn,
			SCTPPPID:        ppid,
			RawPayload:      payload,
		}

		// Parse based on protocol type
		switch protocol {
		case ProtocolM2PA:
			m2paCount++
			if m2paMsg, err := parseM2PA(payload); err == nil {
				parsedMessage.M2PA = m2paMsg

				// Parse MTP3 and ISUP from User Data
				if m2paMsg.Header.MessageClass == 11 && m2paMsg.Header.MessageType == 1 {
					if len(m2paMsg.Data) > 0 {
						if mtp3Msg, err := parseMTP3(m2paMsg.Data); err == nil {
							parsedMessage.MTP3 = mtp3Msg

							if len(mtp3Msg.Data) > 0 {
								if isupMsg, err := isup.ParseISUP(mtp3Msg.Data); err == nil {
									parsedMessage.ISUP = isupMsg
								}
							}
						}
					}
				}
			} else {
				parsedMessage.Error = fmt.Sprintf("M2PA parse error: %v", err)
			}

		case ProtocolM3UA:
			m3uaCount++
			if m3uaMsg, err := parseM3UA(payload); err == nil {
				parsedMessage.M3UA = m3uaMsg

				// Parse ISUP from Protocol Data
				if m3uaMsg.Header.MessageClass == 3 && m3uaMsg.Header.MessageType == 1 {
					if len(m3uaMsg.Data.Data) > 0 {
						if isupMsg, err := isup.ParseISUP(m3uaMsg.Data.Data); err == nil {
							parsedMessage.ISUP = isupMsg
						}
					}
				}
			} else {
				parsedMessage.Error = fmt.Sprintf("M3UA parse error: %v", err)
			}
		}

		allMessages = append(allMessages, parsedMessage)
		successfulParses++

		if packetCount%100 == 0 {
			fmt.Printf("Processed %d packets...\n", packetCount)
		}
	}

	fmt.Printf("\nProcessed %d packets, successfully parsed %d SIGTRAN messages\n",
		packetCount, successfulParses)
	fmt.Printf("M2PA packets: %d, M3UA packets: %d\n", m2paCount, m3uaCount)

	if successfulParses == 0 {
		fmt.Println("!! No SIGTRAN messages found in the pcap file !!")
		fmt.Println("!! Verify the packet contains SCTP with M2PA/M3UA payload !!")
		return
	}

	// Convert to JSON
	jsonData, err := json.MarshalIndent(allMessages, "", "  ")
	if err != nil {
		fmt.Printf("Error marshaling JSON: %v\n", err)
		return
	}

	// Write to file
	filename := "sigtran_analysis.json"
	err = os.WriteFile(filename, jsonData, 0644)
	if err != nil {
		fmt.Printf("Error writing file: %v\n", err)
		return
	}

	fmt.Printf("Successfully parsed and saved %d messages to %s\n",
		successfulParses, filename)

	// Print summary
	fmt.Printf("\nFirst few messages:\n")
	for i, msg := range allMessages {
		if i >= 5 {
			break
		}
		fmt.Printf("Packet %d: %s protocol, PPID: %d\n", msg.PacketNumber, msg.Protocol, msg.SCTPPPID)
		if msg.MTP3 != nil {
			fmt.Printf("  MTP3: OPC=%d, DPC=%d, SI=%d\n", msg.MTP3.RoutingLabel.OPC, msg.MTP3.RoutingLabel.DPC, msg.MTP3.ServiceIndicator)
		}
		if msg.ISUP != nil {
			fmt.Printf("  ISUP: Type=%d, CIC=%d\n", msg.ISUP.Header.MessageType, msg.ISUP.CIC)
		}
		if msg.Error != "" {
			fmt.Printf("  Error: %s\n", msg.Error)
		}
	}
}
