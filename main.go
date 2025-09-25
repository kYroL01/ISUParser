package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"isup-parser/isup"
	"isup-parser/m2pa"
	"isup-parser/m3ua"
	"isup-parser/mtp3"

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

// ISUP types
const (
	ITU  = 5
	ANSI = 2
)

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
	M2PA            *m2pa.Data        `json:"m2pa,omitempty"`
	M3UA            *m3ua.Message     `json:"m3ua,omitempty"`
	MTP3            *mtp3.Message     `json:"mtp3,omitempty"`
	ISUP            *isup.ISUPMessage `json:"isup,omitempty"`
	RawPayload      []byte            `json:"raw_payload,omitempty"`
	Error           string            `json:"error,omitempty"`
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
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
	fmt.Println("\n\tParsing SCTP of new packet...")
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
			if m2paMsg, err := m2pa.ParseM2PA(payload); err == nil {
				parsedMessage.M2PA = m2paMsg

				if m2paMsg.IsUserData() && len(m2paMsg.Data) > 0 {
					if mtp3Msg, err := mtp3.ParseMTP3(m2paMsg.Data); err == nil {
						parsedMessage.MTP3 = mtp3Msg

						if len(mtp3Msg.Data) > 0 {
							if isupMsg, err := isup.ParseISUP(mtp3Msg.Data, mtp3Msg.GetISUPFormat()); err == nil {
								parsedMessage.ISUP = isupMsg
							}
						}
					}
				}
			}

		case ProtocolM3UA:
			m3uaCount++
			if m3uaMsg, err := m3ua.ParseM3UA(payload); err == nil {
				parsedMessage.M3UA = m3uaMsg

				if m3uaMsg.Data != nil && len(m3uaMsg.Data.Data) > 0 {
					if isupMsg, err := isup.ParseISUP(m3uaMsg.Data.Data, m3uaMsg.Data.GetISUPFormat()); err == nil {
						parsedMessage.ISUP = isupMsg
					}
				}
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
	fmt.Printf("\nSummary:\n")
	for i, msg := range allMessages {
		if i >= 5 {
			break
		}
		fmt.Printf("Packet %d: %s protocol, PPID: %d\n", msg.PacketNumber, msg.Protocol, msg.SCTPPPID)
		if msg.MTP3 != nil {
			fmt.Printf("  MTP3: OPC=%d, DPC=%d, SI=%d\n", msg.MTP3.RoutingLabel.OPC, msg.MTP3.RoutingLabel.DPC, msg.MTP3.ServiceIndicator)
		}
		if msg.ISUP != nil {
			fmt.Printf("  ISUP: Type=%d, CIC=%d\n", msg.ISUP.MessageType, msg.ISUP.CIC)
		}
		if msg.Error != "" {
			fmt.Printf("  Error: %s\n", msg.Error)
		}
	}
}
