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
	"isup-parser/sctp"

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

// Complete parsed message structure
type ParsedMessage struct {
	Timestamp       time.Time         `json:"timestamp"`
	PacketNumber    int               `json:"packet_number"`
	ChunkIndex      int               `json:"chunk_index"` // Chunk Index to identify multiple chunks per packet
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
	Error           string            `json:"error,omitempty"`
}

// Extract SCTP payload - handles both complete packets and chunks-only
func extractSCTPPayload(packet gopacket.Packet) ([]*sctp.DataChunk, uint32, error) {
	sctpLayer := packet.Layer(layers.LayerTypeSCTP)

	// Complete parsing for SCTP (non-fragmented packets)
	if sctpLayer != nil {
		sctpHeader := sctpLayer.LayerContents()
		sctpPayload := sctpLayer.LayerPayload()

		if len(sctpHeader) >= 12 {
			dataChunks, totalLength, err := sctp.ParseCompletePacket(sctpHeader, sctpPayload)
			if err == nil {
				// Convert []sctp.DataChunk to []*sctp.DataChunk
				ptrChunks := make([]*sctp.DataChunk, len(dataChunks))
				for i := range dataChunks {
					ptrChunks[i] = &dataChunks[i]
				}
				return ptrChunks, totalLength, nil
			}
			fmt.Printf("Complete packet parsing failed: %v, trying chunks-only...\n", err)
		}
	}

	// Chunks-only parsing for SCTP (fragmented packets)
	if transLayer := packet.TransportLayer(); transLayer != nil {
		rawPayload := transLayer.LayerPayload()
		if len(rawPayload) > 0 {
			dataChunks, totalLength, err := sctp.ParseChunksOnly(rawPayload)
			if err == nil {
				// Convert []sctp.DataChunk to []*sctp.DataChunk
				ptrChunks := make([]*sctp.DataChunk, len(dataChunks))
				for i := range dataChunks {
					ptrChunks[i] = &dataChunks[i]
				}
				return ptrChunks, totalLength, nil
			}
			fmt.Printf("Chunks-only parsing failed: %v\n", err)
		}
	}
	return nil, 0, fmt.Errorf("failed to parse SCTP data")
}

// Detect protocol based on PPID and payload content
func detectProtocol(ppid uint32, payload []byte) string {

	if len(payload) < 4 {
		return ProtocolUnknown
	}

	switch ppid {
	case 5: // M2PA PPID
		// M2PA: version = 1, message class = 11 (Transfer) or 1 (Management)
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

const version = "1.0.1"

func main() {

	fmt.Printf("\n>>--- WELCOME to ISUParser %s --->\n", version)

	if len(os.Args) < 3 {
		fmt.Printf("\nUsage: %s <pcap_file> <isup type (itu or ansi)>\n", os.Args[0])
		return
	}

	pcapFile := os.Args[1]

	isITU := false
	isANSI := false

	MTP3_standard := os.Args[2]
	switch MTP3_standard {
	case "itu":
		isITU = true
	case "ansi":
		isANSI = true
	default:
		fmt.Println("Unknown MTP3 standard specified. Use 'itu' or 'ansi'.")
		return
	}

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

	// Create channel for JSON buffers
	jsonBufferChan := make(chan []byte, 100) // Buffered channel

	// Start a goroutine to process JSON buffers
	go processJSONBuffers(jsonBufferChan)

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

		// Port extraction
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
		dataChunks, sctpLength, err := extractSCTPPayload(packet)
		if err != nil || sctpLength == 0 || len(dataChunks) == 0 {
			fmt.Printf("Packet %d: SCTP parsing failed: %v\n", packetCount, err)
			continue
		}

		// Process each DATA chunk in the packet
		for chunkIndex, dataChunk := range dataChunks {
			// Detect protocol for this chunk
			protocol := detectProtocol(dataChunk.PPID, dataChunk.UserData)
			if protocol == ProtocolUnknown {
				fmt.Printf("Chunk %d: Unknown protocol (PPID: %d)\n", chunkIndex+1, dataChunk.PPID)
				continue
			}

			parsedMessage := ParsedMessage{
				Timestamp:       packet.Metadata().Timestamp,
				PacketNumber:    packetCount,
				ChunkIndex:      chunkIndex + 1, // Add chunk index to identify multiple chunks per packet
				Protocol:        protocol,
				SourceIP:        srcIP,
				DestinationIP:   dstIP,
				SourcePort:      srcPort,
				DestinationPort: dstPort,
				SCTPTSN:         dataChunk.TSN,
				SCTPPPID:        dataChunk.PPID,
			}

			// Parse based on protocol type (M2PA/M3UA logic)
			var jsonBuffer []byte
			switch protocol {
			case ProtocolM2PA:
				m2paCount++
				if m2paMsg, err := m2pa.ParseM2PA(dataChunk.UserData); err == nil {
					parsedMessage.M2PA = m2paMsg

					if m2paMsg.IsUserData() && len(m2paMsg.Data) > 0 {

						// ITU case
						if isITU {
							if mtp3Msg, err := mtp3.ParseMTP3_ITU(m2paMsg.Data); err == nil {
								parsedMessage.MTP3 = mtp3Msg

								if len(mtp3Msg.Data) > 0 {
									if isupMsg, err := isup.ParseISUP_ITU(mtp3Msg.Data); err == nil {
										parsedMessage.ISUP = isupMsg
										// Create JSON buffer for the complete block
										jsonBuffer = createJSONBuffer(parsedMessage)
									}
								}
							}
						} else if isANSI {
							// ANSI case
							if mtp3Msg, err := mtp3.ParseMTP3_ANSI(m2paMsg.Data); err == nil {
								parsedMessage.MTP3 = mtp3Msg

								if len(mtp3Msg.Data) > 0 {
									if isupMsg, err := isup.ParseISUP_ANSI(mtp3Msg.Data); err == nil {
										parsedMessage.ISUP = isupMsg
										// Create JSON buffer for complete block
										jsonBuffer = createJSONBuffer(parsedMessage)
									}
								}
							}
						}
					}
				}
			case ProtocolM3UA:
				m3uaCount++
				if m3uaMsg, err := m3ua.ParseM3UA(dataChunk.UserData); err == nil {
					parsedMessage.M3UA = m3uaMsg

					if m3uaMsg.Data != nil && len(m3uaMsg.Data.Data) > 0 {

						// ITU case
						if isITU {
							if mtp3Msg, err := mtp3.ParseMTP3_ITU(m3uaMsg.Data.Data); err == nil {
								parsedMessage.MTP3 = mtp3Msg

								if len(mtp3Msg.Data) > 0 {
									if isupMsg, err := isup.ParseISUP_ITU(mtp3Msg.Data); err == nil {
										parsedMessage.ISUP = isupMsg
										// Create JSON buffer for complete block
										jsonBuffer = createJSONBuffer(parsedMessage)
									}
								}
							}
						} else if isANSI {
							// ANSI case
							if mtp3Msg, err := mtp3.ParseMTP3_ANSI(m3uaMsg.Data.Data); err == nil {
								parsedMessage.MTP3 = mtp3Msg

								if len(mtp3Msg.Data) > 0 {
									if isupMsg, err := isup.ParseISUP_ANSI(mtp3Msg.Data); err == nil {
										parsedMessage.ISUP = isupMsg
										// Create JSON buffer for complete block
										jsonBuffer = createJSONBuffer(parsedMessage)
									}
								}
							}
						}
					}
				}
			}

			// Send JSON buffer through channel if we have a complete ISUP block
			if jsonBuffer != nil {
				jsonBufferChan <- jsonBuffer
				successfulParses++
			}

			allMessages = append(allMessages, parsedMessage)
			successfulParses++
		}

		if packetCount%100 == 0 {
			fmt.Printf("Processed %d packets...\n", packetCount)
		}
	}

	fmt.Printf("\nProcessed %d packets, successfully parsed %d SIGTRAN messages\n", packetCount, successfulParses)
	fmt.Printf("M2PA packets: %d, M3UA packets: %d\n\n", m2paCount, m3uaCount)

	if successfulParses == 0 {
		fmt.Fprintf(os.Stderr, "!! No SIGTRAN messages found in the pcap file !!")
		fmt.Fprintf(os.Stderr, "!! Verify the packet contains SCTP with M2PA/M3UA payload !!")
		return
	}

	// Close the JSON buffer channel and wait for the process to finish
	close(jsonBufferChan)
	time.Sleep(1 * time.Second) // Wait 1 sec for goroutine to finish

	// Print summary
	fmt.Printf("\nSummary:\n")
	for i, msg := range allMessages {
		if i >= 5 {
			break
		}
		fmt.Printf("Packet %d: %s protocol, PPID: %d, TSN: %d\n",
			msg.PacketNumber, msg.Protocol, msg.SCTPPPID, msg.SCTPTSN)
		if msg.MTP3 != nil {
			fmt.Printf("  MTP3: OPC=%d, DPC=%d, SI=%d\n",
				msg.MTP3.RoutingLabel.OPC, msg.MTP3.RoutingLabel.DPC, msg.MTP3.ServiceIndicator)
		}
		if msg.ISUP != nil {
			fmt.Printf("  ISUP: Type=%d, CIC=%d\n", msg.ISUP.MessageType, msg.ISUP.CIC)
		}
		if msg.Error != "" {
			fmt.Printf("  Error: %s\n", msg.Error)
		}
		fmt.Println()
	}
}

// Helper function to create JSON buffer
func createJSONBuffer(message ParsedMessage) []byte {
	jsonData, err := json.Marshal(message)
	if err != nil {
		fmt.Printf("Error creating JSON buffer: %v\n", err)
		return nil
	}
	return jsonData
}

// Process JSON buffers from channel
func processJSONBuffers(jsonBufferChan <-chan []byte) {
	bufferCount := 0

	for jsonBuffer := range jsonBufferChan {
		bufferCount++

		// Print JSON buffer
		fmt.Printf("=== JSON Buffer #%d (%d bytes) ===\n", bufferCount, len(jsonBuffer))
		fmt.Printf("%s\n", string(jsonBuffer))
		fmt.Printf("=== End Buffer #%d ===\n\n", bufferCount)

		// NOTE: here we can also write to file or send over network
	}

	fmt.Printf("Processed %d JSON buffers total\n", bufferCount)
}
