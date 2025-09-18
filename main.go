package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"

	"isup-parser/isup"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Usage: %s <file.pcap>", os.Args[0])
	}
	handle, err := pcap.OpenOffline(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// We only care about SCTP
		sctpLayer := packet.Layer(layers.LayerTypeSCTP)
		if sctpLayer == nil {
			continue
		}
		sctp, _ := sctpLayer.(*layers.SCTP)

		// SCTP payload may contain multiple chunks; here we treat the entire payload as one chunk.
		payload := sctp.Payload
		if len(payload) == 0 {
			continue
		}

		// NOTE: Real-world M3UA has a header we should strip.
		// For now assume payload starts with ISUP message type.
		msgType := payload[0]
		if msgType == byte(isup.MsgIAM) {
			iam, err := isup.ParseIAM(payload)
			if err != nil {
				log.Println("parse error:", err)
				continue
			}
			fmt.Printf("ISUP IAM found: %s\n", iam)
			fmt.Printf("Hex: %s\n\n", hex.EncodeToString(payload))
		} else {
			fmt.Printf("Other ISUP msg type 0x%02x (%d bytes)\n",
				msgType, len(payload))
			fmt.Printf("Hex: %s\n\n", strings.ToUpper(hex.EncodeToString(payload)))
		}
	}
}
