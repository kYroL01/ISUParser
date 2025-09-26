package sctp

import (
	"encoding/binary"
	"fmt"
)

// SCTP Header
type Header struct {
	SourcePort      uint16
	DestinationPort uint16
	VerificationTag uint32
	Checksum        uint32
}

// SCTP DATA Chunk with extracted fields
type DataChunk struct {
	TSN         uint32
	StreamID    uint16
	Sequence    uint16
	PPID        uint32
	UserData    []byte
	ChunkLength uint32
}

// Parse SCTP header from bytes
func ParseHeader(data []byte) (*Header, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("SCTP header too short (%d bytes)", len(data))
	}

	header := &Header{
		SourcePort:      binary.BigEndian.Uint16(data[0:2]),
		DestinationPort: binary.BigEndian.Uint16(data[2:4]),
		VerificationTag: binary.BigEndian.Uint32(data[4:8]),
		Checksum:        binary.BigEndian.Uint32(data[8:12]),
	}

	return header, nil
}

// Parse SCTP chunks from payload (handles both header+chunks and chunks-only)
func ParseDataChunks(payload []byte) ([]DataChunk, error) {
	var dataChunks []DataChunk

	offset := 0
	for offset < len(payload) {
		if offset+4 > len(payload) {
			return nil, fmt.Errorf("incomplete chunk header at offset %d", offset)
		}

		chunkType := payload[offset]
		chunkFlags := payload[offset+1]
		chunkLength := binary.BigEndian.Uint16(payload[offset+2 : offset+4])

		fmt.Println("Chunk Type:", chunkType, "Flags:", chunkFlags, "Length:", chunkLength)

		if chunkLength < 4 {
			return nil, fmt.Errorf("invalid chunk length %d at offset %d", chunkLength, offset)
		}

		// Process DATA chunk (Type = 0)
		if chunkType == 0 {
			// DATA chunk must have at least 16 bytes of data
			if int(chunkLength) >= 20 { // 4-byte header + 16-byte data
				endOffset := offset + int(chunkLength)
				if endOffset > len(payload) {
					endOffset = len(payload)
				}

				chunkData := payload[offset+4 : endOffset]

				if len(chunkData) >= 16 {
					dataChunk := DataChunk{
						TSN:         binary.BigEndian.Uint32(chunkData[0:4]),
						StreamID:    binary.BigEndian.Uint16(chunkData[4:6]),
						Sequence:    binary.BigEndian.Uint16(chunkData[6:8]),
						PPID:        binary.BigEndian.Uint32(chunkData[8:12]),
						ChunkLength: uint32(chunkLength),
					}

					// User data starts at byte 16
					if len(chunkData) > 12 {
						dataChunk.UserData = chunkData[12:]
					}

					dataChunks = append(dataChunks, dataChunk)

					fmt.Printf("DATA Chunk - TSN: %d, PPID: %d, UserData: %d bytes\n",
						dataChunk.TSN, dataChunk.PPID, len(dataChunk.UserData))
				}
			}
		}

		// Move to next chunk (with padding)
		offset += int(chunkLength)
		if offset%4 != 0 {
			offset += 4 - (offset % 4)
		}
	}

	if len(dataChunks) == 0 {
		return nil, fmt.Errorf("no DATA chunks found")
	}

	return dataChunks, nil
}

// Parse complete SCTP packet (header + chunks)
func ParseCompletePacket(headerData []byte, payload []byte) ([]DataChunk, uint32, error) {
	_, err := ParseHeader(headerData)
	if err != nil {
		return nil, 0, err
	}

	dataChunks, err := ParseDataChunks(payload)
	if err != nil {
		return nil, 0, err
	}

	totalLength := uint32(len(headerData)) + uint32(len(payload))
	return dataChunks, totalLength, nil
}

// Parse chunks only (for fragmented packets without header)
func ParseChunksOnly(payload []byte) ([]DataChunk, uint32, error) {
	dataChunks, err := ParseDataChunks(payload)
	if err != nil {
		return nil, 0, err
	}

	return dataChunks, uint32(len(payload)), nil
}
