package isup

import (
	"fmt"
	"strings"
)

// MessageType represents the ISUP message type.
type MessageType byte

// MessageType constants
const (
	MsgIAM MessageType = 0x01
	MsgACM MessageType = 0x06
	MsgANM MessageType = 0x09
	MsgREL MessageType = 0x0C
)

// IAMFixedPart holds the mandatory fixed part fields.
type IAMFixedPart struct {
	NatureOfConnection    byte   // 1 byte
	ForwardCallIndicators uint16 // 2 bytes
	CallingPartyCategory  byte   // 1 byte
	TransmissionMediumReq byte   // 1 byte
}

// Parameter represents an ISUP parameter (code, length, value).
type Parameter struct {
	Code   byte
	Length int
	Value  []byte
}

// IAMMessage represents a parsed IAM.
type IAMMessage struct {
	Fixed        IAMFixedPart
	CalledParty  string
	CallingParty string
	RawParams    []Parameter
}

// ParseIAM parses an Initial Address Message.
func ParseIAM(b []byte) (*IAMMessage, error) {
	if len(b) < 6 { // 1 (msg type) + 5 (fixed part)
		return nil, fmt.Errorf("IAM too short (%d bytes)", len(b))
	}
	if MessageType(b[0]) != MsgIAM {
		return nil, fmt.Errorf("not an IAM (got type 0x%02x)", b[0])
	}
	i := 1
	iam := &IAMMessage{}
	iam.Fixed = IAMFixedPart{
		NatureOfConnection:    b[i],
		ForwardCallIndicators: uint16(b[i+1]) | uint16(b[i+2])<<8,
		CallingPartyCategory:  b[i+3],
		TransmissionMediumReq: b[i+4],
	}
	i += 5

	// --- Called party number (mandatory variable) ---
	if i >= len(b) {
		return iam, nil // no called party present
	}
	calledLen := int(b[i])
	i++
	if i+calledLen > len(b) {
		return nil, fmt.Errorf("called party length %d exceeds remaining %d bytes", calledLen, len(b)-i)
	}
	calledDigits := decodeBCD(b[i : i+calledLen])
	iam.CalledParty = calledDigits
	i += calledLen

	// --- Optional params (simplified TLV) ---
	for i < len(b) {
		if i+2 > len(b) {
			return nil, fmt.Errorf("parameter header too short at %d", i)
		}
		code := b[i]
		length := int(b[i+1])
		i += 2
		if i+length > len(b) {
			return nil, fmt.Errorf("parameter length %d exceeds remaining %d bytes", length, len(b)-i)
		}
		val := make([]byte, length)
		copy(val, b[i:i+length])
		i += length
		p := Parameter{Code: code, Length: length, Value: val}
		iam.RawParams = append(iam.RawParams, p)

		// Example: code 0x0A = Calling Party Number
		if code == 0x0A {
			iam.CallingParty = decodeBCD(val[1:]) // skip first octet (nature/plan)
		}
	}
	return iam, nil
}

// decodeBCD decodes semi-octet BCD digits (used in ISUP numbers).
func decodeBCD(b []byte) string {
	var sb strings.Builder
	for _, octet := range b {
		lo := octet & 0x0F
		hi := (octet & 0xF0) >> 4
		if lo <= 9 {
			sb.WriteByte('0' + lo)
		} else if lo == 0x0F {
			break
		}
		if hi <= 9 {
			sb.WriteByte('0' + hi)
		}
	}
	return sb.String()
}

// Debug print helper
func (iam *IAMMessage) String() string {
	return fmt.Sprintf("IAM{Called:%s, Calling:%s, Cat:0x%02x, FwdInd:0x%04x, RawParams:%d}",
		iam.CalledParty, iam.CallingParty,
		iam.Fixed.CallingPartyCategory,
		iam.Fixed.ForwardCallIndicators,
		len(iam.RawParams))
}
