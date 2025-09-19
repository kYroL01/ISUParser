package isup

import (
	"encoding/binary"
	"fmt"
)

// ISUP Common Header
type ISUPHeader struct {
	MessageType uint8 `json:"message_type"`
}

// ISUP Message
type ISUPMessage struct {
	Header ISUPHeader `json:"header"`
	CIC    uint16     `json:"cic"`
	Data   []byte     `json:"data"`
}

// ParseISUP parses an ISUP message from bytes
func ParseISUP(data []byte) (*ISUPMessage, error) {
	if len(data) < 3 {
		return nil, fmt.Errorf("ISUP message too short (%d bytes)", len(data))
	}

	// CIC (Circuit Identification Code) - 2 bytes
	cic := binary.BigEndian.Uint16(data[0:2])

	// Message type - 1 byte
	msg := &ISUPMessage{
		CIC: cic,
		Header: ISUPHeader{
			MessageType: data[2],
		},
	}

	if len(data) > 3 {
		msg.Data = data[3:]
	}

	return msg, nil
}

// ISUP message type constants
const (
	ISUPMessageTypeIAM   = 1  // Initial Address Message
	ISUPMessageTypeSAM   = 2  // Subsequent Address Message
	ISUPMessageTypeINR   = 3  // Information Request
	ISUPMessageTypeINF   = 4  // Information
	ISUPMessageTypeCOT   = 5  // Continuity
	ISUPMessageTypeACM   = 6  // Address Complete Message
	ISUPMessageTypeCON   = 7  // Connect
	ISUPMessageTypeFOT   = 8  // Forward Transfer
	ISUPMessageTypeANM   = 9  // Answer Message
	ISUPMessageTypeREL   = 12 // Release
	ISUPMessageTypeSUS   = 13 // Suspend
	ISUPMessageTypeRES   = 14 // Resume
	ISUPMessageTypeRLC   = 16 // Release Complete
	ISUPMessageTypeCCR   = 17 // Continuity Check Request
	ISUPMessageTypeRSC   = 18 // Reset Circuit
	ISUPMessageTypeBLO   = 19 // Blocking
	ISUPMessageTypeUBL   = 20 // Unblocking
	ISUPMessageTypeBLA   = 21 // Blocking Acknowledgment
	ISUPMessageTypeUBA   = 22 // Unblocking Acknowledgment
	ISUPMessageTypeGRS   = 23 // Circuit Group Reset
	ISUPMessageTypeCGB   = 24 // Circuit Group Blocking
	ISUPMessageTypeCGU   = 25 // Circuit Group Unblocking
	ISUPMessageTypeCGBA  = 26 // Circuit Group Blocking Acknowledgment
	ISUPMessageTypeCGUA  = 27 // Circuit Group Unblocking Acknowledgment
	ISUPMessageTypeCMR   = 28 // Call Modification Request
	ISUPMessageTypeCMC   = 29 // Call Modification Completed
	ISUPMessageTypeCMRJ  = 30 // Call Modification Reject
	ISUPMessageTypeFAR   = 31 // Facility Request
	ISUPMessageTypeFAA   = 32 // Facility Accepted
	ISUPMessageTypeFRJ   = 33 // Facility Reject
	ISUPMessageTypeFAD   = 34 // Facility Deactivated
	ISUPMessageTypeFAI   = 35 // Facility Information
	ISUPMessageTypeLPA   = 36 // Loopback Acknowledgment
	ISUPMessageTypeCSVQ  = 37 // CUG Selection and Validation Request
	ISUPMessageTypeCSVR  = 38 // CUG Selection and Validation Response
)

// ISUP message type to string mapping
var ISUPMessageTypeNames = map[uint8]string{
	ISUPMessageTypeIAM:  "IAM (Initial Address Message)",
	ISUPMessageTypeSAM:  "SAM (Subsequent Address Message)",
	ISUPMessageTypeINR:  "INR (Information Request)",
	ISUPMessageTypeINF:  "INF (Information)",
	ISUPMessageTypeCOT:  "COT (Continuity)",
	ISUPMessageTypeACM:  "ACM (Address Complete Message)",
	ISUPMessageTypeCON:  "CON (Connect)",
	ISUPMessageTypeFOT:  "FOT (Forward Transfer)",
	ISUPMessageTypeANM:  "ANM (Answer Message)",
	ISUPMessageTypeREL:  "REL (Release)",
	ISUPMessageTypeSUS:  "SUS (Suspend)",
	ISUPMessageTypeRES:  "RES (Resume)",
	ISUPMessageTypeRLC:  "RLC (Release Complete)",
	ISUPMessageTypeCCR:  "CCR (Continuity Check Request)",
	ISUPMessageTypeRSC:  "RSC (Reset Circuit)",
	ISUPMessageTypeBLO:  "BLO (Blocking)",
	ISUPMessageTypeUBL:  "UBL (Unblocking)",
	ISUPMessageTypeBLA:  "BLA (Blocking Acknowledgment)",
	ISUPMessageTypeUBA:  "UBA (Unblocking Acknowledgment)",
	ISUPMessageTypeGRS:  "GRS (Circuit Group Reset)",
	ISUPMessageTypeCGB:  "CGB (Circuit Group Blocking)",
	ISUPMessageTypeCGU:  "CGU (Circuit Group Unblocking)",
	ISUPMessageTypeCGBA: "CGBA (Circuit Group Blocking Acknowledgment)",
	ISUPMessageTypeCGUA: "CGUA (Circuit Group Unblocking Acknowledgment)",
	ISUPMessageTypeCMR:  "CMR (Call Modification Request)",
	ISUPMessageTypeCMC:  "CMC (Call Modification Completed)",
	ISUPMessageTypeCMRJ: "CMRJ (Call Modification Reject)",
	ISUPMessageTypeFAR:  "FAR (Facility Request)",
	ISUPMessageTypeFAA:  "FAA (Facility Accepted)",
	ISUPMessageTypeFRJ:  "FRJ (Facility Reject)",
	ISUPMessageTypeFAD:  "FAD (Facility Deactivated)",
	ISUPMessageTypeFAI:  "FAI (Facility Information)",
	ISUPMessageTypeLPA:  "LPA (Loopback Acknowledgment)",
	ISUPMessageTypeCSVQ: "CSVQ (CUG Selection and Validation Request)",
	ISUPMessageTypeCSVR: "CSVR (CUG Selection and Validation Response)",
}

// GetISUPMessageTypeName returns the human-readable name for an ISUP message type
func GetISUPMessageTypeName(messageType uint8) string {
	if name, exists := ISUPMessageTypeNames[messageType]; exists {
		return name
	}
	return fmt.Sprintf("Unknown (0x%02X)", messageType)
}