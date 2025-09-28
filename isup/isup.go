package isup

import (
	"fmt"
)

// ISUP Message
type ISUPMessage struct {
	MessageType uint8  `json:"message_type"`
	CIC         uint16 `json:"cic"`
	Data        []byte `json:"data,omitempty"` // ISUP message body
}

// ParseISUP parses an ISUP message from bytes
func ParseISUP(data []byte, ISUPType uint8) (*ISUPMessage, uint32, error) {

	Len := uint32(len(data))

	if Len < 3 {
		return nil, 0, fmt.Errorf("ISUP message too short (%d bytes)", Len)
	}

	// Determine ISUP format (ITU-T or ANSI) based on context or configuration
	if ISUPType != 2 && ISUPType != 5 {
		return nil, Len, fmt.Errorf("unknown ISUP type: %d", ISUPType)
	}

	isANSIFormat := false
	isITUFormat := false
	switch ISUPType {
	case 2:
		isANSIFormat = true // Assume ANSI by default
		fmt.Println("Parsing as ANSI ISUP")
	case 5:
		isITUFormat = true // Assume not ITU-T by default
		fmt.Println("Parsing as ITU-T ISUP")
	}

	var cic uint16

	if isITUFormat {
		fmt.Println("ITU-T ISUP parsing")
		// For ITU-T ISUP (12-bit CIC)
		cicLow := data[0]         // CIC Low-Order Octet
		cicHigh := data[1] & 0x0F // CIC High-Order 4 bits (lower 4 bits of byte)
		cic = (uint16(cicHigh) << 8) | uint16(cicLow)

	} else if isANSIFormat {
		fmt.Println("ANSI ISUP parsing")
		// For ANSI ISUP (14-bit CIC)
		cicLow := data[0]         // CIC Low-Order Octet
		cicHigh := data[1] & 0x3F // CIC High-Order 6 bits (lower 6 bits of byte)
		cic = (uint16(cicHigh) << 8) | uint16(cicLow)

	} else {
		return nil, Len, fmt.Errorf("unknown ISUP format")
	}

	fmt.Println("ISUP CIC:", cic)

	// Message type - 1 byte
	ISUPmsg := &ISUPMessage{
		CIC:         cic,
		MessageType: data[2],
	}

	fmt.Println("ISUP Message Type:", ISUPmsg.MessageType, "(", GetISUPMessageTypeName(ISUPmsg.MessageType), ")")

	ISUPmsg.Data = data[3:]

	Len += 3 // CIC (2 bytes) + Message Type (1 byte)
	return ISUPmsg, Len, nil
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
	ISUPMessageReserved1 = 10 // "Reserved"
	ISUPMessageReserved2 = 11 // "Reserved"
	ISUPMessageTypeREL   = 12 // Release
	ISUPMessageTypeSUS   = 13 // Suspend
	ISUPMessageTypeRES   = 14 // Resume
	ISUPMessageReserved3 = 15 // "Reserved"
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
	ISUPMessageTypeDRS   = 39 // Delayed Release
	ISUPMessageTypePAM   = 40 // Pass Along
	ISUPMessageTypeGRA   = 41 // Circuit Group Reset Acknowledgment
	ISUPMessageTypeCQM   = 42 // Circuit Group Query
	ISUPMessageTypeCQR   = 43 // Circuit Group Query Request
	ISUPMessageTypeCPG   = 44 // Call Progress
	ISUPMessageTypeUSR   = 45 // User-to-User Information
	ISUPMessageTypeUCIC  = 46 // Unequipped Circuit Identification Code
	ISUPMessageTypeCFN   = 47 // Confusion
	ISUPMessageTypeOLM   = 48 // Overload
	ISUPMessageTypeCRG   = 49 // Charge information
	ISUPMessageTypeNRM   = 50 // Network Resource Management
	ISUPMessageTypeFAC   = 51 // Facility
	ISUPMessageTypeUPT   = 52 // User Part Test
	ISUPMessageTypeUPA   = 53 // User Part Available
	ISUPMessageTypeIDR   = 54 // Identification Request
	ISUPMessageTypeIDS   = 55 // Identification Response
	ISUPMessageTypeSEG   = 56 // Segmentation
	ISUPMessageTypeLPR   = 64 // Loop Prevention
	ISUPMessageTypeAPT   = 65 // Application Transport
	ISUPMessageTypePRI   = 66 // Pre-release Information
	ISUPMessageTypeSAN   = 67 // Subsequent Directory Number
)

// ISUPMessageTypeNames maps ISUP message type codes to human-readable names
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
	ISUPMessageTypeDRS:  "DRS (Delayed Release)", // ADDED
	ISUPMessageTypePAM:  "PAM (Pass Along)",      // ADDED
	ISUPMessageTypeGRA:  "GRA (Circuit Group Reset Acknowledgment)",
	ISUPMessageTypeCQM:  "CQM (Circuit Group Query)", // ADDED
	ISUPMessageTypeCQR:  "CQR (Circuit Group Query Request)",
	ISUPMessageTypeCPG:  "CPG (Call Progress)",
	ISUPMessageTypeUSR:  "USR (User-to-User Information)",
	ISUPMessageTypeUCIC: "UCIC (Unequipped Circuit Identification Code)",
	ISUPMessageTypeCFN:  "CFN (Confusion)",
	ISUPMessageTypeOLM:  "OLM (Overload)",
	ISUPMessageTypeCRG:  "CRG (Charge information)", // ADDED
	ISUPMessageTypeNRM:  "NRM (Network Resource Management)",
	ISUPMessageTypeFAC:  "FAC (Facility)",
	ISUPMessageTypeUPT:  "UPT (User Part Test)",
	ISUPMessageTypeUPA:  "UPA (User Part Available)",
	ISUPMessageTypeIDR:  "IDR (Identification Request)",
	ISUPMessageTypeIDS:  "IDS (Identification Response)",
	ISUPMessageTypeSEG:  "SEG (Segmentation)",
	ISUPMessageTypeLPR:  "LPR (Loop Prevention)",
	ISUPMessageTypeAPT:  "APT (Application Transport)",
	ISUPMessageTypePRI:  "PRI (Pre-release Information)",
	ISUPMessageTypeSAN:  "SAN (Subsequent Directory Number)",
}

// GetISUPMessageTypeName returns the human-readable name for an ISUP message type
func GetISUPMessageTypeName(messageType uint8) string {
	if name, exists := ISUPMessageTypeNames[messageType]; exists {
		return name
	}
	return fmt.Sprintf("Unknown (0x%02X)", messageType)
}
