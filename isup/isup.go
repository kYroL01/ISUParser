package isup

import (
	"fmt"
)

// In isup/isup.go

// Updated IAMParameters struct to match C output
type IAMParameters struct {
	NatureOfConnection *NatureOfConnection `json:"nature_of_connection,omitempty"`
	ForwardCall        *ForwardCall        `json:"forward_call,omitempty"`
	CallingParty       *CallingParty       `json:"calling_party,omitempty"`
	TransmissionMedium *TransmissionMedium `json:"transmission_medium,omitempty"`
	CalledNumber       *NumberInfo         `json:"called_number,omitempty"`
	CallingNumber      *NumberInfo         `json:"calling_number,omitempty"`
	HopCounter         *uint8              `json:"hop_counter,omitempty"`
	GenericNumber      *NumberInfo         `json:"generic_number,omitempty"`
	Jurisdiction       *string             `json:"jurisdiction,omitempty"`
	ChargeNumber       *NumberInfo         `json:"charge_number,omitempty"`
	// Add other fields as needed
}

// Updated parameter structures to match C JSON format
type NatureOfConnection struct {
	Satellite           uint8  `json:"satellite"`
	SatelliteName       string `json:"satellite_name"`
	ContinuityCheck     uint8  `json:"continuity_check"`
	ContinuityCheckName string `json:"continuity_check_name"`
	EchoDevice          uint8  `json:"echo_device"`
	EchoDeviceName      string `json:"echo_device_name"`
}

type ForwardCall struct {
	NationalInternationalCall     uint8  `json:"national_international_call"`
	NationalInternationalCallName string `json:"national_international_call_name"`
	EndToEndMethod                uint8  `json:"end_to_end_method"`
	EndToEndMethodName            string `json:"end_to_end_method_name"`
	Interworking                  uint8  `json:"interworking"`
	InterworkingName              string `json:"interworking_name"`
	EndToEndInformation           uint8  `json:"end_to_end_information"`
	EndToEndInformationName       string `json:"end_to_end_information_name"`
	ISUP                          uint8  `json:"isup"`
	ISUPName                      string `json:"isup_name"`
	ISUPPreference                uint8  `json:"isup_preference"`
	ISUPPreferenceName            string `json:"isup_preference_name"`
	ISDNAccess                    uint8  `json:"isdn_access"`
	ISDNAccessName                string `json:"isdn_access_name"`
	SCCPMethod                    uint8  `json:"sccp_method"`
	SCCPMethodName                string `json:"sccp_method_name"`
	PortedNumber                  uint8  `json:"ported_number"`
	PortedNumberName              string `json:"ported_number_name"`
	QueryOnRelease                uint8  `json:"query_on_release"`
	QueryOnReleaseName            string `json:"query_on_release_name"`
}

type CallingParty struct {
	Num  uint8  `json:"num"`
	Name string `json:"name"`
}

type TransmissionMedium struct {
	Num  uint8  `json:"num"`
	Name string `json:"name"`
}

type NumberInfo struct {
	INN          uint8  `json:"inn,omitempty"`
	INNName      string `json:"inn_name,omitempty"`
	TON          uint8  `json:"ton,omitempty"`
	TONName      string `json:"ton_name,omitempty"`
	NPI          uint8  `json:"npi,omitempty"`
	NPIName      string `json:"npi_name,omitempty"`
	NI           uint8  `json:"ni,omitempty"`
	NIName       string `json:"ni_name,omitempty"`
	Restrict     uint8  `json:"restrict,omitempty"`
	RestrictName string `json:"restrict_name,omitempty"`
	Screened     uint8  `json:"screened,omitempty"`
	ScreenedName string `json:"screened_name,omitempty"`
	Number       string `json:"num,omitempty"`
}

type UserServiceInformation struct {
	CodingStandard                string `json:"coding_standard"`
	InformationTransferCapability string `json:"information_transfer_capability"`
	TransferMode                  string `json:"transfer_mode"`
	InformationTransferRate       string `json:"information_transfer_rate"`
	UserInfoLayer1Protocol        string `json:"user_info_layer1_protocol"`
	RawBytes                      []byte `json:"-"`
}

type TransmissionMediumRequirement struct {
	Value  uint8  `json:"value"`
	Medium string `json:"medium"`
}

type AddressField struct {
	OddEvenIndicator         string `json:"odd_even_indicator"`
	NatureOfAddressIndicator string `json:"nature_of_address_indicator"`
	InternalNetworkNumber    string `json:"internal_network_number"`
	NumberingPlanIndicator   string `json:"numbering_plan_indicator"`
	PresentationRestricted   string `json:"presentation_restricted"`
	ScreeningIndicator       string `json:"screening_indicator"`
	AddressDigits            string `json:"address_digits"`
	RawBytes                 []byte `json:"-"`
}

type OriginatingLineInformation struct {
	Value uint8 `json:"value"`
}

type GenericName struct {
	PresentationIndicator string `json:"presentation_indicator"`
	AvailabilityIndicator string `json:"availability_indicator"`
	TypeIndicator         string `json:"type_indicator"`
	Name                  string `json:"name"`
}

type HopCounter struct {
	Value uint8 `json:"value"`
}

type Jurisdiction struct {
	Digits string `json:"digits"`
}

// ISUP Message
type ISUPMessage struct {
	MessageType uint8          `json:"message_type"`
	MessageName string         `json:"message_name,omitempty"`
	CIC         uint16         `json:"cic"`
	Data        []byte         `json:"data,omitempty"` // ISUP message body
	IAM         *IAMParameters `json:"iam,omitempty"`  // IAM-specific parameters
}

// Parse ISUP ITU message
func ParseISUP_ITU(data []byte) (*ISUPMessage, error) {

	Len := uint32(len(data))

	if Len < 3 {
		return nil, fmt.Errorf("ISUP message ITU too short (%d bytes)", Len)
	}

	var cic uint16
	// For ITU-T ISUP (12-bit CIC)
	cicLow := data[0]         // CIC Low-Order Octet
	cicHigh := data[1] & 0x0F // CIC High-Order 4 bits (lower 4 bits of byte)
	cic = (uint16(cicHigh) << 8) | uint16(cicLow)

	fmt.Println("ISUP ITU CIC:", cic)

	// Create ISUP message
	ISUPmsg := &ISUPMessage{
		CIC:         cic,
		MessageType: data[2],
		MessageName: GetISUPMessageTypeName(data[2]),
	}

	fmt.Println("ISUP ITU Message Type:", ISUPmsg.MessageType, "(", ISUPmsg.MessageName, ")")

	ISUPmsg.Data = data[3:]

	Len += 3 // CIC (2 bytes) + Message Type (1 byte)

	// Parse IAM-specific parameters if message type is IAM
	if ISUPmsg.MessageType == ISUPMessageTypeIAM {
		iamParams, err := ParseIAMParameters(ISUPmsg.Data, 0) // Assuming format 0 for ITU
		if err == nil {
			ISUPmsg.IAM = iamParams
		}
	}

	return ISUPmsg, nil
}

// Parse ISUP ANSI message
func ParseISUP_ANSI(data []byte) (*ISUPMessage, error) {

	Len := uint32(len(data))

	if Len < 3 {
		return nil, fmt.Errorf("ISUP message ANSI too short (%d bytes)", Len)
	}

	var cic uint16
	// For ANSI ISUP (14-bit CIC)
	cicLow := data[0]         // CIC Low-Order Octet
	cicHigh := data[1] & 0x3F // CIC High-Order 6 bits (lower 6 bits of byte)
	cic = (uint16(cicHigh) << 8) | uint16(cicLow)

	fmt.Println("ISUP ANSI CIC:", cic)

	// Create ISUP message
	ISUPmsg := &ISUPMessage{
		CIC:         cic,
		MessageType: data[2],
		MessageName: GetISUPMessageTypeName(data[2]),
	}

	fmt.Println("ISUP ANSI Message Type:", ISUPmsg.MessageType, "(", ISUPmsg.MessageName, ")")

	ISUPmsg.Data = data[3:]

	Len += 3 // CIC (2 bytes) + Message Type (1 byte)

	// Parse IAM-specific parameters if message type is IAM
	if ISUPmsg.MessageType == ISUPMessageTypeIAM {
		iamParams, err := ParseIAMParameters(ISUPmsg.Data, 1) // Assuming format 1 for ANSI
		if err == nil {
			ISUPmsg.IAM = iamParams
		}
	}

	return ISUPmsg, nil
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
	ISUPMessageTypeDRS:  "DRS (Delayed Release)", 
	ISUPMessageTypePAM:  "PAM (Pass Along)",      
	ISUPMessageTypeGRA:  "GRA (Circuit Group Reset Acknowledgment)",
	ISUPMessageTypeCQM:  "CQM (Circuit Group Query)", 
	ISUPMessageTypeCQR:  "CQR (Circuit Group Query Request)",
	ISUPMessageTypeCPG:  "CPG (Call Progress)",
	ISUPMessageTypeUSR:  "USR (User-to-User Information)",
	ISUPMessageTypeUCIC: "UCIC (Unequipped Circuit Identification Code)",
	ISUPMessageTypeCFN:  "CFN (Confusion)",
	ISUPMessageTypeOLM:  "OLM (Overload)",
	ISUPMessageTypeCRG:  "CRG (Charge information)", 
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
