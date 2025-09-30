// In isup/iam_parser.go
package isup

import (
	"fmt"
)

// ParseIAMParameters parses IAM message parameters
func ParseIAMParameters(data []byte, format int) (*IAMParameters, error) {
	if len(data) < 3 {
		return nil, fmt.Errorf("IAM message too short")
	}

	iam := &IAMParameters{}
	offset := 0

	// Parse parameters sequentially
	for offset < len(data) {
		paramType := data[offset]
		offset++

		if paramType == 0 { // End of optional parameters
			break
		}

		if offset >= len(data) {
			break // No length byte
		}

		paramLength := int(data[offset])
		offset++

		if offset+paramLength > len(data) {
			break // Incomplete parameter data
		}

		paramData := data[offset : offset+paramLength]
		offset += paramLength

		// Parse specific parameters
		switch paramType {
		case ParamNatureOfConnectionIndicators:
			if len(paramData) >= 1 {
				iam.NatureOfConnectionIndicators = parseNatureOfConnectionIndicators(paramData[0])
			}
		case ParamForwardCallIndicators:
			if len(paramData) >= 2 {
				iam.ForwardCallIndicators = parseForwardCallIndicators(paramData)
			}
		case ParamCallingPartysCategory:
			if len(paramData) >= 1 {
				iam.CallingPartysCategory = parseCallingPartysCategory(paramData[0])
			}
		case ParamCalledPartyNumber:
			iam.CalledPartyNumber = parseAddressField(paramData, format)
		case ParamCallingPartyNumber:
			iam.CallingPartyNumber = parseAddressField(paramData, format)
		case ParamUserServiceInformation:
			iam.UserServiceInformation = parseUserServiceInformation(paramData)
		case ParamChargeNumber:
			iam.ChargeNumber = parseAddressField(paramData, format)
		case ParamOriginatingLineInformation:
			if len(paramData) >= 1 {
				iam.OriginatingLineInformation = &OriginatingLineInformation{Value: paramData[0]}
			}
		case ParamGenericName:
			iam.GenericName = parseGenericName(paramData)
		case ParamHopCounter:
			if len(paramData) >= 1 {
				iam.HopCounter = &HopCounter{Value: paramData[0]}
			}
		case ParamGenericNumber:
			iam.GenericNumber = parseAddressField(paramData, format)
		case ParamJurisdiction:
			iam.Jurisdiction = parseJurisdiction(paramData)
		}
		// Add more parameter cases as needed
	}

	return iam, nil
}

// Individual parameter parsers
func parseNatureOfConnectionIndicators(value uint8) *NatureOfConnectionIndicators {
	return &NatureOfConnectionIndicators{
		SatelliteIndicator:         satelliteIndicators[value&0x03],
		ContinuityCheckIndicator:   continuityCheckIndicators[(value>>2)&0x03],
		EchoControlDeviceIndicator: echoControlIndicators[(value>>4)&0x01],
		RawValue:                   value,
	}
}

func parseForwardCallIndicators(data []byte) *ForwardCallIndicators {
	if len(data) < 2 {
		return nil
	}

	byte1 := data[0]
	byte2 := data[1]
	value := uint16(byte1)<<8 | uint16(byte2)

	return &ForwardCallIndicators{
		NationalInternationalCallIndicator: nationalInternationalIndicators[byte1&0x01],
		EndToEndMethodIndicator:            endToEndMethodIndicators[(byte1>>1)&0x03],
		InterworkingIndicator:              boolToString((byte1>>3)&0x01, "No interworking encountered", "Interworking encountered"),
		EndToEndInformationIndicator:       boolToString((byte1>>4)&0x01, "No end-to-end information available", "End-to-end information available"),
		ISDNUserPartIndicator:              boolToString((byte1>>5)&0x01, "ISDN user part not used all the way", "ISDN user part used all the way"),
		ISDNUserPartPreferenceIndicator:    isdnPreferenceIndicators[(byte1>>6)&0x03],
		ISDNAccessIndicator:                boolToString(byte2&0x01, "Originating access non-ISDN", "Originating access ISDN"),
		SCCPMethodIndicator:                sccpMethodIndicators[(byte2>>1)&0x03],
		PortedNumberTranslationIndicator:   boolToString((byte2>>3)&0x01, "Number not translated", "Number translated"),
		QueryOnReleaseAttemptIndicator:     boolToString((byte2>>4)&0x01, "No QoR routing attempt in progress", "QoR routing attempt in progress"),
		RawValue:                           value,
	}
}

func parseCallingPartysCategory(value uint8) *CallingPartysCategory {
	return &CallingPartysCategory{
		Value:    value,
		Category: callingCategoryValues[value],
	}
}

func parseAddressField(data []byte, format int) *AddressField {
	if len(data) < 1 {
		return nil
	}

	addr := &AddressField{
		RawBytes: data,
	}

	// Parse first byte
	firstByte := data[0]
	addr.OddEvenIndicator = boolToString((firstByte>>7)&0x01, "Even number of address signals", "Odd number of address signals")
	addr.NatureOfAddressIndicator = natureOfAddressValues[firstByte&0x7F]

	if len(data) > 1 {
		secondByte := data[1]
		addr.InternalNetworkNumber = innValues[(secondByte>>7)&0x01]
		addr.NumberingPlanIndicator = numberingPlanValues[(secondByte>>4)&0x07]
		addr.PresentationRestricted = presentationValues[(secondByte>>2)&0x03]
		addr.ScreeningIndicator = screeningValues[secondByte&0x03]
	}

	// Extract address digits (BCD encoded)
	if len(data) > 2 {
		addr.AddressDigits = decodeBCDAddress(data[2:], (data[0]>>7)&0x01 == 1)
	}

	return addr
}

// Helper function to decode BCD address digits
func decodeBCDAddress(data []byte, odd bool) string {
	var digits string
	for i := 0; i < len(data); i++ {
		byteVal := data[i]
		// Low nibble
		lowDigit := byteVal & 0x0F
		if lowDigit <= 9 {
			digits += string('0' + rune(lowDigit))
		}
		// High nibble
		highDigit := (byteVal >> 4) & 0x0F
		if highDigit <= 9 {
			digits += string('0' + rune(highDigit))
		}
	}

	// If odd indicator is set, remove the last digit (filler)
	if odd && len(digits) > 0 {
		digits = digits[:len(digits)-1]
	}

	return digits
}

// Add similar parsers for other parameter types...
