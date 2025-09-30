// In isup/iam_parser.go
package isup

import (
	"fmt"
)

// ParseIAMParameters parses IAM message parameters to match C output format
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

		if paramType == ISUPEndOfOptionalParameters {
			break
		}

		if offset >= len(data) {
			break
		}

		paramLength := int(data[offset])
		offset++

		if offset+paramLength > len(data) {
			break
		}

		paramData := data[offset : offset+paramLength]
		offset += paramLength

		// Parse specific parameters
		switch paramType {
		case ISUPNatureOfConnectionIndicators:
			if len(paramData) >= 1 {
				iam.NatureOfConnection = parseNatureOfConnection(paramData[0])
			}
		case ISUPForwardCallIndicators:
			if len(paramData) >= 2 {
				iam.ForwardCall = parseForwardCall(paramData)
			}
		case ISUPCallingPartysCategory:
			if len(paramData) >= 1 {
				iam.CallingParty = parseCallingParty(paramData[0])
			}
		case ISUPTransmissionMediumRequirement:
			if len(paramData) >= 1 {
				iam.TransmissionMedium = parseTransmissionMedium(paramData[0])
			}
		case ISUPCalledPartyNumber:
			iam.CalledNumber = parseNumberInfo(paramData, false) // false for called number
		case ISUPCallingPartyNumber:
			iam.CallingNumber = parseNumberInfo(paramData, true) // true for calling number
		case ISUPHopCounter:
			if len(paramData) >= 1 {
				hopCounter := paramData[0]
				iam.HopCounter = &hopCounter
			}
		case ISUPGenericNumber:
			iam.GenericNumber = parseNumberInfo(paramData, true)
		case ISUPJurisdiction:
			digits := parseJurisdictionDigits(paramData)
			iam.Jurisdiction = &digits
		case ISUPChargeNumber:
			iam.ChargeNumber = parseNumberInfo(paramData, true)
		}
	}

	return iam, nil
}

// Updated parser functions to match C format
func parseNatureOfConnection(value uint8) *NatureOfConnection {
	satellite := value & 0x03
	continuityCheck := (value >> 2) & 0x03
	echoDevice := (value >> 4) & 0x01

	return &NatureOfConnection{
		Satellite:           satellite,
		SatelliteName:       satelliteIndicators[satellite],
		ContinuityCheck:     continuityCheck,
		ContinuityCheckName: continuityCheckIndicators[continuityCheck],
		EchoDevice:          echoDevice,
		EchoDeviceName:      echoControlIndicators[echoDevice],
	}
}

func parseForwardCall(data []byte) *ForwardCall {
	if len(data) < 2 {
		return nil
	}

	byte1 := data[0]
	byte2 := data[1]

	return &ForwardCall{
		NationalInternationalCall:     byte1 & 0x01,
		NationalInternationalCallName: nationalInternationalIndicators[byte1&0x01],
		EndToEndMethod:                (byte1 >> 1) & 0x03,
		EndToEndMethodName:            endToEndMethodIndicators[(byte1>>1)&0x03],
		Interworking:                  (byte1 >> 3) & 0x01,
		InterworkingName:              interworkingIndicators[(byte1>>3)&0x01],
		EndToEndInformation:           (byte1 >> 4) & 0x01,
		EndToEndInformationName:       endToEndInformationIndicators[(byte1>>4)&0x01],
		ISUP:                          (byte1 >> 5) & 0x01,
		ISUPName:                      isdnUserPartIndicators[(byte1>>5)&0x01],
		ISUPPreference:                (byte1 >> 6) & 0x03,
		ISUPPreferenceName:            isdnPreferenceIndicators[(byte1>>6)&0x03],
		ISDNAccess:                    byte2 & 0x01,
		ISDNAccessName:                isdnAccessIndicators[byte2&0x01],
		SCCPMethod:                    (byte2 >> 1) & 0x03,
		SCCPMethodName:                sccpMethodIndicators[(byte2>>1)&0x03],
		PortedNumber:                  (byte2 >> 3) & 0x01,
		PortedNumberName:              portedNumberIndicators[(byte2>>3)&0x01],
		QueryOnRelease:                (byte2 >> 4) & 0x01,
		QueryOnReleaseName:            queryOnReleaseIndicators[(byte2>>4)&0x01],
	}
}

func parseCallingParty(value uint8) *CallingParty {
	return &CallingParty{
		Num:  value,
		Name: callingCategoryValues[value],
	}
}

func parseTransmissionMedium(value uint8) *TransmissionMedium {
	return &TransmissionMedium{
		Num:  value,
		Name: transmissionMediumValues[value],
	}
}

func parseNumberInfo(data []byte, isCalling bool) *NumberInfo {
	if len(data) < 1 {
		return nil
	}

	info := &NumberInfo{}

	// Parse first byte
	firstByte := data[0]
	info.TON = firstByte & 0x7F
	info.TONName = natureOfAddressValues[info.TON]

	if len(data) > 1 {
		secondByte := data[1]

		if isCalling {
			// For calling number
			info.NI = (secondByte >> 7) & 0x01
			info.NIName = niValues[info.NI]
			info.NPI = (secondByte >> 4) & 0x07
			info.NPIName = npiValues[info.NPI]
			info.Restrict = (secondByte >> 2) & 0x03
			info.RestrictName = restrictValues[info.Restrict]
			info.Screened = secondByte & 0x03
			info.ScreenedName = screenedValues[info.Screened]
		} else {
			// For called number
			info.INN = (secondByte >> 7) & 0x01
			info.INNName = innValues[info.INN]
			info.NPI = (secondByte >> 4) & 0x07
			info.NPIName = npiValues[info.NPI]
		}
	}

	// Extract address digits
	if len(data) > 2 {
		info.Number = decodeBCDAddress(data[2:], (data[0]>>7)&0x01 == 1)
	}

	return info
}

func parseJurisdictionDigits(data []byte) string {
	return decodeBCDAddress(data, false)
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
