package isup

import (
	"fmt"
)

// ParseIAM decodes an IAM packet according to ITU-T Q.763
func ParseIAM(data []byte) (*IAMParameters, error) {
	Len := len(data)
	if Len < 7 {
		return nil, fmt.Errorf("IAM too short")
	}
	offset := 0
	iam := &IAMParameters{}

	/**
	** Fixed mandatory parameters
	**/
	if offset+1 > Len {
		return nil, fmt.Errorf("missing Nature of Connection Indicators")
	}
	// Nature of Connection Indicators
	iam.NatureOfConnection = parseNatureOfConnection(data[offset])
	offset++

	if offset+2 > Len {
		return nil, fmt.Errorf("missing Forward Call Indicators")
	}
	// Forward Call
	iam.ForwardCall = parseForwardCall(data[offset : offset+2])
	offset += 2

	if offset+1 > Len {
		return nil, fmt.Errorf("missing Calling Party Category")
	}
	// Calling Party Category
	iam.CallingPartyCategory = parseCallingPartyCat(data[offset])
	offset++

	// Pointer table start
	if Len < offset+3 {
		return nil, fmt.Errorf("IAM missing pointer table")
	}
	ptrStart := offset
	ptrUSI := int(data[ptrStart+0])      // pointer index 0
	ptrCalled := int(data[ptrStart+1])   // pointer index 1
	ptrOptional := int(data[ptrStart+2]) // pointer index 2

	/**
	** Variable mandatory parameters
	**/

	// User Service Information
	if ptrUSI != 0 {
		pPos := ptrStart + 0
		base := pPos + ptrUSI
		if base+1 <= Len {
			l := int(data[base])
			if base+1+l <= Len {
				iam.UserServiceInformation = parseUserServiceInformation(data[base+1 : base+1+l])
			}
		}
	}

	// Called Party Number
	if ptrCalled != 0 {
		pPos := ptrStart + 1
		base := pPos + ptrCalled
		if base+1 <= Len {
			l := int(data[base])
			if base+1+l <= Len {
				iam.CalledPartyNumber = parseNumberInfoCalled(data[base+1 : base+1+l])
			}
		}
	}

	/**
	** Optional parameters
	**/
	if ptrOptional != 0 {
		pPos := ptrStart + 2
		optStart := pPos + ptrOptional
		offset = optStart
		for offset < Len {
			if offset >= Len {
				break
			}
			t := data[offset]
			offset++
			if t == ISUPEndOfOptionalParameters {
				break
			}
			if offset >= Len {
				break
			}
			l := int(data[offset])
			offset++
			if offset+l > Len {
				break
			}
			val := data[offset : offset+l]
			offset += l

			switch t {
			case ISUPCallingPartyNumber:
				iam.CallingPartyNumber = parseNumberInfoCalling(val)
			case ISUPChargeNumber:
				iam.ChargeNumber = parseNumberInfoCharge(val)
			case ISUPHopCounter:
				if len(val) >= 1 {
					hop := val[0]
					iam.HopCounter = &hop
				}
			case ISUPGenericNumber:
				iam.GenericNumber = parseNumberInfoGeneric(val)
			case ISUPJurisdiction:
				j := parseJurisdictionDigits(val)
				iam.Jurisdiction = &j
			}
		}
	}

	return iam, nil
}

/**
** Helper functions to parse individual parameters
**/

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

	Len := len(data)

	if Len < 2 {
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
		ISUPIndicator:                 (byte1 >> 5) & 0x01,
		ISUPIndicatorName:             isdnUserPartIndicators[(byte1>>5)&0x01],
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

func parseCallingPartyCat(value uint8) *CallingPartyCat {
	return &CallingPartyCat{
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

func parseUserServiceInformation(data []byte) *UserServiceInformation {

	Len := len(data)

	if Len < 3 {
		return nil
	}

	info := &UserServiceInformation{}

	cs := (data[0] & 0x60) >> 5
	info.CodingStandard = CodingStandardValues[cs]
	itc := data[0] & 0x1F
	info.InfoTransferCapability = TransferCapabilityValues[itc]
	tm := (data[1] & 0x60) >> 5
	info.TransferMode = TransferModeValues[tm]
	tr := data[1] & 0x1F
	info.InfoTransferRate = TransferRateValues[tr]

	var octet uint8
	if tr == 0x18 { // If rate is 64 kbps
		if Len >= 4 {
			ulp := data[2] & 0x7F
			info.UserInfoLayer1Protocol = UserInfoLayer1Values[ulp]
			octet = data[3]
		}
	} else {
		octet = data[2]
	}

	layer1ID := (octet & 0x60) >> 5
	info.Layer1ID = layer1ID
	layer1Proto := octet & 0x1F
	info.UserInfoLayer1Protocol = UserInfoLayer1Values[layer1Proto]

	return info
}

func parseNumberInfoCalling(data []byte) *NumberInfoCalling {

	Len := len(data)

	if Len < 1 {
		return nil
	}

	info := &NumberInfoCalling{}

	info.TON = data[0] & 0x7F
	info.TONName = natureOfAddressValues[info.TON]

	if Len > 1 {
		info.NI = (data[1] >> 7) & 0x01
		info.NIName = niValues[info.NI]
		info.NPI = (data[1] >> 4) & 0x07
		info.NPIName = npiValues[info.NPI]
		info.Restrict = (data[1] >> 2) & 0x03
		info.RestrictName = restrictValues[info.Restrict]
		info.Screened = data[1] & 0x03
		info.ScreenedName = screenedValues[info.Screened]
	}

	// Extract address digits
	if Len > 2 {
		info.Number = decodeBCDAddress(data[2:], (data[0]>>7)&0x01 == 1)
	}

	return info
}

func parseNumberInfoCalled(data []byte) *NumberInfoCalled {

	Len := len(data)

	if Len < 1 {
		return nil
	}

	info := &NumberInfoCalled{}

	info.TON = data[0] & 0x7F
	info.TONName = natureOfAddressValues[info.TON]

	if Len > 1 {
		info.INN = (data[1] >> 7) & 0x01
		info.INNName = innValues[info.INN]
		info.NPI = (data[1] >> 4) & 0x07
		info.NPIName = npiValues[info.NPI]
	}

	// Extract address digits
	if Len > 2 {
		info.Number = decodeBCDAddress(data[2:], (data[0]>>7)&0x01 == 1)
	}

	return info
}

func parseNumberInfoCharge(data []byte) *NumberInfoCharge {

	Len := len(data)

	if Len < 2 {
		return nil
	}

	info := &NumberInfoCharge{}

	info.TON = data[0] & 0x7F
	info.TONName = natureOfAddressValues[info.TON]

	if Len > 1 {
		info.NPI = (data[1] >> 4) & 0x07
		info.NPIName = npiValues[info.NPI]
	}

	// Extract address digits
	if Len > 2 {
		info.Number = decodeBCDAddress(data[2:], (data[0]>>7)&0x01 == 1)
	}

	return info
}

func parseNumberInfoGeneric(data []byte) *NumberInfoGeneric {

	Len := len(data)

	if Len < 2 {
		return nil
	}

	info := &NumberInfoGeneric{}

	info.NQI = data[0]
	info.NQIName = nqiValues[info.NQI]

	if Len > 1 {

		info.TON = data[1] & 0x7F
		info.TONName = natureOfAddressValues[info.TON]
		info.NI = (data[2] >> 7) & 0x01
		info.NIName = niValues[info.NI]
		info.NPI = (data[2] >> 4) & 0x07
		info.NPIName = npiValues[info.NPI]
		info.Restrict = (data[2] >> 2) & 0x03
		info.RestrictName = restrictValues[info.Restrict]
		info.Screened = data[2] & 0x03
		info.ScreenedName = screenedValues[info.Screened]
	}

	// Address digits start at index 3
	if Len > 3 {
		odd := (data[1] & 0x80) != 0 // O/E bit is bit 8 of octet 2
		info.Number = decodeBCDAddress(data[3:], odd)
	}

	return info
}

func parseJurisdictionDigits(data []byte) string {
	return decodeBCDAddress(data, false)
}

// Helper function to decode BCD address digits
func decodeBCDAddress(data []byte, odd bool) string {
	var digits string
	for i := range data {
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
