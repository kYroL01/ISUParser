package isup

// ISUP Parameter Type Constants
const (
	ISUPEndOfOptionalParameters             = 0   // End of optional parameters spec: 3.20
	ISUPCallReference                       = 1   // Call reference spec: 3.8
	ISUPTransmissionMediumRequirement       = 2   // Transmission medium requirement spec: 3.54
	ISUPAccessTransport                     = 3   // Access transport spec: 3.3
	ISUPCalledPartyNumber                   = 4   // Called party number spec: 3.9
	ISUPSubsequentNumber                    = 5   // Subsequent number spec: 3.51
	ISUPNatureOfConnectionIndicators        = 6   // Nature of connection indicators spec: 3.35
	ISUPForwardCallIndicators               = 7   // Forward call indicators spec: 3.23
	ISUPOptionalForwardCallIndicators       = 8   // Optional forward call indicators spec: 3.38
	ISUPCallingPartysCategory               = 9   // Calling party's category spec: 3.11
	ISUPCallingPartyNumber                  = 10  // Calling party number spec: 3.10
	ISUPRedirectingNumber                   = 11  // Redirecting number spec: 3.44
	ISUPRedirectionNumber                   = 12  // Redirection number spec: 3.46
	ISUPConnectionRequest                   = 13  // Connection request spec: 3.17
	ISUPInformationRequestIndicators        = 14  // Information request indicators spec: 3.29
	ISUPInformationIndicators               = 15  // Information indicators spec: 3.28
	ISUPContinuityIndicators                = 16  // Continuity indicators spec: 3.18
	ISUPBackwardCallIndicators              = 17  // Backward call indicators spec: 3.5
	ISUPCauseIndicators                     = 18  // Cause indicators spec: 3.12
	ISUPRedirectionInformation              = 19  // Redirection information spec: 3.45
	ISUPCircuitGroupSupervisionMessageType  = 21  // Circuit group supervision message type spec: 3.13
	ISUPRange                               = 22  // Range spec: 3.43b
	ISUPRangeAndStatus                      = 22  // Range and status spec: 3.43
	ISUPFacilityIndicator                   = 24  // Facility indicator spec: 3.22
	ISUPClosedUserGroupInterlockCode        = 26  // Closed user group interlock code spec: 3.15
	ISUPUserServiceInformation              = 29  // User service information spec: 3.57
	ISUPSignallingPointCode                 = 30  // Signalling point code spec: 3.50
	ISUPUserToUserInformation               = 32  // User-to-user information spec: 3.61
	ISUPConnectedNumber                     = 33  // Connected number spec: 3.16
	ISUPSuspendResumeIndicators             = 34  // Suspend/resume indicators spec: 3.52
	ISUPTransitNetworkSelection             = 35  // Transit network selection spec: 3.53
	ISUPEventInformation                    = 36  // Event information spec: 3.21
	ISUPCircuitAssignmentMap                = 37  // Circuit assignment map spec: 3.69
	ISUPCircuitStateIndicator               = 38  // Circuit state indicator spec: 3.14
	ISUPAutomaticCongestionLevel            = 39  // Automatic congestion level spec: 3.4
	ISUPOriginalCalledNumber                = 40  // Original called number spec: 3.39
	ISUPOptionalBackwardCallIndicators      = 41  // Optional backward call indicators spec: 3.37
	ISUPUserToUserIndicators                = 42  // User-to-user indicators spec: 3.60
	ISUPOriginationISCPointCode             = 43  // Origination ISC point code spec: 3.40
	ISUPGenericNotificationIndicator        = 44  // Generic notification indicator spec: 3.25
	ISUPCallHistoryInformation              = 45  // Call history information spec: 3.7
	ISUPAccessDeliveryInformation           = 46  // Access delivery information spec: 3.2
	ISUPNetworkSpecificFacility             = 47  // Network specific facility spec: 3.36
	ISUPUserServiceInformationPrime         = 48  // User service information prime spec: 3.58
	ISUPPropagationDelayCounter             = 49  // Propagation delay counter spec: 3.42
	ISUPRemoteOperations                    = 50  // Remote operations spec: 3.48
	ISUPServiceActivation                   = 51  // Service activation spec: 3.49
	ISUPUserTeleserviceInformation          = 52  // User teleservice information spec: 3.59
	ISUPTransmissionMediumUsed              = 53  // Transmission medium used spec: 3.56
	ISUPCallDiversionInformation            = 54  // Call diversion information spec: 3.6
	ISUPEchoControlInformation              = 55  // Echo control information spec: 3.19
	ISUPMessageCompatibilityInformation     = 56  // Message compatibility information spec: 3.33
	ISUPParameterCompatibilityInformation   = 57  // Parameter compatibility information spec: 3.41
	ISUPMLPPPrecedence                      = 58  // MLPP precedence spec: 3.34
	ISUPMCIDRequestIndicators               = 59  // MCID request indicators spec: 3.31
	ISUPMCIDResponseIndicators              = 60  // MCID response indicators spec: 3.32
	ISUPHopCounter                          = 61  // Hop counter spec: 3.80
	ISUPTransmissionMediumRequirementPrime  = 62  // Transmission medium requirement prime spec: 3.55
	ISUPLocationNumber                      = 63  // Location number spec: 3.30
	ISUPRedirectionNumberRestriction        = 64  // Redirection number restriction spec: 3.47
	ISUPCallTransferReference               = 67  // Call transfer reference spec: 3.65
	ISUPLoopPreventionIndicators            = 68  // Loop prevention indicators spec: 3.67
	ISUPCallTransferNumber                  = 69  // Call transfer number spec: 3.64
	ISUPCCSS                                = 75  // CCSS spec: 3.63
	ISUPForwardGVNS                         = 76  // Forward GVNS spec: 3.66
	ISUPBackwardGVNS                        = 77  // Backward GVNS spec: 3.62
	ISUPRedirectCapability                  = 78  // Redirect capability spec: 3.96
	ISUPNetworkManagementControls           = 91  // Network management controls spec: 3.68
	ISUPCorrelationId                       = 101 // Correlation id spec: 3.70
	ISUPSCFId                               = 102 // SCF id spec: 3.71
	ISUPCallDiversionTreatmentIndicators    = 110 // Call diversion treatment indicators spec: 3.72
	ISUPCalledINNumber                      = 111 // Called IN number spec: 3.73
	ISUPCallOfferingTreatmentIndicators     = 112 // Call offering treatment indicators spec: 3.74
	ISUPChargedPartyIdentification          = 113 // Charged party identification spec: 3.75
	ISUPConferenceTreatmentIndicators       = 114 // Conference treatment indicators spec: 3.76
	ISUPDisplayInformation                  = 115 // Display information spec: 3.77
	ISUPUIDActionIndicators                 = 116 // UID action indicators spec: 3.78
	ISUPUIDCapabilityIndicators             = 117 // UID capability indicators spec: 3.79
	ISUPRedirectCounter                     = 119 // Redirect counter spec: 3.97
	ISUPApplicationTransportParameter       = 120 // Application transport parameter spec: 3.82
	ISUPCollectCallRequest                  = 121 // Collect call request spec: 3.81
	ISUPCCNRPossibleIndicator               = 122 // CCNR possible indicator spec: 3.83
	ISUPPivotCapability                     = 123 // Pivot capability spec: 3.84
	ISUPPivotRoutingIndicators              = 124 // Pivot routing indicators spec: 3.85
	ISUPCalledDirectoryNumber               = 125 // Called directory number spec: 3.86
	ISUPOriginalCalledINNumber              = 127 // Original called IN number spec: 3.87
	ISUPCallingGeodeticLocation             = 129 // Calling geodetic location spec: 3.88
	ISUPGenericReference                    = 130 // Generic reference spec: 3.27
	ISUPHTRInformation                      = 131 // HTR information spec: 3.89
	ISUPNetworkRoutingNumber                = 132 // Network routing number spec: 3.90
	ISUPQoRCapability                       = 133 // QoR capability spec: 3.91
	ISUPPivotStatus                         = 134 // Pivot status spec: 3.92
	ISUPPivotCounter                        = 135 // Pivot counter spec: 3.93
	ISUPPivotRoutingForwardInformation      = 136 // Pivot routing forward information spec: 3.94
	ISUPPivotRoutingBackwardInformation     = 137 // Pivot routing backward information spec: 3.95
	ISUPRedirectStatus                      = 138 // Redirect status spec: 3.98
	ISUPRedirectForwardInformation          = 139 // Redirect forward information spec: 3.99
	ISUPRedirectBackwardInformation         = 140 // Redirect backward information spec: 3.100
	ISUPNumberPortabilityForwardInformation = 141 // Number portability forward information spec: 3.101
	ISUPGenericNumber                       = 192 // Generic number spec: 3.26
	ISUPGenericDigits                       = 193 // Generic digits spec: 3.24
	ISUPJurisdiction                        = 196 // Jurisdiction
)

// Parameter name mapping for debugging/logging
var ISUPPameterNames = map[uint8]string{
	ISUPEndOfOptionalParameters:             "End of optional parameters",
	ISUPCallReference:                       "Call reference",
	ISUPTransmissionMediumRequirement:       "Transmission medium requirement",
	ISUPAccessTransport:                     "Access transport",
	ISUPCalledPartyNumber:                   "Called party number",
	ISUPSubsequentNumber:                    "Subsequent number",
	ISUPNatureOfConnectionIndicators:        "Nature of connection indicators",
	ISUPForwardCallIndicators:               "Forward call indicators",
	ISUPOptionalForwardCallIndicators:       "Optional forward call indicators",
	ISUPCallingPartysCategory:               "Calling party's category",
	ISUPCallingPartyNumber:                  "Calling party number",
	ISUPRedirectingNumber:                   "Redirecting number",
	ISUPRedirectionNumber:                   "Redirection number",
	ISUPConnectionRequest:                   "Connection request",
	ISUPInformationRequestIndicators:        "Information request indicators",
	ISUPInformationIndicators:               "Information indicators",
	ISUPContinuityIndicators:                "Continuity indicators",
	ISUPBackwardCallIndicators:              "Backward call indicators",
	ISUPCauseIndicators:                     "Cause indicators",
	ISUPRedirectionInformation:              "Redirection information",
	ISUPCircuitGroupSupervisionMessageType:  "Circuit group supervision message type",
	ISUPRange:                               "Range",
	ISUPFacilityIndicator:                   "Facility indicator",
	ISUPClosedUserGroupInterlockCode:        "Closed user group interlock code",
	ISUPUserServiceInformation:              "User service information",
	ISUPSignallingPointCode:                 "Signalling point code",
	ISUPUserToUserInformation:               "User-to-user information",
	ISUPConnectedNumber:                     "Connected number",
	ISUPSuspendResumeIndicators:             "Suspend/resume indicators",
	ISUPTransitNetworkSelection:             "Transit network selection",
	ISUPEventInformation:                    "Event information",
	ISUPCircuitAssignmentMap:                "Circuit assignment map",
	ISUPCircuitStateIndicator:               "Circuit state indicator",
	ISUPAutomaticCongestionLevel:            "Automatic congestion level",
	ISUPOriginalCalledNumber:                "Original called number",
	ISUPOptionalBackwardCallIndicators:      "Optional backward call indicators",
	ISUPUserToUserIndicators:                "User-to-user indicators",
	ISUPOriginationISCPointCode:             "Origination ISC point code",
	ISUPGenericNotificationIndicator:        "Generic notification indicator",
	ISUPCallHistoryInformation:              "Call history information",
	ISUPAccessDeliveryInformation:           "Access delivery information",
	ISUPNetworkSpecificFacility:             "Network specific facility",
	ISUPUserServiceInformationPrime:         "User service information prime",
	ISUPPropagationDelayCounter:             "Propagation delay counter",
	ISUPRemoteOperations:                    "Remote operations",
	ISUPServiceActivation:                   "Service activation",
	ISUPUserTeleserviceInformation:          "User teleservice information",
	ISUPTransmissionMediumUsed:              "Transmission medium used",
	ISUPCallDiversionInformation:            "Call diversion information",
	ISUPEchoControlInformation:              "Echo control information",
	ISUPMessageCompatibilityInformation:     "Message compatibility information",
	ISUPParameterCompatibilityInformation:   "Parameter compatibility information",
	ISUPMLPPPrecedence:                      "MLPP precedence",
	ISUPMCIDRequestIndicators:               "MCID request indicators",
	ISUPMCIDResponseIndicators:              "MCID response indicators",
	ISUPHopCounter:                          "Hop counter",
	ISUPTransmissionMediumRequirementPrime:  "Transmission medium requirement prime",
	ISUPLocationNumber:                      "Location number",
	ISUPRedirectionNumberRestriction:        "Redirection number restriction",
	ISUPCallTransferReference:               "Call transfer reference",
	ISUPLoopPreventionIndicators:            "Loop prevention indicators",
	ISUPCallTransferNumber:                  "Call transfer number",
	ISUPCCSS:                                "CCSS",
	ISUPForwardGVNS:                         "Forward GVNS",
	ISUPBackwardGVNS:                        "Backward GVNS",
	ISUPRedirectCapability:                  "Redirect capability",
	ISUPNetworkManagementControls:           "Network management controls",
	ISUPCorrelationId:                       "Correlation id",
	ISUPSCFId:                               "SCF id",
	ISUPCallDiversionTreatmentIndicators:    "Call diversion treatment indicators",
	ISUPCalledINNumber:                      "Called IN number",
	ISUPCallOfferingTreatmentIndicators:     "Call offering treatment indicators",
	ISUPChargedPartyIdentification:          "Charged party identification",
	ISUPConferenceTreatmentIndicators:       "Conference treatment indicators",
	ISUPDisplayInformation:                  "Display information",
	ISUPUIDActionIndicators:                 "UID action indicators",
	ISUPUIDCapabilityIndicators:             "UID capability indicators",
	ISUPRedirectCounter:                     "Redirect counter",
	ISUPApplicationTransportParameter:       "Application transport parameter",
	ISUPCollectCallRequest:                  "Collect call request",
	ISUPCCNRPossibleIndicator:               "CCNR possible indicator",
	ISUPPivotCapability:                     "Pivot capability",
	ISUPPivotRoutingIndicators:              "Pivot routing indicators",
	ISUPCalledDirectoryNumber:               "Called directory number",
	ISUPOriginalCalledINNumber:              "Original called IN number",
	ISUPCallingGeodeticLocation:             "Calling geodetic location",
	ISUPGenericReference:                    "Generic reference",
	ISUPHTRInformation:                      "HTR information",
	ISUPNetworkRoutingNumber:                "Network routing number",
	ISUPQoRCapability:                       "QoR capability",
	ISUPPivotStatus:                         "Pivot status",
	ISUPPivotCounter:                        "Pivot counter",
	ISUPPivotRoutingForwardInformation:      "Pivot routing forward information",
	ISUPPivotRoutingBackwardInformation:     "Pivot routing backward information",
	ISUPRedirectStatus:                      "Redirect status",
	ISUPRedirectForwardInformation:          "Redirect forward information",
	ISUPRedirectBackwardInformation:         "Redirect backward information",
	ISUPNumberPortabilityForwardInformation: "Number portability forward information",
	ISUPGenericNumber:                       "Generic number",
	ISUPGenericDigits:                       "Generic digits",
	ISUPJurisdiction:                        "Jurisdiction",
}

// Helper function to get parameter name
func GetParameterName(paramType uint8) string {
	if name, exists := ISUPPameterNames[paramType]; exists {
		return name
	}
	return "Unknown parameter"
}

// Nature of Connection Indicators
var satelliteIndicators = map[uint8]string{
	0: "No Satellite circuit in connection",
	1: "One Satellite circuit in connection",
	2: "Two Satellite circuits in connection",
	3: "Spare",
}

var continuityCheckIndicators = map[uint8]string{
	0: "Continuity check not required",
	1: "Continuity check required on this circuit",
	2: "Continuity check performed on a previous circuit",
	3: "Spare",
}

var echoControlIndicators = map[uint8]string{
	0: "Echo control device not included",
	1: "Echo control device included",
}

// Forward Call Indicators
var nationalInternationalIndicators = map[uint8]string{
	0: "Call to be treated as national call",
	1: "Call to be treated as international call",
}

var endToEndMethodIndicators = map[uint8]string{
	0: "No End-to-end method available (only link-by-link method available)",
	1: "Pass-along method available",
	2: "SCCP method available",
	3: "Pass-along and SCCP methods available",
}

// Add these missing mappings to constants.go

// ISDN Preference Indicators
var isdnPreferenceIndicators = map[uint8]string{
	0: "ISDN user part preferred all the way",
	1: "ISDN user part not required all the way",
	2: "ISDN user part required all the way",
	3: "spare",
}

// SCCP Method Indicators
var sccpMethodIndicators = map[uint8]string{
	0: "no indication",
	1: "connectionless method available (national use)",
	2: "connection oriented method available",
	3: "connectionless and connection oriented methods available (national use)",
}

// Calling Category Values
var callingCategoryValues = map[uint8]string{
	0x00: "calling party's category unknown at this time (national use)",
	0x01: "operator, language French",
	0x02: "operator, language English",
	0x03: "operator, language German",
	0x04: "operator, language Russian",
	0x05: "operator, language Spanish",
	0x09: "reserved (see ITU-T Recommendation Q.104) (Note) (national use)",
	0x0A: "ordinary calling subscriber",
	0x0B: "calling subscriber with priority",
	0x0C: "data call (voice band data)",
	0x0D: "test call",
	0x0E: "spare",
	0x0F: "payphone",
}

// Transmission Medium Values
var transmissionMediumValues = map[uint8]string{
	0x00: "speech",
	0x01: "spare",
	0x02: "64 kbit/s unrestricted",
	0x03: "3.1 kHz audio",
	0x04: "reserved for alternate speech (service 2)/64 kbit/s unrestricted (service 1)",
	0x05: "reserved for alternate 64 kbit/s unrestricted (service 1)/speech (service 2)",
	0x06: "64 kbit/s preferred",
	0x07: "2 × 64 kbit/s unrestricted",
	0x08: "384 kbit/s unrestricted",
	0x09: "1536 kbit/s unrestricted",
	0x0A: "1920 kbit/s unrestricted",
	0x10: "3 × 64 kbit/s unrestricted",
	0x11: "4 × 64 kbit/s unrestricted",
	0x12: "5 × 64 kbit/s unrestricted",
	0x13: "spare",
	0x14: "7 × 64 kbit/s unrestricted",
	0x15: "8 × 64 kbit/s unrestricted",
	0x16: "9 × 64 kbit/s unrestricted",
	0x17: "10 × 64 kbit/s unrestricted",
	0x18: "11 × 64 kbit/s unrestricted",
	0x19: "12 × 64 kbit/s unrestricted",
	0x1A: "13 × 64 kbit/s unrestricted",
	0x1B: "14 × 64 kbit/s unrestricted",
	0x1C: "15 × 64 kbit/s unrestricted",
	0x1D: "16 × 64 kbit/s unrestricted",
	0x1E: "17 × 64 kbit/s unrestricted",
	0x1F: "18 × 64 kbit/s unrestricted",
	0x20: "19 × 64 kbit/s unrestricted",
	0x21: "20 × 64 kbit/s unrestricted",
	0x22: "21 × 64 kbit/s unrestricted",
	0x23: "22 × 64 kbit/s unrestricted",
	0x24: "23 × 64 kbit/s unrestricted",
	0x25: "spare",
	0x26: "25 × 64 kbit/s unrestricted",
	0x27: "26 × 64 kbit/s unrestricted",
	0x28: "27 × 64 kbit/s unrestricted",
	0x29: "28 × 64 kbit/s unrestricted",
	0x2A: "29 × 64 kbit/s unrestricted",
}

// Nature of Address Values
var natureOfAddressValues = map[uint8]string{
	0x00: "spare",
	0x01: "subscriber number (national use)",
	0x02: "unknown (national use)",
	0x03: "national (significant) number",
	0x04: "international number",
	0x05: "network-specific number (national use)",
	0x06: "network routing number in national (significant) number format (national use)",
	0x07: "network routing number in network-specific number format (national use)",
	0x08: "network routing number concatenated with Called Directory Number (national use)",
}

// Numbering Plan Indicator Values
var npiValues = map[uint8]string{
	0x00: "spare",
	0x01: "ISDN (Telephony) numbering plan (ITU-T Recommendation E.164)",
	0x02: "spare",
	0x03: "Data numbering plan (ITU-T Recommendation X.121) (national use)",
	0x04: "Telex numbering plan (ITU-T Recommendation F.69) (national use)",
	0x05: "reserved for national use",
	0x06: "reserved for national use",
}

// Internal Network Number Values
var innValues = map[uint8]string{
	0x00: "routing to internal network number allowed",
	0x01: "routing to internal network number not allowed",
}

// Number Incomplete Values
var niValues = map[uint8]string{
	0x00: "complete",
	0x01: "incomplete",
}

// Presentation Restricted Values
var restrictValues = map[uint8]string{
	0x00: "presentation allowed",
	0x01: "presentation restricted",
	0x02: "address not available (Note 1) (national use)",
	0x03: "reserved for restriction by the network",
}

// Screening Indicator Values
var screenedValues = map[uint8]string{
	0x00: "reserved (Note 2)",
	0x01: "user provided, verified and passed",
	0x02: "reserved (Note 2)",
	0x03: "network provided",
}

// Interworking Indicators
var interworkingIndicators = map[uint8]string{
	0x00: "no interworking encountered (No. 7 signalling all the way)",
	0x01: "interworking encountered",
}

// End-to-end Information Indicators
var endToEndInformationIndicators = map[uint8]string{
	0x00: "no end-to-end information available",
	0x01: "end-to-end information available",
}

// ISDN User Part Indicators
var isdnUserPartIndicators = map[uint8]string{
	0x00: "ISDN user part not used all the way",
	0x01: "ISDN user part used all the way",
}

// ISDN Access Indicators
var isdnAccessIndicators = map[uint8]string{
	0x00: "originating access non-ISDN",
	0x01: "originating access ISDN",
}

// Ported Number Indicators
var portedNumberIndicators = map[uint8]string{
	0x00: "number not translated",
	0x01: "number translated",
}

// Query on Release Indicators
var queryOnReleaseIndicators = map[uint8]string{
	0x00: "no QoR routing",
	0x01: "QoR routing attempt",
}
