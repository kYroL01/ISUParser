// In isup/constants.go
package isup

// Parameter Type Constants
const (
	ParamNatureOfConnectionIndicators = 6
	ParamForwardCallIndicators        = 7
	ParamCallingPartysCategory        = 9
	ParamCalledPartyNumber            = 4
	ParamCallingPartyNumber           = 10
	ParamUserServiceInformation       = 29
	ParamChargeNumber                 = 235
	ParamOriginatingLineInformation   = 234
	ParamGenericName                  = 199
	ParamHopCounter                   = 61
	ParamGenericNumber                = 192
	ParamJurisdiction                 = 196
)

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

// ... Add all the other mappings from your C code here ...
