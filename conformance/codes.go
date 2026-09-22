package conformance

import (
	"encoding/json"
	"fmt"
)

// Code is a refusal code of section 14.4: the rule family that failed, never
// an implementation's error type or message.
type Code string

const (
	EnvelopeInvalid       Code = "envelope-invalid"
	PolicyInvalid         Code = "policy-invalid"
	PlatformUnsupported   Code = "platform-unsupported"
	ReportInvalid         Code = "report-invalid"
	SignatureInvalid      Code = "signature-invalid"
	ChainInvalid          Code = "chain-invalid"
	MachineNotAllowed     Code = "machine-not-allowed"
	GuestPolicy           Code = "guest-policy"
	BindingMismatch       Code = "binding-mismatch"
	CollateralUnavailable Code = "collateral-unavailable"
	CollateralInvalid     Code = "collateral-invalid"
	Revoked               Code = "revoked"
	TcbNotAllowed         Code = "tcb-not-allowed"
	RegisterMismatch      Code = "register-mismatch"
	LogRequired           Code = "log-required"
	LogInvalid            Code = "log-invalid"
	ReplayMismatch        Code = "replay-mismatch"
	ReferenceMismatch     Code = "reference-mismatch"
	BackingBelowMinimum   Code = "backing-below-minimum"
	DeviceRequired        Code = "device-required"
	DeviceNotAllowed      Code = "device-not-allowed"
	DeviceTokenInvalid    Code = "device-token-invalid"
	DevicePolicy          Code = "device-policy"
	Unsupported           Code = "unsupported"
)

// Codes lists every refusal code in the order of section 14.4.
var Codes = []Code{
	EnvelopeInvalid, PolicyInvalid, PlatformUnsupported, ReportInvalid,
	SignatureInvalid, ChainInvalid, MachineNotAllowed, GuestPolicy,
	BindingMismatch, CollateralUnavailable, CollateralInvalid, Revoked,
	TcbNotAllowed, RegisterMismatch, LogRequired, LogInvalid, ReplayMismatch,
	ReferenceMismatch, BackingBelowMinimum, DeviceRequired, DeviceNotAllowed,
	DeviceTokenInvalid, DevicePolicy, Unsupported,
}

// Valid reports whether c is a code of section 14.4.
func (c Code) Valid() bool {
	for _, k := range Codes {
		if c == k {
			return true
		}
	}
	return false
}

func (c *Code) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if !Code(s).Valid() {
		return fmt.Errorf("%q is not a refusal code of section 14.4", s)
	}
	*c = Code(s)
	return nil
}
