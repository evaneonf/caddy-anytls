package anytls

import (
	"crypto/sha256"
	"fmt"
)

// Decision is the result of protocol detection.
type Decision int

const (
	// DecisionFallback returns the connection to the normal website path.
	DecisionFallback Decision = iota
	// DecisionAnyTLS hands the connection to the AnyTLS session path.
	DecisionAnyTLS
	// DecisionReject closes the connection immediately.
	DecisionReject
)

// Detector inspects the decrypted first bytes and decides how the connection
// should be routed.
type Detector interface {
	Detect(preview []byte) (Decision, error)
}

var (
	errShortPreview      = fmt.Errorf("short preview")
	errUnknownUserHash   = fmt.Errorf("unknown user hash")
	errDisabledUserHash  = fmt.Errorf("disabled user")
	errInvalidAnyTLSPeek = fmt.Errorf("invalid anytls preview")
)

// PasswordHashDetector matches the leading AnyTLS password hash used by the
// sing-anytls server implementation.
type PasswordHashDetector struct {
	users map[[32]byte]bool
}

// NewPasswordHashDetector builds a detector from the configured user list.
func NewPasswordHashDetector(users []User) PasswordHashDetector {
	detector := PasswordHashDetector{
		users: make(map[[32]byte]bool),
	}
	for _, user := range users {
		detector.users[sha256.Sum256([]byte(user.Password))] = user.Enabled
	}
	return detector
}

// Detect checks whether the preview starts with one of the configured AnyTLS
// password hashes.
func (d PasswordHashDetector) Detect(preview []byte) (Decision, error) {
	if len(preview) < 32 {
		return DecisionFallback, fmt.Errorf("%w: need at least 32 bytes", errShortPreview)
	}
	var passwordSha256 [32]byte
	copy(passwordSha256[:], preview[:32])
	enabled, ok := d.users[passwordSha256]
	if !ok {
		return DecisionFallback, fmt.Errorf("%w: password hash did not match any configured user", errUnknownUserHash)
	}
	if !enabled {
		return DecisionReject, fmt.Errorf("%w: password hash matched a disabled user", errDisabledUserHash)
	}
	return DecisionAnyTLS, nil
}
