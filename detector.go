package anytls

import (
	"crypto/sha256"
	"errors"
	"fmt"
)

type routingDecision uint8

const (
	routeFallback routingDecision = iota
	routeAnyTLS
	routeReject
)

var (
	errShortPreview     = errors.New("short preview")
	errUnknownUserHash  = errors.New("unknown user hash")
	errDisabledUserHash = errors.New("disabled user")
)

type passwordHashDetector struct {
	users map[[32]byte]detectedUser
}

type detectedUser struct {
	name    string
	enabled bool
}

func newPasswordHashDetector(users []User) passwordHashDetector {
	detector := passwordHashDetector{
		users: make(map[[32]byte]detectedUser),
	}
	for _, user := range users {
		detector.users[sha256.Sum256([]byte(user.Password))] = detectedUser{name: user.Name, enabled: user.Enabled}
	}
	return detector
}

func (d passwordHashDetector) detect(preview []byte) (routingDecision, error) {
	_, decision, err := d.identify(preview)
	return decision, err
}

func (d passwordHashDetector) identify(preview []byte) (string, routingDecision, error) {
	if len(preview) < 32 {
		return "", routeFallback, fmt.Errorf("%w: need at least 32 bytes", errShortPreview)
	}
	var passwordSha256 [32]byte
	copy(passwordSha256[:], preview[:32])
	user, ok := d.users[passwordSha256]
	if !ok {
		return "", routeFallback, fmt.Errorf("%w: password hash did not match any configured user", errUnknownUserHash)
	}
	if !user.enabled {
		return user.name, routeReject, fmt.Errorf("%w: password hash matched a disabled user", errDisabledUserHash)
	}
	return user.name, routeAnyTLS, nil
}
