package anytls

import (
	"fmt"
	"net/netip"
	"strings"
)

// validateSNI accepts one concrete ASCII DNS name (including punycode).
// SNI is required so the AnyTLS entry point is always explicit.
func validateSNI(name string) error {
	if name == "" {
		return fmt.Errorf("sni is required")
	}
	invalid := func() error {
		return fmt.Errorf("sni must be a concrete DNS name without a port or wildcard: %q", name)
	}
	if len(name) > 253 {
		return invalid()
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return invalid()
	}
	for label := range strings.SplitSeq(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return invalid()
		}
		for _, c := range label {
			switch {
			case c == '-', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			default:
				return invalid()
			}
		}
	}
	return nil
}
