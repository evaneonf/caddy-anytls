package anytls

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

// UnmarshalCaddyfile configures the listener wrapper from Caddyfile tokens.
func (lw *ListenerWrapper) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()
	if d.NextArg() {
		return d.ArgErr()
	}

	for d.NextBlock(0) {
		switch d.Val() {
		case "probe_timeout":
			dur, err := parseDurationDirective(d, "probe_timeout")
			if err != nil {
				return err
			}
			lw.ProbeTimeout = caddy.Duration(dur)

		case "idle_timeout":
			dur, err := parseDurationDirective(d, "idle_timeout")
			if err != nil {
				return err
			}
			lw.IdleTimeout = caddy.Duration(dur)

		case "connect_timeout":
			dur, err := parseDurationDirective(d, "connect_timeout")
			if err != nil {
				return err
			}
			lw.ConnectTimeout = caddy.Duration(dur)

		case "max_concurrent":
			value, err := parseIntDirective(d, "max_concurrent")
			if err != nil {
				return err
			}
			lw.MaxConcurrent = value

		case "max_pending_probes":
			value, err := parseIntDirective(d, "max_pending_probes")
			if err != nil {
				return err
			}
			lw.MaxPendingProbes = value

		case "max_streams_per_session":
			value, err := parseIntDirective(d, "max_streams_per_session")
			if err != nil {
				return err
			}
			lw.MaxStreamsPerSession = value

		case "max_concurrent_streams":
			value, err := parseIntDirective(d, "max_concurrent_streams")
			if err != nil {
				return err
			}
			lw.MaxConcurrentStreams = value

		case "log_node_info":
			value, err := parseBoolDirective(d, "log_node_info")
			if err != nil {
				return err
			}
			lw.LogNodeInfo = value

		case "sni":
			value, err := parseStringDirective(d)
			if err != nil {
				return err
			}
			if value == "" {
				return d.Err("sni must not be empty")
			}
			lw.SNI = value

		case "user":
			args := d.RemainingArgs()
			if len(args) != 2 && len(args) != 3 {
				return d.ArgErr()
			}
			user := User{
				Name:     args[0],
				Password: args[1],
				Enabled:  true,
			}
			if len(args) == 3 {
				user.Outbound = args[2]
			}
			lw.Users = append(lw.Users, user)

		case "outbound":
			if !d.NextArg() {
				return d.ArgErr()
			}
			outboundName := d.Val()
			if !d.NextArg() {
				return d.ArgErr()
			}
			moduleName := d.Val()
			if d.NextArg() {
				return d.ArgErr()
			}
			if _, ok := lw.OutboundsRaw[outboundName]; ok {
				return d.Errf("outbound %q may only be declared once", outboundName)
			}
			raw, err := unmarshalOutboundModule(d, moduleName)
			if err != nil {
				return err
			}
			if lw.OutboundsRaw == nil {
				lw.OutboundsRaw = make(map[string]json.RawMessage)
			}
			lw.OutboundsRaw[outboundName] = raw

		case "default_outbound":
			if lw.DefaultOutbound != "" {
				return d.Errf("default_outbound may only be specified once")
			}
			if !d.NextArg() {
				return d.ArgErr()
			}
			lw.DefaultOutbound = d.Val()
			if lw.DefaultOutbound == "" {
				return d.Errf("default_outbound must not be empty")
			}
			if d.NextArg() {
				return d.ArgErr()
			}

		default:
			return d.ArgErr()
		}
	}

	return nil
}

// unmarshalOutboundModule parses one outbound module body starting at the
// current dispenser position (the module-name token) and returns it in the
// JSON object form stored in the outbound raw fields.
func unmarshalOutboundModule(d *caddyfile.Dispenser, moduleName string) (json.RawMessage, error) {
	modID := "caddy.listeners.anytls.outbounds." + moduleName
	unm, err := caddyfile.UnmarshalModule(d, modID)
	if err != nil {
		return nil, err
	}
	if _, ok := unm.(Outbound); !ok {
		return nil, d.Errf("module %s is not an anytls outbound", modID)
	}
	return caddyconfig.JSONModuleObject(unm, "dialer", moduleName, nil), nil
}

// UnmarshalJSON rejects unsupported configuration fields and decodes users.
func (lw *ListenerWrapper) UnmarshalJSON(data []byte) error {
	type config ListenerWrapper
	return caddy.StrictUnmarshalJSON(data, (*config)(lw))
}

// UnmarshalJSON makes JSON users enabled by default while still allowing
// "enabled": false to disable an account.
func (u *User) UnmarshalJSON(data []byte) error {
	type userAlias User
	var raw struct {
		userAlias
		Enabled json.RawMessage `json:"enabled"`
	}
	if err := caddy.StrictUnmarshalJSON(data, &raw); err != nil {
		return err
	}
	enabled, err := unmarshalDefaultTrueBool(raw.Enabled, "enabled")
	if err != nil {
		return err
	}
	*u = User(raw.userAlias)
	u.Enabled = enabled
	return nil
}

func unmarshalDefaultTrueBool(raw json.RawMessage, field string) (value bool, err error) {
	if raw == nil {
		return true, nil
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return false, fmt.Errorf("JSON field %q must not be null", field)
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		return false, fmt.Errorf("JSON field %q must be a boolean: %w", field, err)
	}
	return value, nil
}

func parseDurationDirective(d *caddyfile.Dispenser, name string) (time.Duration, error) {
	value, err := parseStringDirective(d)
	if err != nil {
		return 0, err
	}
	dur, err := caddy.ParseDuration(value)
	if err != nil {
		return 0, d.Errf("parsing %s duration: %v", name, err)
	}
	return dur, nil
}

func parseBoolDirective(d *caddyfile.Dispenser, name string) (bool, error) {
	rawValue, err := parseStringDirective(d)
	if err != nil {
		return false, err
	}
	value, err := strconv.ParseBool(rawValue)
	if err != nil {
		return false, d.Errf("parsing %s boolean: %v", name, err)
	}
	return value, nil
}

func parseIntDirective(d *caddyfile.Dispenser, name string) (int, error) {
	rawValue, err := parseStringDirective(d)
	if err != nil {
		return 0, err
	}
	value, err := strconv.Atoi(rawValue)
	if err != nil {
		return 0, d.Errf("parsing %s: %v", name, err)
	}
	return value, nil
}

func parseStringDirective(d *caddyfile.Dispenser) (string, error) {
	if !d.NextArg() {
		return "", d.ArgErr()
	}
	value := d.Val()
	if d.NextArg() {
		return "", d.ArgErr()
	}
	return value, nil
}

// parseUniqueStringDirective reads an outbound option that may be set once.
func parseUniqueStringDirective(d *caddyfile.Dispenser, target *string) error {
	if *target != "" {
		return d.ArgErr()
	}
	value, err := parseStringDirective(d)
	if err != nil {
		return err
	}
	*target = value
	return nil
}
