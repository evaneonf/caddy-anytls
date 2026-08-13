package anytls

import (
	"encoding/json"
	"errors"
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

		case "fallback":
			value, err := parseBoolDirective(d, "fallback")
			if err != nil {
				return err
			}
			lw.Fallback = value
			lw.fallbackSet = true

		case "padding_scheme":
			value, err := parseStringDirective(d)
			if err != nil {
				return err
			}
			lw.PaddingScheme = value

		case "log_node_info":
			value, err := parseBoolDirective(d, "log_node_info")
			if err != nil {
				return err
			}
			lw.LogNodeInfo = value

		case "node_host":
			values := d.RemainingArgs()
			if len(values) == 0 {
				return d.ArgErr()
			}
			lw.NodeHosts = append(lw.NodeHosts, values...)

		case "node_port":
			value, err := parsePortDirective(d, "node_port")
			if err != nil {
				return err
			}
			lw.NodePort = value

		case "node_sni":
			value, err := parseStringDirective(d)
			if err != nil {
				return err
			}
			lw.NodeSNI = value

		case "node_insecure":
			value, err := parseBoolDirective(d, "node_insecure")
			if err != nil {
				return err
			}
			lw.NodeInsecure = value

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

// UnmarshalJSON preserves explicit false values for booleans with non-zero
// defaults and applies the documented enabled-by-default user behavior.
func (lw *ListenerWrapper) UnmarshalJSON(data []byte) error {
	var config struct {
		Users                []User                     `json:"users,omitempty"`
		ProbeTimeout         caddy.Duration             `json:"probe_timeout,omitempty"`
		IdleTimeout          caddy.Duration             `json:"idle_timeout,omitempty"`
		ConnectTimeout       caddy.Duration             `json:"connect_timeout,omitempty"`
		MaxConcurrent        int                        `json:"max_concurrent,omitempty"`
		MaxPendingProbes     int                        `json:"max_pending_probes,omitempty"`
		MaxStreamsPerSession int                        `json:"max_streams_per_session,omitempty"`
		MaxConcurrentStreams int                        `json:"max_concurrent_streams,omitempty"`
		Fallback             bool                       `json:"fallback,omitempty"`
		PaddingScheme        string                     `json:"padding_scheme,omitempty"`
		LogNodeInfo          bool                       `json:"log_node_info,omitempty"`
		NodeHosts            []string                   `json:"node_hosts,omitempty"`
		NodePort             uint16                     `json:"node_port,omitempty"`
		NodeSNI              string                     `json:"node_sni,omitempty"`
		NodeInsecure         bool                       `json:"node_insecure,omitempty"`
		OutboundsRaw         map[string]json.RawMessage `json:"outbounds,omitempty"`
		DefaultOutbound      string                     `json:"default_outbound,omitempty"`
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return err
	}
	lw.Users = config.Users
	lw.ProbeTimeout = config.ProbeTimeout
	lw.IdleTimeout = config.IdleTimeout
	lw.ConnectTimeout = config.ConnectTimeout
	lw.MaxConcurrent = config.MaxConcurrent
	lw.MaxPendingProbes = config.MaxPendingProbes
	lw.MaxStreamsPerSession = config.MaxStreamsPerSession
	lw.MaxConcurrentStreams = config.MaxConcurrentStreams
	lw.Fallback = config.Fallback
	lw.PaddingScheme = config.PaddingScheme
	lw.LogNodeInfo = config.LogNodeInfo
	lw.NodeHosts = config.NodeHosts
	lw.NodePort = config.NodePort
	lw.NodeSNI = config.NodeSNI
	lw.NodeInsecure = config.NodeInsecure
	lw.OutboundsRaw = config.OutboundsRaw
	lw.DefaultOutbound = config.DefaultOutbound

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if _, ok := raw["outbound"]; ok {
		return errors.New("JSON field \"outbound\" is not supported; declare a named entry in \"outbounds\" and select it with \"default_outbound\"")
	}
	if _, ok := raw["fallback"]; ok {
		lw.fallbackSet = true
	} else {
		lw.Fallback = true
	}
	return nil
}

// UnmarshalJSON makes JSON users enabled by default while still allowing
// "enabled": false to disable an account.
func (u *User) UnmarshalJSON(data []byte) error {
	type userAlias User
	var alias userAlias
	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}
	*u = User(alias)

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if _, ok := raw["enabled"]; !ok {
		u.Enabled = true
	}
	return nil
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

func parsePortDirective(d *caddyfile.Dispenser, name string) (uint16, error) {
	rawValue, err := parseStringDirective(d)
	if err != nil {
		return 0, err
	}
	value, err := strconv.ParseUint(rawValue, 10, 16)
	if err != nil || value == 0 {
		return 0, d.Errf("parsing %s port %q: must be between 1 and 65535", name, rawValue)
	}
	return uint16(value), nil
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
