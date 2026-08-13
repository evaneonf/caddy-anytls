// Package anytls implements a Caddy listener wrapper that detects AnyTLS
// connections after TLS termination and falls back to the normal site path
// for non-AnyTLS traffic.
package anytls

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync/atomic"
	"time"

	singanytls "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/padding"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(&ListenerWrapper{})
}

// ListenerWrapper is a Caddy listener wrapper that peeks decrypted bytes to
// decide whether the connection should be handled as AnyTLS or returned to the
// normal website path.
type ListenerWrapper struct {
	Users                []User         `json:"users,omitempty"`
	ProbeTimeout         caddy.Duration `json:"probe_timeout,omitempty"`
	IdleTimeout          caddy.Duration `json:"idle_timeout,omitempty"`
	ConnectTimeout       caddy.Duration `json:"connect_timeout,omitempty"`
	MaxConcurrent        int            `json:"max_concurrent,omitempty"`
	MaxPendingProbes     int            `json:"max_pending_probes,omitempty"`
	MaxStreamsPerSession int            `json:"max_streams_per_session,omitempty"`
	MaxConcurrentStreams int            `json:"max_concurrent_streams,omitempty"`
	Fallback             bool           `json:"fallback,omitempty"`
	AllowPrivateTargets  bool           `json:"allow_private_targets,omitempty"`
	AllowCIDRs           []string       `json:"allow_cidrs,omitempty"`
	DenyCIDRs            []string       `json:"deny_cidrs,omitempty"`
	AllowPorts           []uint16       `json:"allow_ports,omitempty"`
	DenyPorts            []uint16       `json:"deny_ports,omitempty"`
	AllowDomains         []string       `json:"allow_domains,omitempty"`
	DenyDomains          []string       `json:"deny_domains,omitempty"`
	PaddingScheme        string         `json:"padding_scheme,omitempty"`
	LogNodeInfo          bool           `json:"log_node_info,omitempty"`
	NodeHosts            []string       `json:"node_hosts,omitempty"`
	NodePort             uint16         `json:"node_port,omitempty"`
	NodeSNI              string         `json:"node_sni,omitempty"`
	NodeInsecure         bool           `json:"node_insecure,omitempty"`

	// OutboundRaw selects the module used to reach AnyTLS targets. When empty
	// the built-in "direct" outbound is used. With named outbounds configured,
	// it acts as the default outbound for users without an explicit reference
	// (unless default_outbound overrides it).
	OutboundRaw json.RawMessage `json:"outbound,omitempty" caddy:"namespace=caddy.listeners.anytls.outbounds inline_key=dialer"`

	// OutboundsRaw declares named outbounds that users can reference by name.
	// The names "direct" and "default" are reserved: "direct" always resolves
	// to the built-in direct outbound and never needs to be declared.
	OutboundsRaw map[string]json.RawMessage `json:"outbounds,omitempty" caddy:"namespace=caddy.listeners.anytls.outbounds inline_key=dialer"`

	// DefaultOutbound selects the named outbound used for users without an
	// explicit outbound reference. When empty, the single "outbound" module is
	// used if configured, otherwise the built-in direct outbound.
	DefaultOutbound string `json:"default_outbound,omitempty"`

	logger              *zap.Logger
	outbound            Outbound
	namedOutbounds      map[string]Outbound
	defaultOutbound     Outbound
	defaultOutboundName string
	userOutbound        map[string]Outbound
	userOutboundName    map[string]string
	active              int64
	activeStreams       int64
	connSeq             uint64
	fallbackSet         bool
	registry            *sessionRegistry
	detector            Detector
	service             *singanytls.Service
	allowCIDRPrefixes   []netip.Prefix
	denyCIDRPrefixes    []netip.Prefix
	dialFunc            func(ctx context.Context, network string, address string) (net.Conn, error)
	listenPacketFunc    func(ctx context.Context, network string, address string) (net.PacketConn, error)
	resolveFunc         func(ctx context.Context, network string, host string) ([]netip.Addr, error)
}

// User defines one AnyTLS account.
type User struct {
	Name     string `json:"name,omitempty"`
	Password string `json:"password,omitempty"`
	Enabled  bool   `json:"enabled,omitempty"`
	// Outbound references a named outbound (or the built-in "direct") used
	// for this user's egress traffic. Empty selects the default outbound.
	Outbound string `json:"outbound,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (*ListenerWrapper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.anytls",
		New: func() caddy.Module { return new(ListenerWrapper) },
	}
}

// Provision sets defaults and runtime dependencies.
func (lw *ListenerWrapper) Provision(ctx caddy.Context) error {
	lw.logger = ctx.Logger(lw)

	if lw.ProbeTimeout == 0 {
		lw.ProbeTimeout = caddy.Duration(5 * time.Second)
	}
	if lw.IdleTimeout == 0 {
		lw.IdleTimeout = caddy.Duration(2 * time.Minute)
	}
	if lw.ConnectTimeout == 0 {
		lw.ConnectTimeout = caddy.Duration(10 * time.Second)
	}
	if lw.MaxConcurrent == 0 {
		lw.MaxConcurrent = 128
	}
	if lw.MaxPendingProbes == 0 {
		lw.MaxPendingProbes = 256
	}
	if lw.MaxStreamsPerSession == 0 {
		lw.MaxStreamsPerSession = 256
	}
	if lw.MaxConcurrentStreams == 0 {
		lw.MaxConcurrentStreams = 1024
	}
	if !lw.fallbackSet {
		lw.Fallback = true
	}
	if lw.PaddingScheme == "" {
		lw.PaddingScheme = string(padding.DefaultPaddingScheme)
	}
	if lw.registry == nil {
		lw.registry = newSessionRegistry()
	}
	var server *caddyhttp.Server
	if serverFromContext, ok := ctx.Value(caddyhttp.ServerCtxKey).(*caddyhttp.Server); ok && serverFromContext != nil {
		server = serverFromContext
	}
	if err := lw.compileCIDRPolicies(); err != nil {
		return err
	}

	// A configured outbound is loaded only when the raw config is a real module
	// object. An explicit JSON null (or an empty value) falls back to direct,
	// matching the documented default.
	hasSingleOutbound := len(lw.OutboundRaw) > 0 && string(lw.OutboundRaw) != "null"
	if hasSingleOutbound {
		mod, err := ctx.LoadModule(lw, "OutboundRaw")
		if err != nil {
			return fmt.Errorf("load outbound module: %w", err)
		}
		outbound, ok := mod.(Outbound)
		if !ok {
			return fmt.Errorf("configured outbound %T is not an anytls outbound", mod)
		}
		lw.outbound = outbound
	}
	if lw.outbound == nil {
		lw.outbound = new(DirectOutbound)
	}
	if err := lw.provisionNamedOutbounds(ctx, hasSingleOutbound); err != nil {
		return err
	}

	lw.detector = NewPasswordHashDetector(lw.Users)

	service, err := singanytls.NewService(singanytls.ServiceConfig{
		PaddingScheme: []byte(lw.PaddingScheme),
		Users:         lw.anyTLSUsers(),
		Handler:       &directTCPHandler{config: lw},
		Logger:        zapLogger{base: lw.logger},
	})
	if err != nil {
		return fmt.Errorf("create sing-anytls service: %w", err)
	}
	lw.service = service
	lw.logNodeInfo(server)

	return nil
}

// provisionNamedOutbounds loads the declared named outbounds, injects the
// built-in "direct" reserved name, resolves the default outbound, and builds
// the per-user outbound maps. All reference validation happens here (not in
// Validate) because ctx.LoadModule zeroes the raw fields and only the loaded
// namedOutbounds map reflects the declared names. The resulting maps are
// read-only after Provision, so concurrent reads at dial time need no locking.
func (lw *ListenerWrapper) provisionNamedOutbounds(ctx caddy.Context, hasSingleOutbound bool) error {
	// The reserved-name check must run before the built-in "direct" entry is
	// injected, otherwise the injection would shadow a user declaration.
	for name := range lw.OutboundsRaw {
		if name == "" {
			return errors.New("named outbound must not have an empty name")
		}
		if name == reservedOutboundDirect || name == reservedOutboundDefault {
			return fmt.Errorf("outbound name %q is reserved", name)
		}
	}

	lw.namedOutbounds = make(map[string]Outbound, len(lw.OutboundsRaw)+1)
	if len(lw.OutboundsRaw) > 0 {
		mods, err := ctx.LoadModule(lw, "OutboundsRaw")
		if err != nil {
			return fmt.Errorf("load named outbound modules: %w", err)
		}
		outboundMods, ok := mods.(map[string]any)
		if !ok {
			return fmt.Errorf("named outbound modules loaded as unexpected type %T", mods)
		}
		for name, mod := range outboundMods {
			outbound, ok := mod.(Outbound)
			if !ok {
				return fmt.Errorf("named outbound %q: configured module %T is not an anytls outbound", name, mod)
			}
			lw.namedOutbounds[name] = outbound
		}
	}
	lw.namedOutbounds[reservedOutboundDirect] = new(DirectOutbound)

	// Default outbound resolution order (backward compatible):
	// default_outbound name > single "outbound" module > built-in direct.
	switch {
	case lw.DefaultOutbound != "":
		outbound, ok := lw.namedOutbounds[lw.DefaultOutbound]
		if !ok {
			return fmt.Errorf("default_outbound %q references an undeclared outbound", lw.DefaultOutbound)
		}
		lw.defaultOutbound = outbound
		lw.defaultOutboundName = lw.DefaultOutbound
	case hasSingleOutbound:
		lw.defaultOutbound = lw.outbound
		lw.defaultOutboundName = reservedOutboundDefault
	default:
		lw.defaultOutbound = lw.outbound
		lw.defaultOutboundName = reservedOutboundDirect
	}

	// Both maps hold entries only for users with an explicit outbound
	// reference and always share the same key set.
	lw.userOutbound = make(map[string]Outbound)
	lw.userOutboundName = make(map[string]string)
	for _, user := range lw.Users {
		if user.Outbound == "" {
			continue
		}
		outbound, ok := lw.namedOutbounds[user.Outbound]
		if !ok {
			return fmt.Errorf("user %q references an undeclared outbound %q", user.Name, user.Outbound)
		}
		lw.userOutbound[user.Name] = outbound
		lw.userOutboundName[user.Name] = user.Outbound
	}

	return nil
}

// resolveDefaultOutbound returns the outbound and log name used when the
// authenticated user has no explicit outbound reference. Provision always
// sets defaultOutbound; the trailing config.outbound and DirectOutbound
// tiers keep wrappers built without Provision (hand-made test fixtures)
// working.
func (lw *ListenerWrapper) resolveDefaultOutbound() (Outbound, string) {
	if lw.defaultOutbound != nil {
		return lw.defaultOutbound, lw.defaultOutboundName
	}
	if lw.outbound != nil {
		return lw.outbound, reservedOutboundDefault
	}
	return &DirectOutbound{}, reservedOutboundDirect
}

// Cleanup closes all active AnyTLS sessions when the config is unloaded.
// This must be the module's own Cleanup: callbacks registered via
// ctx.OnCancel inside Provision are appended to a copy of the caddy.Context
// (value receiver) and never run in caddy v2.11.4. Note that caddy gives no
// ordering guarantee across module cleanups, so outbound modules may be
// cleaned up before or after this runs.
func (lw *ListenerWrapper) Cleanup() error {
	if lw.registry != nil {
		lw.closeActiveSessions("config_unload")
	}
	return nil
}

// Validate checks static configuration safety.
func (lw *ListenerWrapper) Validate() error {
	if lw.MaxConcurrent < 0 {
		return fmt.Errorf("max_concurrent must be positive")
	}
	if lw.MaxPendingProbes < 0 {
		return fmt.Errorf("max_pending_probes must be positive")
	}
	if lw.MaxStreamsPerSession < 0 {
		return fmt.Errorf("max_streams_per_session must be positive")
	}
	if lw.MaxConcurrentStreams < 0 {
		return fmt.Errorf("max_concurrent_streams must be positive")
	}
	if lw.ProbeTimeout < 0 {
		return fmt.Errorf("probe_timeout must be non-negative")
	}
	if lw.IdleTimeout < 0 {
		return fmt.Errorf("idle_timeout must be non-negative")
	}
	if lw.ConnectTimeout < 0 {
		return fmt.Errorf("connect_timeout must be non-negative")
	}
	if err := lw.compileCIDRPolicies(); err != nil {
		return err
	}
	for _, domain := range append(append([]string{}, lw.AllowDomains...), lw.DenyDomains...) {
		if domain == "" {
			return fmt.Errorf("domain policy entry must not be empty")
		}
	}

	seen := make([]string, 0, len(lw.Users))
	passwords := make(map[[32]byte]string, len(lw.Users))
	for _, user := range lw.Users {
		if user.Name == "" {
			return fmt.Errorf("user name must not be empty")
		}
		if user.Password == "" {
			return fmt.Errorf("user %q password must not be empty", user.Name)
		}
		if slices.Contains(seen, user.Name) {
			return fmt.Errorf("duplicate user %q", user.Name)
		}
		passwordHash := sha256.Sum256([]byte(user.Password))
		if existing, ok := passwords[passwordHash]; ok {
			return fmt.Errorf("users %q and %q must not share a password", existing, user.Name)
		}
		passwords[passwordHash] = user.Name
		seen = append(seen, user.Name)
	}

	return nil
}

// WrapListener wraps the listener with AnyTLS-aware connection routing.
func (lw *ListenerWrapper) WrapListener(l net.Listener) net.Listener {
	return newWrappedListener(l, lw)
}

var (
	_ caddy.Provisioner     = (*ListenerWrapper)(nil)
	_ caddy.Validator       = (*ListenerWrapper)(nil)
	_ caddy.CleanerUpper    = (*ListenerWrapper)(nil)
	_ caddy.ListenerWrapper = (*ListenerWrapper)(nil)
	_ caddyfile.Unmarshaler = (*ListenerWrapper)(nil)
)

func (lw *ListenerWrapper) anyTLSUsers() []singanytls.User {
	users := make([]singanytls.User, 0, len(lw.Users))
	for _, user := range lw.Users {
		if !user.Enabled {
			continue
		}
		users = append(users, singanytls.User{
			Name:     user.Name,
			Password: user.Password,
		})
	}
	return users
}

func (lw *ListenerWrapper) logFallback(conn net.Conn, err error) {
	lw.logger.Debug("connection routed to website",
		zap.String("remote", conn.RemoteAddr().String()),
		zap.String("event", "fallback"),
		zap.String("outcome", "fallback"),
		zap.String("reason", probeFailureReason(err)),
		zap.Error(err),
	)
}

func (lw *ListenerWrapper) prepareWebsiteConn(conn *bufferedConn) (net.Conn, error) {
	prefix, err := conn.BufferedBytes()
	if err != nil {
		return nil, err
	}

	websiteConn := newPrependConn(conn.Conn, prefix)
	if stater, ok := conn.Conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
		return tlsStateConn{
			Conn:  websiteConn,
			state: stater.ConnectionState(),
		}, nil
	}

	return websiteConn, nil
}

var (
	errInvalidDestination       = errors.New("invalid destination")
	errPrivateDestinationDenied = errors.New("private destination denied")
	errDestinationPolicyDenied  = errors.New("destination policy denied")
	errInvalidUDPOverTCPRequest = errors.New("invalid udp over tcp request")
	errUnsupportedUDPOverTCP    = errors.New("unsupported udp over tcp")
	errStreamLimitExceeded      = errors.New("stream concurrency limit exceeded")
)

func (lw *ListenerWrapper) nextConnectionID() uint64 {
	return atomic.AddUint64(&lw.connSeq, 1)
}

func probeFailureReason(err error) string {
	switch {
	case errors.Is(err, errShortPreview):
		return "short_preview"
	case errors.Is(err, errUnknownUserHash):
		return "unknown_user_hash"
	case errors.Is(err, errDisabledUserHash):
		return "disabled_user"
	default:
		return "probe_error"
	}
}

func dialFailureReason(err error) string {
	switch {
	case errors.Is(err, errInvalidDestination):
		return "invalid_destination"
	case errors.Is(err, errPrivateDestinationDenied):
		return "private_target_denied"
	case errors.Is(err, errDestinationPolicyDenied):
		return "destination_policy_denied"
	case errors.Is(err, errInvalidUDPOverTCPRequest):
		return "invalid_udp_over_tcp_request"
	case errors.Is(err, errUnsupportedUDPOverTCP):
		return "udp_over_tcp_unsupported"
	case errors.Is(err, errStreamLimitExceeded):
		return "stream_limit_exceeded"
	default:
		return "dial_failed"
	}
}
