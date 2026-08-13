package anytls

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	M "github.com/sagernet/sing/common/metadata"
)

// PacketConn is the packet-oriented connection returned by a StreamOutbound.
// Unlike net.PacketConn, destinations remain M.Socksaddr values, so an
// outbound can receive a domain name without the AnyTLS relay resolving it on
// the host first.
//
// ReadPacket and WritePacket are called concurrently by the two relay
// directions. Implementations must not retain p after either method returns.
type PacketConn interface {
	ReadPacket(p []byte) (n int, source M.Socksaddr, err error)
	WritePacket(p []byte, destination M.Socksaddr) error
	Close() error
}

// Outbound handles one authenticated AnyTLS session. Stream-based outbounds
// call session.ServeLocal to let this server decode the session and dispatch
// its individual targets. Session-based outbounds can instead relay the intact
// AnyTLS protocol stream to another server.
type Outbound interface {
	HandleSession(ctx context.Context, session *OutboundSession) error
}

// StreamOutbound establishes the target connections used after an AnyTLS
// session is decoded locally. Implementations own all target resolution and
// routing decisions; unresolved domains are passed through unchanged.
type StreamOutbound interface {
	DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error)
	OpenPacket(ctx context.Context) (PacketConn, error)
}

// OutboundSession describes one authenticated AnyTLS session selected for an
// outbound. Its protocol bytes have only been peeked, not consumed.
type OutboundSession struct {
	conn           net.Conn
	user           string
	source         M.Socksaddr
	connectTimeout time.Duration
	serveLocal     func(StreamOutbound) error
}

func newOutboundSession(conn net.Conn, user string, source M.Socksaddr, connectTimeout time.Duration, serveLocal func(StreamOutbound) error) *OutboundSession {
	return &OutboundSession{
		conn:           conn,
		user:           user,
		source:         source,
		connectTimeout: connectTimeout,
		serveLocal:     serveLocal,
	}
}

// Connection returns the decrypted AnyTLS protocol connection. Callers that
// relay it must preserve all bytes after the 32-byte authentication hash.
func (s *OutboundSession) Connection() net.Conn { return s.conn }

// User returns the locally authenticated user name.
func (s *OutboundSession) User() string { return s.user }

// Source returns the client address observed by this server.
func (s *OutboundSession) Source() M.Socksaddr { return s.source }

// ConnectTimeout returns the configured timeout for establishing an outbound
// connection. It does not limit the lifetime of an established session.
func (s *OutboundSession) ConnectTimeout() time.Duration { return s.connectTimeout }

// ServeLocal decodes this session locally and sends its streams through the
// provided target-level outbound.
func (s *OutboundSession) ServeLocal(outbound StreamOutbound) error {
	if s.serveLocal == nil {
		return errors.New("local AnyTLS session handler is unavailable")
	}
	return s.serveLocal(outbound)
}

// reservedOutboundDirect always refers to the zero-configuration built-in
// direct outbound and cannot be redeclared.
const reservedOutboundDirect = "direct"

func init() {
	caddy.RegisterModule(&DirectOutbound{})
}

// DirectOutbound reaches targets through the host network stack. It is the
// default when no outbound is configured.
type DirectOutbound struct{}

// HandleSession lets the local AnyTLS service decode the session and dispatch
// each stream through the host network stack.
func (o *DirectOutbound) HandleSession(_ context.Context, session *OutboundSession) error {
	return session.ServeLocal(o)
}

// CaddyModule returns the Caddy module information.
func (*DirectOutbound) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.anytls.outbounds.direct",
		New: func() caddy.Module { return new(DirectOutbound) },
	}
}

// DialContext dials a TCP target directly. net.Dialer delegates domain
// resolution to the host resolver.
func (*DirectOutbound) DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	if err := validateDestination(destination); err != nil {
		return nil, err
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", destination.String())
}

// OpenPacket opens an unconnected host UDP socket. Domain targets are resolved
// by the host resolver when their datagram is sent; no project-level DNS cache
// is maintained.
func (*DirectOutbound) OpenPacket(ctx context.Context) (PacketConn, error) {
	var listenConfig net.ListenConfig
	conn, err := listenConfig.ListenPacket(ctx, "udp", "")
	if err != nil {
		return nil, err
	}
	return &directPacketConn{PacketConn: conn}, nil
}

type directPacketConn struct {
	net.PacketConn
}

func (c *directPacketConn) ReadPacket(p []byte) (int, M.Socksaddr, error) {
	n, source, err := c.ReadFrom(p)
	if err != nil {
		return 0, M.Socksaddr{}, err
	}
	return n, M.SocksaddrFromNet(source).Unwrap(), nil
}

func (c *directPacketConn) WritePacket(p []byte, destination M.Socksaddr) error {
	if err := validateDestination(destination); err != nil {
		return err
	}

	var address net.Addr
	if destination.Addr.IsValid() {
		address = destination.UDPAddr()
	} else {
		resolved, err := net.ResolveUDPAddr("udp", destination.String())
		if err != nil {
			return fmt.Errorf("resolve UDP target %s: %w", destination, err)
		}
		address = resolved
	}

	n, err := c.WriteTo(p, address)
	if err != nil {
		return err
	}
	if n != len(p) {
		return io.ErrShortWrite
	}
	return nil
}

func validateDestination(destination M.Socksaddr) error {
	if !destination.IsValid() || destination.Port == 0 {
		return fmt.Errorf("%w: %s", errInvalidDestination, destination.String())
	}
	return nil
}

// UnmarshalCaddyfile accepts the bare directive and rejects any options.
func (*DirectOutbound) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()
	if d.NextArg() {
		return d.ArgErr()
	}
	for d.NextBlock(0) {
		return d.Errf("unrecognized direct outbound option %q", d.Val())
	}
	return nil
}

var (
	_ Outbound              = (*DirectOutbound)(nil)
	_ StreamOutbound        = (*DirectOutbound)(nil)
	_ PacketConn            = (*directPacketConn)(nil)
	_ caddy.Module          = (*DirectOutbound)(nil)
	_ caddyfile.Unmarshaler = (*DirectOutbound)(nil)
)
