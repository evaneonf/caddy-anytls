package anytls

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
	"github.com/sagernet/sing/protocol/socks/socks5"
)

func init() {
	caddy.RegisterModule(&SOCKS5Outbound{})
}

// SOCKS5Outbound reaches TCP and UDP targets through a SOCKS5 proxy. Target
// domains are encoded in the SOCKS5 request and resolved by the proxy.
type SOCKS5Outbound struct {
	Address  string `json:"address,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`

	server M.Socksaddr
	dialer contextDialer
}

type contextDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// HandleSession lets the local AnyTLS service decode the session and dispatch
// each stream through this SOCKS5 proxy.
func (o *SOCKS5Outbound) HandleSession(_ context.Context, session *OutboundSession) error {
	return session.ServeLocal(o)
}

// CaddyModule returns the Caddy module information.
func (*SOCKS5Outbound) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.anytls.outbounds.socks5",
		New: func() caddy.Module { return new(SOCKS5Outbound) },
	}
}

// Provision validates the proxy endpoint and credentials before the listener
// starts accepting connections.
func (o *SOCKS5Outbound) Provision(caddy.Context) error {
	server, err := parseSOCKS5ServerAddress(o.Address)
	if err != nil {
		return err
	}
	if o.Username == "" && o.Password != "" {
		return errors.New("socks5 outbound password requires username")
	}
	if len(o.Username) > 255 || len(o.Password) > 255 {
		return errors.New("socks5 outbound username and password must not exceed 255 bytes")
	}
	o.server = server
	if o.dialer == nil {
		o.dialer = new(net.Dialer)
	}
	return nil
}

// DialContext establishes a SOCKS5 CONNECT tunnel. destination is written to
// the request without local name resolution.
func (o *SOCKS5Outbound) DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	if err := validateDestination(destination); err != nil {
		return nil, err
	}
	conn, err := o.openControlConnection(ctx)
	if err != nil {
		return nil, err
	}
	if err := handshakeWithContext(ctx, conn, func() error {
		_, handshakeErr := socks.ClientHandshake5(conn, socks5.CommandConnect, destination, o.Username, o.Password)
		return handshakeErr
	}); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5 connect %s: %w", destination, err)
	}
	return conn, nil
}

// OpenPacket establishes one SOCKS5 UDP ASSOCIATE session. Individual target
// domains remain in the SOCKS5 UDP headers and are resolved by the proxy.
func (o *SOCKS5Outbound) OpenPacket(ctx context.Context) (PacketConn, error) {
	controlConn, err := o.openControlConnection(ctx)
	if err != nil {
		return nil, err
	}

	var response socks5.Response
	requestAddress := M.SocksaddrFrom(netip.IPv4Unspecified(), 0)
	if err := handshakeWithContext(ctx, controlConn, func() error {
		var handshakeErr error
		response, handshakeErr = socks.ClientHandshake5(controlConn, socks5.CommandUDPAssociate, requestAddress, o.Username, o.Password)
		return handshakeErr
	}); err != nil {
		_ = controlConn.Close()
		return nil, fmt.Errorf("socks5 UDP associate: %w", err)
	}

	bindAddress, err := normalizeSOCKS5BindAddress(response.Bind, controlConn.RemoteAddr())
	if err != nil {
		_ = controlConn.Close()
		return nil, err
	}

	udpConn, err := o.dialContext(ctx, "udp", bindAddress.String())
	if err != nil {
		_ = controlConn.Close()
		return nil, fmt.Errorf("connect socks5 UDP relay %s: %w", bindAddress, err)
	}

	associate := socks.NewAssociatePacketConn(udpConn, M.Socksaddr{}, controlConn)
	return &socks5PacketConn{conn: associate}, nil
}

func (o *SOCKS5Outbound) openControlConnection(ctx context.Context) (net.Conn, error) {
	serverAddress, err := o.serverAddress()
	if err != nil {
		return nil, err
	}
	conn, err := o.dialContext(ctx, "tcp", serverAddress.String())
	if err != nil {
		return nil, fmt.Errorf("connect socks5 proxy %s: %w", serverAddress, err)
	}
	return conn, nil
}

func (o *SOCKS5Outbound) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if o.dialer != nil {
		return o.dialer.DialContext(ctx, network, address)
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, address)
}

func (o *SOCKS5Outbound) serverAddress() (M.Socksaddr, error) {
	if o.server.IsValid() {
		return o.server, nil
	}
	return parseSOCKS5ServerAddress(o.Address)
}

func parseSOCKS5ServerAddress(rawAddress string) (M.Socksaddr, error) {
	address := M.ParseSocksaddr(rawAddress)
	if !address.IsValid() || address.Port == 0 {
		return M.Socksaddr{}, fmt.Errorf("invalid socks5 outbound address %q", rawAddress)
	}
	return address, nil
}

func normalizeSOCKS5BindAddress(bind M.Socksaddr, controlRemote net.Addr) (M.Socksaddr, error) {
	if bind.Port == 0 {
		return M.Socksaddr{}, fmt.Errorf("socks5 proxy returned invalid UDP bind address %s", bind)
	}
	if (bind.Addr.IsValid() && !bind.Addr.IsUnspecified()) || bind.IsDomain() {
		return bind, nil
	}

	remote := M.SocksaddrFromNet(controlRemote).Unwrap()
	if !remote.Addr.IsValid() {
		return M.Socksaddr{}, fmt.Errorf("cannot derive socks5 UDP relay address from %v", controlRemote)
	}
	bind.Addr = remote.Addr
	bind.Fqdn = ""
	return bind, nil
}

func handshakeWithContext(ctx context.Context, conn net.Conn, handshake func() error) error {
	deadline, hasDeadline := ctx.Deadline()
	if hasDeadline {
		if err := conn.SetDeadline(deadline); err != nil {
			return err
		}
	}
	stop := context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(time.Now())
	})
	err := handshake()
	stop()
	if clearErr := conn.SetDeadline(time.Time{}); err == nil {
		err = clearErr
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	// A connection deadline and its context deadline expire at the same instant,
	// but the network poller may report the timeout before the context timer has
	// published DeadlineExceeded. Keep the API deterministic in that race.
	if err != nil && hasDeadline && !time.Now().Before(deadline) {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return context.DeadlineExceeded
		}
	}
	return err
}

type socks5PacketConn struct {
	conn N.PacketConn
}

func (c *socks5PacketConn) ReadPacket(p []byte) (int, M.Socksaddr, error) {
	buffer := buf.NewSize(len(p) + 3 + M.MaxSocksaddrLength)
	defer buffer.Release()
	source, err := c.conn.ReadPacket(buffer)
	if err != nil {
		return 0, M.Socksaddr{}, err
	}
	if buffer.Len() > len(p) {
		return 0, M.Socksaddr{}, io.ErrShortBuffer
	}
	return copy(p, buffer.Bytes()), source, nil
}

func (c *socks5PacketConn) WritePacket(p []byte, destination M.Socksaddr) error {
	if err := validateDestination(destination); err != nil {
		return err
	}
	headroom := 3 + M.SocksaddrSerializer.AddrPortLen(destination)
	buffer := buf.NewSize(headroom + len(p))
	buffer.Resize(headroom, 0)
	if _, err := buffer.Write(p); err != nil {
		buffer.Release()
		return err
	}
	// sing PacketWriter takes ownership of buffer, including on failure.
	return c.conn.WritePacket(buffer, destination)
}

func (c *socks5PacketConn) Close() error {
	return c.conn.Close()
}

// UnmarshalCaddyfile parses a SOCKS5 proxy endpoint and optional credentials.
func (o *SOCKS5Outbound) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()
	if d.NextArg() {
		return d.ArgErr()
	}
	for d.NextBlock(0) {
		switch d.Val() {
		case "address":
			if o.Address != "" || !d.NextArg() {
				return d.ArgErr()
			}
			o.Address = d.Val()
			if d.NextArg() {
				return d.ArgErr()
			}
		case "username":
			if o.Username != "" || !d.NextArg() {
				return d.ArgErr()
			}
			o.Username = d.Val()
			if d.NextArg() {
				return d.ArgErr()
			}
		case "password":
			if o.Password != "" || !d.NextArg() {
				return d.ArgErr()
			}
			o.Password = d.Val()
			if d.NextArg() {
				return d.ArgErr()
			}
		default:
			return d.Errf("unrecognized socks5 outbound option %q", d.Val())
		}
	}
	if o.Address == "" {
		return d.Err("socks5 outbound requires an address")
	}
	return nil
}

var (
	_ Outbound              = (*SOCKS5Outbound)(nil)
	_ StreamOutbound        = (*SOCKS5Outbound)(nil)
	_ PacketConn            = (*socks5PacketConn)(nil)
	_ caddy.Module          = (*SOCKS5Outbound)(nil)
	_ caddy.Provisioner     = (*SOCKS5Outbound)(nil)
	_ caddyfile.Unmarshaler = (*SOCKS5Outbound)(nil)
)
