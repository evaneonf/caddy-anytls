package anytls

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func init() {
	caddy.RegisterModule(&AnyTLSOutbound{})
}

// AnyTLSOutbound relays an authenticated AnyTLS session to another AnyTLS
// server. Only the 32-byte password hash is replaced; padding and all session
// frames remain intact and are interpreted by the upstream server.
type AnyTLSOutbound struct {
	Address               string `json:"address,omitempty"`
	Password              string `json:"password,omitempty"`
	ServerName            string `json:"server_name,omitempty"`
	TLSInsecureSkipVerify bool   `json:"tls_insecure_skip_verify,omitempty"`

	dialer    contextDialer
	tlsConfig *tls.Config
}

// CaddyModule returns the Caddy module information.
func (*AnyTLSOutbound) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.anytls.outbounds.anytls",
		New: func() caddy.Module { return new(AnyTLSOutbound) },
	}
}

// Provision validates the upstream endpoint and prepares its TLS client.
func (o *AnyTLSOutbound) Provision(caddy.Context) error {
	host, _, err := net.SplitHostPort(o.Address)
	if err != nil || host == "" {
		return fmt.Errorf("invalid anytls outbound address %q: expected host:port", o.Address)
	}
	if o.Password == "" {
		return errors.New("anytls outbound password must not be empty")
	}

	serverName := o.ServerName
	if serverName == "" {
		serverName = strings.Trim(host, "[]")
	}
	o.tlsConfig = &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         serverName,
		InsecureSkipVerify: o.TLSInsecureSkipVerify,
	}
	if o.dialer == nil {
		o.dialer = new(net.Dialer)
	}
	return nil
}

// HandleSession authenticates to the upstream with its configured password,
// then relays the rest of the original AnyTLS session without decoding it.
func (o *AnyTLSOutbound) HandleSession(ctx context.Context, session *OutboundSession) error {
	if session == nil || session.Connection() == nil {
		return errors.New("anytls outbound session is unavailable")
	}
	if o.dialer == nil || o.tlsConfig == nil {
		return errors.New("anytls outbound is not provisioned")
	}

	connectCtx := ctx
	if timeout := session.ConnectTimeout(); timeout > 0 {
		var cancel context.CancelFunc
		connectCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	rawUpstream, err := o.dialer.DialContext(connectCtx, "tcp", o.Address)
	if err != nil {
		return fmt.Errorf("dial anytls upstream %s: %w", o.Address, err)
	}
	upstream := tls.Client(rawUpstream, o.tlsConfig.Clone())
	if err := upstream.HandshakeContext(connectCtx); err != nil {
		_ = rawUpstream.Close()
		return fmt.Errorf("handshake with anytls upstream %s: %w", o.Address, err)
	}

	if _, err := io.CopyN(io.Discard, session.Connection(), sha256.Size); err != nil {
		_ = upstream.Close()
		return fmt.Errorf("read local anytls authentication hash: %w", err)
	}
	upstreamPasswordHash := sha256.Sum256([]byte(o.Password))
	if err := writeFull(upstream, upstreamPasswordHash[:]); err != nil {
		_ = upstream.Close()
		return fmt.Errorf("write upstream anytls authentication hash: %w", err)
	}

	return relayConnections(ctx, session.Connection(), upstream, nil)
}

func writeFull(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		n, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		payload = payload[n:]
	}
	return nil
}

// UnmarshalCaddyfile parses an upstream AnyTLS server and TLS options.
func (o *AnyTLSOutbound) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
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
		case "password":
			if o.Password != "" || !d.NextArg() {
				return d.ArgErr()
			}
			o.Password = d.Val()
			if d.NextArg() {
				return d.ArgErr()
			}
		case "server_name":
			if o.ServerName != "" || !d.NextArg() {
				return d.ArgErr()
			}
			o.ServerName = d.Val()
			if d.NextArg() {
				return d.ArgErr()
			}
		case "tls_insecure_skip_verify":
			if o.TLSInsecureSkipVerify || d.NextArg() {
				return d.ArgErr()
			}
			o.TLSInsecureSkipVerify = true
		default:
			return d.Errf("unrecognized anytls outbound option %q", d.Val())
		}
	}
	if o.Address == "" {
		return d.Err("anytls outbound requires an address")
	}
	if o.Password == "" {
		return d.Err("anytls outbound requires a password")
	}
	return nil
}

var (
	_ Outbound              = (*AnyTLSOutbound)(nil)
	_ caddy.Module          = (*AnyTLSOutbound)(nil)
	_ caddy.Provisioner     = (*AnyTLSOutbound)(nil)
	_ caddyfile.Unmarshaler = (*AnyTLSOutbound)(nil)
)
