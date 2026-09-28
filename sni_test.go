package anytls

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"golang.org/x/net/http2"
)

func TestSNIConfiguration(t *testing.T) {
	for _, name := range []string{"proxy.example.com", "PROXY.example.com", "xn--bcher-kva.example"} {
		t.Run(name, func(t *testing.T) {
			var wrapper ListenerWrapper
			data, _ := json.Marshal(map[string]string{"sni": name})
			if err := json.Unmarshal(data, &wrapper); err != nil {
				t.Fatal(err)
			}
			if wrapper.SNI != name {
				t.Fatalf("SNI = %q", wrapper.SNI)
			}
			if err := wrapper.Validate(); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, name := range []string{"", "*.example.com", "example.com:443", "https://example.com", "127.0.0.1", "::1", "a..com", "-a.com", "a-.com", "a b.com", "{host}", strings.Repeat("a", 64) + ".com"} {
		t.Run(name, func(t *testing.T) {
			wrapper := &ListenerWrapper{SNI: name}
			if wrapper.Validate() == nil {
				t.Fatal("accepted invalid SNI")
			}
		})
	}

}

func TestSNIRoutingAfterTLSHandshake(t *testing.T) {
	certificate := newTestCertificate(t)
	hash := sha256.Sum256([]byte("secret"))
	unknownHash := sha256.Sum256([]byte("unknown"))
	for _, tt := range []struct {
		name, configured, clientSNI, alpn, payload string
		bypass, anytls, reject                     bool
	}{
		{name: "different SNI with correct password", configured: "proxy.example.com", clientSNI: "other.example.com", payload: string(hash[:]), bypass: true},
		{name: "missing SNI with correct password", configured: "proxy.example.com", payload: string(hash[:]), bypass: true},
		{name: "unknown password falls back", configured: "proxy.example.com", clientSNI: "proxy.example.com", payload: string(unknownHash[:])},
		{name: "disabled user rejected", configured: "proxy.example.com", clientSNI: "proxy.example.com", payload: string(hash[:]), reject: true},
		{name: "matching SNI", configured: "proxy.example.com", clientSNI: "proxy.example.com", payload: string(hash[:]), anytls: true},
		{name: "case insensitive SNI", configured: "proxy.example.com", clientSNI: "PROXY.EXAMPLE.COM", payload: string(hash[:]), anytls: true},
		{name: "matching HTTP1", configured: "proxy.example.com", clientSNI: "proxy.example.com", alpn: "http/1.1", payload: "GET / HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n"},
		{name: "matching HTTP2", configured: "proxy.example.com", clientSNI: "proxy.example.com", alpn: "h2", payload: http2.ClientPreface},
		{name: "other HTTP1", configured: "proxy.example.com", clientSNI: "other.example.com", alpn: "http/1.1", payload: "GET / HTTP/1.1\r\nHost: other.example.com\r\n\r\n", bypass: true},
		{name: "other HTTP2", configured: "proxy.example.com", clientSNI: "other.example.com", alpn: "h2", payload: http2.ClientPreface, bypass: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: !tt.reject}})
			wrapper.SNI = tt.configured
			wrapper.ProbeTimeout = caddy.Duration(5 * time.Second)
			capture := &captureSessionOutbound{sessions: make(chan struct{}, 1)}
			wrapper.userSelections = map[string]outboundSelection{"alice": {outbound: capture, name: "capture"}}
			serverRaw, clientRaw := net.Pipe()
			defer func() { _ = serverRaw.Close() }()
			defer func() { _ = clientRaw.Close() }()
			_ = serverRaw.SetDeadline(time.Now().Add(10 * time.Second))
			_ = clientRaw.SetDeadline(time.Now().Add(10 * time.Second))
			server := tls.Server(serverRaw, &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: []string{"h2", "http/1.1"}})
			client := tls.Client(clientRaw, &tls.Config{InsecureSkipVerify: true, ServerName: tt.clientSNI})
			if tt.alpn != "" {
				client = tls.Client(clientRaw, &tls.Config{InsecureSkipVerify: true, ServerName: tt.clientSNI, NextProtos: []string{tt.alpn}})
			}
			type result struct {
				conn net.Conn
				err  error
			}
			routed := make(chan result, 1)
			go func() {
				conn, err := (&wrappedListener{config: wrapper}).classifyAcceptedConn(server, 1)
				routed <- result{conn, err}
			}()
			if err := client.HandshakeContext(t.Context()); err != nil {
				t.Fatal(err)
			}
			var route result
			receive := func() result {
				t.Helper()
				select {
				case r := <-routed:
					return r
				case <-time.After(2 * time.Second):
					t.Fatal("routing waited for application data or timed out")
					return result{}
				}
			}
			if tt.bypass {
				route = receive()
			} // No application bytes have been sent yet.
			written := make(chan error, 1)
			go func() {
				_, err := io.WriteString(client, tt.payload)
				written <- err
				if tt.reject {
					_, _ = io.Copy(io.Discard, client)
				}
			}()
			if !tt.bypass {
				route = receive()
			}
			if route.err != nil {
				t.Fatal(route.err)
			}
			if tt.reject {
				if route.conn != nil {
					t.Fatal("disabled user fell back to website")
				}
				select {
				case <-capture.sessions:
					t.Fatal("disabled user reached outbound")
				default:
				}
			} else if tt.anytls {
				if route.conn != nil {
					t.Fatal("AnyTLS went to website")
				}
				select {
				case <-capture.sessions:
				case <-time.After(2 * time.Second):
					t.Fatal("AnyTLS outbound not called")
				}
			} else {
				if route.conn == nil {
					t.Fatal("website connection missing")
				}
				state := route.conn.(interface{ ConnectionState() tls.ConnectionState }).ConnectionState()
				if state.ServerName != tt.clientSNI || state.NegotiatedProtocol != tt.alpn || !state.HandshakeComplete {
					t.Fatalf("TLS state not preserved: %+v", state)
				}
				data := make([]byte, len(tt.payload))
				if _, err := io.ReadFull(route.conn, data); err != nil {
					t.Fatal(err)
				}
				if string(data) != tt.payload {
					t.Fatal("fallback bytes changed")
				}
				select {
				case <-capture.sessions:
					t.Fatal("SNI bypass reached AnyTLS")
				default:
				}
			}
			if err := <-written; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSNIWithoutTLSStateBypassesProbe(t *testing.T) {
	wrapper := newTestWrapper(t, nil)
	wrapper.SNI = "proxy.example.com"
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()
	// No peer write: routing must return without trying to read the password.
	conn, err := (&wrappedListener{config: wrapper}).classifyAcceptedConn(server, 1)
	if err != nil || conn != server {
		t.Fatalf("conn = %v, err = %v", conn, err)
	}
}

func TestMissingSNIRejectsConfiguration(t *testing.T) {
	for _, data := range []string{`{"users":[{"name":"alice","password":"secret"}]}`, `{"sni":"","users":[{"name":"alice","password":"secret"}]}`, `{"sni":null,"users":[{"name":"alice","password":"secret"}]}`} {
		var wrapper ListenerWrapper
		if err := json.Unmarshal([]byte(data), &wrapper); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
		err := wrapper.Provision(ctx)
		cancel()
		if err == nil || !strings.Contains(err.Error(), "sni is required") {
			t.Fatalf("Provision(%s) = %v, want required SNI error", data, err)
		}
	}
	var wrapper ListenerWrapper
	if err := wrapper.UnmarshalCaddyfile(caddyfile.NewTestDispenser("anytls {\nuser alice secret\n}")); err != nil {
		t.Fatal(err)
	}
	if err := wrapper.Validate(); err == nil || !strings.Contains(err.Error(), "sni is required") {
		t.Fatalf("Validate() = %v, want required SNI error", err)
	}
}

type captureSessionOutbound struct{ sessions chan struct{} }

func (o *captureSessionOutbound) HandleSession(context.Context, *OutboundSession) error {
	o.sessions <- struct{}{}
	return nil
}
