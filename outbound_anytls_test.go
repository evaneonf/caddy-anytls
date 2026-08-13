package anytls

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	M "github.com/sagernet/sing/common/metadata"
)

func TestAnyTLSOutboundRelaysSessionAndRewritesPassword(t *testing.T) {
	certificate := newTestCertificate(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate},
	})
	if err != nil {
		t.Fatalf("tls.Listen() error = %v", err)
	}
	t.Cleanup(func() { closeTest(listener) })

	upstreamPassword := "upstream-secret"
	wantHash := sha256.Sum256([]byte(upstreamPassword))
	upstreamReceived := make(chan []byte, 1)
	upstreamErr := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			upstreamErr <- acceptErr
			return
		}
		defer closeTest(conn)

		request := make([]byte, 32+len("session-payload"))
		if _, readErr := io.ReadFull(conn, request); readErr != nil {
			upstreamErr <- readErr
			return
		}
		upstreamReceived <- request
		if _, writeErr := conn.Write([]byte("upstream-reply")); writeErr != nil {
			upstreamErr <- writeErr
			return
		}
		upstreamErr <- nil
	}()

	outbound := &AnyTLSOutbound{
		Address:               listener.Addr().String(),
		Password:              upstreamPassword,
		ServerName:            "example.test",
		TLSInsecureSkipVerify: true,
	}
	if err := outbound.Provision(caddy.Context{Context: t.Context()}); err != nil {
		t.Fatalf("Provision() error = %v", err)
	}

	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() {
		closeTest(serverConn)
		closeTest(clientConn)
	})
	session := newOutboundSession(
		serverConn,
		"alice",
		M.ParseSocksaddr("192.0.2.10:12345"),
		time.Second,
		nil,
	)
	relayErr := make(chan error, 1)
	go func() { relayErr <- outbound.HandleSession(t.Context(), session) }()

	localHash := sha256.Sum256([]byte("local-secret"))
	if _, err := clientConn.Write(append(localHash[:], []byte("session-payload")...)); err != nil {
		t.Fatalf("client Write() error = %v", err)
	}
	reply := make([]byte, len("upstream-reply"))
	if _, err := io.ReadFull(clientConn, reply); err != nil {
		t.Fatalf("client ReadFull() error = %v", err)
	}
	if string(reply) != "upstream-reply" {
		t.Fatalf("reply = %q, want upstream-reply", reply)
	}
	closeTest(clientConn)

	request := <-upstreamReceived
	if string(request[:32]) != string(wantHash[:]) {
		t.Fatalf("upstream password hash was not rewritten")
	}
	if got := string(request[32:]); got != "session-payload" {
		t.Fatalf("upstream payload = %q, want session-payload", got)
	}
	if err := <-upstreamErr; err != nil {
		t.Fatalf("upstream error = %v", err)
	}
	select {
	case err := <-relayErr:
		if err != nil && err != io.EOF && err != context.Canceled {
			t.Fatalf("HandleSession() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("HandleSession() did not return")
	}
}

func TestAnyTLSOutboundCaddyfile(t *testing.T) {
	dispenser := caddyfile.NewTestDispenser(`
	anytls {
		user alice local-secret relay
		outbound relay anytls {
			address upstream.example.com:443
			password upstream-secret
			server_name edge.example.com
		}
	}
	`)
	var wrapper ListenerWrapper
	if err := wrapper.UnmarshalCaddyfile(dispenser); err != nil {
		t.Fatalf("UnmarshalCaddyfile() error = %v", err)
	}

	raw := wrapper.OutboundsRaw["relay"]
	if len(raw) == 0 {
		t.Fatal("relay outbound was not parsed")
	}
	if got := string(raw); !strings.Contains(got, `"dialer":"anytls"`) ||
		!strings.Contains(got, `"address":"upstream.example.com:443"`) ||
		!strings.Contains(got, `"server_name":"edge.example.com"`) {
		t.Fatalf("relay outbound JSON = %s", got)
	}
}

func TestAnyTLSOutboundProvisionRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name     string
		outbound AnyTLSOutbound
	}{
		{name: "missing address", outbound: AnyTLSOutbound{Password: "secret"}},
		{name: "missing port", outbound: AnyTLSOutbound{Address: "upstream.example.com", Password: "secret"}},
		{name: "missing password", outbound: AnyTLSOutbound{Address: "upstream.example.com:443"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.outbound.Provision(caddy.Context{Context: t.Context()}); err == nil {
				t.Fatal("Provision() error = nil, want validation error")
			}
		})
	}
}

func TestProvisionLoadsNamedAnyTLSOutbound(t *testing.T) {
	wrapper, err := newProvisionedWrapper(t, `{
		"users": [{"name": "alice", "password": "local-secret", "outbound": "relay"}],
		"outbounds": {
			"relay": {
				"dialer": "anytls",
				"address": "upstream.example.com:443",
				"password": "upstream-secret"
			}
		}
	}`)
	if err != nil {
		t.Fatalf("Provision() error = %v", err)
	}
	outbound, ok := wrapper.userSelections["alice"].outbound.(*AnyTLSOutbound)
	if !ok {
		t.Fatalf("alice outbound = %T, want *AnyTLSOutbound", wrapper.userSelections["alice"].outbound)
	}
	if outbound.tlsConfig == nil {
		t.Fatal("AnyTLS outbound TLS config was not provisioned")
	}
	if outbound.tlsConfig.ServerName != "upstream.example.com" {
		t.Fatalf("TLS server name = %q, want upstream.example.com", outbound.tlsConfig.ServerName)
	}
}

type captureSessionOutbound struct {
	users chan string
}

func (o *captureSessionOutbound) HandleSession(_ context.Context, session *OutboundSession) error {
	o.users <- session.User()
	return nil
}

func TestListenerSelectsAnyTLSOutboundFromDetectedUser(t *testing.T) {
	wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "local-secret", Enabled: true}})
	capture := &captureSessionOutbound{users: make(chan string, 1)}
	wrapper.userSelections = map[string]outboundSelection{
		"alice": {outbound: capture, name: "relay"},
	}
	if !wrapper.acquire() {
		t.Fatal("acquire() = false")
	}

	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() {
		closeTest(serverConn)
		closeTest(clientConn)
	})
	done := make(chan struct{})
	go func() {
		(&wrappedListener{config: wrapper}).serveAnyTLS(newBufferedConn(serverConn), 1)
		close(done)
	}()

	localHash := sha256.Sum256([]byte("local-secret"))
	if _, err := clientConn.Write(localHash[:]); err != nil {
		t.Fatalf("client Write() error = %v", err)
	}
	select {
	case user := <-capture.users:
		if user != "alice" {
			t.Fatalf("selected user = %q, want alice", user)
		}
	case <-time.After(time.Second):
		t.Fatal("AnyTLS outbound was not selected")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("serveAnyTLS() did not return")
	}
}
