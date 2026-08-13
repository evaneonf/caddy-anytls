package anytls

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/varbin"
	"github.com/sagernet/sing/protocol/socks/socks5"
	"go.uber.org/zap"
)

// recordingOutbound wraps another StreamOutbound and records the addresses it dials,
// so tests can assert the handler routes egress through the configured module.
type recordingOutbound struct {
	inner      StreamOutbound
	mu         sync.Mutex
	dialed     []M.Socksaddr
	openCount  int
	packetConn PacketConn
}

func (o *recordingOutbound) HandleSession(_ context.Context, session *OutboundSession) error {
	return session.ServeLocal(o)
}

func (o *recordingOutbound) DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	o.mu.Lock()
	o.dialed = append(o.dialed, destination)
	o.mu.Unlock()
	return o.inner.DialContext(ctx, destination)
}

func (o *recordingOutbound) OpenPacket(ctx context.Context) (PacketConn, error) {
	o.mu.Lock()
	o.openCount++
	packetConn := o.packetConn
	o.mu.Unlock()
	if packetConn != nil {
		return packetConn, nil
	}
	return o.inner.OpenPacket(ctx)
}

func (o *recordingOutbound) dials() []M.Socksaddr {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]M.Socksaddr(nil), o.dialed...)
}

type stubPacketConn struct{}

func (*stubPacketConn) ReadPacket([]byte) (int, M.Socksaddr, error) { return 0, M.Socksaddr{}, io.EOF }
func (*stubPacketConn) WritePacket([]byte, M.Socksaddr) error       { return nil }
func (*stubPacketConn) Close() error                                { return nil }

type blockingOutbound struct{}

func (o *blockingOutbound) HandleSession(_ context.Context, session *OutboundSession) error {
	return session.ServeLocal(o)
}

type contextDialerFunc func(context.Context, string, string) (net.Conn, error)

func (f contextDialerFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

func (*blockingOutbound) DialContext(ctx context.Context, _ M.Socksaddr) (net.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (*blockingOutbound) OpenPacket(ctx context.Context) (PacketConn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// testRecorderOutbound is a registered outbound module used to verify Caddyfile
// selection and module loading end to end.
type testRecorderOutbound struct {
	DirectOutbound
}

func (*testRecorderOutbound) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.anytls.outbounds.test-recorder",
		New: func() caddy.Module { return new(testRecorderOutbound) },
	}
}

// UnmarshalCaddyfile is inherited from the embedded DirectOutbound.

// testNotOutbound registers in the outbounds namespace WITHOUT implementing
// Outbound, to exercise the JSON-path type check in Provision.
type testNotOutbound struct{}

func (*testNotOutbound) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.anytls.outbounds.test-not-outbound",
		New: func() caddy.Module { return new(testNotOutbound) },
	}
}

func init() {
	caddy.RegisterModule(&testRecorderOutbound{})
	caddy.RegisterModule(&testNotOutbound{})
}

func TestDirectOutboundDialsTCP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	defer closeTest(listener)

	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		_, _ = conn.Write([]byte("ok"))
		_ = conn.Close()
	}()

	var outbound DirectOutbound
	conn, err := outbound.DialContext(t.Context(), M.ParseSocksaddr(listener.Addr().String()))
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	defer closeTest(conn)

	buf := make([]byte, 2)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if string(buf) != "ok" {
		t.Fatalf("Read() = %q, want %q", buf, "ok")
	}
}

func TestDirectOutboundOpenPacket(t *testing.T) {
	var outbound DirectOutbound
	packetConn, err := outbound.OpenPacket(t.Context())
	if err != nil {
		t.Fatalf("OpenPacket() error = %v", err)
	}
	defer closeTest(packetConn)
}

func TestSOCKS5OutboundPreservesTCPDomain(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	requestCh := make(chan socks5.Request, 1)
	serverErr := make(chan error, 1)
	go func() {
		defer closeTest(serverSide)
		request, err := serveSOCKS5Handshake(serverSide, "alice", "secret", socks5.CommandConnect, M.SocksaddrFrom(netip.IPv4Unspecified(), 0))
		if err != nil {
			serverErr <- err
			return
		}
		requestCh <- request
		data := make([]byte, 4)
		if _, err := io.ReadFull(serverSide, data); err != nil {
			serverErr <- err
			return
		}
		_, err = serverSide.Write([]byte("pong"))
		serverErr <- err
	}()

	outbound := &SOCKS5Outbound{
		Address:  "proxy.example.test:1080",
		Username: "alice",
		Password: "secret",
		dialer: contextDialerFunc(func(_ context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != "proxy.example.test:1080" {
				return nil, errors.New("unexpected proxy dial")
			}
			return clientSide, nil
		}),
	}

	destination := M.ParseSocksaddr("service.example.test:443")
	conn, err := outbound.DialContext(t.Context(), destination)
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	defer closeTest(conn)

	request := <-requestCh
	if request.Destination != destination {
		t.Fatalf("SOCKS5 destination = %s, want unresolved client domain %s", request.Destination, destination)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("ReadFull() error = %v", err)
	}
	if string(reply) != "pong" {
		t.Fatalf("reply = %q, want pong", reply)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("SOCKS5 server error = %v", err)
	}
}

func TestSOCKS5OutboundPreservesUDPDomain(t *testing.T) {
	controlClient, controlServer := net.Pipe()
	udpClient, udpServer := net.Pipe()
	requestCh := make(chan socks5.Request, 1)
	controlErr := make(chan error, 1)
	go func() {
		request, err := serveSOCKS5Handshake(controlServer, "", "", socks5.CommandUDPAssociate, M.ParseSocksaddr("127.0.0.1:53000"))
		if err != nil {
			controlErr <- err
			return
		}
		requestCh <- request
		_, err = io.Copy(io.Discard, controlServer)
		controlErr <- err
	}()

	var dialMu sync.Mutex
	dialCount := make(map[string]int)
	outbound := &SOCKS5Outbound{
		Address: "127.0.0.1:1080",
		dialer: contextDialerFunc(func(_ context.Context, network, address string) (net.Conn, error) {
			dialMu.Lock()
			defer dialMu.Unlock()
			dialCount[network]++
			switch network {
			case "tcp":
				return controlClient, nil
			case "udp":
				if address != "127.0.0.1:53000" {
					return nil, errors.New("unexpected UDP relay address")
				}
				return udpClient, nil
			default:
				return nil, errors.New("unexpected proxy network")
			}
		}),
	}

	packetConn, err := outbound.OpenPacket(t.Context())
	if err != nil {
		t.Fatalf("OpenPacket() error = %v", err)
	}
	defer closeTest(packetConn)
	request := <-requestCh
	if request.Command != socks5.CommandUDPAssociate {
		t.Fatalf("SOCKS5 command = %d, want UDP ASSOCIATE", request.Command)
	}

	destination := M.ParseSocksaddr("dns.example.test:53")
	writeErr := make(chan error, 1)
	go func() { writeErr <- packetConn.WritePacket([]byte("query"), destination) }()
	wire := make([]byte, 512)
	n, err := udpServer.Read(wire)
	if err != nil {
		t.Fatalf("read SOCKS5 UDP packet: %v", err)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("WritePacket() error = %v", err)
	}
	gotDestination, payload, err := decodeSOCKS5UDPPacket(wire[:n])
	if err != nil {
		t.Fatalf("decode SOCKS5 UDP packet: %v", err)
	}
	if gotDestination != destination || string(payload) != "query" {
		t.Fatalf("SOCKS5 UDP packet = (%s, %q), want (%s, query)", gotDestination, payload, destination)
	}

	source := M.ParseSocksaddr("reply.example.test:5353")
	encodedReply := encodeSOCKS5UDPPacket(t, source, []byte("answer"))
	replyWriteErr := make(chan error, 1)
	go func() {
		_, writeErr := udpServer.Write(encodedReply)
		replyWriteErr <- writeErr
	}()
	reply := make([]byte, 64)
	n, gotSource, err := packetConn.ReadPacket(reply)
	if err != nil {
		t.Fatalf("ReadPacket() error = %v", err)
	}
	if gotSource != source || string(reply[:n]) != "answer" {
		t.Fatalf("UDP reply = (%s, %q), want (%s, answer)", gotSource, reply[:n], source)
	}
	if err := <-replyWriteErr; err != nil {
		t.Fatalf("write SOCKS5 UDP reply: %v", err)
	}

	closeTest(packetConn)
	if err := <-controlErr; err != nil {
		t.Fatalf("SOCKS5 control connection error = %v", err)
	}
	dialMu.Lock()
	defer dialMu.Unlock()
	if dialCount["tcp"] != 1 || dialCount["udp"] != 1 {
		t.Fatalf("proxy dials = %v, want one TCP and one UDP", dialCount)
	}
}

func TestSOCKS5OutboundHandshakeHonorsContext(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	defer closeTest(serverSide)
	outbound := &SOCKS5Outbound{
		Address: "127.0.0.1:1080",
		dialer: contextDialerFunc(func(context.Context, string, string) (net.Conn, error) {
			return clientSide, nil
		}),
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	_, err := outbound.DialContext(ctx, M.ParseSocksaddr("example.test:443"))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("DialContext() error = %v, want context deadline exceeded", err)
	}
}

func TestNormalizeSOCKS5BindAddress(t *testing.T) {
	remote := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 1080}
	got, err := normalizeSOCKS5BindAddress(M.ParseSocksaddr("0.0.0.0:53000"), remote)
	if err != nil {
		t.Fatalf("normalizeSOCKS5BindAddress() error = %v", err)
	}
	if got.String() != "192.0.2.10:53000" {
		t.Fatalf("normalized bind address = %s, want 192.0.2.10:53000", got)
	}

	explicit := M.ParseSocksaddr("198.51.100.20:53000")
	got, err = normalizeSOCKS5BindAddress(explicit, remote)
	if err != nil || got != explicit {
		t.Fatalf("explicit bind address = (%s, %v), want (%s, nil)", got, err, explicit)
	}
}

func serveSOCKS5Handshake(conn net.Conn, username, password string, command byte, bind M.Socksaddr) (socks5.Request, error) {
	reader := varbin.StubReader(conn)
	authRequest, err := socks5.ReadAuthRequest(reader)
	if err != nil {
		return socks5.Request{}, err
	}
	wantMethod := socks5.AuthTypeNotRequired
	if username != "" {
		wantMethod = socks5.AuthTypeUsernamePassword
	}
	if len(authRequest.Methods) != 1 || authRequest.Methods[0] != wantMethod {
		return socks5.Request{}, errors.New("unexpected SOCKS5 auth method")
	}
	if err := socks5.WriteAuthResponse(conn, socks5.AuthResponse{Method: wantMethod}); err != nil {
		return socks5.Request{}, err
	}
	if wantMethod == socks5.AuthTypeUsernamePassword {
		credentials, err := socks5.ReadUsernamePasswordAuthRequest(reader)
		if err != nil {
			return socks5.Request{}, err
		}
		if credentials.Username != username || credentials.Password != password {
			return socks5.Request{}, errors.New("unexpected SOCKS5 credentials")
		}
		if err := socks5.WriteUsernamePasswordAuthResponse(conn, socks5.UsernamePasswordAuthResponse{Status: socks5.UsernamePasswordStatusSuccess}); err != nil {
			return socks5.Request{}, err
		}
	}
	request, err := socks5.ReadRequest(reader)
	if err != nil {
		return socks5.Request{}, err
	}
	if request.Command != command {
		return socks5.Request{}, errors.New("unexpected SOCKS5 command")
	}
	if err := socks5.WriteResponse(conn, socks5.Response{ReplyCode: socks5.ReplyCodeSuccess, Bind: bind}); err != nil {
		return socks5.Request{}, err
	}
	return request, nil
}

func decodeSOCKS5UDPPacket(packet []byte) (M.Socksaddr, []byte, error) {
	if len(packet) < 3 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		return M.Socksaddr{}, nil, errors.New("invalid SOCKS5 UDP header")
	}
	reader := bytes.NewReader(packet[3:])
	destination, err := M.SocksaddrSerializer.ReadAddrPort(reader)
	if err != nil {
		return M.Socksaddr{}, nil, err
	}
	return destination, packet[len(packet)-reader.Len():], nil
}

func encodeSOCKS5UDPPacket(t *testing.T, source M.Socksaddr, payload []byte) []byte {
	t.Helper()
	packet := buf.NewSize(3 + M.SocksaddrSerializer.AddrPortLen(source) + len(payload))
	defer packet.Release()
	if err := packet.WriteZeroN(3); err != nil {
		t.Fatalf("write SOCKS5 UDP header: %v", err)
	}
	if err := M.SocksaddrSerializer.WriteAddrPort(packet, source); err != nil {
		t.Fatalf("write SOCKS5 UDP source: %v", err)
	}
	if _, err := packet.Write(payload); err != nil {
		t.Fatalf("write SOCKS5 UDP payload: %v", err)
	}
	return append([]byte(nil), packet.Bytes()...)
}

func TestUnmarshalCaddyfileRejectsUnnamedOutbound(t *testing.T) {
	dispenser := caddyfile.NewTestDispenser(`
	anytls {
		user alice secret
		outbound direct
	}
	`)

	var wrapper ListenerWrapper
	if err := wrapper.UnmarshalCaddyfile(dispenser); err == nil {
		t.Fatal("UnmarshalCaddyfile() error = nil, want named outbound requirement")
	}
}

func TestUnmarshalCaddyfileSOCKS5Outbound(t *testing.T) {
	dispenser := caddyfile.NewTestDispenser(`
	anytls {
		user alice secret proxy
		outbound proxy socks5 {
			address 127.0.0.1:1080
			username proxy-user
			password proxy-pass
		}
		default_outbound proxy
	}
	`)

	var wrapper ListenerWrapper
	if err := wrapper.UnmarshalCaddyfile(dispenser); err != nil {
		t.Fatalf("UnmarshalCaddyfile() error = %v", err)
	}
	raw := wrapper.OutboundsRaw["proxy"]
	var config struct {
		Dialer   string `json:"dialer"`
		Address  string `json:"address"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal(raw, &config); err != nil {
		t.Fatalf("unmarshal socks5 outbound JSON: %v", err)
	}
	if config.Dialer != "socks5" || config.Address != "127.0.0.1:1080" || config.Username != "proxy-user" || config.Password != "proxy-pass" {
		t.Fatalf("socks5 outbound JSON = %#v", config)
	}
}

func TestProvisionSOCKS5Outbound(t *testing.T) {
	wrapper, err := newProvisionedWrapper(t, `{
		"users": [{"name": "alice", "password": "secret", "outbound": "proxy"}],
		"outbounds": {
			"proxy": {
				"dialer": "socks5",
				"address": "127.0.0.1:1080",
				"username": "proxy-user",
				"password": "proxy-pass"
			}
		}
	}`)
	if err != nil {
		t.Fatalf("Provision() error = %v", err)
	}
	outbound, ok := wrapper.userSelections["alice"].outbound.(*SOCKS5Outbound)
	if !ok {
		t.Fatalf("alice outbound = %T, want *SOCKS5Outbound", wrapper.userSelections["alice"].outbound)
	}
	if outbound.Address != "127.0.0.1:1080" || outbound.Username != "proxy-user" || outbound.Password != "proxy-pass" {
		t.Fatalf("SOCKS5 outbound = %#v", outbound)
	}
}

func TestSOCKS5OutboundRejectsInvalidConfiguration(t *testing.T) {
	for _, test := range []struct {
		name     string
		outbound SOCKS5Outbound
	}{
		{name: "missing address", outbound: SOCKS5Outbound{}},
		{name: "missing port", outbound: SOCKS5Outbound{Address: "127.0.0.1"}},
		{name: "password without username", outbound: SOCKS5Outbound{Address: "127.0.0.1:1080", Password: "secret"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.outbound.Provision(caddy.Context{Context: t.Context()}); err == nil {
				t.Fatal("Provision() error = nil, want invalid configuration error")
			}
		})
	}
}

func TestUnmarshalCaddyfileRejectsDuplicateOutbound(t *testing.T) {
	dispenser := caddyfile.NewTestDispenser(`
	anytls {
		user alice secret
		outbound proxy direct
		outbound proxy direct
	}
	`)

	var wrapper ListenerWrapper
	if err := wrapper.UnmarshalCaddyfile(dispenser); err == nil {
		t.Fatal("UnmarshalCaddyfile() error = nil, want duplicate outbound error")
	}
}

func TestUnmarshalCaddyfileRejectsUnknownOutbound(t *testing.T) {
	dispenser := caddyfile.NewTestDispenser(`
	anytls {
		user alice secret
		outbound missing
	}
	`)

	var wrapper ListenerWrapper
	if err := wrapper.UnmarshalCaddyfile(dispenser); err == nil {
		t.Fatal("UnmarshalCaddyfile() error = nil, want unknown module error")
	}
}

func TestProvisionDefaultsToDirectOutbound(t *testing.T) {
	wrapper := &ListenerWrapper{
		Users:    []User{{Name: "alice", Password: "secret", Enabled: true}},
		logger:   zap.NewNop(),
		registry: newSessionRegistry(),
	}
	if err := wrapper.Provision(caddy.Context{Context: t.Context()}); err != nil {
		t.Fatalf("Provision() error = %v", err)
	}
	if _, ok := wrapper.defaultSelection.outbound.(*DirectOutbound); !ok || wrapper.defaultSelection.name != "direct" {
		t.Fatalf("default outbound = (%T, %q), want (*DirectOutbound, direct)", wrapper.defaultSelection.outbound, wrapper.defaultSelection.name)
	}
}

func TestUnmarshalJSONRejectsLegacyUnnamedOutbound(t *testing.T) {
	var wrapper ListenerWrapper
	if err := json.Unmarshal([]byte(`{"users":[{"name":"alice","password":"secret"}],"outbound":{"dialer":"direct"}}`), &wrapper); err == nil {
		t.Fatal("json.Unmarshal() error = nil, want legacy outbound field rejection")
	}
}

func TestProvisionLoadsConfiguredDefaultOutbound(t *testing.T) {
	dispenser := caddyfile.NewTestDispenser(`
	anytls {
		user alice secret
		outbound proxy test-recorder
		default_outbound proxy
	}
	`)

	wrapper := &ListenerWrapper{
		logger:   zap.NewNop(),
		registry: newSessionRegistry(),
	}
	if err := wrapper.UnmarshalCaddyfile(dispenser); err != nil {
		t.Fatalf("UnmarshalCaddyfile() error = %v", err)
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	defer cancel()
	if err := wrapper.Provision(ctx); err != nil {
		t.Fatalf("Provision() error = %v", err)
	}
	if _, ok := wrapper.defaultSelection.outbound.(*testRecorderOutbound); !ok || wrapper.defaultSelection.name != "proxy" {
		t.Fatalf("default outbound = (%T, %q), want (*testRecorderOutbound, proxy)", wrapper.defaultSelection.outbound, wrapper.defaultSelection.name)
	}
}

func TestProvisionRejectsNonOutboundModule(t *testing.T) {
	wrapper := &ListenerWrapper{
		Users:        []User{{Name: "alice", Password: "secret", Enabled: true}},
		OutboundsRaw: map[string]json.RawMessage{"bad": json.RawMessage(`{"dialer":"test-not-outbound"}`)},
		logger:       zap.NewNop(),
		registry:     newSessionRegistry(),
	}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	defer cancel()
	err := wrapper.Provision(ctx)
	if err == nil || !strings.Contains(err.Error(), "is not an anytls outbound") {
		t.Fatalf("Provision() error = %v, want rejection of a module that does not implement Outbound", err)
	}
}

func TestDirectOutboundUnmarshalCaddyfileRejectsConfig(t *testing.T) {
	if err := new(DirectOutbound).UnmarshalCaddyfile(caddyfile.NewTestDispenser("direct extra")); err == nil {
		t.Fatal("UnmarshalCaddyfile() accepted an extra argument, want error")
	}
	if err := new(DirectOutbound).UnmarshalCaddyfile(caddyfile.NewTestDispenser("direct {\n\tfoo\n}")); err == nil {
		t.Fatal("UnmarshalCaddyfile() accepted a config block, want error")
	}
}

func TestHandlerDialsThroughConfiguredOutbound(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	defer closeTest(listener)
	go acceptLoop(t.Context(), listener)

	recorder := &recordingOutbound{inner: new(DirectOutbound)}
	wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}})
	wrapper.defaultSelection = outboundSelection{outbound: recorder, name: "proxy"}

	handler := &proxyHandler{config: wrapper}
	conn, err := handler.dialContext(t.Context(), M.ParseSocksaddr(listener.Addr().String()))
	if err != nil {
		t.Fatalf("dialContext() error = %v", err)
	}
	closeTest(conn)

	dials := recorder.dials()
	if len(dials) != 1 || dials[0].String() != listener.Addr().String() {
		t.Fatalf("recorded dials = %v, want [%s]", dials, listener.Addr().String())
	}
}

func TestHandlerOpensPacketsThroughConfiguredOutbound(t *testing.T) {
	packetConn := new(stubPacketConn)
	recorder := &recordingOutbound{packetConn: packetConn}
	wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}})
	wrapper.defaultSelection = outboundSelection{outbound: recorder, name: "proxy"}

	got, err := (&proxyHandler{config: wrapper}).openPacketContext(t.Context())
	if err != nil {
		t.Fatalf("openPacketContext() error = %v", err)
	}
	if got != packetConn {
		t.Fatalf("openPacketContext() = %T, want configured packet connection", got)
	}
	recorder.mu.Lock()
	openCount := recorder.openCount
	recorder.mu.Unlock()
	if openCount != 1 {
		t.Fatalf("OpenPacket() call count = %d, want 1", openCount)
	}
}

func TestHandlerOutboundDialHonorsConnectTimeout(t *testing.T) {
	wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}})
	wrapper.ConnectTimeout = caddy.Duration(20 * time.Millisecond)
	wrapper.defaultSelection = outboundSelection{outbound: new(blockingOutbound), name: "proxy"}

	_, err := (&proxyHandler{config: wrapper}).dialContext(t.Context(), M.ParseSocksaddr("192.0.2.1:443"))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("dialContext() error = %v, want context deadline exceeded", err)
	}
}

func TestHandlerOutboundOpenPacketHonorsConnectTimeout(t *testing.T) {
	wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}})
	wrapper.ConnectTimeout = caddy.Duration(20 * time.Millisecond)
	wrapper.defaultSelection = outboundSelection{outbound: new(blockingOutbound), name: "proxy"}

	_, err := (&proxyHandler{config: wrapper}).openPacketContext(t.Context())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("openPacketContext() error = %v, want context deadline exceeded", err)
	}
}

func TestHandlerOutboundDialPropagatesCancellation(t *testing.T) {
	wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}})
	wrapper.ConnectTimeout = caddy.Duration(time.Second)
	wrapper.defaultSelection = outboundSelection{outbound: new(blockingOutbound), name: "proxy"}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := (&proxyHandler{config: wrapper}).dialContext(ctx, M.ParseSocksaddr("192.0.2.1:443"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("dialContext() error = %v, want context canceled", err)
	}
}

func TestHandlerPassesClientTargetToSelectedOutbound(t *testing.T) {
	for _, address := range []string{"service.test:443", "127.0.0.1:8080"} {
		t.Run(address, func(t *testing.T) {
			recorder := &recordingOutbound{inner: new(blockingOutbound)}
			wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}})
			wrapper.userSelections = map[string]outboundSelection{
				"alice": {outbound: recorder, name: "proxy"},
			}

			ctx, cancel := context.WithCancel(auth.ContextWithUser(t.Context(), "alice"))
			cancel()
			_, _ = (&proxyHandler{config: wrapper}).dialContext(ctx, M.ParseSocksaddr(address))

			dials := recorder.dials()
			if len(dials) != 1 || dials[0].String() != address {
				t.Fatalf("recorded dials = %v, want [%s]", dials, address)
			}
		})
	}
}

func TestUnmarshalCaddyfileNamedOutbounds(t *testing.T) {
	dispenser := caddyfile.NewTestDispenser(`
	anytls {
		user alice secret exit-a
		user bob secret2
		outbound exit-a test-recorder
		outbound exit-b direct
		default_outbound exit-b
	}
	`)

	var wrapper ListenerWrapper
	if err := wrapper.UnmarshalCaddyfile(dispenser); err != nil {
		t.Fatalf("UnmarshalCaddyfile() error = %v", err)
	}

	if len(wrapper.OutboundsRaw) != 2 {
		t.Fatalf("len(OutboundsRaw) = %d, want 2", len(wrapper.OutboundsRaw))
	}
	for name, wantDialer := range map[string]string{"exit-a": "test-recorder", "exit-b": "direct"} {
		raw, ok := wrapper.OutboundsRaw[name]
		if !ok {
			t.Fatalf("OutboundsRaw missing key %q", name)
		}
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil {
			t.Fatalf("OutboundsRaw[%q] is not a JSON object: %v", name, err)
		}
		var dialer string
		if err := json.Unmarshal(object["dialer"], &dialer); err != nil {
			t.Fatalf("OutboundsRaw[%q] dialer key not decodable: %v", name, err)
		}
		if dialer != wantDialer {
			t.Fatalf("OutboundsRaw[%q] dialer = %q, want %q", name, dialer, wantDialer)
		}
	}
	if wrapper.DefaultOutbound != "exit-b" {
		t.Fatalf("DefaultOutbound = %q, want %q", wrapper.DefaultOutbound, "exit-b")
	}
	if len(wrapper.Users) != 2 || wrapper.Users[0].Outbound != "exit-a" || wrapper.Users[1].Outbound != "" {
		t.Fatalf("Users = %#v, want alice with outbound exit-a and bob without", wrapper.Users)
	}
}

func TestUnmarshalCaddyfileRejectsDuplicateNamedOutbound(t *testing.T) {
	dispenser := caddyfile.NewTestDispenser(`
	anytls {
		user alice secret
		outbound proxy direct
		outbound proxy direct
	}
	`)

	var wrapper ListenerWrapper
	err := wrapper.UnmarshalCaddyfile(dispenser)
	if err == nil || !strings.Contains(err.Error(), "may only be declared once") {
		t.Fatalf("UnmarshalCaddyfile() error = %v, want duplicate named outbound error", err)
	}
}

func TestUnmarshalCaddyfileRejectsDuplicateDefaultOutbound(t *testing.T) {
	dispenser := caddyfile.NewTestDispenser(`
	anytls {
		user alice secret
		outbound proxy direct
		default_outbound proxy
		default_outbound proxy
	}
	`)

	var wrapper ListenerWrapper
	err := wrapper.UnmarshalCaddyfile(dispenser)
	if err == nil || !strings.Contains(err.Error(), "may only be specified once") {
		t.Fatalf("UnmarshalCaddyfile() error = %v, want duplicate default_outbound error", err)
	}
}

func TestUnmarshalCaddyfileDefaultOutboundArgCount(t *testing.T) {
	for name, input := range map[string]string{
		"missing argument": "anytls {\n\tdefault_outbound\n}",
		"extra argument":   "anytls {\n\tdefault_outbound proxy extra\n}",
	} {
		t.Run(name, func(t *testing.T) {
			var wrapper ListenerWrapper
			if err := wrapper.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err == nil {
				t.Fatal("UnmarshalCaddyfile() error = nil, want argument count error")
			}
		})
	}
}

func TestUnmarshalCaddyfileUserArgCount(t *testing.T) {
	for name, input := range map[string]string{
		"one argument":   "anytls {\n\tuser alice\n}",
		"four arguments": "anytls {\n\tuser alice secret proxy extra\n}",
	} {
		t.Run(name, func(t *testing.T) {
			var wrapper ListenerWrapper
			if err := wrapper.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err == nil {
				t.Fatal("UnmarshalCaddyfile() error = nil, want argument count error")
			}
		})
	}
}

func TestUnmarshalJSONNamedOutboundFields(t *testing.T) {
	input := `{
		"users": [{"name": "alice", "password": "secret", "outbound": "proxy"}],
		"outbounds": {"proxy": {"dialer": "direct"}},
		"default_outbound": "proxy"
	}`

	var wrapper ListenerWrapper
	if err := json.Unmarshal([]byte(input), &wrapper); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if _, ok := wrapper.OutboundsRaw["proxy"]; !ok {
		t.Fatalf("OutboundsRaw = %v, want key proxy", wrapper.OutboundsRaw)
	}
	if wrapper.DefaultOutbound != "proxy" {
		t.Fatalf("DefaultOutbound = %q, want %q", wrapper.DefaultOutbound, "proxy")
	}
	if len(wrapper.Users) != 1 || wrapper.Users[0].Outbound != "proxy" {
		t.Fatalf("Users = %#v, want alice referencing proxy", wrapper.Users)
	}
}

func newProvisionedWrapper(t *testing.T, configJSON string) (*ListenerWrapper, error) {
	t.Helper()

	var wrapper ListenerWrapper
	if err := json.Unmarshal([]byte(configJSON), &wrapper); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	wrapper.logger = zap.NewNop()
	wrapper.registry = newSessionRegistry()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	t.Cleanup(cancel)
	return &wrapper, wrapper.Provision(ctx)
}

func TestProvisionNamedOutboundsAndUserMaps(t *testing.T) {
	wrapper, err := newProvisionedWrapper(t, `{
		"users": [
			{"name": "alice", "password": "a-pw", "outbound": "rec"},
			{"name": "bob", "password": "b-pw", "outbound": "direct"},
			{"name": "carol", "password": "c-pw"}
		],
		"outbounds": {
			"rec": {"dialer": "test-recorder"},
			"other": {"dialer": "direct"}
		},
		"default_outbound": "other"
	}`)
	if err != nil {
		t.Fatalf("Provision() error = %v", err)
	}

	if len(wrapper.namedOutbounds) != 3 {
		t.Fatalf("len(namedOutbounds) = %d, want 3 (rec, other, injected direct)", len(wrapper.namedOutbounds))
	}
	if _, ok := wrapper.namedOutbounds["rec"].(*testRecorderOutbound); !ok {
		t.Fatalf("namedOutbounds[rec] = %T, want *testRecorderOutbound", wrapper.namedOutbounds["rec"])
	}
	if _, ok := wrapper.namedOutbounds["direct"].(*DirectOutbound); !ok {
		t.Fatalf("namedOutbounds[direct] = %T, want injected *DirectOutbound", wrapper.namedOutbounds["direct"])
	}
	if wrapper.defaultSelection.outbound != wrapper.namedOutbounds["other"] || wrapper.defaultSelection.name != "other" {
		t.Fatalf("default outbound = (%T, %q), want (namedOutbounds[other], other)", wrapper.defaultSelection.outbound, wrapper.defaultSelection.name)
	}
	if len(wrapper.userSelections) != 2 {
		t.Fatalf("len(userSelections) = %d, want 2: only explicit references get entries", len(wrapper.userSelections))
	}
	if selection := wrapper.userSelections["alice"]; selection.outbound != wrapper.namedOutbounds["rec"] || selection.name != "rec" {
		t.Fatalf("alice outbound = (%T, %q), want (namedOutbounds[rec], rec)", selection.outbound, selection.name)
	}
	if selection := wrapper.userSelections["bob"]; selection.outbound != wrapper.namedOutbounds["direct"] || selection.name != "direct" {
		t.Fatalf("bob outbound = (%T, %q), want the built-in direct without a declaration", selection.outbound, selection.name)
	}
	if _, ok := wrapper.userSelections["carol"]; ok {
		t.Fatal("userSelections has entry for carol, want none for users without explicit outbound")
	}
}

func TestProvisionDefaultOutboundResolution(t *testing.T) {
	t.Run("configured named default", func(t *testing.T) {
		wrapper, err := newProvisionedWrapper(t, `{
			"users": [{"name": "alice", "password": "secret"}],
			"outbounds": {"named": {"dialer": "test-recorder"}},
			"default_outbound": "named"
		}`)
		if err != nil {
			t.Fatalf("Provision() error = %v", err)
		}
		if wrapper.defaultSelection.outbound != wrapper.namedOutbounds["named"] || wrapper.defaultSelection.name != "named" {
			t.Fatalf("default outbound = (%T, %q), want (namedOutbounds[named], named)", wrapper.defaultSelection.outbound, wrapper.defaultSelection.name)
		}
	})

	t.Run("no outbound falls back to direct", func(t *testing.T) {
		wrapper, err := newProvisionedWrapper(t, `{
			"users": [{"name": "alice", "password": "secret"}]
		}`)
		if err != nil {
			t.Fatalf("Provision() error = %v", err)
		}
		if _, ok := wrapper.defaultSelection.outbound.(*DirectOutbound); !ok || wrapper.defaultSelection.name != "direct" {
			t.Fatalf("default outbound = (%T, %q), want (*DirectOutbound, direct)", wrapper.defaultSelection.outbound, wrapper.defaultSelection.name)
		}
	})
}

func TestProvisionRejectsReservedOutboundNames(t *testing.T) {
	for _, reserved := range []string{"direct"} {
		t.Run("json declares "+reserved, func(t *testing.T) {
			_, err := newProvisionedWrapper(t, `{
				"users": [{"name": "alice", "password": "secret"}],
				"outbounds": {"`+reserved+`": {"dialer": "direct"}}
			}`)
			if err == nil || !strings.Contains(err.Error(), "reserved") {
				t.Fatalf("Provision() error = %v, want reserved name error", err)
			}
		})
	}

	t.Run("caddyfile declares direct", func(t *testing.T) {
		dispenser := caddyfile.NewTestDispenser(`
		anytls {
			user alice secret
			outbound direct direct
		}
		`)
		wrapper := &ListenerWrapper{logger: zap.NewNop(), registry: newSessionRegistry()}
		if err := wrapper.UnmarshalCaddyfile(dispenser); err != nil {
			t.Fatalf("UnmarshalCaddyfile() error = %v", err)
		}
		ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
		defer cancel()
		err := wrapper.Provision(ctx)
		if err == nil || !strings.Contains(err.Error(), "reserved") {
			t.Fatalf("Provision() error = %v, want reserved name error", err)
		}
	})
}

func TestProvisionRejectsUndeclaredOutboundReferences(t *testing.T) {
	t.Run("json user reference", func(t *testing.T) {
		_, err := newProvisionedWrapper(t, `{
			"users": [{"name": "alice", "password": "secret", "outbound": "missing"}]
		}`)
		if err == nil || !strings.Contains(err.Error(), "undeclared") {
			t.Fatalf("Provision() error = %v, want undeclared outbound error", err)
		}
	})

	t.Run("json default_outbound reference", func(t *testing.T) {
		_, err := newProvisionedWrapper(t, `{
			"users": [{"name": "alice", "password": "secret"}],
			"default_outbound": "missing"
		}`)
		if err == nil || !strings.Contains(err.Error(), "undeclared") {
			t.Fatalf("Provision() error = %v, want undeclared outbound error", err)
		}
	})

	t.Run("caddyfile user reference", func(t *testing.T) {
		dispenser := caddyfile.NewTestDispenser(`
		anytls {
			user alice secret missing
		}
		`)
		wrapper := &ListenerWrapper{logger: zap.NewNop(), registry: newSessionRegistry()}
		if err := wrapper.UnmarshalCaddyfile(dispenser); err != nil {
			t.Fatalf("UnmarshalCaddyfile() error = %v", err)
		}
		ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
		defer cancel()
		err := wrapper.Provision(ctx)
		if err == nil || !strings.Contains(err.Error(), "undeclared") {
			t.Fatalf("Provision() error = %v, want undeclared outbound error", err)
		}
	})
}

func TestProvisionAllowsDirectReferenceWithoutDeclaration(t *testing.T) {
	wrapper, err := newProvisionedWrapper(t, `{
		"users": [{"name": "alice", "password": "secret", "outbound": "direct"}]
	}`)
	if err != nil {
		t.Fatalf("Provision() error = %v", err)
	}
	if _, ok := wrapper.userSelections["alice"].outbound.(*DirectOutbound); !ok {
		t.Fatalf("userSelections[alice].outbound = %T, want *DirectOutbound", wrapper.userSelections["alice"].outbound)
	}
	if wrapper.userSelections["alice"].name != "direct" {
		t.Fatalf("userSelections[alice].name = %q, want %q", wrapper.userSelections["alice"].name, "direct")
	}
}

func TestProvisionRejectsEmptyNamedOutboundName(t *testing.T) {
	wrapper := &ListenerWrapper{
		Users:        []User{{Name: "alice", Password: "secret", Enabled: true}},
		OutboundsRaw: map[string]json.RawMessage{"": json.RawMessage(`{"dialer":"direct"}`)},
		logger:       zap.NewNop(),
		registry:     newSessionRegistry(),
	}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	defer cancel()
	err := wrapper.Provision(ctx)
	if err == nil || !strings.Contains(err.Error(), "empty name") {
		t.Fatalf("Provision() error = %v, want empty name error", err)
	}
}

func TestProvisionRejectsNonOutboundNamedModule(t *testing.T) {
	_, err := newProvisionedWrapper(t, `{
		"users": [{"name": "alice", "password": "secret"}],
		"outbounds": {"bad": {"dialer": "test-not-outbound"}}
	}`)
	if err == nil || !strings.Contains(err.Error(), "is not an anytls outbound") {
		t.Fatalf("Provision() error = %v, want rejection of a module that does not implement Outbound", err)
	}
}

func TestOutboundForUserSelection(t *testing.T) {
	recorder := &recordingOutbound{inner: new(DirectOutbound)}
	named := &recordingOutbound{inner: new(DirectOutbound)}

	// Nothing configured at all uses the built-in direct outbound.
	bare := &proxyHandler{config: &ListenerWrapper{}}
	selection := bare.outboundForUser(t.Context())
	if _, ok := selection.outbound.(*DirectOutbound); !ok || selection.name != "direct" {
		t.Fatalf("bare wrapper outbound = (%T, %q), want (*DirectOutbound, direct)", selection.outbound, selection.name)
	}

	wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}})
	handler := &proxyHandler{config: wrapper}
	// A configured default applies when the user has no explicit selection.
	wrapper.defaultSelection = outboundSelection{outbound: named, name: "exit-home"}
	selection = handler.outboundForUser(t.Context())
	if selection.outbound != Outbound(named) || selection.name != "exit-home" {
		t.Fatalf("default tier = (%T, %q), want (named default, exit-home)", selection.outbound, selection.name)
	}

	// An explicit per-user reference wins over the configured default.
	wrapper.userSelections = map[string]outboundSelection{
		"alice": {outbound: recorder, name: "exit-a"},
	}
	selection = handler.outboundForUser(auth.ContextWithUser(t.Context(), "alice"))
	if selection.outbound != Outbound(recorder) || selection.name != "exit-a" {
		t.Fatalf("user tier = (%T, %q), want (user outbound, exit-a)", selection.outbound, selection.name)
	}
	// Unknown users still get the default.
	selection = handler.outboundForUser(auth.ContextWithUser(t.Context(), "mallory"))
	if selection.outbound != Outbound(named) || selection.name != "exit-home" {
		t.Fatalf("unknown user = (%T, %q), want the default outbound", selection.outbound, selection.name)
	}
}

// Each connection must use the outbound selected for its authenticated user.
func TestDialContextSelectsPerUserOutbound(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	defer closeTest(listener)
	go acceptLoop(t.Context(), listener)
	address := listener.Addr().String()

	recA := &recordingOutbound{inner: new(DirectOutbound)}
	recB := &recordingOutbound{inner: new(DirectOutbound)}
	recDefault := &recordingOutbound{inner: new(DirectOutbound)}
	users := []User{
		{Name: "alice", Password: "a-pw", Enabled: true, Outbound: "exit-a"},
		{Name: "bob", Password: "b-pw", Enabled: true, Outbound: "exit-b"},
		{Name: "carol", Password: "c-pw", Enabled: true},
	}
	wrapper := newTestWrapper(t, users)
	wrapper.defaultSelection = outboundSelection{outbound: recDefault, name: "default-exit"}
	wrapper.userSelections = map[string]outboundSelection{
		"alice": {outbound: recA, name: "exit-a"},
		"bob":   {outbound: recB, name: "exit-b"},
	}
	handler := &proxyHandler{config: wrapper}

	for _, tt := range []struct {
		user     string
		recorder *recordingOutbound
	}{
		{user: "alice", recorder: recA},
		{user: "bob", recorder: recB},
		{user: "carol", recorder: recDefault},
	} {
		conn, err := handler.dialContext(auth.ContextWithUser(t.Context(), tt.user), M.ParseSocksaddr(address))
		if err != nil {
			t.Fatalf("dialContext(%s) error = %v", tt.user, err)
		}
		closeTest(conn)
		dials := tt.recorder.dials()
		if len(dials) != 1 || dials[0].String() != address {
			t.Fatalf("user %s recorded dials = %v, want exactly [%s]", tt.user, dials, address)
		}
	}

	if extra := recA.dials(); len(extra) != 1 {
		t.Fatalf("recA dials = %v, want no cross-user dials", extra)
	}
	if extra := recB.dials(); len(extra) != 1 {
		t.Fatalf("recB dials = %v, want no cross-user dials", extra)
	}
}

func TestOpenPacketContextSelectsPerUserOutbound(t *testing.T) {
	packetA := new(stubPacketConn)
	packetB := new(stubPacketConn)
	packetDefault := new(stubPacketConn)
	recA := &recordingOutbound{packetConn: packetA}
	recB := &recordingOutbound{packetConn: packetB}
	recDefault := &recordingOutbound{packetConn: packetDefault}

	users := []User{
		{Name: "alice", Password: "a-pw", Enabled: true, Outbound: "exit-a"},
		{Name: "bob", Password: "b-pw", Enabled: true, Outbound: "exit-b"},
	}
	wrapper := newTestWrapper(t, users)
	wrapper.defaultSelection = outboundSelection{outbound: recDefault, name: "default-exit"}
	wrapper.userSelections = map[string]outboundSelection{
		"alice": {outbound: recA, name: "exit-a"},
		"bob":   {outbound: recB, name: "exit-b"},
	}
	handler := &proxyHandler{config: wrapper}

	for _, tt := range []struct {
		name string
		ctx  context.Context
		want PacketConn
	}{
		{name: "alice", ctx: auth.ContextWithUser(t.Context(), "alice"), want: packetA},
		{name: "bob", ctx: auth.ContextWithUser(t.Context(), "bob"), want: packetB},
		{name: "no user", ctx: t.Context(), want: packetDefault},
	} {
		got, err := handler.openPacketContext(tt.ctx)
		if err != nil {
			t.Fatalf("openPacketContext(%s) error = %v", tt.name, err)
		}
		if got != tt.want {
			t.Fatalf("openPacketContext(%s) = %p, want the per-user packet connection", tt.name, got)
		}
	}
}
