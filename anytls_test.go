package anytls

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	singanytls "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/padding"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	_ "github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestBufferedConnPeekPreservesBytes(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		_, _ = client.Write([]byte("GET / HTTP/1.1\r\n"))
	}()

	conn := newBufferedConn(server)
	preview, err := conn.Peek(1, time.Second)
	if err != nil {
		t.Fatalf("Peek() error = %v", err)
	}
	if string(preview) != "G" {
		t.Fatalf("Peek() = %q, want %q", string(preview), "G")
	}

	buf := make([]byte, 3)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("ReadFull() error = %v", err)
	}
	if string(buf) != "GET" {
		t.Fatalf("read bytes = %q, want %q", string(buf), "GET")
	}
}

func TestBufferedConnPreservesConnectionState(t *testing.T) {
	expected := tls.ConnectionState{
		ServerName:         "example.com",
		NegotiatedProtocol: "h2",
	}

	conn := newBufferedConn(testTLSStateConn{
		Conn:  &net.TCPConn{},
		state: expected,
	})

	got := conn.ConnectionState()
	if got.ServerName != expected.ServerName {
		t.Fatalf("ConnectionState().ServerName = %q, want %q", got.ServerName, expected.ServerName)
	}
	if got.NegotiatedProtocol != expected.NegotiatedProtocol {
		t.Fatalf("ConnectionState().NegotiatedProtocol = %q, want %q", got.NegotiatedProtocol, expected.NegotiatedProtocol)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  ListenerWrapper
		wantErr bool
	}{
		{
			name: "valid config",
			config: ListenerWrapper{
				MaxConcurrent: 1,
				Users: []User{
					{Name: "alice", Password: "secret", Enabled: true},
				},
			},
			wantErr: false,
		},
		{
			name: "duplicate user",
			config: ListenerWrapper{
				Users: []User{
					{Name: "alice", Password: "secret"},
					{Name: "alice", Password: "secret-2"},
				},
			},
			wantErr: true,
		},
		{
			name: "negative concurrency",
			config: ListenerWrapper{
				MaxConcurrent: -1,
			},
			wantErr: true,
		},
		{
			name: "empty password",
			config: ListenerWrapper{
				Users: []User{
					{Name: "alice"},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr && err == nil {
				t.Fatal("Validate() error = nil, want non-nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("Validate() error = %v, want nil", err)
			}
		})
	}
}

func TestWebsiteFallbackEndToEnd(t *testing.T) {
	wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}}, false)

	base := newChanListener()
	defer base.Close()

	wrapped := wrapper.WrapListener(base)
	request := "GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n"
	response := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"

	serverErr := make(chan error, 1)
	go func() {
		conn, err := wrapped.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()

		buf := make([]byte, len(request))
		if _, err := io.ReadFull(conn, buf); err != nil {
			serverErr <- err
			return
		}
		if string(buf) != request {
			serverErr <- io.ErrUnexpectedEOF
			return
		}

		_, err = io.WriteString(conn, response)
		serverErr <- err
	}()

	serverConn, client := net.Pipe()
	defer client.Close()
	base.enqueue(serverConn)

	if _, err := io.WriteString(client, request); err != nil {
		t.Fatalf("WriteString() error = %v", err)
	}
	body, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if string(body) != response {
		t.Fatalf("response = %q, want %q", string(body), response)
	}

	if err := <-serverErr; err != nil {
		t.Fatalf("server error = %v", err)
	}
}

func TestAnyTLSEndToEndProxy(t *testing.T) {
	destinationAddress := "service.example.internal:443"
	destination := newChanListener()
	defer destination.Close()
	wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}}, true)
	wrapper.dialFunc = func(ctx context.Context, network string, address string) (net.Conn, error) {
		if address != destinationAddress {
			return nil, errors.New("unexpected destination address")
		}
		serverConn, clientConn := net.Pipe()
		destination.enqueue(serverConn)
		return clientConn, nil
	}

	destDone := make(chan error, 1)
	go func() {
		conn, err := destination.Accept()
		if err != nil {
			destDone <- err
			return
		}
		defer conn.Close()

		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			destDone <- err
			return
		}

		_, err = io.WriteString(conn, strings.ToUpper(line))
		destDone <- err
	}()

	base := newChanListener()
	defer base.Close()

	wrapped := wrapper.WrapListener(base)
	acceptCtx, cancelAccept := context.WithCancel(context.Background())
	defer cancelAccept()
	go acceptLoop(acceptCtx, wrapped)

	client, err := singanytls.NewClient(context.Background(), singanytls.ClientConfig{
		Password:                 "secret",
		IdleSessionCheckInterval: 100 * time.Millisecond,
		IdleSessionTimeout:       time.Second,
		MinIdleSession:           0,
		DialOut: func(ctx context.Context) (net.Conn, error) {
			serverConn, clientConn := net.Pipe()
			base.enqueue(serverConn)
			return clientConn, nil
		},
		Logger: zapLogger{base: zap.NewNop()},
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	proxyConn, err := client.CreateProxy(context.Background(), M.ParseSocksaddr(destinationAddress))
	if err != nil {
		t.Fatalf("CreateProxy() error = %v", err)
	}
	defer proxyConn.Close()

	if _, err := io.WriteString(proxyConn, "hello through anytls\n"); err != nil {
		t.Fatalf("WriteString() error = %v", err)
	}

	reply, err := bufio.NewReader(proxyConn).ReadString('\n')
	if err != nil {
		t.Fatalf("ReadString() error = %v", err)
	}
	if reply != "HELLO THROUGH ANYTLS\n" {
		t.Fatalf("reply = %q, want %q", reply, "HELLO THROUGH ANYTLS\n")
	}

	if err := <-destDone; err != nil {
		t.Fatalf("destination error = %v", err)
	}
}

func TestAnyTLSEndToEndUDPOverTCP(t *testing.T) {
	serverPacketConn, handlerPacketConn := newPacketPipe()
	defer serverPacketConn.Close()
	defer handlerPacketConn.Close()

	udpDone := make(chan error, 1)
	go func() {
		buffer := make([]byte, 2048)
		n, addr, err := serverPacketConn.ReadFrom(buffer)
		if err != nil {
			udpDone <- err
			return
		}
		_, err = serverPacketConn.WriteTo([]byte(strings.ToUpper(string(buffer[:n]))), addr)
		udpDone <- err
	}()

	wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}}, true)
	wrapper.listenPacketFunc = func(ctx context.Context, network string, address string) (net.PacketConn, error) {
		return handlerPacketConn, nil
	}
	base := newChanListener()
	defer base.Close()

	wrapped := wrapper.WrapListener(base)
	acceptCtx, cancelAccept := context.WithCancel(context.Background())
	defer cancelAccept()
	go acceptLoop(acceptCtx, wrapped)

	client, err := singanytls.NewClient(context.Background(), singanytls.ClientConfig{
		Password:                 "secret",
		IdleSessionCheckInterval: 100 * time.Millisecond,
		IdleSessionTimeout:       time.Second,
		MinIdleSession:           0,
		DialOut: func(ctx context.Context) (net.Conn, error) {
			serverConn, clientConn := net.Pipe()
			base.enqueue(serverConn)
			return clientConn, nil
		},
		Logger: zapLogger{base: zap.NewNop()},
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	uotClient := &uot.Client{
		Dialer:  anyTLSTestDialer{client: client},
		Version: uot.Version,
	}

	uotConn, err := uotClient.DialContext(context.Background(), N.NetworkUDP, M.ParseSocksaddr("1.1.1.1:53"))
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	defer uotConn.Close()

	if _, err := io.WriteString(uotConn, "hello over udp\n"); err != nil {
		t.Fatalf("WriteString() error = %v", err)
	}

	reply, err := bufio.NewReader(uotConn).ReadString('\n')
	if err != nil {
		t.Fatalf("ReadString() error = %v", err)
	}
	if reply != "HELLO OVER UDP\n" {
		t.Fatalf("reply = %q, want %q", reply, "HELLO OVER UDP\n")
	}

	if err := <-udpDone; err != nil {
		t.Fatalf("udp server error = %v", err)
	}
}

func TestAnyTLSEndToEndUDPOverTCPDatagramMode(t *testing.T) {
	serverPacketConn, handlerPacketConn := newPacketPipe()
	defer serverPacketConn.Close()
	defer handlerPacketConn.Close()

	firstDone := make(chan error, 1)
	secondDone := make(chan error, 1)
	go func() {
		buffer := make([]byte, 2048)
		n, addr, err := serverPacketConn.ReadFrom(buffer)
		if err != nil {
			firstDone <- err
			return
		}
		_, err = serverPacketConn.WriteTo([]byte(strings.ToUpper(string(buffer[:n]))), addr)
		firstDone <- err
	}()
	go func() {
		buffer := make([]byte, 2048)
		n, addr, err := serverPacketConn.ReadFrom(buffer)
		if err != nil {
			secondDone <- err
			return
		}
		_, err = serverPacketConn.WriteTo([]byte(strings.ToUpper(string(buffer[:n]))), addr)
		secondDone <- err
	}()

	wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}}, true)
	wrapper.listenPacketFunc = func(ctx context.Context, network string, address string) (net.PacketConn, error) {
		return handlerPacketConn, nil
	}
	base := newChanListener()
	defer base.Close()

	go acceptLoop(context.Background(), wrapper.WrapListener(base))

	client, err := singanytls.NewClient(context.Background(), singanytls.ClientConfig{
		Password:                 "secret",
		IdleSessionCheckInterval: 100 * time.Millisecond,
		IdleSessionTimeout:       time.Second,
		MinIdleSession:           0,
		DialOut: func(ctx context.Context) (net.Conn, error) {
			serverConn, clientConn := net.Pipe()
			base.enqueue(serverConn)
			return clientConn, nil
		},
		Logger: zapLogger{base: zap.NewNop()},
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	uotClient := &uot.Client{
		Dialer:  anyTLSTestDialer{client: client},
		Version: uot.Version,
	}

	packetConn, err := uotClient.ListenPacket(context.Background(), M.ParseSocksaddr("1.1.1.1:53"))
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer packetConn.Close()

	dest1 := M.ParseSocksaddr("1.1.1.1:53")
	dest2 := M.ParseSocksaddr("8.8.8.8:53")
	if _, err := packetConn.WriteTo([]byte("first datagram"), dest1); err != nil {
		t.Fatalf("WriteTo(dest1) error = %v", err)
	}
	if _, err := packetConn.WriteTo([]byte("second datagram"), dest2); err != nil {
		t.Fatalf("WriteTo(dest2) error = %v", err)
	}

	buf := make([]byte, 2048)
	replies := make(map[string]string, 2)
	for i := 0; i < 2; i++ {
		n, addr, err := packetConn.ReadFrom(buf)
		if err != nil {
			t.Fatalf("ReadFrom() error = %v", err)
		}
		replies[addr.String()] = string(buf[:n])
	}
	if replies[dest1.String()] != "FIRST DATAGRAM" {
		t.Fatalf("reply for %s = %q, want %q", dest1.String(), replies[dest1.String()], "FIRST DATAGRAM")
	}
	if replies[dest2.String()] != "SECOND DATAGRAM" {
		t.Fatalf("reply for %s = %q, want %q", dest2.String(), replies[dest2.String()], "SECOND DATAGRAM")
	}

	if err := <-firstDone; err != nil {
		t.Fatalf("first udp server error = %v", err)
	}
	if err := <-secondDone; err != nil {
		t.Fatalf("second udp server error = %v", err)
	}
}

func TestUnmarshalCaddyfile(t *testing.T) {
	dispenser := caddyfile.NewTestDispenser(`
	anytls {
		probe_timeout 2s
		idle_timeout 3m
		connect_timeout 4s
		max_concurrent 64
		fallback true
		allow_private_targets false
		user alice secret
	}
	`)

	var wrapper ListenerWrapper
	if err := wrapper.UnmarshalCaddyfile(dispenser); err != nil {
		t.Fatalf("UnmarshalCaddyfile() error = %v", err)
	}

	if wrapper.ProbeTimeout != caddy.Duration(2*time.Second) {
		t.Fatalf("ProbeTimeout = %v, want %v", wrapper.ProbeTimeout, 2*time.Second)
	}
	if wrapper.IdleTimeout != caddy.Duration(3*time.Minute) {
		t.Fatalf("IdleTimeout = %v, want %v", wrapper.IdleTimeout, 3*time.Minute)
	}
	if wrapper.ConnectTimeout != caddy.Duration(4*time.Second) {
		t.Fatalf("ConnectTimeout = %v, want %v", wrapper.ConnectTimeout, 4*time.Second)
	}
	if wrapper.MaxConcurrent != 64 {
		t.Fatalf("MaxConcurrent = %d, want %d", wrapper.MaxConcurrent, 64)
	}
	if !wrapper.Fallback {
		t.Fatal("Fallback = false, want true")
	}
	if wrapper.AllowPrivateTargets {
		t.Fatal("AllowPrivateTargets = true, want false")
	}
	if len(wrapper.Users) != 1 || wrapper.Users[0].Name != "alice" || wrapper.Users[0].Password != "secret" || !wrapper.Users[0].Enabled {
		t.Fatalf("Users = %#v, want one enabled user", wrapper.Users)
	}
}

func TestReloadStyleUserDisableStopsNewAnyTLSDetection(t *testing.T) {
	enabled := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}}, true)
	disabled := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: false}}, true)

	sum := sha256.Sum256([]byte("secret"))
	preview := sum[:]

	decision, err := enabled.detector.Detect(preview)
	if err != nil || decision != DecisionAnyTLS {
		t.Fatalf("enabled detector = (%v, %v), want AnyTLS", decision, err)
	}

	decision, err = disabled.detector.Detect(preview)
	if err == nil || decision != DecisionReject {
		t.Fatalf("disabled detector = (%v, %v), want reject with error", decision, err)
	}
}

func TestStructuredLogsForFallbackAndProxy(t *testing.T) {
	core, logs := observer.New(zapcore.DebugLevel)
	logger := zap.New(core)

	fallbackWrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}}, false)
	fallbackWrapper.logger = logger
	fallbackWrapper.service, _ = singanytls.NewService(singanytls.ServiceConfig{
		PaddingScheme: []byte(fallbackWrapper.PaddingScheme),
		Users:         fallbackWrapper.anyTLSUsers(),
		Handler:       &directTCPHandler{config: fallbackWrapper},
		Logger:        zapLogger{base: logger},
	})

	base := newChanListener()
	defer base.Close()
	wrapped := fallbackWrapper.WrapListener(base)
	serverConn, client := net.Pipe()
	base.enqueue(serverConn)
	go func() {
		conn, err := wrapped.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()
	_, _ = io.WriteString(client, "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
	_ = client.Close()

	if !waitForLogs(logs, "connection routed to website") {
		t.Fatal("expected fallback log entry")
	}
	if logs.FilterFieldKey("outcome").Len() == 0 {
		t.Fatal("expected structured outcome field in logs")
	}
	if logs.FilterFieldKey("reason").Len() == 0 {
		t.Fatal("expected structured reason field in logs")
	}

	core2, logs2 := observer.New(zapcore.DebugLevel)
	logger2 := zap.New(core2)
	destinationAddress := "service.example.internal:443"
	destination := newChanListener()
	defer destination.Close()
	proxyWrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}}, true)
	proxyWrapper.logger = logger2
	proxyWrapper.dialFunc = func(ctx context.Context, network string, address string) (net.Conn, error) {
		if address != destinationAddress {
			return nil, errors.New("unexpected destination address")
		}
		serverConn, clientConn := net.Pipe()
		destination.enqueue(serverConn)
		return clientConn, nil
	}
	service, err := singanytls.NewService(singanytls.ServiceConfig{
		PaddingScheme: []byte(proxyWrapper.PaddingScheme),
		Users:         proxyWrapper.anyTLSUsers(),
		Handler:       &directTCPHandler{config: proxyWrapper},
		Logger:        zapLogger{base: logger2},
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	proxyWrapper.service = service

	destDone := make(chan error, 1)
	go func() {
		conn, err := destination.Accept()
		if err != nil {
			destDone <- err
			return
		}
		defer conn.Close()
		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			destDone <- err
			return
		}
		_, err = io.WriteString(conn, strings.ToUpper(line))
		destDone <- err
	}()

	base2 := newChanListener()
	defer base2.Close()
	go acceptLoop(context.Background(), proxyWrapper.WrapListener(base2))

	client2, err := singanytls.NewClient(context.Background(), singanytls.ClientConfig{
		Password:                 "secret",
		IdleSessionCheckInterval: 100 * time.Millisecond,
		IdleSessionTimeout:       time.Second,
		MinIdleSession:           0,
		DialOut: func(ctx context.Context) (net.Conn, error) {
			serverConn, clientConn := net.Pipe()
			base2.enqueue(serverConn)
			return clientConn, nil
		},
		Logger: zapLogger{base: zap.NewNop()},
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client2.Close()

	proxyConn, err := client2.CreateProxy(context.Background(), M.ParseSocksaddr(destinationAddress))
	if err != nil {
		t.Fatalf("CreateProxy() error = %v", err)
	}
	defer proxyConn.Close()
	if _, err := io.WriteString(proxyConn, "ping\n"); err != nil {
		t.Fatalf("WriteString() error = %v", err)
	}
	if _, err := bufio.NewReader(proxyConn).ReadString('\n'); err != nil {
		t.Fatalf("ReadString() error = %v", err)
	}
	if err := <-destDone; err != nil {
		t.Fatalf("destination error = %v", err)
	}

	entry := logs2.FilterMessage("anytls connection established")
	if entry.Len() == 0 {
		t.Fatal("expected anytls connection log entry")
	}
	if entry.FilterFieldKey("user").Len() == 0 || entry.FilterFieldKey("destination").Len() == 0 || entry.FilterFieldKey("connection_id").Len() == 0 {
		t.Fatal("expected structured user, destination, and connection_id fields")
	}
	if entry.FilterFieldKey("protocol").Len() == 0 {
		t.Fatal("expected structured protocol field")
	}
}

func TestReloadStyleClosesExistingSessions(t *testing.T) {
	core, logs := observer.New(zapcore.DebugLevel)
	logger := zap.New(core)

	destinationAddress := "service.example.internal:443"
	destination := newChanListener()
	defer destination.Close()

	wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}}, true)
	wrapper.logger = logger
	wrapper.dialFunc = func(ctx context.Context, network string, address string) (net.Conn, error) {
		if address != destinationAddress {
			return nil, errors.New("unexpected destination address")
		}
		serverConn, clientConn := net.Pipe()
		destination.enqueue(serverConn)
		return clientConn, nil
	}
	service, err := singanytls.NewService(singanytls.ServiceConfig{
		PaddingScheme: []byte(wrapper.PaddingScheme),
		Users:         wrapper.anyTLSUsers(),
		Handler:       &directTCPHandler{config: wrapper},
		Logger:        zapLogger{base: logger},
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	wrapper.service = service

	destReady := make(chan net.Conn, 1)
	go func() {
		conn, err := destination.Accept()
		if err != nil {
			return
		}
		destReady <- conn
	}()

	base := newChanListener()
	defer base.Close()
	go acceptLoop(context.Background(), wrapper.WrapListener(base))

	client, err := singanytls.NewClient(context.Background(), singanytls.ClientConfig{
		Password:                 "secret",
		IdleSessionCheckInterval: 100 * time.Millisecond,
		IdleSessionTimeout:       time.Second,
		MinIdleSession:           0,
		DialOut: func(ctx context.Context) (net.Conn, error) {
			serverConn, clientConn := net.Pipe()
			base.enqueue(serverConn)
			return clientConn, nil
		},
		Logger: zapLogger{base: zap.NewNop()},
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer client.Close()

	proxyConn, err := client.CreateProxy(context.Background(), M.ParseSocksaddr(destinationAddress))
	if err != nil {
		t.Fatalf("CreateProxy() error = %v", err)
	}
	defer proxyConn.Close()

	if _, err := io.WriteString(proxyConn, "hold-open\n"); err != nil {
		t.Fatalf("WriteString() error = %v", err)
	}

	var destConn net.Conn
	select {
	case destConn = <-destReady:
		defer destConn.Close()
	case <-time.After(time.Second):
		t.Fatal("destination connection was not established")
	}

	if !waitForCondition(time.Second, func() bool { return wrapper.activeSessionCount() == 1 }) {
		t.Fatal("expected one active session")
	}

	wrapper.closeActiveSessions("config_unload")

	_ = proxyConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 1)
	_, err = proxyConn.Read(buf)
	if err == nil {
		t.Fatal("expected closed proxy connection after config unload")
	}

	if !waitForLogs(logs, "anytls session terminated") {
		t.Fatal("expected termination audit log")
	}
}

func TestCaddyfileAdapterIncludesAnyTLSListenerWrapper(t *testing.T) {
	adapter := caddyconfig.GetAdapter("caddyfile")
	if adapter == nil {
		t.Fatal("caddyfile adapter is not registered")
	}

	configJSON, warnings, err := adapter.Adapt([]byte(`
{
	servers :443 {
		listener_wrappers {
			anytls {
				probe_timeout 5s
				idle_timeout 2m
				connect_timeout 10s
				max_concurrent 64
				fallback true
				allow_private_targets false
				user alice secret
			}
		}
	}
}

example.com {
	respond "ok"
}
`), nil)
	if err != nil {
		t.Fatalf("Adapt() error = %v", err)
	}
	for _, warning := range warnings {
		if !strings.Contains(warning.Message, "not formatted") {
			t.Fatalf("Adapt() warnings = %v, want only formatting warnings or none", warnings)
		}
	}

	var adapted map[string]any
	if err := json.Unmarshal(configJSON, &adapted); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	apps := adapted["apps"].(map[string]any)
	httpApp := apps["http"].(map[string]any)
	servers := httpApp["servers"].(map[string]any)
	var found bool
	for _, rawServer := range servers {
		server := rawServer.(map[string]any)
		rawWrappers, ok := server["listener_wrappers"].([]any)
		if !ok {
			continue
		}
		for _, rawWrapper := range rawWrappers {
			wrapper := rawWrapper.(map[string]any)
			if wrapper["wrapper"] == "anytls" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("adapted config does not contain anytls listener wrapper")
	}
}

func newTestWrapper(t *testing.T, users []User, allowPrivateTargets bool) *ListenerWrapper {
	t.Helper()

	wrapper := &ListenerWrapper{
		Users:               users,
		ProbeTimeout:        caddy.Duration(250 * time.Millisecond),
		IdleTimeout:         caddy.Duration(2 * time.Second),
		ConnectTimeout:      caddy.Duration(time.Second),
		MaxConcurrent:       8,
		Fallback:            true,
		AllowPrivateTargets: allowPrivateTargets,
		PaddingScheme:       string(padding.DefaultPaddingScheme),
		logger:              zap.NewNop(),
		registry:            newSessionRegistry(),
	}
	wrapper.detector = NewPasswordHashDetector(wrapper.Users)

	service, err := singanytls.NewService(singanytls.ServiceConfig{
		PaddingScheme: []byte(wrapper.PaddingScheme),
		Users:         wrapper.anyTLSUsers(),
		Handler:       &directTCPHandler{config: wrapper},
		Logger:        zapLogger{base: wrapper.logger},
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	wrapper.service = service

	return wrapper
}

func acceptLoop(ctx context.Context, l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			return
		}
		_ = conn.Close()
	}
}

func waitForLogs(logs *observer.ObservedLogs, message string) bool {
	return waitForCondition(500*time.Millisecond, func() bool {
		return logs.FilterMessage(message).Len() > 0
	})
}

func waitForCondition(timeout time.Duration, fn func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fn()
}

type chanListener struct {
	connCh chan net.Conn
	once   sync.Once
	closed chan struct{}
}

type testTLSStateConn struct {
	net.Conn
	state tls.ConnectionState
}

func (c testTLSStateConn) ConnectionState() tls.ConnectionState {
	return c.state
}

type anyTLSTestDialer struct {
	client *singanytls.Client
}

func (d anyTLSTestDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return d.client.CreateProxy(ctx, destination)
}

func (d anyTLSTestDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("not implemented in tests")
}

func newChanListener() *chanListener {
	return &chanListener{
		connCh: make(chan net.Conn, 16),
		closed: make(chan struct{}),
	}
}

func (l *chanListener) enqueue(conn net.Conn) {
	select {
	case <-l.closed:
		_ = conn.Close()
	case l.connCh <- conn:
	}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case <-l.closed:
		return nil, net.ErrClosed
	case conn := <-l.connCh:
		return conn, nil
	}
}

func (l *chanListener) Close() error {
	l.once.Do(func() {
		close(l.closed)
	})
	return nil
}

func (l *chanListener) Addr() net.Addr {
	return dummyAddr("chan-listener")
}

type dummyAddr string

func (a dummyAddr) Network() string { return "memory" }

func (a dummyAddr) String() string { return string(a) }

type packetPayload struct {
	data []byte
	addr net.Addr
}

type packetConn struct {
	localAddr net.Addr
	peer      *packetConn
	recvCh    chan packetPayload
	closed    chan struct{}
	once      sync.Once
}

func newPacketPipe() (*packetConn, *packetConn) {
	left := &packetConn{
		localAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 10), Port: 10010},
		recvCh:    make(chan packetPayload, 16),
		closed:    make(chan struct{}),
	}
	right := &packetConn{
		localAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 11), Port: 10011},
		recvCh:    make(chan packetPayload, 16),
		closed:    make(chan struct{}),
	}
	left.peer = right
	right.peer = left
	return left, right
}

func (c *packetConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case <-c.closed:
		return 0, nil, net.ErrClosed
	case payload := <-c.recvCh:
		n := copy(p, payload.data)
		return n, payload.addr, nil
	}
}

func (c *packetConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	case <-c.peer.closed:
		return 0, net.ErrClosed
	default:
	}

	data := append([]byte(nil), p...)
	select {
	case c.peer.recvCh <- packetPayload{data: data, addr: addr}:
		return len(p), nil
	case <-c.closed:
		return 0, net.ErrClosed
	case <-c.peer.closed:
		return 0, net.ErrClosed
	}
}

func (c *packetConn) Close() error {
	c.once.Do(func() {
		close(c.closed)
	})
	return nil
}

func (c *packetConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *packetConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *packetConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *packetConn) SetWriteDeadline(t time.Time) error {
	return nil
}
