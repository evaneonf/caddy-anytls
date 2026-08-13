package anytls

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	singanytls "github.com/anytls/sing-anytls"
	"github.com/caddyserver/caddy/v2"
	B "github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"golang.org/x/net/http2"
)

func TestBufferedConnPeekPreservesBytes(t *testing.T) {
	server, client := net.Pipe()
	defer closeTest(server)
	defer closeTest(client)

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

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  *ListenerWrapper
		wantErr bool
	}{
		{
			name: "valid config",
			config: &ListenerWrapper{
				MaxConcurrent: 1,
				Users: []User{
					{Name: "alice", Password: "secret", Enabled: true},
				},
			},
			wantErr: false,
		},
		{
			name: "duplicate user",
			config: &ListenerWrapper{
				Users: []User{
					{Name: "alice", Password: "secret"},
					{Name: "alice", Password: "secret-2"},
				},
			},
			wantErr: true,
		},
		{
			name: "duplicate password",
			config: &ListenerWrapper{
				Users: []User{
					{Name: "alice", Password: "secret"},
					{Name: "bob", Password: "secret"},
				},
			},
			wantErr: true,
		},
		{
			name: "negative concurrency",
			config: &ListenerWrapper{
				MaxConcurrent: -1,
			},
			wantErr: true,
		},
		{
			name: "empty password",
			config: &ListenerWrapper{
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

func TestWrappedListenerDoesNotBlockAcceptOnSlowProbe(t *testing.T) {
	wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}})
	wrapper.ProbeTimeout = caddy.Duration(time.Second)
	wrapper.MaxPendingProbes = 2
	base := newChanListener()
	wrapped := wrapper.WrapListener(base)
	defer closeTest(wrapped)

	slowServer, slowClient := net.Pipe()
	defer closeTest(slowClient)
	base.enqueue(slowServer)

	websiteServer, websiteClient := net.Pipe()
	defer closeTest(websiteClient)
	base.enqueue(websiteServer)
	go func() {
		_, _ = io.WriteString(websiteClient, "GET / HTTP/1.1\r\n")
	}()

	accepted := make(chan net.Conn, 1)
	errs := make(chan error, 1)
	go func() {
		conn, err := wrapped.Accept()
		if err != nil {
			errs <- err
			return
		}
		accepted <- conn
	}()

	select {
	case conn := <-accepted:
		defer closeTest(conn)
		prefix := make([]byte, len("GET "))
		if _, err := io.ReadFull(conn, prefix); err != nil {
			t.Fatalf("ReadFull() error = %v", err)
		}
		if string(prefix) != "GET " {
			t.Fatalf("accepted prefix = %q, want GET", prefix)
		}
	case err := <-errs:
		t.Fatalf("Accept() error = %v", err)
	case <-time.After(250 * time.Millisecond):
		t.Fatal("fast website connection was blocked behind slow probe")
	}
}

func TestStreamLimits(t *testing.T) {
	wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}})
	wrapper.MaxStreamsPerSession = 1
	wrapper.MaxConcurrentStreams = 1
	server, client := net.Pipe()
	defer closeTest(server)
	defer closeTest(client)
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	wrapper.registerSession(1, server, cancel, "alice")
	defer wrapper.unregisterSession(1)

	if !wrapper.acquireStream(1) {
		t.Fatal("first stream was rejected")
	}
	if wrapper.acquireStream(1) {
		t.Fatal("second stream exceeded per-session limit but was accepted")
	}
	wrapper.releaseStream(1)
	if !wrapper.acquireStream(1) {
		t.Fatal("stream slot was not released")
	}
	wrapper.releaseStream(1)

	if wrapper.acquireStream(999) {
		t.Fatal("stream for unknown session was accepted")
	}
}

func TestHandlerReportsHandshakeSuccess(t *testing.T) {
	reportErr := errors.New("send success acknowledgment")
	tests := []struct {
		name        string
		destination M.Socksaddr
		successErr  error
		setup       func(t *testing.T, wrapper *ListenerWrapper)
	}{
		{
			name:        "tcp success",
			destination: M.ParseSocksaddr("service.example.internal:443"),
			setup:       setupHandshakeSuccessTCP,
		},
		{
			name:        "tcp report failure",
			destination: M.ParseSocksaddr("service.example.internal:443"),
			successErr:  reportErr,
			setup:       setupHandshakeSuccessTCP,
		},
		{
			name:        "udp over tcp success",
			destination: M.ParseSocksaddr(uot.LegacyMagicAddress + ":443"),
			setup:       setupHandshakeSuccessUDP,
		},
		{
			name:        "udp over tcp report failure",
			destination: M.ParseSocksaddr(uot.LegacyMagicAddress + ":443"),
			successErr:  reportErr,
			setup:       setupHandshakeSuccessUDP,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}})
			tt.setup(t, wrapper)

			serverConn, clientConn := net.Pipe()
			defer closeTest(serverConn)
			defer closeTest(clientConn)
			reportingConn := &handshakeReportConn{Conn: serverConn, successErr: tt.successErr}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx = contextWithConnectionID(ctx, 1)
			streamOutbound, ok := wrapper.defaultSelection.outbound.(StreamOutbound)
			if !ok {
				t.Fatalf("test outbound %T does not implement StreamOutbound", wrapper.defaultSelection.outbound)
			}
			ctx = contextWithStreamOutbound(ctx, wrapper.defaultSelection.name, streamOutbound)
			wrapper.registerSession(1, reportingConn, cancel, "alice")
			defer wrapper.unregisterSession(1)

			closed := make(chan error, 1)
			handler := &proxyHandler{config: wrapper}
			handler.NewConnectionEx(ctx, reportingConn, M.ParseSocksaddr("192.0.2.10:12345"), tt.destination, func(err error) {
				closed <- err
			})

			if reportingConn.successCalls != 1 {
				t.Fatalf("HandshakeSuccess() calls = %d, want 1", reportingConn.successCalls)
			}
			if tt.successErr != nil {
				select {
				case err := <-closed:
					if !errors.Is(err, tt.successErr) {
						t.Fatalf("close error = %v, want %v", err, tt.successErr)
					}
				default:
					t.Fatal("handler did not close the stream after HandshakeSuccess() failed")
				}
				if wrapper.activeStreams != 0 {
					t.Fatalf("active streams = %d, want 0", wrapper.activeStreams)
				}
				return
			}

			select {
			case err := <-closed:
				t.Fatalf("handler closed a successfully acknowledged stream: %v", err)
			default:
			}
			closeTest(clientConn)
			if !waitForCondition(time.Second, func() bool { return atomic.LoadInt64(&wrapper.activeStreams) == 0 }) {
				t.Fatal("stream slot was not released after the connection closed")
			}
		})
	}
}

func setupHandshakeSuccessTCP(t *testing.T, wrapper *ListenerWrapper) {
	t.Helper()
	targetConn, targetPeer := net.Pipe()
	t.Cleanup(func() {
		closeTest(targetConn)
		closeTest(targetPeer)
	})
	wrapper.defaultSelection = outboundSelection{outbound: &testOutbound{
		dial: func(context.Context, M.Socksaddr) (net.Conn, error) {
			return targetConn, nil
		},
	}, name: "test"}
}

func setupHandshakeSuccessUDP(t *testing.T, wrapper *ListenerWrapper) {
	t.Helper()
	packetConn, packetPeer := newPacketPipe()
	t.Cleanup(func() {
		closeTest(packetConn)
		closeTest(packetPeer)
	})
	wrapper.defaultSelection = outboundSelection{outbound: &testOutbound{
		open: func(context.Context) (PacketConn, error) {
			return &packetConnAdapter{PacketConn: packetConn}, nil
		},
	}, name: "test"}
}

func TestWebsiteFallbackEndToEnd(t *testing.T) {
	wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}})
	core, logs := observer.New(zapcore.DebugLevel)
	wrapper.logger = zap.New(core)

	base := newChanListener()
	defer closeTest(base)

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
		defer closeTest(conn)

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
	defer closeTest(client)
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

	entries := logs.FilterMessage("connection routed to website").All()
	if len(entries) != 1 {
		t.Fatalf("website fallback logs = %d, want 1", len(entries))
	}
	fields := entries[0].ContextMap()
	if fields["event"] != "fallback" || fields["outcome"] != "fallback" || fields["reason"] != "website_protocol" {
		t.Fatalf("website fallback log fields = %v", fields)
	}
}

func TestHTTP2FallbackPreservesConnectionState(t *testing.T) {
	wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}})

	base := newChanListener()
	defer closeTest(base)

	tlsListener := tls.NewListener(base, &tls.Config{
		Certificates: []tls.Certificate{newTestCertificate(t)},
		NextProtos:   []string{"h2", "http/1.1"},
	})
	wrapped := wrapper.WrapListener(tlsListener)

	serverErr := make(chan error, 1)
	go func() {
		conn, err := wrapped.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer closeTest(conn)

		stater, ok := conn.(interface{ ConnectionState() tls.ConnectionState })
		if !ok {
			serverErr <- errors.New("wrapped listener did not preserve ConnectionState on fallback connection")
			return
		}
		if got := stater.ConnectionState().NegotiatedProtocol; got != "h2" {
			serverErr <- errors.New("unexpected negotiated protocol: " + got)
			return
		}

		preface := make([]byte, len(http2.ClientPreface))
		if _, err := io.ReadFull(conn, preface); err != nil {
			serverErr <- err
			return
		}
		if string(preface) != http2.ClientPreface {
			serverErr <- errors.New("http2 preface was not preserved")
			return
		}

		serverErr <- nil
	}()

	serverConn, clientConn := net.Pipe()
	base.enqueue(serverConn)

	client := tls.Client(clientConn, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2"},
		ServerName:         "example.test",
	})
	defer closeTest(client)

	if err := client.Handshake(); err != nil {
		t.Fatalf("client Handshake() error = %v", err)
	}
	if got := client.ConnectionState().NegotiatedProtocol; got != "h2" {
		t.Fatalf("client negotiated protocol = %q, want %q", got, "h2")
	}
	if _, err := io.WriteString(client, http2.ClientPreface); err != nil {
		t.Fatalf("WriteString() error = %v", err)
	}

	if err := <-serverErr; err != nil {
		t.Fatalf("server error = %v", err)
	}
}

func TestHTTP1FallbackPreservesConnectionState(t *testing.T) {
	wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}})

	base := newChanListener()
	defer closeTest(base)

	tlsListener := tls.NewListener(base, &tls.Config{
		Certificates: []tls.Certificate{newTestCertificate(t)},
		NextProtos:   []string{"http/1.1"},
	})
	wrapped := wrapper.WrapListener(tlsListener)

	serverErr := make(chan error, 1)
	go func() {
		conn, err := wrapped.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer closeTest(conn)

		stater, ok := conn.(interface{ ConnectionState() tls.ConnectionState })
		if !ok {
			serverErr <- errors.New("wrapped listener did not preserve ConnectionState on fallback connection")
			return
		}
		state := stater.ConnectionState()
		if got := state.NegotiatedProtocol; got != "http/1.1" {
			serverErr <- errors.New("unexpected negotiated protocol: " + got)
			return
		}
		if got := state.ServerName; got != "example.test" {
			serverErr <- errors.New("unexpected server name: " + got)
			return
		}

		request := "GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n"
		buf := make([]byte, len(request))
		if _, err := io.ReadFull(conn, buf); err != nil {
			serverErr <- err
			return
		}
		if string(buf) != request {
			serverErr <- errors.New("http/1.1 request bytes were not preserved")
			return
		}

		serverErr <- nil
	}()

	serverConn, clientConn := net.Pipe()
	base.enqueue(serverConn)

	client := tls.Client(clientConn, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
		ServerName:         "example.test",
	})
	defer closeTest(client)

	if err := client.Handshake(); err != nil {
		t.Fatalf("client Handshake() error = %v", err)
	}
	if got := client.ConnectionState().NegotiatedProtocol; got != "http/1.1" {
		t.Fatalf("client negotiated protocol = %q, want %q", got, "http/1.1")
	}
	if _, err := io.WriteString(client, "GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("WriteString() error = %v", err)
	}

	if err := <-serverErr; err != nil {
		t.Fatalf("server error = %v", err)
	}
}

func TestWebsiteFallbackWithoutTLSStateRemainsOpaque(t *testing.T) {
	wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}})

	server, client := net.Pipe()
	defer closeTest(server)
	defer closeTest(client)

	buffered := newBufferedConn(server)
	go func() {
		_, _ = client.Write([]byte("GET / HTTP/1.1\r\n"))
	}()
	if _, err := buffered.Peek(1, time.Second); err != nil {
		t.Fatalf("Peek() error = %v", err)
	}

	websiteConn := wrapper.prepareWebsiteConn(buffered)

	if _, ok := websiteConn.(interface{ ConnectionState() tls.ConnectionState }); ok {
		t.Fatal("non-TLS fallback connection unexpectedly implements ConnectionState")
	}
}

func TestPostTLSWrapperAfterAnyTLSDoesNotSeeAnyTLSConnections(t *testing.T) {
	destinationAddress := "service.example.internal:443"
	destination := newChanListener()
	defer closeTest(destination)

	wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}})
	wrapper.ProbeTimeout = caddy.Duration(time.Second)
	wrapper.defaultSelection = outboundSelection{outbound: &testOutbound{
		dial: func(ctx context.Context, destinationAddressValue M.Socksaddr) (net.Conn, error) {
			if destinationAddressValue.String() != destinationAddress {
				return nil, errors.New("unexpected destination address")
			}
			serverConn, clientConn := net.Pipe()
			destination.enqueue(serverConn)
			return clientConn, nil
		},
	}, name: "test"}

	destDone := make(chan error, 1)
	go func() {
		conn, err := destination.Accept()
		if err != nil {
			destDone <- err
			return
		}
		defer closeTest(conn)

		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			destDone <- err
			return
		}

		_, err = io.WriteString(conn, strings.ToUpper(line))
		destDone <- err
	}()

	base := newChanListener()
	defer closeTest(base)
	tlsListener := tls.NewListener(base, &tls.Config{
		Certificates: []tls.Certificate{newTestCertificate(t)},
		NextProtos:   []string{"h2", "http/1.1"},
	})
	afterAnyTLS := wrapper.WrapListener(tlsListener)
	websiteConn := make(chan net.Conn, 1)
	go func() {
		conn, err := afterAnyTLS.Accept()
		if err == nil {
			websiteConn <- conn
		}
	}()

	client, err := singanytls.NewClient(context.Background(), singanytls.ClientConfig{
		Password:                 "secret",
		IdleSessionCheckInterval: 100 * time.Millisecond,
		IdleSessionTimeout:       time.Second,
		MinIdleSession:           0,
		DialOut: func(ctx context.Context) (net.Conn, error) {
			serverConn, clientConn := net.Pipe()
			base.enqueue(serverConn)

			tlsClient := tls.Client(clientConn, &tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         []string{"h2", "http/1.1"},
				ServerName:         "example.test",
			})
			if err := tlsClient.HandshakeContext(ctx); err != nil {
				_ = tlsClient.Close()
				return nil, err
			}
			return tlsClient, nil
		},
		Logger: zapLogger{base: zap.NewNop()},
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	defer closeTest(client)

	proxyConn, err := client.CreateProxy(context.Background(), M.ParseSocksaddr(destinationAddress))
	if err != nil {
		t.Fatalf("CreateProxy() error = %v", err)
	}
	defer closeTest(proxyConn)

	if _, err := io.WriteString(proxyConn, "hello through anytls over tls\n"); err != nil {
		t.Fatalf("WriteString() error = %v", err)
	}

	reply, err := bufio.NewReader(proxyConn).ReadString('\n')
	if err != nil {
		t.Fatalf("ReadString() error = %v", err)
	}
	if reply != "HELLO THROUGH ANYTLS OVER TLS\n" {
		t.Fatalf("reply = %q, want %q", reply, "HELLO THROUGH ANYTLS OVER TLS\n")
	}

	if err := <-destDone; err != nil {
		t.Fatalf("destination error = %v", err)
	}

	select {
	case conn := <-websiteConn:
		_ = conn.Close()
		t.Fatal("post-TLS wrapper should not see AnyTLS connections")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestAnyTLSEndToEndUDPOverTCP(t *testing.T) {
	serverPacketConn, handlerPacketConn := newPacketPipe()
	defer closeTest(serverPacketConn)
	defer closeTest(handlerPacketConn)

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

	wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}})
	wrapper.defaultSelection = outboundSelection{outbound: &testOutbound{
		open: func(ctx context.Context) (PacketConn, error) {
			return &packetConnAdapter{PacketConn: handlerPacketConn}, nil
		},
	}, name: "test"}
	base := newChanListener()
	defer closeTest(base)

	go acceptLoop(wrapper.WrapListener(base))

	client := newTestAnyTLSClient(t, base, "secret")

	uotClient := &uot.Client{
		Dialer:  anyTLSTestDialer{client: client},
		Version: uot.Version,
	}

	uotConn, err := uotClient.DialContext(context.Background(), N.NetworkUDP, M.ParseSocksaddr("1.1.1.1:53"))
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	defer closeTest(uotConn)

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
	defer closeTest(serverPacketConn)
	defer closeTest(handlerPacketConn)

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

	wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}})
	wrapper.defaultSelection = outboundSelection{outbound: &testOutbound{
		open: func(ctx context.Context) (PacketConn, error) {
			return &packetConnAdapter{PacketConn: handlerPacketConn}, nil
		},
	}, name: "test"}
	base := newChanListener()
	defer closeTest(base)

	go acceptLoop(wrapper.WrapListener(base))

	client := newTestAnyTLSClient(t, base, "secret")

	uotClient := &uot.Client{
		Dialer:  anyTLSTestDialer{client: client},
		Version: uot.Version,
	}

	packetConn, err := uotClient.ListenPacket(context.Background(), M.ParseSocksaddr("1.1.1.1:53"))
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer closeTest(packetConn)

	dest1 := M.ParseSocksaddr("1.1.1.1:53")
	dest2 := M.ParseSocksaddr("dns.example.test:53")
	if _, err := packetConn.WriteTo([]byte("first datagram"), dest1); err != nil {
		t.Fatalf("WriteTo(dest1) error = %v", err)
	}
	if _, err := packetConn.WriteTo([]byte("second datagram"), dest2); err != nil {
		t.Fatalf("WriteTo(dest2) error = %v", err)
	}

	packetBuffer := B.NewPacket()
	defer packetBuffer.Release()
	packetReader, ok := packetConn.(N.PacketReader)
	if !ok {
		t.Fatalf("packet connection = %T, want network.PacketReader", packetConn)
	}
	replies := make(map[string]string, 2)
	for i := 0; i < 2; i++ {
		packetBuffer.Reset()
		addr, err := packetReader.ReadPacket(packetBuffer)
		if err != nil {
			t.Fatalf("ReadPacket() error = %v", err)
		}
		replies[addr.String()] = string(packetBuffer.Bytes())
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

func TestIdleTimeoutConnPreservesExplicitDeadlines(t *testing.T) {
	base := &deadlineConn{}
	conn := newIdleTimeoutConn(base, time.Minute)
	defer closeTest(conn)

	writeDeadline := time.Now().Add(5 * time.Second)
	if err := conn.SetWriteDeadline(writeDeadline); err != nil {
		t.Fatalf("SetWriteDeadline() error = %v", err)
	}

	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if !base.writeDeadline.Equal(writeDeadline) {
		t.Fatalf("write deadline = %v, want preserved %v", base.writeDeadline, writeDeadline)
	}
}

func TestIdleTimeoutConnTreatsWritesAsActivity(t *testing.T) {
	server, client := net.Pipe()
	defer closeTest(client)
	conn := newIdleTimeoutConn(server, 40*time.Millisecond)
	defer closeTest(conn)
	serverReadDone := make(chan error, 1)
	go func() {
		buffer := make([]byte, 1)
		_, err := conn.Read(buffer)
		serverReadDone <- err
	}()

	for range 4 {
		readDone := make(chan error, 1)
		go func() {
			buffer := make([]byte, 1)
			_, err := client.Read(buffer)
			readDone <- err
		}()
		if _, err := conn.Write([]byte("x")); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
		if err := <-readDone; err != nil {
			t.Fatalf("client Read() error = %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	readDone := make(chan error, 1)
	go func() {
		buffer := make([]byte, 1)
		_, err := client.Read(buffer)
		readDone <- err
	}()
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatalf("connection closed despite continuous write activity: %v", err)
	}
	if err := <-readDone; err != nil {
		t.Fatalf("client Read() error = %v", err)
	}
	if _, err := client.Write([]byte("y")); err != nil {
		t.Fatalf("client Write() error = %v", err)
	}
	if err := <-serverReadDone; err != nil {
		t.Fatalf("blocked Read() expired despite write activity: %v", err)
	}
}

func TestDetectorRejectsDisabledUser(t *testing.T) {
	enabled := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}})
	disabled := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: false}})

	sum := sha256.Sum256([]byte("secret"))
	preview := sum[:]

	_, decision, err := enabled.detector.identify(preview)
	if err != nil || decision != routeAnyTLS {
		t.Fatalf("enabled detector = (%v, %v), want AnyTLS", decision, err)
	}

	_, decision, err = disabled.detector.identify(preview)
	if err == nil || decision != routeReject {
		t.Fatalf("disabled detector = (%v, %v), want reject with error", decision, err)
	}
}

func TestCleanupClosesActiveSessions(t *testing.T) {
	core, logs := observer.New(zapcore.DebugLevel)
	logger := zap.New(core)

	wrapper := newTestWrapper(t, []User{{Name: "alice", Password: "secret", Enabled: true}})
	wrapper.logger = logger
	target, targetPeer := net.Pipe()
	defer closeTest(targetPeer)
	wrapper.defaultSelection = outboundSelection{outbound: &testOutbound{
		dial: func(context.Context, M.Socksaddr) (net.Conn, error) {
			return target, nil
		},
	}, name: "test"}
	go func() { _, _ = io.Copy(io.Discard, targetPeer) }()

	base := newChanListener()
	defer closeTest(base)
	go acceptLoop(wrapper.WrapListener(base))

	client := newTestAnyTLSClient(t, base, "secret")
	proxyConn, err := client.CreateProxy(t.Context(), M.ParseSocksaddr("service.test:443"))
	if err != nil {
		t.Fatalf("CreateProxy() error = %v", err)
	}
	defer closeTest(proxyConn)
	if _, err := io.WriteString(proxyConn, "hold-open\n"); err != nil {
		t.Fatalf("WriteString() error = %v", err)
	}

	if !waitForCondition(time.Second, func() bool { return testActiveSessionCount(wrapper) == 1 }) {
		t.Fatalf("active sessions = %d, want 1", testActiveSessionCount(wrapper))
	}

	if err := wrapper.Cleanup(); err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}

	_ = proxyConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := proxyConn.Read(make([]byte, 1)); err == nil {
		t.Fatal("proxy connection still open after config unload")
	}

	if !waitForCondition(time.Second, func() bool {
		return logs.FilterMessage("anytls session terminated").Len() == 1
	}) {
		t.Fatalf("termination audit logs = %d, want 1", logs.FilterMessage("anytls session terminated").Len())
	}
}

// End-to-end per-user outbound selection through real authentication: two
// accounts on the same wrapper egress through different outbounds, and the
// Info-level established log carries the outbound name exactly once per
// connection. The destination is an IP literal so each connection performs
// exactly one deterministic DialContext.
func TestPerUserOutboundSelectionEndToEnd(t *testing.T) {
	core, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(core)

	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	defer closeTest(target)
	go func() {
		for {
			conn, acceptErr := target.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer closeTest(c)
				line, readErr := bufio.NewReader(c).ReadString('\n')
				if readErr != nil {
					return
				}
				_, _ = io.WriteString(c, strings.ToUpper(line))
			}(conn)
		}
	}()
	targetAddress := target.Addr().String()

	users := []User{
		{Name: "home", Password: "home-pass", Enabled: true, Outbound: "exit-home"},
		{Name: "away", Password: "away-pass", Enabled: true},
	}
	wrapper := newTestWrapper(t, users)
	wrapper.logger = logger
	recHome := &recordingOutbound{inner: new(DirectOutbound)}
	recAway := &recordingOutbound{inner: new(DirectOutbound)}
	wrapper.userSelections = map[string]outboundSelection{
		"home": {outbound: recHome, name: "exit-home"},
	}
	wrapper.defaultSelection = outboundSelection{outbound: recAway, name: "exit-away"}

	base := newChanListener()
	defer closeTest(base)
	go acceptLoop(wrapper.WrapListener(base))

	for _, tt := range []struct {
		user     string
		password string
		recorder *recordingOutbound
		outbound string
	}{
		{user: "home", password: "home-pass", recorder: recHome, outbound: "exit-home"},
		{user: "away", password: "away-pass", recorder: recAway, outbound: "exit-away"},
	} {
		client := newTestAnyTLSClient(t, base, tt.password)
		proxyConn, err := client.CreateProxy(t.Context(), M.ParseSocksaddr(targetAddress))
		if err != nil {
			t.Fatalf("CreateProxy(%s) error = %v", tt.user, err)
		}
		if _, err := io.WriteString(proxyConn, "ping\n"); err != nil {
			t.Fatalf("WriteString(%s) error = %v", tt.user, err)
		}
		if _, err := bufio.NewReader(proxyConn).ReadString('\n'); err != nil {
			t.Fatalf("ReadString(%s) error = %v", tt.user, err)
		}
		closeTest(proxyConn)

		dials := tt.recorder.dials()
		if len(dials) != 1 || dials[0].String() != targetAddress {
			t.Fatalf("user %s recorded dials = %v, want exactly [%s]", tt.user, dials, targetAddress)
		}

		userEntries := 0
		for _, entry := range logs.FilterMessage("anytls connection established").All() {
			fields := entry.ContextMap()
			if fields["user"] != tt.user {
				continue
			}
			userEntries++
			if fields["outbound"] != tt.outbound {
				t.Fatalf("established log outbound = %v, want %q for user %s", fields["outbound"], tt.outbound, tt.user)
			}
		}
		if userEntries != 1 {
			t.Fatalf("established log entries for user %s = %d, want exactly 1", tt.user, userEntries)
		}
	}

	if dials := recHome.dials(); len(dials) != 1 {
		t.Fatalf("recHome dials = %v, want no cross-user dials", dials)
	}
	if dials := recAway.dials(); len(dials) != 1 {
		t.Fatalf("recAway dials = %v, want no cross-user dials", dials)
	}
}
