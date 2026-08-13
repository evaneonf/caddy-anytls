package anytls

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	singanytls "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/padding"
	"github.com/caddyserver/caddy/v2"
	M "github.com/sagernet/sing/common/metadata"
	"go.uber.org/zap"
)

func newTestWrapper(t *testing.T, users []User) *ListenerWrapper {
	t.Helper()

	wrapper := &ListenerWrapper{
		Users:            users,
		ProbeTimeout:     caddy.Duration(250 * time.Millisecond),
		IdleTimeout:      caddy.Duration(2 * time.Second),
		ConnectTimeout:   caddy.Duration(time.Second),
		MaxConcurrent:    8,
		MaxPendingProbes: 256,
		Fallback:         true,
		PaddingScheme:    string(padding.DefaultPaddingScheme),
		logger:           zap.NewNop(),
		registry:         newSessionRegistry(),
		defaultSelection: outboundSelection{outbound: new(DirectOutbound), name: reservedOutboundDirect},
	}
	wrapper.detector = newPasswordHashDetector(wrapper.Users)

	service, err := singanytls.NewService(singanytls.ServiceConfig{
		PaddingScheme: []byte(wrapper.PaddingScheme),
		Users:         wrapper.anyTLSUsers(),
		Handler:       &proxyHandler{config: wrapper},
		Logger:        zapLogger{base: wrapper.logger},
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	wrapper.service = service

	return wrapper
}

// newTestAnyTLSClient builds a sing-anytls client whose outgoing connections
// are enqueued on the given chanListener.
func newTestAnyTLSClient(t *testing.T, base *chanListener, password string) *singanytls.Client {
	t.Helper()

	client, err := singanytls.NewClient(context.Background(), singanytls.ClientConfig{
		Password:                 password,
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
	t.Cleanup(func() { closeTest(client) })
	return client
}

func newTestCertificate(t *testing.T) tls.Certificate {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "example.test",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              []string{"example.test"},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("x509.CreateCertificate() error = %v", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  privateKey,
		Leaf:        template,
	}
}

func acceptLoop(l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		_ = conn.Close()
	}
}

func testActiveSessionCount(wrapper *ListenerWrapper) int {
	wrapper.registry.mu.Lock()
	defer wrapper.registry.mu.Unlock()
	return len(wrapper.registry.sessions)
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

func closeTest(closer io.Closer) {
	_ = closer.Close()
}

type chanListener struct {
	connCh chan net.Conn
	once   sync.Once
	closed chan struct{}
}

type handshakeReportConn struct {
	net.Conn
	successErr   error
	successCalls int
}

func (c *handshakeReportConn) HandshakeSuccess() error {
	c.successCalls++
	return c.successErr
}

type anyTLSTestDialer struct {
	client *singanytls.Client
}

type testOutbound struct {
	dial func(context.Context, M.Socksaddr) (net.Conn, error)
	open func(context.Context) (PacketConn, error)
}

func (o *testOutbound) HandleSession(_ context.Context, session *OutboundSession) error {
	return session.ServeLocal(o)
}

func (o *testOutbound) DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	if o.dial == nil {
		return nil, errors.New("TCP outbound not configured for test")
	}
	return o.dial(ctx, destination)
}

func (o *testOutbound) OpenPacket(ctx context.Context) (PacketConn, error) {
	if o.open == nil {
		return nil, errors.New("UDP outbound not configured for test")
	}
	return o.open(ctx)
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

type deadlineConn struct {
	readDeadline  time.Time
	writeDeadline time.Time
}

func (c *deadlineConn) Read(p []byte) (int, error) {
	if len(p) > 0 {
		p[0] = 'x'
	}
	return 1, nil
}

func (c *deadlineConn) Write(p []byte) (int, error) {
	return len(p), nil
}

func (c *deadlineConn) Close() error {
	return nil
}

func (c *deadlineConn) LocalAddr() net.Addr {
	return dummyAddr("local")
}

func (c *deadlineConn) RemoteAddr() net.Addr {
	return dummyAddr("remote")
}

func (c *deadlineConn) SetDeadline(t time.Time) error {
	c.readDeadline = t
	c.writeDeadline = t
	return nil
}

func (c *deadlineConn) SetReadDeadline(t time.Time) error {
	c.readDeadline = t
	return nil
}

func (c *deadlineConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline = t
	return nil
}

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

// packetConnAdapter preserves domain destinations in tests. It models the
// domain-aware PacketConn contract without invoking the host resolver.
type packetConnAdapter struct {
	net.PacketConn
}

func (c *packetConnAdapter) ReadPacket(p []byte) (int, M.Socksaddr, error) {
	n, source, err := c.ReadFrom(p)
	return n, M.SocksaddrFromNet(source), err
}

func (c *packetConnAdapter) WritePacket(p []byte, destination M.Socksaddr) error {
	_, err := c.WriteTo(p, destination)
	return err
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
