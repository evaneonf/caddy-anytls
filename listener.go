package anytls

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	"go.uber.org/zap"
)

type wrappedListener struct {
	net.Listener
	config      *ListenerWrapper
	startOnce   sync.Once
	stopOnce    sync.Once
	done        chan struct{}
	ready       chan net.Conn
	probeSlots  chan struct{}
	terminalMu  sync.Mutex
	terminalErr error
}

func newWrappedListener(listener net.Listener, config *ListenerWrapper) *wrappedListener {
	return &wrappedListener{
		Listener:   listener,
		config:     config,
		done:       make(chan struct{}),
		ready:      make(chan net.Conn),
		probeSlots: make(chan struct{}, config.MaxPendingProbes),
	}
}

func (wl *wrappedListener) Accept() (net.Conn, error) {
	wl.startOnce.Do(func() { go wl.acceptLoop() })
	select {
	case conn := <-wl.ready:
		return conn, nil
	case <-wl.done:
		return nil, wl.getTerminalError()
	}
}

func (wl *wrappedListener) Close() error {
	err := wl.Listener.Close()
	wl.stop(net.ErrClosed)
	return err
}

func (wl *wrappedListener) acceptLoop() {
	for {
		select {
		case wl.probeSlots <- struct{}{}:
		case <-wl.done:
			return
		}

		conn, err := wl.Listener.Accept()
		if err != nil {
			<-wl.probeSlots
			select {
			case <-wl.done:
				return
			default:
				wl.stop(fmt.Errorf("accept connection: %w", err))
				return
			}
		}

		go wl.processAcceptedConn(conn)
	}
}

func (wl *wrappedListener) processAcceptedConn(conn net.Conn) {
	defer func() { <-wl.probeSlots }()
	connectionID := wl.config.nextConnectionID()

	websiteConn, err := wl.classifyAcceptedConn(conn, connectionID)
	if err != nil {
		wl.config.logger.Warn("connection routing failed",
			zap.Uint64("connection_id", connectionID),
			zap.String("remote", conn.RemoteAddr().String()),
			zap.String("event", "anytls_probe"),
			zap.String("outcome", "error"),
			zap.Error(err),
		)
		_ = conn.Close()
		return
	}
	if websiteConn == nil {
		return
	}

	select {
	case wl.ready <- websiteConn:
	case <-wl.done:
		_ = websiteConn.Close()
	}
}

func (wl *wrappedListener) classifyAcceptedConn(conn net.Conn, connectionID uint64) (net.Conn, error) {
	if tlsConn, ok := conn.(*tls.Conn); ok {
		if err := wl.handshakeTLSConn(tlsConn); err != nil {
			wl.config.logger.Debug("connection rejected during anytls probe",
				zap.Uint64("connection_id", connectionID),
				zap.String("remote", conn.RemoteAddr().String()),
				zap.String("event", "anytls_probe"),
				zap.String("outcome", "rejected"),
				zap.String("reason", "tls_handshake_failed"),
				zap.Error(err),
			)
			_ = conn.Close()
			return nil, nil
		}
	}

	buffered := newBufferedConn(conn)
	return wl.routeBufferedConn(conn, buffered, connectionID)
}

func (wl *wrappedListener) stop(err error) {
	wl.stopOnce.Do(func() {
		wl.terminalMu.Lock()
		wl.terminalErr = err
		wl.terminalMu.Unlock()
		close(wl.done)
	})
}

func (wl *wrappedListener) getTerminalError() error {
	wl.terminalMu.Lock()
	defer wl.terminalMu.Unlock()
	if wl.terminalErr == nil {
		return net.ErrClosed
	}
	return wl.terminalErr
}

func (wl *wrappedListener) routeBufferedConn(rawConn net.Conn, buffered *bufferedConn, connectionID uint64) (net.Conn, error) {
	route, detectErr := wl.classifyBufferedConn(buffered)
	decision := route.decision
	if detectErr != nil {
		if decision == routeFallback && wl.config.Fallback {
			wl.config.logFallback(rawConn, detectErr)
			return wl.config.prepareWebsiteConn(buffered), nil
		}
		wl.config.logger.Warn("connection rejected during anytls probe",
			zap.Uint64("connection_id", connectionID),
			zap.String("remote", rawConn.RemoteAddr().String()),
			zap.String("event", "anytls_probe"),
			zap.String("outcome", "rejected"),
			zap.String("reason", probeFailureReason(detectErr)),
			zap.Error(detectErr),
		)
		_ = rawConn.Close()
		return nil, nil
	}

	switch decision {
	case routeFallback:
		wl.config.logger.Debug("connection routed to website",
			zap.Uint64("connection_id", connectionID),
			zap.String("remote", rawConn.RemoteAddr().String()),
			zap.String("event", "fallback"),
			zap.String("outcome", "fallback"),
			zap.String("reason", "website_protocol"),
		)
		return wl.config.prepareWebsiteConn(buffered), nil
	case routeAnyTLS:
		if !wl.config.acquire() {
			wl.config.logger.Warn("rejecting AnyTLS connection due to concurrency limit",
				zap.String("remote", rawConn.RemoteAddr().String()),
			)
			_ = rawConn.Close()
			return nil, nil
		}
		wl.config.logger.Debug("connection detected as anytls",
			zap.Uint64("connection_id", connectionID),
			zap.String("remote", rawConn.RemoteAddr().String()),
			zap.String("event", "anytls_probe"),
			zap.String("outcome", "anytls"),
		)
		go wl.serveAnyTLS(buffered, connectionID, route.user)
		return nil, nil
	}
	return nil, fmt.Errorf("unknown routing decision %d", decision)
}

func (wl *wrappedListener) handshakeTLSConn(conn *tls.Conn) error {
	if time.Duration(wl.config.ProbeTimeout) > 0 {
		deadline := time.Now().Add(time.Duration(wl.config.ProbeTimeout))
		if err := conn.SetReadDeadline(deadline); err != nil {
			return err
		}
		if err := conn.SetWriteDeadline(deadline); err != nil {
			return err
		}
		defer func() {
			_ = conn.SetReadDeadline(time.Time{})
			_ = conn.SetWriteDeadline(time.Time{})
		}()
	}

	return conn.Handshake()
}

type classifiedRoute struct {
	decision routingDecision
	user     string
}

func (wl *wrappedListener) classifyBufferedConn(conn *bufferedConn) (classifiedRoute, error) {
	if website, err := wl.classifyWebsiteFastPath(conn); website || err != nil {
		return classifiedRoute{decision: routeFallback}, err
	}

	preview, err := conn.Peek(32, time.Duration(wl.config.ProbeTimeout))
	if err != nil && !errors.Is(err, net.ErrClosed) {
		return classifiedRoute{decision: routeFallback}, fmt.Errorf("peek first bytes: %w", err)
	}
	if len(preview) == 0 {
		return classifiedRoute{decision: routeFallback}, nil
	}

	user, decision, err := wl.config.detector.identify(preview)
	if err != nil {
		err = fmt.Errorf("detect anytls: %w", err)
	}
	return classifiedRoute{decision: decision, user: user}, err
}

func (wl *wrappedListener) classifyWebsiteFastPath(conn *bufferedConn) (bool, error) {
	first, err := conn.Peek(1, time.Duration(wl.config.ProbeTimeout))
	if err != nil {
		if errors.Is(err, net.ErrClosed) {
			return true, nil
		}
		return false, fmt.Errorf("peek first byte: %w", err)
	}
	switch first[0] {
	case 'P':
		preview, err := conn.Peek(4, time.Duration(wl.config.ProbeTimeout))
		if err != nil {
			return false, fmt.Errorf("peek website prefix: %w", err)
		}
		switch string(preview) {
		case "POST":
			return wl.matchWebsitePrefix(conn, "POST ")
		case "PRI ":
			return wl.matchWebsitePrefix(conn, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
		}
		return false, nil
	case 'G':
		return wl.matchWebsitePrefix(conn, "GET ")
	case 'H':
		return wl.matchWebsitePrefix(conn, "HEAD ")
	case 'O':
		return wl.matchWebsitePrefix(conn, "OPTIONS ")
	case 'D':
		return wl.matchWebsitePrefix(conn, "DELETE ")
	case 'T':
		return wl.matchWebsitePrefix(conn, "TRACE ")
	case 'C':
		return wl.matchWebsitePrefix(conn, "CONNECT ")
	case 'R':
		return wl.matchWebsitePrefix(conn, "REPORT ")
	case 'M':
		return wl.matchWebsitePrefix(conn, "MKCOL ")
	case 'N':
		return wl.matchWebsitePrefix(conn, "NOTIFY ")
	case 'S':
		preview, err := conn.Peek(3, time.Duration(wl.config.ProbeTimeout))
		if err != nil {
			return false, fmt.Errorf("peek website prefix: %w", err)
		}
		switch string(preview) {
		case "SUB":
			return wl.matchWebsitePrefix(conn, "SUBSCRIBE ")
		case "SEA":
			return wl.matchWebsitePrefix(conn, "SEARCH ")
		}
		return false, nil
	case 'U':
		return wl.matchWebsitePrefix(conn, "UNSUBSCRIBE ")
	case 'L':
		return wl.matchWebsitePrefix(conn, "LOCK ")
	case 'A':
		return wl.matchWebsitePrefix(conn, "ACL ")
	case 'B':
		return wl.matchWebsitePrefix(conn, "BIND ")
	}
	return false, nil
}

func (wl *wrappedListener) matchWebsitePrefix(conn *bufferedConn, prefix string) (bool, error) {
	preview, err := conn.Peek(len(prefix), time.Duration(wl.config.ProbeTimeout))
	if err != nil {
		if errors.Is(err, net.ErrClosed) {
			return true, nil
		}
		return false, fmt.Errorf("peek website prefix: %w", err)
	}
	if string(preview) == prefix {
		return true, nil
	}
	return false, nil
}

func (wl *wrappedListener) serveAnyTLS(buffered *bufferedConn, connectionID uint64, user string) {
	defer wl.config.release()
	startedAt := time.Now()
	selection := wl.config.outboundSelectionForUser(user)

	conn := newIdleTimeoutConn(buffered, time.Duration(wl.config.IdleTimeout))

	source := M.SocksaddrFromNet(conn.RemoteAddr())
	baseCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := contextWithConnectionID(baseCtx, connectionID)
	wl.config.registerSession(connectionID, conn, cancel, user)
	defer wl.config.unregisterSession(connectionID)
	wl.config.logger.Info("anytls session authenticated",
		zap.Uint64("connection_id", connectionID),
		zap.String("event", "anytls_session"),
		zap.String("outcome", "authenticated"),
		zap.String("user", user),
		zap.String("outbound", selection.name),
		zap.String("source", source.String()),
	)
	onClose := func(err error) {
		duration := time.Since(startedAt)
		if err != nil && !errors.Is(err, io.EOF) {
			wl.config.logger.Debug("anytls session closed",
				zap.Uint64("connection_id", connectionID),
				zap.String("remote", conn.RemoteAddr().String()),
				zap.String("event", "anytls_session"),
				zap.String("outcome", "error"),
				zap.String("reason", "session_error"),
				zap.Duration("duration", duration),
				zap.Error(err),
			)
			return
		}
		wl.config.logger.Debug("anytls session closed",
			zap.Uint64("connection_id", connectionID),
			zap.String("remote", conn.RemoteAddr().String()),
			zap.String("event", "anytls_session"),
			zap.String("outcome", "closed"),
			zap.Duration("duration", duration),
		)
	}
	session := newOutboundSession(conn, user, source, time.Duration(wl.config.ConnectTimeout), func(streamOutbound StreamOutbound) error {
		selectedCtx := contextWithStreamOutbound(ctx, selection.name, streamOutbound)
		return wl.config.service.NewConnection(selectedCtx, conn, source, onClose)
	})
	err := selection.outbound.HandleSession(ctx, session)
	if err != nil && !errors.Is(err, io.EOF) {
		wl.config.logger.Debug("anytls session finished",
			zap.Uint64("connection_id", connectionID),
			zap.String("remote", conn.RemoteAddr().String()),
			zap.String("event", "anytls_session"),
			zap.String("outcome", "finished"),
			zap.String("reason", "service_returned_error"),
			zap.Duration("duration", time.Since(startedAt)),
			zap.Error(err),
		)
	}
	_ = conn.Close()
}

type idleTimeoutConn struct {
	net.Conn
	timeout      time.Duration
	mu           sync.Mutex
	timer        *time.Timer
	closed       bool
	lastActivity time.Time
}

func newIdleTimeoutConn(conn net.Conn, timeout time.Duration) net.Conn {
	if timeout <= 0 {
		return conn
	}
	connWithTimeout := &idleTimeoutConn{
		Conn:         conn,
		timeout:      timeout,
		lastActivity: time.Now(),
	}
	connWithTimeout.timer = time.AfterFunc(timeout, connWithTimeout.expire)
	return connWithTimeout
}

func (c *idleTimeoutConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.touch()
	}
	return n, err
}

func (c *idleTimeoutConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.touch()
	}
	return n, err
}

func (c *idleTimeoutConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return net.ErrClosed
	}
	c.closed = true
	c.timer.Stop()
	c.mu.Unlock()
	return c.Conn.Close()
}

func (c *idleTimeoutConn) touch() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.lastActivity = time.Now()
		c.timer.Reset(c.timeout)
	}
}

func (c *idleTimeoutConn) expire() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	idleFor := time.Since(c.lastActivity)
	if idleFor < c.timeout {
		c.timer.Reset(c.timeout - idleFor)
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.mu.Unlock()
	_ = c.Conn.Close()
}
