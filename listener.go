package anytls

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	"go.uber.org/zap"
)

type wrappedListener struct {
	net.Listener
	config *ListenerWrapper
}

func (wl *wrappedListener) Accept() (net.Conn, error) {
	for {
		conn, err := wl.Listener.Accept()
		if err != nil {
			return nil, fmt.Errorf("accept connection: %w", err)
		}
		connectionID := wl.config.nextConnectionID()

		if tlsConn, ok := conn.(*tls.Conn); ok {
			if err := wl.handshakeTLSConn(tlsConn); err != nil {
				wl.config.logger.Warn("connection rejected during anytls probe",
					zap.Uint64("connection_id", connectionID),
					zap.String("remote", conn.RemoteAddr().String()),
					zap.String("event", "anytls_probe"),
					zap.String("outcome", "rejected"),
					zap.String("reason", "tls_handshake_failed"),
					zap.Error(err),
				)
				_ = conn.Close()
				continue
			}
			buffered := newBufferedConn(tlsConn)
			decision, detectErr := wl.classifyBufferedConn(buffered)

			switch {
			case detectErr != nil && decision == DecisionFallback && wl.config.Fallback:
				wl.config.logFallback(conn, detectErr)
				websiteConn, err := wl.config.prepareWebsiteConn(buffered)
				if err != nil {
					return nil, fmt.Errorf("prepare fallback connection: %w", err)
				}
				return websiteConn, nil
			case detectErr != nil && decision == DecisionReject:
				wl.config.logger.Warn("connection rejected during anytls probe",
					zap.Uint64("connection_id", connectionID),
					zap.String("remote", conn.RemoteAddr().String()),
					zap.String("event", "anytls_probe"),
					zap.String("outcome", "rejected"),
					zap.String("reason", probeFailureReason(detectErr)),
					zap.Error(detectErr),
				)
				_ = conn.Close()
				continue
			case detectErr != nil:
				wl.config.logger.Warn("connection rejected during anytls probe",
					zap.Uint64("connection_id", connectionID),
					zap.String("remote", conn.RemoteAddr().String()),
					zap.String("event", "anytls_probe"),
					zap.String("outcome", "rejected"),
					zap.String("reason", probeFailureReason(detectErr)),
					zap.Error(detectErr),
				)
				_ = conn.Close()
				continue
			case decision == DecisionFallback:
				wl.config.logger.Debug("connection routed to website",
					zap.Uint64("connection_id", connectionID),
					zap.String("remote", conn.RemoteAddr().String()),
					zap.String("event", "fallback"),
					zap.String("outcome", "fallback"),
				)
				websiteConn, err := wl.config.prepareWebsiteConn(buffered)
				if err != nil {
					return nil, fmt.Errorf("prepare fallback connection: %w", err)
				}
				return websiteConn, nil
			case decision == DecisionReject:
				wl.config.logger.Warn("connection rejected by anytls detector",
					zap.Uint64("connection_id", connectionID),
					zap.String("remote", conn.RemoteAddr().String()),
					zap.String("event", "anytls_probe"),
					zap.String("outcome", "rejected"),
				)
				_ = conn.Close()
				continue
			case decision == DecisionAnyTLS:
				if !wl.config.acquire() {
					wl.config.logger.Warn("rejecting AnyTLS connection due to concurrency limit",
						zap.String("remote", conn.RemoteAddr().String()),
					)
					_ = conn.Close()
					continue
				}
				wl.config.logger.Debug("connection detected as anytls",
					zap.Uint64("connection_id", connectionID),
					zap.String("remote", conn.RemoteAddr().String()),
					zap.String("event", "anytls_probe"),
					zap.String("outcome", "anytls"),
				)
				go wl.serveAnyTLS(buffered, connectionID)
				continue
			default:
				websiteConn, err := wl.config.prepareWebsiteConn(buffered)
				if err != nil {
					return nil, fmt.Errorf("prepare fallback connection: %w", err)
				}
				return websiteConn, nil
			}
		}

		buffered := newBufferedConn(conn)
		decision, detectErr := wl.classifyBufferedConn(buffered)
		switch {
		case detectErr != nil && decision == DecisionFallback && wl.config.Fallback:
			wl.config.logFallback(conn, detectErr)
			return buffered, nil
		case detectErr != nil && decision == DecisionReject:
			wl.config.logger.Warn("connection rejected during anytls probe",
				zap.Uint64("connection_id", connectionID),
				zap.String("remote", conn.RemoteAddr().String()),
				zap.String("event", "anytls_probe"),
				zap.String("outcome", "rejected"),
				zap.String("reason", probeFailureReason(detectErr)),
				zap.Error(detectErr),
			)
			_ = conn.Close()
			continue
		case detectErr != nil:
			wl.config.logger.Warn("connection rejected during anytls probe",
				zap.Uint64("connection_id", connectionID),
				zap.String("remote", conn.RemoteAddr().String()),
				zap.String("event", "anytls_probe"),
				zap.String("outcome", "rejected"),
				zap.String("reason", probeFailureReason(detectErr)),
				zap.Error(detectErr),
			)
			_ = conn.Close()
			continue
		case decision == DecisionFallback:
			wl.config.logger.Debug("connection routed to website",
				zap.Uint64("connection_id", connectionID),
				zap.String("remote", conn.RemoteAddr().String()),
				zap.String("event", "fallback"),
				zap.String("outcome", "fallback"),
			)
			return buffered, nil
		case decision == DecisionReject:
			wl.config.logger.Warn("connection rejected by anytls detector",
				zap.Uint64("connection_id", connectionID),
				zap.String("remote", conn.RemoteAddr().String()),
				zap.String("event", "anytls_probe"),
				zap.String("outcome", "rejected"),
			)
			_ = conn.Close()
			continue
		case decision == DecisionAnyTLS:
			if !wl.config.acquire() {
				wl.config.logger.Warn("rejecting AnyTLS connection due to concurrency limit",
					zap.String("remote", conn.RemoteAddr().String()),
				)
				_ = conn.Close()
				continue
			}
			wl.config.logger.Debug("connection detected as anytls",
				zap.Uint64("connection_id", connectionID),
				zap.String("remote", conn.RemoteAddr().String()),
				zap.String("event", "anytls_probe"),
				zap.String("outcome", "anytls"),
			)
			go wl.serveAnyTLS(buffered, connectionID)
			continue
		default:
			return buffered, nil
		}
	}
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

func (wl *wrappedListener) classifyBufferedConn(conn *bufferedConn) (Decision, error) {
	preview, err := conn.Peek(32, time.Duration(wl.config.ProbeTimeout))
	if err != nil && !errors.Is(err, net.ErrClosed) {
		return DecisionFallback, fmt.Errorf("peek first bytes: %w", err)
	}
	return wl.classifyPreview(preview)
}

func (wl *wrappedListener) classifyPreview(preview []byte) (Decision, error) {
	if len(preview) == 0 {
		return DecisionFallback, nil
	}

	decision, detectErr := wl.config.detector.Detect(preview)
	if detectErr != nil {
		return decision, fmt.Errorf("detect anytls: %w", detectErr)
	}

	return decision, nil
}

func (wl *wrappedListener) serveAnyTLS(conn net.Conn, connectionID uint64) {
	defer wl.config.release()
	startedAt := time.Now()

	_ = conn.SetDeadline(time.Now().Add(time.Duration(wl.config.IdleTimeout)))

	source := M.SocksaddrFromNet(conn.RemoteAddr())
	baseCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := contextWithConnectionID(baseCtx, connectionID)
	wl.config.registerSession(connectionID, conn, cancel)
	defer wl.config.unregisterSession(connectionID)
	err := wl.config.service.NewConnection(ctx, conn, source, func(err error) {
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
	})
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
