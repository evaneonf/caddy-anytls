package anytls

import (
	"context"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"
)

type sessionRegistry struct {
	mu       sync.Mutex
	sessions map[uint64]*activeSession
}

type activeSession struct {
	cancel        context.CancelFunc
	conn          net.Conn
	startedAt     time.Time
	user          string
	activeStreams int
}

func newSessionRegistry() *sessionRegistry {
	return &sessionRegistry{
		sessions: make(map[uint64]*activeSession),
	}
}

func (lw *ListenerWrapper) registerSession(connectionID uint64, conn net.Conn, cancel context.CancelFunc) {
	lw.registry.mu.Lock()
	defer lw.registry.mu.Unlock()
	lw.registry.sessions[connectionID] = &activeSession{
		cancel:    cancel,
		conn:      conn,
		startedAt: time.Now(),
	}
}

func (lw *ListenerWrapper) updateSessionUser(connectionID uint64, user string) {
	lw.registry.mu.Lock()
	defer lw.registry.mu.Unlock()
	session, ok := lw.registry.sessions[connectionID]
	if !ok {
		return
	}
	session.user = user
}

func (lw *ListenerWrapper) unregisterSession(connectionID uint64) {
	lw.registry.mu.Lock()
	defer lw.registry.mu.Unlock()
	delete(lw.registry.sessions, connectionID)
}

func (lw *ListenerWrapper) acquireSessionStream(connectionID uint64) bool {
	lw.registry.mu.Lock()
	defer lw.registry.mu.Unlock()
	session, ok := lw.registry.sessions[connectionID]
	if !ok {
		return false
	}
	if lw.MaxStreamsPerSession > 0 && session.activeStreams >= lw.MaxStreamsPerSession {
		return false
	}
	session.activeStreams++
	return true
}

func (lw *ListenerWrapper) releaseSessionStream(connectionID uint64) {
	lw.registry.mu.Lock()
	defer lw.registry.mu.Unlock()
	if session, ok := lw.registry.sessions[connectionID]; ok && session.activeStreams > 0 {
		session.activeStreams--
	}
}

func (lw *ListenerWrapper) closeActiveSessions(reason string) {
	lw.registry.mu.Lock()
	snapshots := make([]struct {
		connectionID uint64
		cancel       context.CancelFunc
		conn         net.Conn
		startedAt    time.Time
		user         string
	}, 0, len(lw.registry.sessions))
	for connectionID, session := range lw.registry.sessions {
		snapshots = append(snapshots, struct {
			connectionID uint64
			cancel       context.CancelFunc
			conn         net.Conn
			startedAt    time.Time
			user         string
		}{
			connectionID: connectionID,
			cancel:       session.cancel,
			conn:         session.conn,
			startedAt:    session.startedAt,
			user:         session.user,
		})
	}
	lw.registry.mu.Unlock()

	for _, item := range snapshots {
		item.cancel()
		_ = item.conn.Close()
		lw.logger.Info("anytls session terminated",
			zap.Uint64("connection_id", item.connectionID),
			zap.String("event", "anytls_session"),
			zap.String("outcome", "terminated"),
			zap.String("reason", reason),
			zap.String("user", item.user),
			zap.Duration("duration", time.Since(item.startedAt)),
		)
	}
}
