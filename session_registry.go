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
	cancel    context.CancelFunc
	conn      net.Conn
	startedAt time.Time
	user      string
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

func (lw *ListenerWrapper) activeSessionCount() int {
	lw.registry.mu.Lock()
	defer lw.registry.mu.Unlock()
	return len(lw.registry.sessions)
}

func (lw *ListenerWrapper) closeActiveSessions(reason string) {
	lw.registry.mu.Lock()
	snapshots := make([]struct {
		connectionID uint64
		session      *activeSession
	}, 0, len(lw.registry.sessions))
	for connectionID, session := range lw.registry.sessions {
		snapshots = append(snapshots, struct {
			connectionID uint64
			session      *activeSession
		}{
			connectionID: connectionID,
			session:      session,
		})
	}
	lw.registry.mu.Unlock()

	for _, item := range snapshots {
		item.session.cancel()
		_ = item.session.conn.Close()
		lw.logger.Info("anytls session terminated",
			zap.Uint64("connection_id", item.connectionID),
			zap.String("event", "anytls_session"),
			zap.String("outcome", "terminated"),
			zap.String("reason", reason),
			zap.String("user", item.session.user),
			zap.Duration("duration", time.Since(item.session.startedAt)),
		)
	}
}
