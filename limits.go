package anytls

import "sync/atomic"

func (lw *ListenerWrapper) acquire() bool {
	return acquireCounter(&lw.active, lw.MaxConcurrent)
}

func (lw *ListenerWrapper) release() {
	if lw.MaxConcurrent <= 0 {
		return
	}
	lw.active.Add(-1)
}

func (lw *ListenerWrapper) acquireStream(connectionID uint64) bool {
	if !lw.acquireSessionStream(connectionID) {
		return false
	}
	if !acquireCounter(&lw.activeStreams, lw.MaxConcurrentStreams) {
		lw.releaseSessionStream(connectionID)
		return false
	}
	return true
}

func (lw *ListenerWrapper) releaseStream(connectionID uint64) {
	if lw.MaxConcurrentStreams > 0 {
		lw.activeStreams.Add(-1)
	}
	lw.releaseSessionStream(connectionID)
}

func acquireCounter(counter *atomic.Int64, limit int) bool {
	if limit <= 0 {
		return true
	}
	for {
		current := counter.Load()
		if int(current) >= limit {
			return false
		}
		if counter.CompareAndSwap(current, current+1) {
			return true
		}
	}
}
