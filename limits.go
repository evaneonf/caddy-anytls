package anytls

import "sync/atomic"

func (lw *ListenerWrapper) acquire() bool {
	if lw.MaxConcurrent <= 0 {
		return true
	}

	for {
		current := atomic.LoadInt64(&lw.active)
		if int(current) >= lw.MaxConcurrent {
			return false
		}
		if atomic.CompareAndSwapInt64(&lw.active, current, current+1) {
			return true
		}
	}
}

func (lw *ListenerWrapper) release() {
	if lw.MaxConcurrent <= 0 {
		return
	}
	atomic.AddInt64(&lw.active, -1)
}
