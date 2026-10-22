package server

import (
	"sync"
	"time"
)

// RateLimiter counts events per client over a sliding window.
type RateLimiter struct {
	max    int
	window time.Duration
	// Now is the clock; nil is time.Now in UTC.
	Now func() time.Time

	mu        sync.Mutex
	events    map[string][]time.Time
	lastSweep time.Time
}

// NewRateLimiter returns a limiter; a disabled configuration allows everything.
func NewRateLimiter(cfg RateLimitConfig) *RateLimiter {
	limiter := &RateLimiter{events: map[string][]time.Time{}}
	if cfg.Enabled {
		limiter.max = cfg.Max
		limiter.window = cfg.Window.Duration
	}
	return limiter
}

// settings are the allowance in force.
func (l *RateLimiter) settings() (int, time.Duration) {
	if l == nil {
		return 0, 0
	}
	return l.max, l.window
}

// Enabled reports a limiter that refuses anything.
func (l *RateLimiter) Enabled() bool {
	max, window := l.settings()
	return max > 0 && window > 0
}

// Allow charges one event and, on refusal, when a slot reopens.
func (l *RateLimiter) Allow(client string) (bool, time.Duration) {
	max, window := l.settings()
	if max <= 0 || window <= 0 {
		return true, 0
	}
	now := l.now()
	cutoff := now.Add(-window)

	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweep(cutoff, window)

	kept := prune(l.events[client], cutoff)
	if len(kept) >= max {
		l.events[client] = kept
		retry := kept[0].Add(window).Sub(now)
		if retry < time.Second {
			retry = time.Second
		}
		return false, retry
	}
	l.events[client] = append(kept, now)
	return true, 0
}

// Clients is how many addresses the limiter still tracks.
func (l *RateLimiter) Clients() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.events)
}

// sweep drops clients with nothing left in the window, once per window at
// most. Callers hold the lock.
func (l *RateLimiter) sweep(cutoff time.Time, window time.Duration) {
	if !l.lastSweep.IsZero() && cutoff.Sub(l.lastSweep) < window {
		return
	}
	l.lastSweep = cutoff
	for client, events := range l.events {
		if kept := prune(events, cutoff); len(kept) == 0 {
			delete(l.events, client)
		} else {
			l.events[client] = kept
		}
	}
}

// prune drops the events that have left the window; they are in order.
func prune(events []time.Time, cutoff time.Time) []time.Time {
	at := 0
	for at < len(events) && !events[at].After(cutoff) {
		at++
	}
	return events[at:]
}

func (l *RateLimiter) now() time.Time {
	if l.Now != nil {
		return l.Now()
	}
	return time.Now().UTC()
}
