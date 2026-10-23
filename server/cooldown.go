package server

import (
	"sync"
	"time"
)

// maxCached bounds the cache; past it the cache starts over.
const maxCached = 10000

// refreshFloor is how old a result must be before a refresh runs a fresh check.
const refreshFloor = time.Minute

// cooldown answers repeated checks of one host from its last result and
// runs concurrent checks of one host once.
type cooldown struct {
	window time.Duration
	now    func() time.Time

	mu        sync.Mutex
	entries   map[string]cached
	inflight  map[string]*flight
	lastSweep time.Time
}

type cached struct {
	report Report
	at     time.Time
}

type flight struct {
	oracle bool
	done   chan struct{}
	report Report
	err    error
}

func newCooldown(window time.Duration, now func() time.Time) *cooldown {
	return &cooldown{window: window, now: now, entries: map[string]cached{}, inflight: map[string]*flight{}}
}

// do returns a fresh result for host, waits for a check already running, or
// runs fn. A result without the oracle does not answer a request for it, and a
// refresh passes over a result older than refreshFloor.
func (c *cooldown) do(host string, oracle, refresh bool, fn func() (Report, error)) (Report, bool, error) {
	c.mu.Lock()
	now := c.now()
	c.sweep(now)
	if e, ok := c.entries[host]; ok && now.Sub(e.at) < c.window && (e.report.OracleRun || !oracle) && !(refresh && now.Sub(e.at) >= refreshFloor) {
		c.mu.Unlock()
		return e.report, true, nil
	}
	if f, ok := c.inflight[host]; ok && (f.oracle || !oracle) {
		c.mu.Unlock()
		<-f.done
		return f.report, true, f.err
	}
	f := &flight{oracle: oracle, done: make(chan struct{})}
	c.inflight[host] = f
	c.mu.Unlock()

	report, err := fn()

	c.mu.Lock()
	if c.inflight[host] == f {
		delete(c.inflight, host)
	}
	if err == nil && c.window > 0 {
		if len(c.entries) >= maxCached {
			c.entries = map[string]cached{}
		}
		c.entries[host] = cached{report: report, at: c.now()}
	}
	c.mu.Unlock()
	f.report, f.err = report, err
	close(f.done)
	return report, false, err
}

// sweep drops expired entries once per window. Callers hold the lock.
func (c *cooldown) sweep(now time.Time) {
	if c.window <= 0 || (!c.lastSweep.IsZero() && now.Sub(c.lastSweep) < c.window) {
		return
	}
	c.lastSweep = now
	for host, e := range c.entries {
		if now.Sub(e.at) >= c.window {
			delete(c.entries, host)
		}
	}
}
