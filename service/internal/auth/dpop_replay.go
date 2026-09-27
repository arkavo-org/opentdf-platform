package auth

import (
	"sync"
	"time"
)

const dpopReplaySweepInterval = time.Minute

// dpopReplayCache remembers COSE-bound proof ids until the proof they came
// from could no longer be accepted, so a replay inside the acceptance window
// always collides. It is per process: replicas do not share it.
type dpopReplayCache struct {
	mu        sync.Mutex
	seen      map[string]time.Time
	nextSweep time.Time
	now       func() time.Time
}

func newDPoPReplayCache(now func() time.Time) *dpopReplayCache {
	return &dpopReplayCache{seen: make(map[string]time.Time), now: now}
}

// claim records key as used until expiry and reports whether it was unused.
// An entry still blocks at exactly its expiry, because validateDPoP accepts
// a proof up to and including iat + dpopskew.
func (c *dpopReplayCache) claim(key string, expiry time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if now.After(c.nextSweep) {
		for k, exp := range c.seen {
			if now.After(exp) {
				delete(c.seen, k)
			}
		}
		c.nextSweep = now.Add(dpopReplaySweepInterval)
	}
	if exp, used := c.seen[key]; used && !now.After(exp) {
		return false
	}
	c.seen[key] = expiry
	return true
}
