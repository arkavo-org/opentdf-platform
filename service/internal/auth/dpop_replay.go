package auth

import (
	"crypto/sha256"
	"sync"
	"time"
)

const dpopReplaySweepInterval = time.Minute

// dpopReplayCache remembers key-bound proof ids until the proof they came
// from could no longer be accepted, so a replay inside the acceptance window
// always collides. It is per process: replicas do not share it. Entries are
// SHA-256 digests because the key holder chooses the id.
type dpopReplayCache struct {
	mu        sync.Mutex
	seen      map[[sha256.Size]byte]time.Time
	nextSweep time.Time
	now       func() time.Time
}

func newDPoPReplayCache(now func() time.Time) *dpopReplayCache {
	return &dpopReplayCache{seen: make(map[[sha256.Size]byte]time.Time), now: now}
}

// claim records id as used until expiry and reports whether it was unused.
// now is the reading the caller judged the proof live on. The replay
// decision must use it: a later reading could fall past expiry and let a
// proof the caller still accepts be claimed twice. An entry blocks up to and
// including expiry, because validateDPoP accepts a proof up to and including
// iat + dpopskew.
func (c *dpopReplayCache) claim(id string, expiry, now time.Time) bool {
	key := sha256.Sum256([]byte(id))
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sweep()
	if exp, used := c.seen[key]; used && !now.After(exp) {
		return false
	}
	c.seen[key] = expiry
	return true
}

// sweep drops expired entries on the cache's own clock. It keeps each entry
// one sweep interval past its expiry, so a reading taken earlier by a
// concurrent or slow request still finds the entry.
func (c *dpopReplayCache) sweep() {
	sweepNow := c.now()
	if !sweepNow.After(c.nextSweep) {
		return
	}
	for k, exp := range c.seen {
		if sweepNow.After(exp.Add(dpopReplaySweepInterval)) {
			delete(c.seen, k)
		}
	}
	c.nextSweep = sweepNow.Add(dpopReplaySweepInterval)
}
