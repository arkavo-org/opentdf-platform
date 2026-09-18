package authz

import (
	"context"
	"sync"
)

// Session carries state an evaluator may reuse across every decision of one
// request.
//
// A decision request is cheap to ask but not always cheap to answer: an
// evaluator backed by the policy graph has to assemble that graph before it
// can decide anything. One request that asks a hundred questions should
// assemble it once, not a hundred times.
//
// A session is scoped to a single inbound request. It is not a cache: it
// never outlives the request, so policy is exactly as fresh as it would be
// for a request that asked a single question.
type Session struct {
	mu     sync.Mutex
	values map[any]sessionEntry
}

type sessionEntry struct {
	value any
	err   error
}

type sessionContextKey struct{}

// NewSession returns an empty session.
func NewSession() *Session {
	return &Session{values: make(map[any]sessionEntry)}
}

// ContextWithSession scopes a session to a context. Enforcement points that
// ask more than one question per request should establish one.
func ContextWithSession(ctx context.Context, s *Session) context.Context {
	if s == nil {
		return ctx
	}
	return context.WithValue(ctx, sessionContextKey{}, s)
}

// SessionFromContext returns the request's session, or nil when the caller
// did not establish one.
func SessionFromContext(ctx context.Context) *Session {
	session, _ := ctx.Value(sessionContextKey{}).(*Session)
	return session
}

// Do returns the value stored under key, building it on first use. The
// result — value or error — is remembered for the life of the session, so a
// build that failed is not retried for every question in the same request.
//
// Do is safe for concurrent use, and holds the session lock across build:
// the questions of one request are answered in sequence, and serializing
// them is what makes a single build shared rather than raced.
func (s *Session) Do(key any, build func() (any, error)) (any, error) {
	if s == nil {
		return build()
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if entry, ok := s.values[key]; ok {
		return entry.value, entry.err
	}
	value, err := build()
	s.values[key] = sessionEntry{value: value, err: err}
	return value, err
}
