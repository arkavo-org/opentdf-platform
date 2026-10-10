package jev

import (
	"context"
	"sync"
)

// Observation records one consultation of the model and what came of it.
//
// Seams publish observations rather than writing their own audit records, so
// that a single request produces a single audit event with the model's
// influence recorded inline. See Collect and Observations.
type Observation struct {
	// Seam names the integration point, e.g. "obligations".
	Seam string `json:"seam"`
	// Mode is the seam's mode at the time of the call.
	Mode Mode `json:"mode"`

	Model      string `json:"model,omitempty"`
	ResponseID string `json:"response_id,omitempty"`

	// Question is the key in the request's questions map.
	Question   string       `json:"question,omitempty"`
	AnswerType QuestionType `json:"answer_type,omitempty"`
	// Answer is the typed value: bool, string, or float64.
	Answer any `json:"answer,omitempty"`

	Certainty float64 `json:"certainty,omitempty"`
	Threshold float64 `json:"threshold,omitempty"`

	// Applied reports whether the answer changed the outcome. It is false in
	// shadow mode, below threshold, or when the answer implied no change.
	Applied bool `json:"applied"`
	// Effect describes the change in enforcing mode, e.g. an added obligation.
	Effect string `json:"effect,omitempty"`

	Cost float64 `json:"cost,omitempty"`
	// Error is set when the model could not be consulted. Together with
	// Applied=false it shows a fail-open path in the audit trail.
	Error string `json:"error,omitempty"`
}

type collector struct {
	observations []Observation
	mu           sync.Mutex
}

type collectorKey struct{}

// Collect returns a context that accumulates observations for one request.
// Call it once at the top of a request; Observe is a no-op without it, so
// seams never need to know whether collection is active.
func Collect(ctx context.Context) context.Context {
	if _, ok := ctx.Value(collectorKey{}).(*collector); ok {
		return ctx
	}
	return context.WithValue(ctx, collectorKey{}, &collector{})
}

// Observe records an observation on the request's collector, if one is
// installed. It is safe to call concurrently.
func Observe(ctx context.Context, obs Observation) {
	c, ok := ctx.Value(collectorKey{}).(*collector)
	if !ok {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.observations = append(c.observations, obs)
}

// Observations returns what was recorded on this request, or nil if nothing
// was recorded. Audit emission folds the result into the decision event.
func Observations(ctx context.Context) []Observation {
	c, ok := ctx.Value(collectorKey{}).(*collector)
	if !ok {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.observations) == 0 {
		return nil
	}
	out := make([]Observation, len(c.observations))
	copy(out, c.observations)
	return out
}

// TakeObservations returns and clears the request's observations. Audit
// emission uses this destructive read so a multi-entity decision does not
// duplicate the same model calls and costs into every per-entity event.
func TakeObservations(ctx context.Context) []Observation {
	c, ok := ctx.Value(collectorKey{}).(*collector)
	if !ok {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.observations) == 0 {
		return nil
	}
	out := make([]Observation, len(c.observations))
	copy(out, c.observations)
	c.observations = nil
	return out
}
