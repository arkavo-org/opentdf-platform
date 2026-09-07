package authz

import (
	"context"
	"sync"
)

// EvaluatorRegistry is the hand-off point between the PEP, which is built
// during server construction, and the PDP, which is registered later when
// services start. Holding the evaluator behind a registry keeps the
// authorization engine free of a startup-ordering dependency on the
// authorization service, and keeps both sides free of an RPC hop.
//
// The zero value is not usable; construct one with NewEvaluatorRegistry.
type EvaluatorRegistry struct {
	mu        sync.RWMutex
	evaluator Evaluator
}

// NewEvaluatorRegistry returns an empty registry.
func NewEvaluatorRegistry() *EvaluatorRegistry {
	return &EvaluatorRegistry{}
}

// Register installs the platform policy evaluator. The last registration
// wins; passing nil clears it.
func (r *EvaluatorRegistry) Register(e Evaluator) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.evaluator = e
}

// Evaluator returns the registered evaluator, or nil when policy-backed
// evaluation is not available in this process (for example, a deployment
// mode that does not run the authorization service).
func (r *EvaluatorRegistry) Evaluator() Evaluator {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.evaluator
}

// Evaluate satisfies Evaluator so a registry can be used directly as one.
// It abstains when no evaluator is registered.
func (r *EvaluatorRegistry) Evaluate(ctx context.Context, req DecisionRequest) (Decision, error) {
	e := r.Evaluator()
	if e == nil {
		return Decision{Effect: EffectAbstain, Source: "policy", Reason: "no policy evaluator registered"}, nil
	}
	return e.Evaluate(ctx, req)
}
