package access

import (
	"context"
	"log/slog"
)

// DecisionRestrictor narrows a decision that policy has already made.
//
// The interface is deliberately one-directional: an implementation returns the
// resources to deny, never a Decision. The caller independently applies those
// denials only to policy's permit set, enforcing finalPermits ⊆ policyPermits.
// This guarantee concerns returned values; an in-process interface cannot rule
// out unrelated side effects by a malicious implementation.
type DecisionRestrictor interface {
	// Deny reports which resources to deny, keyed by ephemeral resource ID,
	// with a short human-readable reason for the audit trail. Returning an
	// empty map leaves the decision untouched.
	//
	// An error fails the decision, which is how an implementation expresses
	// fail-closed behavior. To fail open, return no denials and no error.
	Deny(ctx context.Context, req RestrictionRequest) (map[string]string, error)
}

// RestrictionRequest describes a decision that policy has already evaluated.
type RestrictionRequest struct {
	// EntityID identifies the requesting entity.
	EntityID string
	// ActionName is the action being taken.
	ActionName string
	// Resources are the resources evaluated, with the decision policy reached.
	Resources []RestrictionResource
}

// RestrictionResource is one resource as policy decided it.
type RestrictionResource struct {
	// EphemeralID matches ResourceDecision.ResourceID, and is the key a
	// restrictor returns to deny this resource.
	EphemeralID string
	// Name is the resource name, when the request carried one.
	Name string
	// AttributeValueFQNs are the attribute values on this resource.
	AttributeValueFQNs []string
	// Permitted reports what policy decided. A restrictor denying a resource
	// that was already denied changes nothing.
	Permitted bool
}

// buildRestrictionRequest projects a Decision into the read-only view a
// restrictor sees.
func buildRestrictionRequest(entityID, actionName string, decision *Decision) RestrictionRequest {
	resources := make([]RestrictionResource, 0, len(decision.Results))

	for _, result := range decision.Results {
		fqns := make([]string, 0)
		for _, rule := range result.DataRuleResults {
			fqns = append(fqns, rule.ResourceValueFQNs...)
		}

		resources = append(resources, RestrictionResource{
			EphemeralID:        result.ResourceID,
			Name:               result.ResourceName,
			AttributeValueFQNs: fqns,
			Permitted:          result.Passed,
		})
	}

	return RestrictionRequest{
		EntityID:   entityID,
		ActionName: actionName,
		Resources:  resources,
	}
}

// applyRestrictions consults the restrictor and narrows the decision.
//
// Narrowing is enforced here rather than trusted to the restrictor: a resource
// only ever moves from permitted to denied, and AllPermitted is only ever
// cleared, never set.
//
// It returns the denials actually applied, so callers can mirror them into the
// audit copies of the resource decisions before emitting the audit event.
func (p *JustInTimePDP) applyRestrictions(ctx context.Context, entityID, actionName string, decision *Decision) (map[string]string, error) {
	// "Nothing was restricted" is an empty map rather than nil: identical to
	// callers, and every success path returns a usable value.
	if p.restrictor == nil || decision == nil {
		return noRestrictions(), nil
	}

	denials, err := p.restrictor.Deny(ctx, buildRestrictionRequest(entityID, actionName, decision))
	if err != nil {
		return nil, err
	}
	if len(denials) == 0 {
		return noRestrictions(), nil
	}

	applied := make(map[string]string, len(denials))
	for i := range decision.Results {
		result := &decision.Results[i]
		reason, denied := denials[result.ResourceID]
		if !denied || !result.Passed {
			continue
		}

		result.Passed = false
		applied[result.ResourceID] = reason
		p.logger.WarnContext(ctx, "decision restricted by decision model",
			slog.String("resource_id", result.ResourceID),
			slog.String("reason", reason),
		)
	}

	// Conjunction, never assignment: a restrictor cannot make AllPermitted true.
	if len(applied) > 0 {
		decision.AllPermitted = false
	}
	return applied, nil
}

// noRestrictions is the empty result: policy's decision stands unchanged.
func noRestrictions() map[string]string {
	return map[string]string{}
}

// markRestrictedAuditDecisions mirrors applied denials into the audit copies of
// the resource decisions. Those copies are built before the restrictor runs, so
// without this the audit record would disagree with the decision the caller
// received.
func markRestrictedAuditDecisions(auditResourceDecisions []ResourceDecision, denials map[string]string) {
	if len(denials) == 0 {
		return
	}
	for i := range auditResourceDecisions {
		if _, denied := denials[auditResourceDecisions[i].ResourceID]; denied {
			auditResourceDecisions[i].Passed = false
		}
	}
}
