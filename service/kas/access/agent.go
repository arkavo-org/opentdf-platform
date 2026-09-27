package access

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"

	"github.com/lestrrat-go/jwx/v2/jwt"
	kaspb "github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/service/internal/agentstatus"
	"github.com/opentdf/platform/service/logger/audit"
	ctxAuth "github.com/opentdf/platform/service/pkg/auth"
)

const (
	claimNPE       = "arkavo_npe"
	claimRoles     = "arkavo_roles"
	claimWorkload  = "arkavo_workload"
	claimSwarm     = "arkavo_swarm"
	claimAccountID = "arkavo_account_id"
	roleAgent      = "agent"
	// npeTypeDevice is the only non-agent arkavo_npe authnz-rs mints (the
	// DeviceCheck assertion token). Any other arkavo_npe is gated.
	npeTypeDevice = "device"

	agentDeniedMsg            = "agent rewrap denied"
	reasonNoProofOfPossession = "agent token presented without a DPoP proof"
	// reasonProofNotKeyBound: the proof matched only a cnf.jkt thumbprint, so
	// its algorithm was not held to the key and its jti was not spent.
	// authnz-rs binds every agent token to a cnf key.
	reasonProofNotKeyBound = "agent token DPoP binding is not key-bound (cnf.jkt instead of a cnf key)"
	reasonCheckerPanicked  = "agent status checker panicked"
)

// agentFromToken returns the agent a verified bearer describes, or nil when
// the bearer carries no agent marker. The markers are an arkavo_npe that is
// not a device descriptor, an "agent" arkavo_roles entry, and the presence of
// arkavo_workload or arkavo_swarm. Any one of them gates the bearer: a token
// that looks partly like an agent token must be refused by the gate, never
// released as a human. Claims of the wrong type read as absent, which the
// status check refuses.
func agentFromToken(tok jwt.Token) *agentstatus.Subject {
	claims := tok.PrivateClaims()
	if !hasAgentMarker(claims) {
		return nil
	}
	workload, _ := claims[claimWorkload].(string)
	swarm, _ := claims[claimSwarm].(string)
	owner, _ := claims[claimAccountID].(string)
	return &agentstatus.Subject{DID: tok.Subject(), Workload: workload, Swarm: swarm, Owner: owner}
}

func hasAgentMarker(claims map[string]any) bool {
	if _, ok := claims[claimWorkload]; ok {
		return true
	}
	if _, ok := claims[claimSwarm]; ok {
		return true
	}
	if npe, ok := claims[claimNPE]; ok && !isDeviceNPE(npe) {
		return true
	}
	return hasAgentRole(claims[claimRoles])
}

func isDeviceNPE(npe any) bool {
	m, ok := npe.(map[string]any)
	if !ok {
		return false
	}
	t, ok := m["type"].(string)
	return ok && t == npeTypeDevice
}

// hasAgentRole reads arkavo_roles as a string or []any; the verifiers
// decode every array claim to []any, so no other slice type can arrive.
func hasAgentRole(roles any) bool {
	switch r := roles.(type) {
	case string:
		return r == roleAgent
	case []any:
		for _, role := range r {
			if role == roleAgent {
				return true
			}
		}
	}
	return false
}

// agentReleaseDenied reports whether an agent must be refused now. It holds
// that the agent proved possession of its cnf key under the key-bound rules
// (the interceptor put the DPoP key in context and marked it key-bound) and
// that authnz-rs says its workload is eligible for this DID, swarm and
// owner. The status client bounds its own calls; ctx is the caller's, so a
// cancelled rewrap stops the check. The reason is logged, never returned to
// the caller.
func (p *Provider) agentReleaseDenied(ctx context.Context, agent *agentstatus.Subject) bool {
	var err error
	switch {
	// canAccess reads an empty agentSub as "not an agent", so an agent without
	// a DID must never get past the gate, whatever the checker says.
	case agent.DID == "":
		err = &agentstatus.DenialError{Reason: agentstatus.ReasonMissingSubject, Workload: agent.Workload}
	case ctxAuth.GetJWKFromContext(ctx, p.Logger) == nil:
		err = &agentstatus.DenialError{Reason: reasonNoProofOfPossession, Workload: agent.Workload}
	case !ctxAuth.IsDPoPKeyBound(ctx):
		err = &agentstatus.DenialError{Reason: reasonProofNotKeyBound, Workload: agent.Workload}
	case p.AgentStatus == nil:
		err = &agentstatus.DenialError{Reason: agentstatus.ReasonUnconfigured, Workload: agent.Workload}
	default:
		err = p.checkStatus(ctx, *agent)
	}
	if err == nil {
		return false
	}
	p.logAgentDenial(ctx, agent, err)
	return true
}

// checkStatus runs the checker, turning a panic into a denial so a faulty
// checker refuses the agent instead of escaping into the transport.
func (p *Provider) checkStatus(ctx context.Context, agent agentstatus.Subject) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = &agentstatus.DenialError{Reason: reasonCheckerPanicked, Workload: agent.Workload, Cause: fmt.Errorf("%v", r)}
		}
	}()
	return p.AgentStatus.Check(ctx, agent)
}

// logAgentDenial records who was refused and why. The bearer, the DPoP proof
// and the status client's credentials are never among the attributes.
func (p *Provider) logAgentDenial(ctx context.Context, agent *agentstatus.Subject, err error) {
	attrs := []slog.Attr{
		slog.String("agent", agent.DID),
		slog.String("owner", agent.Owner),
		slog.String("workload", agent.Workload),
		slog.String("swarm", agent.Swarm),
	}
	level := slog.LevelWarn
	var d *agentstatus.DenialError
	if errors.As(err, &d) {
		attrs = append(attrs,
			slog.String("reason", d.Reason),
			slog.String("incident", d.Incident),
			slog.Uint64("generation", d.Generation),
		)
		if d.Cause != nil {
			attrs = append(attrs, slog.String("cause", d.Cause.Error()))
		}
		// These refuse every agent until an operator fixes config (or, for a
		// panic, the code), so they are errors rather than per-agent warnings.
		switch d.Reason {
		case agentstatus.ReasonStatusForbidden, agentstatus.ReasonStatusCredentialsRejected, agentstatus.ReasonUnconfigured, reasonCheckerPanicked:
			level = slog.LevelError
		}
	} else {
		attrs = append(attrs, slog.String("reason", err.Error()))
	}
	p.Logger.LogAttrs(ctx, level, agentDeniedMsg, attrs...)
}

// denyAgentRewrap refuses every KAO of every request with the "forbidden" an
// ABAC denial produces, and audits each as a failure. It runs before any KAO
// is unwrapped, so a refused agent learns nothing about its KAOs: a tampered
// binding and a valid one get the same answer.
func (p *Provider) denyAgentRewrap(ctx context.Context, requests []*kaspb.UnsignedRewrapRequest_WithPolicyRequest) policyKAOResults {
	results := make(policyKAOResults)
	for _, req := range requests {
		if req.GetPolicy().GetId() == "" {
			continue
		}
		p.refuseRequest(ctx, results, req, err403("forbidden"))
	}
	return results
}

// refuseRequest fails every KAO of req with err and audits each as a
// failure, without unwrapping anything. A KAO with no key access object gets
// the 400 the normal path gives it and, as there, no audit record. Requests
// sharing a policy Id share one result map, so none of their KAOs drops out
// of the response. The policy is decoded only to name it in the audit
// record.
func (p *Provider) refuseRequest(ctx context.Context, results policyKAOResults, req *kaspb.UnsignedRewrapRequest_WithPolicyRequest, err error) {
	policyID := req.GetPolicy().GetId()
	kaoResults, ok := results[policyID]
	if !ok {
		kaoResults = make(map[string]kaoResult)
		results[policyID] = kaoResults
	}
	policy, decodeErr := decodePolicy(req.GetPolicy().GetBody())
	if decodeErr != nil {
		policy = &Policy{}
	}
	kasPolicy := ConvertToAuditKasPolicy(*policy)
	for _, kao := range req.GetKeyAccessObjects() {
		if kao.GetKeyAccessObject() == nil {
			failedKAORewrap(kaoResults, kao, err400("key access object is nil"))
			continue
		}
		p.Logger.Audit.RewrapFailure(ctx, audit.RewrapAuditEventParams{
			Policy:        kasPolicy,
			TDFFormat:     "tdf3",
			Algorithm:     req.GetAlgorithm(),
			PolicyBinding: kao.GetKeyAccessObject().GetPolicyBinding().GetHash(),
			KeyID:         kao.GetKeyAccessObject().GetKid(),
		})
		failedKAORewrap(kaoResults, kao, err)
	}
}

// refuseDuplicatePolicyIDs fails every request whose policy Id another
// request also carries, and returns the rest. Results are keyed by policy
// Id, so two such requests cannot both be answered: without this the later
// one's results replace the earlier's, its KAOs are then looked up in the
// wrong map, and an unmatched KAO reaches Encapsulate with no key. Requests
// without a policy Id pass through untouched, as before.
func (p *Provider) refuseDuplicatePolicyIDs(ctx context.Context, requests []*kaspb.UnsignedRewrapRequest_WithPolicyRequest, results policyKAOResults) []*kaspb.UnsignedRewrapRequest_WithPolicyRequest {
	seen := make(map[string]int, len(requests))
	for _, req := range requests {
		if id := req.GetPolicy().GetId(); id != "" {
			seen[id]++
		}
	}
	unique := make([]*kaspb.UnsignedRewrapRequest_WithPolicyRequest, 0, len(requests))
	for _, req := range requests {
		id := req.GetPolicy().GetId()
		if id == "" || seen[id] == 1 {
			unique = append(unique, req)
			continue
		}
		p.Logger.WarnContext(ctx, "rewrap: policy id shared by more than one request", slog.String("policy_id", id))
		p.refuseRequest(ctx, results, req, err400("bad request"))
	}
	return unique
}

// dissemAllows reports whether a policy's dissemination list admits an agent.
// An empty list defers entirely to ABAC; a non-empty one must name the DID
// exactly (DIDs are case-sensitive, so no folding or trimming). An empty DID
// is never admitted, even by an empty entry.
func dissemAllows(dissem []string, agentSub string) bool {
	if len(dissem) == 0 {
		return true
	}
	return agentSub != "" && slices.Contains(dissem, agentSub)
}
