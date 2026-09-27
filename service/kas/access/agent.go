package access

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"time"

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

	// agentStatusDeadline bounds one gate decision, however many calls to
	// identity it makes (up to four: token, status, and a retry of both
	// after a 401). It is contract v1's status lease: identity being slow
	// cannot hold a rewrap longer than a quarantine takes to reach this KAS.
	agentStatusDeadline = 5 * time.Second
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
// that the agent proved possession of its cnf key (the interceptor put the
// DPoP key in context) and that authnz-rs says its workload is eligible for
// this DID, swarm and owner. The reason is logged, never returned to the
// caller.
func (p *Provider) agentReleaseDenied(ctx context.Context, agent *agentstatus.Subject) bool {
	var err error
	switch {
	// canAccess reads an empty agentSub as "not an agent", so an agent without
	// a DID must never get past the gate, whatever the checker says.
	case agent.DID == "":
		err = &agentstatus.DenialError{Reason: agentstatus.ReasonMissingSubject, Workload: agent.Workload}
	case ctxAuth.GetJWKFromContext(ctx, p.Logger) == nil:
		err = &agentstatus.DenialError{Reason: reasonNoProofOfPossession, Workload: agent.Workload}
	case p.AgentStatus == nil:
		err = &agentstatus.DenialError{Reason: agentstatus.ReasonUnconfigured, Workload: agent.Workload}
	default:
		checkCtx, cancel := context.WithTimeout(ctx, agentStatusDeadline)
		err = p.AgentStatus.Check(checkCtx, *agent)
		cancel()
	}
	if err == nil {
		return false
	}
	p.logAgentDenial(ctx, agent, err)
	return true
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
		// These two refuse every agent until an operator fixes config, so they
		// are errors rather than per-agent warnings.
		if d.Reason == agentstatus.ReasonStatusForbidden || d.Reason == agentstatus.ReasonUnconfigured {
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
// binding and a valid one get the same answer. The policy is decoded only to
// name it in the audit record.
func (p *Provider) denyAgentRewrap(ctx context.Context, requests []*kaspb.UnsignedRewrapRequest_WithPolicyRequest) policyKAOResults {
	results := make(policyKAOResults)
	for _, req := range requests {
		policyID := req.GetPolicy().GetId()
		if policyID == "" {
			continue
		}
		kaoResults := make(map[string]kaoResult)
		results[policyID] = kaoResults
		policy, err := decodePolicy(req.GetPolicy().GetBody())
		if err != nil {
			policy = &Policy{}
		}
		kasPolicy := ConvertToAuditKasPolicy(*policy)
		for _, kao := range req.GetKeyAccessObjects() {
			p.Logger.Audit.RewrapFailure(ctx, audit.RewrapAuditEventParams{
				Policy:        kasPolicy,
				TDFFormat:     "tdf3",
				Algorithm:     req.GetAlgorithm(),
				PolicyBinding: kao.GetKeyAccessObject().GetPolicyBinding().GetHash(),
				KeyID:         kao.GetKeyAccessObject().GetKid(),
			})
			failedKAORewrap(kaoResults, kao, err403("forbidden"))
		}
	}
	return results
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
