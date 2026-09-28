package arkavo

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/opentdf/platform/service/internal/agentstatus"
)

// Claims the agent gate reads. authnz-rs contract v2 mints
// arkavo_state_version and arkavo_swarm on agent tokens; cnf is the RFC 7800
// confirmation claim (the CWT verifier renders an RFC 8747 COSE_Key cnf as
// cnf.jwk).
const (
	claimStateVersion = "arkavo_state_version"
	claimSwarm        = "arkavo_swarm"
	claimCnf          = "cnf"
	claimNpe          = "arkavo_npe"
	claimRoles        = "arkavo_roles"
	npeTypeAgent      = "agent"
	roleAgent         = "agent"

	agentWithheldMsg = "arkavo: agent entitlements withheld"
	// reasonNotKeyBound: checkToken holds a DPoP proof to the algorithm of
	// the cnf key and spends its jti only when cnf carries the key itself
	// (cnf.jwk). An agent token without one was not sender-constrained that
	// way. authnz-rs binds every agent token to a COSE_Key cnf.
	reasonNotKeyBound = "agent token cnf carries no public key (cnf.jwk with kty OKP or EC): its DPoP proof was not key-bound"
	// reasonNotAgentProfile: the subject carries an agent marker but is not
	// an arkavo_npe of type agent. Such a token is refused, never resolved
	// as a person; a new NPE type is refused until it is allowed here.
	reasonNotAgentProfile = "token carries an agent marker but arkavo_npe.type is not agent"
	reasonCheckerPanicked = "agent status checker panicked"
)

// gated reports whether a trusted subject carries any agent marker: an
// arkavo_npe of any type but device (including a missing, empty or
// malformed type), arkavo_swarm, arkavo_state_version (whatever its
// value), or an agent role. A token that looks partly like an
// agent's is judged as one, never resolved as a person. Person and device
// subjects carry none of these, so they never reach the status service and
// an identity outage cannot change their decisions. A marker only ever
// widens gating: it grants nothing by itself.
func gated(c arkavoClaims) bool {
	npeNotDevice := c.HasNpe && (c.Npe == nil || c.Npe.Type != npeTypeDevice)
	return npeNotDevice || c.HasSwarm || c.HasStateVersion || c.AgentRole
}

// isAgentProfile: the only consistent shape for a gated subject.
func isAgentProfile(c arkavoClaims) bool {
	return c.Npe != nil && c.Npe.Type == npeTypeAgent
}

// hasAgentRole reads arkavo_roles as a string or a list.
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

// hasKeyCnf reports whether cnf carries a well-formed public key (cnf.jwk):
// an object with kty OKP and x, or kty EC with x and y. A null, empty or
// other-typed jwk does not count.
func hasKeyCnf(cnf any) bool {
	members, ok := cnf.(map[string]any)
	if !ok {
		return false
	}
	key, ok := members["jwk"].(map[string]any)
	if !ok {
		return false
	}
	x, _ := key["x"].(string)
	switch key["kty"] {
	case "OKP":
		return x != ""
	case "EC":
		y, _ := key["y"].(string)
		return x != "" && y != ""
	}
	return false
}

// agentSubject is the agent as its subject claims describe it. The owner is
// read from the configured client-id claim, where entitiesFromToken copied
// arkavo_account_id.
func (s *EntityResolutionService) agentSubject(claims map[string]any, c arkavoClaims) agentstatus.Subject {
	owner, _ := claims[s.cfg.ClientIDClaim].(string)
	return agentstatus.Subject{DID: c.Sub, Swarm: c.Swarm, Owner: owner, StateVersion: c.StateVersion}
}

// agentDenial returns nil when the subject is not gated or the agent is
// eligible, and why it is refused otherwise. It never fails the resolution:
// a refused agent resolves with no entitlements and no claims, so the PDP
// denies and the KAS answers each KAO with "forbidden".
func (s *EntityResolutionService) agentDenial(ctx context.Context, subject agentstatus.Subject, c arkavoClaims) error {
	switch {
	case !gated(c):
		return nil
	case !isAgentProfile(c):
		return &agentstatus.DenialError{Reason: reasonNotAgentProfile, Agent: subject.DID}
	case !c.KeyBound:
		return &agentstatus.DenialError{Reason: reasonNotKeyBound, Agent: subject.DID}
	case s.agentStatus == nil:
		return &agentstatus.DenialError{Reason: agentstatus.ReasonUnconfigured, Agent: subject.DID}
	}
	return s.checkStatus(ctx, subject)
}

// checkStatus runs the checker, turning a panic into a denial so a faulty
// checker withholds entitlements instead of failing the decision.
func (s *EntityResolutionService) checkStatus(ctx context.Context, subject agentstatus.Subject) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = &agentstatus.DenialError{Reason: reasonCheckerPanicked, Agent: subject.DID, Cause: fmt.Errorf("%v", r)}
		}
	}()
	return s.agentStatus.Check(ctx, subject)
}

// logAgentDenial records who was refused and why. No token, proof or status
// credential is ever among the attributes.
func (s *EntityResolutionService) logAgentDenial(ctx context.Context, subject agentstatus.Subject, err error) {
	attrs := []slog.Attr{
		slog.String("agent", subject.DID),
		slog.String("owner", subject.Owner),
		slog.String("swarm", subject.Swarm),
		slog.Uint64("token_state_version", subject.StateVersion),
	}
	level := slog.LevelWarn
	var d *agentstatus.DenialError
	if errors.As(err, &d) {
		attrs = append(attrs,
			slog.String("reason", d.Reason),
			slog.String("state", d.State),
			slog.String("incident", d.Incident),
			slog.Uint64("state_version", d.StateVersion),
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
	s.logger.LogAttrs(ctx, level, agentWithheldMsg, attrs...)
}
