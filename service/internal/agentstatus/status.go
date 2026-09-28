package agentstatus

import (
	"context"
	"strings"
)

const (
	stateEligible = "eligible"
	// didKeyPrefix and base58Alphabet bound what reaches the status URL: an
	// Ed25519 did:key is "did:key:z" and base58btc (contract v2, CWT sub).
	didKeyPrefix   = "did:key:z"
	didKeyMaxLen   = 128
	base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
)

// Denial reasons. They go to the server log only: the resolver withholds
// every entitlement, and the KAS answers with its generic "forbidden".
const (
	ReasonUnconfigured = "agent status not configured"
	ReasonUnreachable  = "status service unreachable"
	// ReasonUnknownAgent: authnz-rs has no live delegation for the DID
	// (unknown, revoked or expired, and not quarantined).
	ReasonUnknownAgent    = "agent unknown to identity, or its delegation revoked or expired (404)"
	ReasonStatusForbidden = "misconfiguration: this platform's status client is not in authnz-rs AGENT_STATUS_CLIENT_IDS (403)"
	// ReasonStatusCredentialsRejected is the token endpoint refusing this
	// platform's client_id/client_secret (401 or 403): a wrong secret, not a
	// transient fault.
	ReasonStatusCredentialsRejected = "misconfiguration: identity rejected agent_status.client_id/client_secret at /oauth/token"
	ReasonMissingSubject            = "agent token has no sub"
	ReasonMalformedDID              = "sub is not a did:key (did:key:z + base58btc, at most 128 characters)"
	ReasonMissingStateVersion       = "agent token has no arkavo_state_version (minted before contract v2)"
	ReasonMissingSwarm              = "agent token has no arkavo_swarm"
	ReasonMissingOwner              = "agent token has no arkavo_account_id"
	ReasonAgentMismatch             = "status is for a different agent"
	ReasonNotEligible               = "agent is not eligible"
	ReasonStatusMissingVersion      = "status has no state_version (contract v2 starts at 1)"
	ReasonStateVersionRegressed     = "status state_version went backwards"
	ReasonTokenVersionStale         = "token was minted before the agent's latest state change (arkavo_state_version below state_version)"
	ReasonStatusBehindToken         = "status state_version is below the token's arkavo_state_version"
	ReasonSwarmMismatch             = "arkavo_swarm does not match the agent's swarm"
	ReasonOwnerMismatch             = "arkavo_account_id is not the agent's owner"
)

// Status is the body of GET /agents/{did}/status (contract v2).
type Status struct {
	Agent          string  `json:"agent"`
	Owner          string  `json:"owner"`
	Swarm          string  `json:"swarm"`
	State          string  `json:"state"`
	StateVersion   uint64  `json:"state_version"`
	AppraisedUntil *int64  `json:"appraised_until"`
	AppraisedBy    *string `json:"appraised_by"`
	Incident       *string `json:"incident"`
	ValidUntil     int64   `json:"valid_until"`
}

// Subject is the agent as its verified token describes it.
type Subject struct {
	DID   string
	Swarm string
	Owner string // the token's arkavo_account_id
	// StateVersion is the token's arkavo_state_version; 0 when absent.
	StateVersion uint64
}

// DenialError explains a refused agent for logs and audit.
type DenialError struct {
	Reason string
	Agent  string
	// State and StateVersion are the status's, when one was read.
	State        string
	StateVersion uint64
	Incident     string
	Cause        error
}

func (d *DenialError) Error() string {
	if d.Cause != nil {
		return "agent denied: " + d.Reason + ": " + d.Cause.Error()
	}
	return "agent denied: " + d.Reason
}

func (d *DenialError) Unwrap() error { return d.Cause }

// Checker decides whether an agent may be released a key right now: nil for
// an eligible agent, a *DenialError otherwise.
type Checker interface {
	Check(ctx context.Context, s Subject) error
}

// checkSubject refuses an agent token that cannot be scoped. A token minted
// before contract v2 has no arkavo_state_version and is refused here. A sub
// outside the did:key shape never reaches the status URL.
func checkSubject(s Subject) *DenialError {
	switch {
	case s.DID == "":
		return &DenialError{Reason: ReasonMissingSubject}
	case !validAgentDID(s.DID):
		return &DenialError{Reason: ReasonMalformedDID, Agent: s.DID}
	case s.StateVersion == 0:
		return &DenialError{Reason: ReasonMissingStateVersion, Agent: s.DID}
	case s.Swarm == "":
		return &DenialError{Reason: ReasonMissingSwarm, Agent: s.DID}
	case s.Owner == "":
		return &DenialError{Reason: ReasonMissingOwner, Agent: s.DID}
	}
	return nil
}

// validAgentDID accepts "did:key:z" followed by base58btc, at most
// didKeyMaxLen characters in all: nothing that could climb or split the
// status path.
func validAgentDID(did string) bool {
	rest, ok := strings.CutPrefix(did, didKeyPrefix)
	if !ok || rest == "" || len(did) > didKeyMaxLen {
		return false
	}
	for _, r := range rest {
		if !strings.ContainsRune(base58Alphabet, r) {
			return false
		}
	}
	return true
}

// evaluate applies the release conditions to a live status. highWater is the
// largest state_version this process had seen for the agent before st.
//
// An empty status field never matches, even an empty claim: contract v2 uses
// "" for "none" (swarm before specialization), and release must not hinge on
// checkSubject having run first.
func evaluate(st Status, s Subject, highWater uint64) *DenialError {
	d := &DenialError{Agent: s.DID, State: st.State, StateVersion: st.StateVersion}
	if st.Incident != nil {
		d.Incident = *st.Incident
	}
	switch {
	case !bound(st.Agent, s.DID):
		d.Reason = ReasonAgentMismatch
	case st.State != stateEligible:
		d.Reason = ReasonNotEligible
	case st.StateVersion == 0:
		d.Reason = ReasonStatusMissingVersion
	case st.StateVersion < highWater:
		d.Reason = ReasonStateVersionRegressed
	case s.StateVersion < st.StateVersion:
		d.Reason = ReasonTokenVersionStale
	case s.StateVersion > st.StateVersion:
		d.Reason = ReasonStatusBehindToken
	case !bound(st.Swarm, s.Swarm):
		d.Reason = ReasonSwarmMismatch
	case !bound(st.Owner, s.Owner):
		d.Reason = ReasonOwnerMismatch
	default:
		return nil
	}
	return d
}

// bound reports whether a status field names the token's value.
func bound(status, claim string) bool { return status != "" && status == claim }
