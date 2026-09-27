package agentstatus

import (
	"context"
	"strings"
)

const (
	stateEligible    = "eligible"
	workloadIDPrefix = "wl-"
	workloadIDHexLen = 32
)

// Denial reasons. They go to the server log only: the resolver withholds
// every entitlement, and the KAS answers with its generic "forbidden".
const (
	ReasonUnconfigured    = "agent status not configured"
	ReasonUnreachable     = "status service unreachable"
	ReasonUnknownWorkload = "workload unknown to identity (404)"
	ReasonStatusForbidden = "misconfiguration: this platform's status client is not in authnz-rs AGENT_STATUS_CLIENT_IDS (403)"
	// ReasonStatusCredentialsRejected is the token endpoint refusing this
	// platform's client_id/client_secret (401 or 403): a wrong secret, not a
	// transient fault.
	ReasonStatusCredentialsRejected = "misconfiguration: identity rejected agent_status.client_id/client_secret at /oauth/token"
	ReasonMissingSubject            = "agent token has no sub"
	ReasonMissingWorkload           = "agent token has no arkavo_workload (pre-workload token)"
	ReasonMissingSwarm              = "agent token has no arkavo_swarm"
	ReasonMalformedWorkload         = "arkavo_workload is not wl- followed by 32 lowercase hex"
	ReasonWorkloadMismatch          = "status is for a different workload"
	ReasonNotEligible               = "workload is not eligible"
	ReasonGenerationRegressed       = "status generation went backwards"
	ReasonMissingGeneration         = "status has no generation (contract v1 starts at 1)"
	ReasonDIDMismatch               = "sub is not the workload's current_did"
	ReasonSwarmMismatch             = "arkavo_swarm does not match the workload's swarm"
	ReasonMissingOwner              = "agent token has no arkavo_account_id"
	ReasonOwnerMismatch             = "arkavo_account_id is not the workload's owner"
)

// Status is the body of GET /agents/workloads/{workload}/status (contract v1).
type Status struct {
	Workload   string  `json:"workload"`
	Owner      string  `json:"owner"`
	CurrentDID string  `json:"current_did"`
	Swarm      string  `json:"swarm"`
	State      string  `json:"state"`
	Generation uint64  `json:"generation"`
	Incident   *string `json:"incident"`
	ValidUntil int64   `json:"valid_until"`
}

// Subject is the agent as its verified token describes it.
type Subject struct {
	DID      string
	Workload string
	Swarm    string
	Owner    string // the token's arkavo_account_id
}

// DenialError explains a refused agent for logs and audit.
type DenialError struct {
	Reason     string
	Workload   string
	Generation uint64
	Incident   string
	Cause      error
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
// before workloads existed (identity-plane track 1) has no arkavo_workload
// and is refused here. A workload id outside contract v1's shape never
// reaches the status URL.
func checkSubject(s Subject) *DenialError {
	switch {
	case s.DID == "":
		return &DenialError{Reason: ReasonMissingSubject, Workload: s.Workload}
	case s.Workload == "":
		return &DenialError{Reason: ReasonMissingWorkload}
	case s.Swarm == "":
		return &DenialError{Reason: ReasonMissingSwarm, Workload: s.Workload}
	case s.Owner == "":
		return &DenialError{Reason: ReasonMissingOwner, Workload: s.Workload}
	case !validWorkloadID(s.Workload):
		return &DenialError{Reason: ReasonMalformedWorkload, Workload: s.Workload}
	}
	return nil
}

// validWorkloadID accepts contract v1's workload id: "wl-" + 32 lowercase hex.
func validWorkloadID(id string) bool {
	hexPart, ok := strings.CutPrefix(id, workloadIDPrefix)
	if !ok || len(hexPart) != workloadIDHexLen {
		return false
	}
	for _, r := range hexPart {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// evaluate applies the release conditions to a live status. highWater is the
// largest generation this process had seen for the workload before st.
//
// An empty status field never matches, even an empty claim: contract v1 uses
// "" for "none" (current_did after recovery, swarm before specialization),
// and release must not hinge on checkSubject having run first.
func evaluate(st Status, s Subject, highWater uint64) *DenialError {
	d := &DenialError{Workload: s.Workload, Generation: st.Generation}
	if st.Incident != nil {
		d.Incident = *st.Incident
	}
	switch {
	case !bound(st.Workload, s.Workload):
		d.Reason = ReasonWorkloadMismatch
	case st.State != stateEligible:
		d.Reason = ReasonNotEligible
	case st.Generation == 0:
		d.Reason = ReasonMissingGeneration
	case st.Generation < highWater:
		d.Reason = ReasonGenerationRegressed
	case !bound(st.CurrentDID, s.DID):
		d.Reason = ReasonDIDMismatch
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
