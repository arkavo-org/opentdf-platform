package agentstatus

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testDID     = "did:key:z6Mkagent" // contract v2: the agent identity is its did:key
	testSwarm   = "kit-42"
	testVersion = 3
)

func subject() Subject {
	return Subject{DID: testDID, Swarm: testSwarm, Owner: "owner-1", StateVersion: testVersion}
}

func liveStatus() Status {
	return Status{Agent: testDID, Owner: "owner-1", Swarm: testSwarm, State: "eligible", StateVersion: testVersion}
}

func TestEvaluate(t *testing.T) {
	incident := "inc-9"
	tests := []struct {
		name      string
		mutate    func(*Status)
		highWater uint64
		reason    string
	}{
		{"eligible and matching", func(*Status) {}, testVersion, ""},
		{"quarantined", func(s *Status) { s.State = "quarantined"; s.Incident = &incident }, 0, ReasonNotEligible},
		// Contract v2: authnz-rs derives suspended from an expired appraisal.
		{"suspended", func(s *Status) { s.State = "suspended" }, 0, ReasonNotEligible},
		// New identities and recovered ones wait for an appraisal.
		{"unassessed", func(s *Status) { s.State = "unassessed"; s.StateVersion = testVersion + 1 }, 0, ReasonNotEligible},
		{"unknown state fails closed", func(s *Status) { s.State = "revoked" }, 0, ReasonNotEligible},
		{"state_version went backwards", func(*Status) {}, testVersion + 1, ReasonStateVersionRegressed},
		// Contract v2: state_version starts at 1, so 0 means the field was absent.
		{"state_version absent or zero", func(s *Status) { s.StateVersion = 0 }, 0, ReasonStatusMissingVersion},
		// Recovered and re-appraised: the pre-quarantine token stays dead.
		{"token minted before the latest state change", func(s *Status) { s.StateVersion = testVersion + 2 }, 0, ReasonTokenVersionStale},
		{"status older than the token", func(s *Status) { s.StateVersion = testVersion - 1 }, 0, ReasonStatusBehindToken},
		{"swarm mismatch", func(s *Status) { s.Swarm = "kit-other" }, 0, ReasonSwarmMismatch},
		// Contract v2: swarm is "" while the agent has no swarm.
		{"agent has no swarm", func(s *Status) { s.Swarm = "" }, 0, ReasonSwarmMismatch},
		{"owner mismatch", func(s *Status) { s.Owner = "owner-2" }, 0, ReasonOwnerMismatch},
		{"status has no owner", func(s *Status) { s.Owner = "" }, 0, ReasonOwnerMismatch},
		{"status for another agent", func(s *Status) { s.Agent = "did:key:z6Mkother" }, 0, ReasonAgentMismatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := liveStatus()
			tt.mutate(&st)
			d := evaluate(st, subject(), tt.highWater)
			if tt.reason == "" {
				assert.Nil(t, d)
				return
			}
			if assert.NotNil(t, d) {
				assert.Equal(t, tt.reason, d.Reason)
				assert.Equal(t, testDID, d.Agent)
				assert.Equal(t, st.StateVersion, d.StateVersion)
				assert.Equal(t, st.State, d.State)
			}
		})
	}
	d := evaluate(func() Status { s := liveStatus(); s.State = "quarantined"; s.Incident = &incident; return s }(), subject(), 0)
	require.NotNil(t, d)
	assert.Equal(t, "inc-9", d.Incident)
}

// evaluate must not depend on checkSubject having run first: an empty token
// claim must never "match" an empty status field.
func TestEvaluateEmptyNeverMatchesEmpty(t *testing.T) {
	for name, tt := range map[string]struct {
		mutate func(*Status, *Subject)
		reason string
	}{
		"no agent on either side":              {func(st *Status, s *Subject) { st.Agent = ""; s.DID = "" }, ReasonAgentMismatch},
		"no-swarm status, token without swarm": {func(st *Status, s *Subject) { st.Swarm = ""; s.Swarm = "" }, ReasonSwarmMismatch},
		"no owner on either side":              {func(st *Status, s *Subject) { st.Owner = ""; s.Owner = "" }, ReasonOwnerMismatch},
		"no version on either side":            {func(st *Status, s *Subject) { st.StateVersion = 0; s.StateVersion = 0 }, ReasonStatusMissingVersion},
	} {
		t.Run(name, func(t *testing.T) {
			st, s := liveStatus(), subject()
			tt.mutate(&st, &s)
			d := evaluate(st, s, 0)
			if assert.NotNil(t, d) {
				assert.Equal(t, tt.reason, d.Reason)
			}
		})
	}
}

func TestCheckSubject(t *testing.T) {
	assert.Nil(t, checkSubject(subject()))
	with := func(mutate func(*Subject)) Subject { s := subject(); mutate(&s); return s }
	for name, tt := range map[string]struct {
		s      Subject
		reason string
	}{
		"no sub": {with(func(s *Subject) { s.DID = "" }), ReasonMissingSubject},
		// A track-1 or contract v1 token carries no arkavo_state_version.
		"token minted before contract v2": {with(func(s *Subject) { s.StateVersion = 0 }), ReasonMissingStateVersion},
		// Contract v2 omits arkavo_swarm while the agent has no swarm; such a
		// token is refused before any status call.
		"no arkavo_swarm":         {with(func(s *Subject) { s.Swarm = "" }), ReasonMissingSwarm},
		"no arkavo_account_id":    {with(func(s *Subject) { s.Owner = "" }), ReasonMissingOwner},
		"a v1 workload id":        {with(func(s *Subject) { s.DID = "wl-00112233445566778899aabbccddeeff" }), ReasonMalformedDID},
		"another DID method":      {with(func(s *Subject) { s.DID = "did:web:example.com" }), ReasonMalformedDID},
		"did:key without a key":   {with(func(s *Subject) { s.DID = "did:key:z" }), ReasonMalformedDID},
		"not base58 (0, O, I, l)": {with(func(s *Subject) { s.DID = "did:key:z6Mk0OIl" }), ReasonMalformedDID},
		"climbs":                  {with(func(s *Subject) { s.DID = "did:key:z/../../admin" }), ReasonMalformedDID},
		"escapes":                 {with(func(s *Subject) { s.DID = "did:key:z6Mk%2F" }), ReasonMalformedDID},
		"over 128 characters":     {with(func(s *Subject) { s.DID = "did:key:z" + strings.Repeat("6", 120) }), ReasonMalformedDID},
	} {
		t.Run(name, func(t *testing.T) {
			d := checkSubject(tt.s)
			if assert.NotNil(t, d) {
				assert.Equal(t, tt.reason, d.Reason)
			}
		})
	}
	assert.Nil(t, checkSubject(with(func(s *Subject) { s.DID = "did:key:z" + strings.Repeat("6", 119) })), "128 characters fit")
}

func TestDenialError(t *testing.T) {
	d := &DenialError{Reason: ReasonNotEligible}
	assert.Equal(t, "agent denied: "+ReasonNotEligible, d.Error())

	cause := errors.New("dial tcp: connection refused")
	wrapped := &DenialError{Reason: ReasonUnreachable, Cause: cause}
	assert.Equal(t, "agent denied: "+ReasonUnreachable+": dial tcp: connection refused", wrapped.Error())
	require.ErrorIs(t, wrapped, cause)
}
