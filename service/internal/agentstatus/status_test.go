package agentstatus

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testDID      = "did:key:z6Mkagent"
	testWorkload = "wl-00112233445566778899aabbccddeeff" // contract v1: "wl-" + 32 lowercase hex
	testSwarm    = "kit-42"
)

func subject() Subject {
	return Subject{DID: testDID, Workload: testWorkload, Swarm: testSwarm, Owner: "owner-1"}
}

func liveStatus() Status {
	return Status{Workload: testWorkload, Owner: "owner-1", CurrentDID: testDID, Swarm: testSwarm, State: "eligible", Generation: 3}
}

func TestEvaluate(t *testing.T) {
	incident := "inc-9"
	tests := []struct {
		name      string
		mutate    func(*Status)
		highWater uint64
		reason    string
	}{
		{"eligible and matching", func(*Status) {}, 3, ""},
		{"quarantined", func(s *Status) { s.State = "quarantined"; s.Incident = &incident }, 0, ReasonNotEligible},
		{"unknown state fails closed", func(s *Status) { s.State = "revoked" }, 0, ReasonNotEligible},
		{"generation went backwards", func(*Status) {}, 4, ReasonGenerationRegressed},
		// Contract v1: generation starts at 1, so 0 means the field was absent.
		{"generation absent or zero", func(s *Status) { s.Generation = 0 }, 0, ReasonMissingGeneration},
		{"sub is not current_did", func(s *Status) { s.CurrentDID = "did:key:z6Mkrotated" }, 0, ReasonDIDMismatch},
		// Contract v1: recovery sets state=eligible, current_did="" and
		// generation+1; nothing may be released until the owner authorizes again.
		{"recovered, not yet re-authorized", func(s *Status) { s.CurrentDID = ""; s.Generation = 4 }, 3, ReasonDIDMismatch},
		{"swarm mismatch", func(s *Status) { s.Swarm = "kit-other" }, 0, ReasonSwarmMismatch},
		// Contract v1: swarm is "" while the workload has no swarm.
		{"workload has no swarm", func(s *Status) { s.Swarm = "" }, 0, ReasonSwarmMismatch},
		{"owner mismatch", func(s *Status) { s.Owner = "owner-2" }, 0, ReasonOwnerMismatch},
		{"status has no owner", func(s *Status) { s.Owner = "" }, 0, ReasonOwnerMismatch},
		{"status for another workload", func(s *Status) { s.Workload = "wl-8" }, 0, ReasonWorkloadMismatch},
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
				assert.Equal(t, testWorkload, d.Workload)
				assert.Equal(t, st.Generation, d.Generation)
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
		"recovered status, token without sub":  {func(st *Status, s *Subject) { st.CurrentDID = ""; s.DID = "" }, ReasonDIDMismatch},
		"no-swarm status, token without swarm": {func(st *Status, s *Subject) { st.Swarm = ""; s.Swarm = "" }, ReasonSwarmMismatch},
		"no owner on either side":              {func(st *Status, s *Subject) { st.Owner = ""; s.Owner = "" }, ReasonOwnerMismatch},
		"no workload on either side":           {func(st *Status, s *Subject) { st.Workload = ""; s.Workload = "" }, ReasonWorkloadMismatch},
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
	for name, tt := range map[string]struct {
		s      Subject
		reason string
	}{
		"no sub": {Subject{Workload: testWorkload, Swarm: testSwarm, Owner: "owner-1"}, ReasonMissingSubject},
		"pre-workload (track-1) token has no arkavo_workload": {Subject{DID: testDID, Swarm: testSwarm, Owner: "owner-1"}, ReasonMissingWorkload},
		"workload hex too short":                              {Subject{DID: testDID, Workload: "wl-7", Swarm: testSwarm, Owner: "owner-1"}, ReasonMalformedWorkload},
		"workload hex uppercase":                              {Subject{DID: testDID, Workload: "wl-00112233445566778899AABBCCDDEEFF", Swarm: testSwarm, Owner: "owner-1"}, ReasonMalformedWorkload},
		"workload hex too long":                               {Subject{DID: testDID, Workload: "wl-00112233445566778899aabbccddeeff0", Swarm: testSwarm, Owner: "owner-1"}, ReasonMalformedWorkload},
		"workload with a non-hex lowercase letter":            {Subject{DID: testDID, Workload: "wl-00112233445566778899aabbccddeefg", Swarm: testSwarm, Owner: "owner-1"}, ReasonMalformedWorkload},
		"workload without the wl- prefix":                     {Subject{DID: testDID, Workload: "00112233445566778899aabbccddeeff", Swarm: testSwarm, Owner: "owner-1"}, ReasonMalformedWorkload},
		// Contract v1 omits arkavo_swarm while the workload has no swarm; such a
		// token is refused before any status call.
		"no arkavo_swarm":      {Subject{DID: testDID, Workload: testWorkload, Owner: "owner-1"}, ReasonMissingSwarm},
		"no arkavo_account_id": {Subject{DID: testDID, Workload: testWorkload, Swarm: testSwarm}, ReasonMissingOwner},
		"workload climbs":      {Subject{DID: testDID, Workload: "..", Swarm: testSwarm, Owner: "owner-1"}, ReasonMalformedWorkload},
		"workload splits path": {Subject{DID: testDID, Workload: "wl/../../admin", Swarm: testSwarm, Owner: "owner-1"}, ReasonMalformedWorkload},
	} {
		t.Run(name, func(t *testing.T) {
			d := checkSubject(tt.s)
			if assert.NotNil(t, d) {
				assert.Equal(t, tt.reason, d.Reason)
			}
		})
	}
}

func TestDenialError(t *testing.T) {
	d := &DenialError{Reason: ReasonNotEligible}
	assert.Equal(t, "agent denied: "+ReasonNotEligible, d.Error())

	cause := errors.New("dial tcp: connection refused")
	wrapped := &DenialError{Reason: ReasonUnreachable, Cause: cause}
	assert.Equal(t, "agent denied: "+ReasonUnreachable+": dial tcp: connection refused", wrapped.Error())
	require.ErrorIs(t, wrapped, cause)
}
