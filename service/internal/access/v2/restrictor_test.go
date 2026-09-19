package access

import (
	"context"
	"errors"
	"math/rand"
	"strconv"
	"testing"

	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hostileRestrictor denies everything it is asked about. Combined with the
// monotonicity test below, it stands in for any buggy or malicious
// implementation: the interface gives it no way to grant.
type hostileRestrictor struct {
	err      error
	denyAll  bool
	denyIDs  map[string]string
	captured RestrictionRequest
}

func (h *hostileRestrictor) Deny(_ context.Context, req RestrictionRequest) (map[string]string, error) {
	h.captured = req
	if h.err != nil {
		return nil, h.err
	}
	if h.denyAll {
		out := make(map[string]string, len(req.Resources))
		for _, r := range req.Resources {
			out[r.EphemeralID] = "denied by test"
		}
		return out, nil
	}
	return h.denyIDs, nil
}

func newPDP(r DecisionRestrictor) *JustInTimePDP {
	return &JustInTimePDP{logger: logger.CreateTestLogger(), restrictor: r}
}

func decisionWith(passed ...bool) *Decision {
	results := make([]ResourceDecision, len(passed))
	all := true
	for i, p := range passed {
		results[i] = ResourceDecision{ResourceID: "r-" + strconv.Itoa(i), Passed: p}
		if !p {
			all = false
		}
	}
	return &Decision{AllPermitted: all, Results: results}
}

func TestRestrictorDeniesPermittedResource(t *testing.T) {
	pdp := newPDP(&hostileRestrictor{denyIDs: map[string]string{"r-1": "anomalous"}})
	decision := decisionWith(true, true, true)

	_, err := pdp.applyRestrictions(t.Context(), "e", "read", decision)
	require.NoError(t, err)

	assert.True(t, decision.Results[0].Passed)
	assert.False(t, decision.Results[1].Passed, "the named resource must be denied")
	assert.True(t, decision.Results[2].Passed)
	assert.False(t, decision.AllPermitted, "denying any resource must clear AllPermitted")
}

func TestRestrictorCannotGrantDeniedResource(t *testing.T) {
	// The interface has no "permit" to express, so the only way a restrictor
	// could grant is if applyRestrictions mishandled a resource policy denied.
	pdp := newPDP(&hostileRestrictor{denyAll: true})
	decision := decisionWith(false, false)

	_, err := pdp.applyRestrictions(t.Context(), "e", "read", decision)
	require.NoError(t, err)

	assert.False(t, decision.Results[0].Passed)
	assert.False(t, decision.Results[1].Passed)
	assert.False(t, decision.AllPermitted)
}

func TestRestrictorCannotSetAllPermittedTrue(t *testing.T) {
	pdp := newPDP(&hostileRestrictor{denyIDs: map[string]string{}})
	decision := decisionWith(true, false) // policy already denied r-1
	require.False(t, decision.AllPermitted)

	_, err := pdp.applyRestrictions(t.Context(), "e", "read", decision)
	require.NoError(t, err)

	assert.False(t, decision.AllPermitted,
		"an empty denial set must not resurrect a denied decision")
}

// TestRestrictionsAreMonotonic is the core safety property of this seam: across
// arbitrary decisions and arbitrary denial sets, no resource and no overall
// decision ever moves from denied to permitted.
func TestRestrictionsAreMonotonic(t *testing.T) {
	rng := rand.New(rand.NewSource(1))

	for range 500 {
		size := 1 + rng.Intn(6)
		passed := make([]bool, size)
		for i := range passed {
			passed[i] = rng.Intn(2) == 0
		}
		decision := decisionWith(passed...)

		denials := make(map[string]string)
		for i := range size {
			if rng.Intn(2) == 0 {
				denials["r-"+strconv.Itoa(i)] = "because"
			}
		}
		// Denials naming resources that do not exist must be harmless.
		if rng.Intn(3) == 0 {
			denials["r-does-not-exist"] = "because"
		}

		beforePermitted := decision.AllPermitted
		before := make([]bool, size)
		for i, r := range decision.Results {
			before[i] = r.Passed
		}

		pdp := newPDP(&hostileRestrictor{denyIDs: denials})
		_, err := pdp.applyRestrictions(t.Context(), "e", "read", decision)
		require.NoError(t, err)

		for i, r := range decision.Results {
			if !before[i] {
				require.False(t, r.Passed,
					"resource %d moved from denied to permitted", i)
			}
		}
		if !beforePermitted {
			require.False(t, decision.AllPermitted,
				"AllPermitted moved from false to true")
		}
	}
}

func TestRestrictorSeesPolicyOutcomeAndAttributes(t *testing.T) {
	restrictor := &hostileRestrictor{}
	pdp := newPDP(restrictor)

	decision := &Decision{
		AllPermitted: true,
		Results: []ResourceDecision{{
			ResourceID:   "r-0",
			ResourceName: "doc",
			Passed:       true,
			DataRuleResults: []DataRuleResult{{
				ResourceValueFQNs: []string{"https://example.org/attr/a/value/b"},
			}},
		}},
	}

	_, err := pdp.applyRestrictions(t.Context(), "entity-7", "read", decision)
	require.NoError(t, err)

	require.Len(t, restrictor.captured.Resources, 1)
	assert.Equal(t, "entity-7", restrictor.captured.EntityID)
	assert.Equal(t, "read", restrictor.captured.ActionName)
	assert.Equal(t, "doc", restrictor.captured.Resources[0].Name)
	assert.True(t, restrictor.captured.Resources[0].Permitted)
	assert.Equal(t, []string{"https://example.org/attr/a/value/b"},
		restrictor.captured.Resources[0].AttributeValueFQNs)
}

func TestRestrictorErrorFailsTheDecision(t *testing.T) {
	pdp := newPDP(&hostileRestrictor{err: errors.New("model unreachable")})
	decision := decisionWith(true)

	_, err := pdp.applyRestrictions(t.Context(), "e", "read", decision)

	require.Error(t, err, "an error is how a restrictor expresses fail-closed")
	assert.True(t, decision.Results[0].Passed, "a failed call must not half-apply")
}

func TestNoRestrictorLeavesDecisionUntouched(t *testing.T) {
	pdp := newPDP(nil)
	decision := decisionWith(true, true)

	_, err := pdp.applyRestrictions(t.Context(), "e", "read", decision)
	require.NoError(t, err)
	assert.True(t, decision.AllPermitted)
}

func TestNilDecisionIsSafe(t *testing.T) {
	pdp := newPDP(&hostileRestrictor{denyAll: true})
	_, err := pdp.applyRestrictions(t.Context(), "e", "read", nil)
	require.NoError(t, err)
}

func TestMarkRestrictedAuditDecisionsMirrorsDenials(t *testing.T) {
	// Audit copies of the resource decisions are built before the restrictor
	// runs, so they must be reconciled or the audit record would disagree with
	// the decision the caller received.
	auditDecisions := []ResourceDecision{
		{ResourceID: "r-0", Passed: true},
		{ResourceID: "r-1", Passed: true},
	}

	markRestrictedAuditDecisions(auditDecisions, map[string]string{"r-1": "anomalous"})

	assert.True(t, auditDecisions[0].Passed)
	assert.False(t, auditDecisions[1].Passed,
		"the audit record must show the resource as denied")
}

func TestMarkRestrictedAuditDecisionsIsNoopWithoutDenials(t *testing.T) {
	auditDecisions := []ResourceDecision{{ResourceID: "r-0", Passed: true}}

	markRestrictedAuditDecisions(auditDecisions, nil)

	assert.True(t, auditDecisions[0].Passed)
}

func TestAppliedDenialsExcludeAlreadyDeniedResources(t *testing.T) {
	// Only denials that actually changed something are reported, so audit
	// reconciliation does not claim credit for policy's own denials.
	pdp := newPDP(&hostileRestrictor{denyAll: true})
	decision := decisionWith(true, false)

	applied, err := pdp.applyRestrictions(t.Context(), "e", "read", decision)
	require.NoError(t, err)

	assert.Contains(t, applied, "r-0")
	assert.NotContains(t, applied, "r-1",
		"policy already denied r-1; the restrictor did not change it")
}
