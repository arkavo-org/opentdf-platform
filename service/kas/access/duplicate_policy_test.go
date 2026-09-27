package access

import (
	"testing"

	"connectrpc.com/connect"
	"github.com/lestrrat-go/jwx/v2/jwt"
	kaspb "github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/service/internal/agentstatus"
	"github.com/opentdf/platform/service/logger/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sharedPolicyID = "policy-shared"

// assertBadRequest checks every KAO result under policyID is the generic 400
// and carries no key.
func assertBadRequest(t *testing.T, results policyKAOResults, policyID string, wantKAOs int) {
	t.Helper()
	byKAO, ok := results[policyID]
	require.True(t, ok, "policy %s has results", policyID)
	require.Len(t, byKAO, wantKAOs)
	for id, r := range byKAO {
		require.Error(t, r.Error, id)
		assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(r.Error), id)
		assert.Contains(t, r.Error.Error(), "bad request", id)
		assert.Empty(t, r.Encapped, id)
	}
}

func countAudits(t *testing.T, results []any) (int, int) {
	t.Helper()
	var success, failure int
	for _, r := range results {
		switch r {
		case audit.ActionResultSuccess.String():
			success++
		case audit.ActionResultError.String():
			failure++
		}
	}
	return success, failure
}

// Two requests share a policy Id: one policy lists the agent in dissem, the
// other excludes it. Response results are keyed by policy Id, so the KAS
// cannot answer both; every KAO of both is refused before any unwrap, in
// either order and whether or not the KAO ids collide.
func TestTDF3Rewrap_DuplicatePolicyIDRefusedForAgent(t *testing.T) {
	listing := policyBytes(t, dissemPolicy(false, agentDID))
	excluding := policyBytes(t, dissemPolicy(false, otherDID))
	for _, tt := range []struct {
		name     string
		first    []byte
		second   []byte
		kaoIDs   [2]string
		wantKAOs int
	}{
		{"listing first, distinct KAO ids", listing, excluding, [2]string{"kao-1", "kao-2"}, 2},
		{"excluding first, distinct KAO ids", excluding, listing, [2]string{"kao-1", "kao-2"}, 2},
		{"listing first, same KAO id", listing, excluding, [2]string{"kao-1", "kao-1"}, 1},
		{"excluding first, same KAO id", excluding, listing, [2]string{"kao-1", "kao-1"}, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			checker := &fakeChecker{}
			p, km, buf := releasingProvider(t, checker)
			reqs := []*kaspb.UnsignedRewrapRequest_WithPolicyRequest{
				requestWithBody(t, tt.first, sharedPolicyID, tt.kaoIDs[0]),
				requestWithBody(t, tt.second, sharedPolicyID, tt.kaoIDs[1]),
			}
			var results policyKAOResults
			require.NotPanics(t, func() {
				results = rewrapAudited(t, p, agentDPoPKey(t), agentToken(t), reqs)
			})
			require.Len(t, results, 1)
			assertBadRequest(t, results, sharedPolicyID, tt.wantKAOs)
			assert.Equal(t, int32(0), km.decrypts.Load(), "a duplicate policy Id must be refused before unwrap")
			success, failure := countAudits(t, rewrapAuditResults(t, buf))
			assert.Equal(t, 0, success)
			assert.Equal(t, 2, failure, "each refused KAO is audited")
		})
	}
}

func TestTDF3Rewrap_DuplicatePolicyIDRefusedForHuman(t *testing.T) {
	p, km, _ := releasingProvider(t, nil)
	human := tokenWith(t, map[string]any{jwt.SubjectKey: agentOwner, "arkavo_roles": []any{"user"}})
	reqs := []*kaspb.UnsignedRewrapRequest_WithPolicyRequest{
		releasableRequest(t, sharedPolicyID, "kao-1"),
		releasableRequest(t, sharedPolicyID, "kao-2"),
	}
	var results policyKAOResults
	require.NotPanics(t, func() { results = rewrapAudited(t, p, nil, human, reqs) })
	require.Len(t, results, 1)
	assertBadRequest(t, results, sharedPolicyID, 2)
	assert.Equal(t, int32(0), km.decrypts.Load())
}

// Only the requests that share an Id are refused; a unique one alongside
// them is released as usual.
func TestTDF3Rewrap_DuplicatePolicyIDDoesNotAffectUniqueIDs(t *testing.T) {
	for name, bearer := range map[string]func(t *testing.T) jwt.Token{
		"agent": agentToken,
		"human": func(t *testing.T) jwt.Token {
			return tokenWith(t, map[string]any{jwt.SubjectKey: agentOwner, "arkavo_roles": []any{"user"}})
		},
	} {
		t.Run(name, func(t *testing.T) {
			p, km, _ := releasingProvider(t, &fakeChecker{})
			reqs := []*kaspb.UnsignedRewrapRequest_WithPolicyRequest{
				releasableRequest(t, sharedPolicyID, "kao-d1"),
				releasableRequest(t, "policy-unique", "kao-u1", "kao-u2"),
				releasableRequest(t, sharedPolicyID, "kao-d2"),
			}
			var results policyKAOResults
			require.NotPanics(t, func() { results = rewrapAudited(t, p, agentDPoPKey(t), bearer(t), reqs) })
			require.Len(t, results, 2)
			assertBadRequest(t, results, sharedPolicyID, 2)
			require.Len(t, results["policy-unique"], 2)
			for id, r := range results["policy-unique"] {
				require.NoError(t, r.Error, id)
				assert.NotEmpty(t, r.Encapped, id)
			}
			assert.Equal(t, int32(2), km.decrypts.Load(), "only the unique policy's KAOs are unwrapped")
		})
	}
}

// A denied agent's response still names every KAO of every request, even
// when two requests share a policy Id.
func TestDenyAgentRewrap_KeepsEveryKAOUnderASharedID(t *testing.T) {
	p, km, _ := releasingProvider(t, &fakeChecker{err: &agentstatus.DenialError{Reason: agentstatus.ReasonNotEligible}})
	reqs := []*kaspb.UnsignedRewrapRequest_WithPolicyRequest{
		releasableRequest(t, sharedPolicyID, "kao-1"),
		releasableRequest(t, sharedPolicyID, "kao-2"),
	}
	results := rewrapAudited(t, p, agentDPoPKey(t), agentToken(t), reqs)
	require.Len(t, results[sharedPolicyID], 2)
	for id, r := range results[sharedPolicyID] {
		assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(r.Error), id)
	}
	assert.Equal(t, int32(0), km.decrypts.Load())
}
