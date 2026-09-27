package arkavo

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/entity"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	"github.com/opentdf/platform/protocol/go/policy"
	otdf "github.com/opentdf/platform/sdk"
	access "github.com/opentdf/platform/service/internal/access/v2"
	"github.com/opentdf/platform/service/internal/agentstatus"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	"github.com/opentdf/platform/service/policy/filestore"
	"github.com/stretchr/testify/require"
)

// inProcessERS hands the JIT PDP's ERS calls to the resolver under test, as
// the platform's in-process (IPC) SDK does.
type inProcessERS struct{ svc *EntityResolutionService }

func (e inProcessERS) ResolveEntities(ctx context.Context, req *entityresolutionV2.ResolveEntitiesRequest) (*entityresolutionV2.ResolveEntitiesResponse, error) {
	res, err := e.svc.ResolveEntities(ctx, connect.NewRequest(req))
	if err != nil {
		return nil, err
	}
	return res.Msg, nil
}

func (e inProcessERS) CreateEntityChainsFromTokens(ctx context.Context, req *entityresolutionV2.CreateEntityChainsFromTokensRequest) (*entityresolutionV2.CreateEntityChainsFromTokensResponse, error) {
	res, err := e.svc.CreateEntityChainsFromTokens(ctx, connect.NewRequest(req))
	if err != nil {
		return nil, err
	}
	return res.Msg, nil
}

// statusAnswer is a status checker that always gives the same answer.
type statusAnswer struct{ err error }

func (s statusAnswer) Check(context.Context, agentstatus.Subject) error { return s.err }

// TestAgentGate_ThroughTheV2PDP runs the KAS's decision path end to end in
// process: a token identifier through the real v2 JustInTimePDP (policy from
// examples/config/policy.arkavo.yaml via the file-backed store the
// authorization service uses for policy_file) and this resolver. Before the
// gate is wired, the quarantined agent is permitted.
func TestAgentGate_ThroughTheV2PDP(t *testing.T) {
	store, err := filestore.NewStoreFromFile("../../../../examples/config/policy.arkavo.yaml")
	require.NoError(t, err)
	agent := buildJWT(t, map[string]interface{}{
		"iss": issuer, "sub": "did:key:z6Mkagent",
		"arkavo_account_id":   "00000000-0000-0000-0000-000000000001",
		"arkavo_entitlements": []interface{}{"https://arkavo.ai/attr/tdf/value/decrypt"},
		"arkavo_npe":          map[string]interface{}{"type": "agent"},
		"arkavo_workload":     "wl-00112233445566778899aabbccddeeff",
		"arkavo_swarm":        "kit-42",
		"cnf": map[string]interface{}{"jwk": map[string]interface{}{
			"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
		}},
	})
	decide := func(t *testing.T, statusErr error) bool {
		t.Helper()
		svc := newSvc(t, Config{TrustMaterializedClaims: true, TrustedIssuer: issuer})
		svc.agentStatus = statusAnswer{err: statusErr}
		sdk := &otdf.SDK{EntityResolutionV2: inProcessERS{svc: svc}}
		pdp, err := access.NewJustInTimePDP(t.Context(), logger.CreateTestLogger(), sdk, store, true, false)
		require.NoError(t, err)
		// The PDP audits each decision into the request's audit transaction,
		// which the server's interceptor normally opens.
		ctx := audit.ContextWithActorID(t.Context(), "kas")
		decision, err := pdp.GetDecision(ctx,
			&authzV2.EntityIdentifier{Identifier: &authzV2.EntityIdentifier_Token{Token: &entity.Token{EphemeralId: "rewrap-token", Jwt: agent}}},
			&policy.Action{Name: "read"},
			[]*authzV2.Resource{{EphemeralId: "rewrap-0", Resource: &authzV2.Resource_AttributeValues_{
				AttributeValues: &authzV2.Resource_AttributeValues{Fqns: []string{"https://arkavo.ai/attr/tdf/value/decrypt"}},
			}}},
			nil, nil)
		require.NoError(t, err, "a withheld agent is a deny, never an error")
		return decision.AllPermitted
	}
	t.Run("eligible agent is permitted", func(t *testing.T) {
		require.True(t, decide(t, nil))
	})
	t.Run("quarantined agent is denied", func(t *testing.T) {
		require.False(t, decide(t, &agentstatus.DenialError{Reason: agentstatus.ReasonNotEligible}),
			"a quarantined agent's token must be denied by the v2 PDP")
	})
	t.Run("unreachable identity is denied", func(t *testing.T) {
		require.False(t, decide(t, &agentstatus.DenialError{Reason: agentstatus.ReasonUnreachable}))
	})
}
