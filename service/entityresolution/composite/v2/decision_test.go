package composite

import (
	"context"
	"maps"
	"testing"
	"time"

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

const (
	patreonPolicy = "../../../../examples/config/policy.patreon.yaml"
	arkavoPolicy  = "../../../../examples/config/policy.arkavo.yaml"
	patreonAttrNS = "https://patreon.arkavo.com/attr/"
)

// inProcessERS hands the JIT PDP's ERS calls to the composite, as the
// platform's in-process (IPC) SDK does.
type inProcessERS struct{ svc *Service }

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

// pdpFor is the real v2 JustInTimePDP over a policy file, loaded by the
// file-backed store the authorization service uses for policy_file, with
// allow_direct_entitlements, resolving entities through svc.
func pdpFor(t *testing.T, svc *Service, policyFile string) *access.JustInTimePDP {
	t.Helper()
	store, err := filestore.NewStoreFromFile(policyFile)
	require.NoError(t, err)
	sdk := &otdf.SDK{EntityResolutionV2: inProcessERS{svc: svc}}
	pdp, err := access.NewJustInTimePDP(t.Context(), logger.CreateTestLogger(), sdk, store, true, false)
	require.NoError(t, err)
	return pdp
}

// permitted asks pdp whether the entity may read every one of fqns, for a
// caller with clientID. The PDP audits each decision into the request's
// audit transaction, which the server's interceptor normally opens.
func permitted(t *testing.T, pdp *access.JustInTimePDP, clientID string, id *authzV2.EntityIdentifier, fqns ...string) bool {
	t.Helper()
	ctx := callerContext(audit.ContextWithActorID(t.Context(), clientID), clientID)
	decision, err := pdp.GetDecision(ctx, id, &policy.Action{Name: "read"},
		[]*authzV2.Resource{{EphemeralId: "resource-0", Resource: &authzV2.Resource_AttributeValues_{
			AttributeValues: &authzV2.Resource_AttributeValues{Fqns: fqns},
		}}},
		nil, nil)
	require.NoError(t, err, "an unentitled subject is a deny, never an error")
	return decision.AllPermitted
}

func tokenIdentifier(jwt string) *authzV2.EntityIdentifier {
	return &authzV2.EntityIdentifier{Identifier: &authzV2.EntityIdentifier_Token{
		Token: &entity.Token{EphemeralId: "rewrap-token", Jwt: jwt},
	}}
}

func chainIdentifier(entities ...*entity.Entity) *authzV2.EntityIdentifier {
	return &authzV2.EntityIdentifier{Identifier: &authzV2.EntityIdentifier_EntityChain{
		EntityChain: &entity.EntityChain{EphemeralId: "catalog-chain", Entities: entities},
	}}
}

// patronClaims are a patron's claims as identity.arkavo.net mints them: the
// membership in arkavo_patreon and, for an active membership only, its
// campaign and tier values in arkavo_entitlements.
func patronClaims(campaign, patronStatus string) map[string]any {
	claims := map[string]any{
		"iss":               testIssuer,
		"sub":               "did:key:z6Mkpatron",
		"arkavo_account_id": "00000000-0000-0000-0000-00000000beef",
		"arkavo_patreon": map[string]any{"role": "consumer", "memberships": []any{map[string]any{
			"campaign_id":   campaign,
			"patron_status": patronStatus,
			"tier_slugs":    []any{"supporter"},
		}}},
		"arkavo_entitlements": []any{},
	}
	if patronStatus == "active_patron" {
		claims["arkavo_entitlements"] = []any{
			patreonAttrNS + "campaign/value/" + campaign,
			patreonAttrNS + "campaign-tier/value/" + campaign + "_supporter",
		}
	}
	return claims
}

// TestPatreonDecisions_ThroughTheV2PDP runs every route a Patreon decision
// takes end to end in process: the real v2 JustInTimePDP over
// examples/config/policy.patreon.yaml, and the composite. On the licence and
// KAS routes the PDP hands the composite a token; on the catalog route the
// catalog node sends the claims it verified as a chain. A creator gets one
// answer on every route, with no creator-specific handling.
func TestPatreonDecisions_ThroughTheV2PDP(t *testing.T) {
	svc := newTestService(t, pepConfig(), verifiersFor(&fakeVerifier{}),
		[]configuredSource{pepPatreonSource(), identityCoreSource()}, nil)
	pdp := pdpFor(t, svc, patreonPolicy)
	exp := time.Now().Add(time.Hour)
	// The creator's own content: campaign 13167240, tier supporter.
	content := []string{creatorCampaign, creatorSupporter}

	// viaToken is the licence and KAS routes. Both ERS calls arrive with the
	// calling service's client ID, which is not on claims_chain_peps.
	viaToken := func(t *testing.T, claims map[string]any, fqns ...string) bool {
		t.Helper()
		claims = maps.Clone(claims)
		claims["exp"] = exp
		return permitted(t, pdp, "arks-media", tokenIdentifier(signCWT(t, claims)), fqns...)
	}
	// viaCatalog is the catalog route, from the caller clientID.
	viaCatalog := func(t *testing.T, clientID string, claims map[string]any, fqns ...string) bool {
		t.Helper()
		return permitted(t, pdp, clientID, chainIdentifier(claimsEntity(t, "catalog-subject", claims)), fqns...)
	}

	t.Run("licence and KAS: creator token", func(t *testing.T) {
		require.True(t, viaToken(t, creatorClaims(exp), content...))
	})
	t.Run("catalog: creator claims from the allowlisted PEP", func(t *testing.T) {
		require.True(t, viaCatalog(t, testPEP, catalogCreatorClaims(), content...))
	})
	t.Run("catalog: same claims from another client", func(t *testing.T) {
		require.False(t, viaCatalog(t, "arks-media", catalogCreatorClaims(), content...))
	})
	t.Run("patron of 13167240, tier supporter, token route", func(t *testing.T) {
		require.True(t, viaToken(t, patronClaims("13167240", "active_patron"), content...))
	})
	t.Run("patron of 13167240, catalog route", func(t *testing.T) {
		require.True(t, viaCatalog(t, testPEP, patronClaims("13167240", "active_patron"), content...))
	})
	t.Run("cross-campaign: patron of 7237273 only", func(t *testing.T) {
		patron := patronClaims("7237273", "active_patron")
		require.False(t, viaToken(t, patron, content...))
		require.False(t, viaCatalog(t, testPEP, patron, content...))
		own := []string{patreonAttrNS + "campaign/value/7237273", patreonAttrNS + "campaign-tier/value/7237273_supporter"}
		require.True(t, viaToken(t, patron, own...), "the patron's own campaign is permitted, so the denial is the campaign's")
	})
	t.Run("declined and former patrons of 13167240", func(t *testing.T) {
		for _, status := range []string{"declined_patron", "former_patron"} {
			patron := patronClaims("13167240", status)
			require.False(t, viaToken(t, patron, content...), status)
			require.False(t, viaCatalog(t, testPEP, patron, content...), status)
		}
	})
}

// TestAgentGate_ThroughTheV2PDP runs the KAS's decision path end to end in
// process: a token identifier through the real v2 JustInTimePDP, over
// examples/config/policy.arkavo.yaml, and the composite with a token-claims
// source owning https://arkavo.ai/attr/tdf. Only an eligible agent is
// permitted.
func TestAgentGate_ThroughTheV2PDP(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	// A test CWT: the fake verifier accepts it and answers with the agent's
	// claims, as the real one would once it had checked the signature.
	token := signCWT(t, map[string]any{"iss": testIssuer, "sub": agentDID, "exp": exp})
	decide := func(t *testing.T, statusErr error) bool {
		t.Helper()
		svc := newTestService(t, testConfig(), verifiersFor(&fakeVerifier{claims: agentClaims(exp)}),
			[]configuredSource{tdfSource()}, statusAnswer{err: statusErr})
		return permitted(t, pdpFor(t, svc, arkavoPolicy), "kas", tokenIdentifier(token), decryptValue)
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
