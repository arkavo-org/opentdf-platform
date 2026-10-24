package composite

import (
	"context"
	"maps"
	"slices"
	"testing"
	"time"

	"connectrpc.com/connect"
	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/entity"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	"github.com/opentdf/platform/protocol/go/policy"
	otdf "github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/service/entityresolution/source"
	access "github.com/opentdf/platform/service/internal/access/v2"
	"github.com/opentdf/platform/service/internal/agentstatus"
	"github.com/opentdf/platform/service/internal/chaindevice"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	"github.com/opentdf/platform/service/policy/filestore"
	"github.com/stretchr/testify/assert"
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
	return permittedTo(t, pdp, clientID, "read", id, fqns...)
}

// permittedTo is permitted for another action, such as publish.
func permittedTo(t *testing.T, pdp *access.JustInTimePDP, clientID, action string, id *authzV2.EntityIdentifier, fqns ...string) bool {
	t.Helper()
	ctx := callerContext(audit.ContextWithActorID(t.Context(), clientID), clientID)
	decision, err := pdp.GetDecision(ctx, id, &policy.Action{Name: action}, resourceOf(fqns...), nil, nil)
	require.NoError(t, err, "an unentitled subject is a deny, never an error")
	return decision.AllPermitted
}

// resourceOf is one resource tagged with fqns.
func resourceOf(fqns ...string) []*authzV2.Resource {
	return []*authzV2.Resource{{EphemeralId: "resource-0", Resource: &authzV2.Resource_AttributeValues_{
		AttributeValues: &authzV2.Resource_AttributeValues{Fqns: fqns},
	}}}
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

// deviceClaims are a DeviceCheck device as arks forwards it: the
// allowlisted fields, and arkavo_npe when the device has a class. With no
// class it is still a device, by its audience.
func deviceClaims(kid, class string) map[string]any {
	claims := map[string]any{
		"iss": testIssuer,
		"sub": "550e8400-e29b-41d4-a716-446655440000",
		"aud": "arkavo:devicecheck",
		"kid": kid,
	}
	if class != "" {
		claims["arkavo_npe"] = map[string]any{"type": "device", "class": class}
	}
	return claims
}

// recordingERS records the entities of every ResolveEntities call.
type recordingERS struct {
	inProcessERS
	seen *[][]*entity.Entity
}

func (e recordingERS) ResolveEntities(ctx context.Context, req *entityresolutionV2.ResolveEntitiesRequest) (*entityresolutionV2.ResolveEntitiesResponse, error) {
	*e.seen = append(*e.seen, req.GetEntities())
	return e.inProcessERS.ResolveEntities(ctx, req)
}

// A non-claims environment entity, such as the client ID Keycloak puts in a
// token's chain, can never be a device, so it is skipped before the ERS as
// upstream does: resolving it would cost a lookup that can fail the decision.
func TestChainDevices_NonClaimsEnvironmentNeverReachesTheERS(t *testing.T) {
	svc := newTestService(t, pepConfig(), verifiersFor(&fakeVerifier{}),
		[]configuredSource{pepPatreonSource(), identityCoreSource()}, nil)
	var seen [][]*entity.Entity
	store, err := filestore.NewStoreFromFile(patreonPolicy)
	require.NoError(t, err)
	sdk := &otdf.SDK{EntityResolutionV2: recordingERS{inProcessERS: inProcessERS{svc: svc}, seen: &seen}}
	pdp, err := access.NewJustInTimePDP(t.Context(), logger.CreateTestLogger(), sdk, store, true, false)
	require.NoError(t, err)

	client := &entity.Entity{
		EntityType:  &entity.Entity_ClientId{ClientId: "tdf-iroh-s3"},
		EphemeralId: "client",
		Category:    entity.Entity_CATEGORY_ENVIRONMENT,
	}
	// The device is a bound device token, so it narrows nothing under a
	// policy with no device rules and the decision turns on the routing alone.
	device := deviceTokenEnv(t, "e1", signCWT(t, deviceTokenClaims(time.Now().Add(time.Hour))))
	chain := chainIdentifier(claimsEntity(t, "e0", catalogCreatorClaims()), client, device)
	require.True(t, permitted(t, pdp, testPEP, chain, creatorCampaign, creatorSupporter))
	require.Len(t, seen, 1)
	ids := make([]string, 0, len(seen[0]))
	for _, e := range seen[0] {
		ids = append(ids, e.GetEphemeralId())
	}
	require.Equal(t, []string{"e0", "e1"}, ids, "the claims device is resolved; the client ID is not")
}

const (
	// deviceRulesPolicy is policy.patreon.yaml plus the arkavo-creator
	// attribute and the device rules of the design's section 3: publishing
	// needs an attested device running the production iOS or Creator app, and
	// a managed device keeps a person to campaign and tier content.
	deviceRulesPolicy = "testdata/policy.device-rules.yaml"

	contentTypeDef = patreonAttrNS + "content-type"
	contentVideo   = contentTypeDef + "/value/video"
	statusFormer   = patreonAttrNS + "status/value/former"

	// creatorApp is the macOS app the rules list; scriptedApp is not listed.
	creatorApp  = "M8GS7ZT95Y.com.arkavo.ArkavoCreator"
	scriptedApp = "ABCDE12345.com.example.Scripted"
)

// pepIdentityCoreSource is the identity-core source with pep_assertable set,
// which production leaves unset: without it a person the catalog node
// vouches for holds no publish grant, so no device could decide publish on
// the chain route.
func pepIdentityCoreSource() configuredSource {
	sc := SourceConfig{
		ID: "identity-core", Issuer: testIssuer,
		Grants:        []string{creatorDef},
		Actions:       []string{"publish"},
		PEPAssertable: true,
	}
	return sourceOf(sc, newTokenClaimsSource("arkavo_entitlements", sc.Grants))
}

// contentTypeSource grants the content-type values in arkavo_entitlements.
// Nothing in the example configuration does, but a person needs to hold a
// value no cap keeps for a cap to be seen dropping it.
func contentTypeSource() configuredSource {
	sc := SourceConfig{ID: "content-type", Issuer: testIssuer, Grants: []string{contentTypeDef}, PEPAssertable: true}
	return sourceOf(sc, newTokenClaimsSource("arkavo_entitlements", sc.Grants))
}

// deviceRulesPDP is the v2 PDP over policyFile, resolving through the
// composite with the Patreon, identity-core and content-type sources.
func deviceRulesPDP(t *testing.T, policyFile string) *access.JustInTimePDP {
	t.Helper()
	svc := newTestService(t, pepConfig(), verifiersFor(&fakeVerifier{}),
		[]configuredSource{pepPatreonSource(), pepIdentityCoreSource(), contentTypeSource()}, nil)
	return pdpFor(t, svc, policyFile)
}

// deviceFor is the environment entity a PEP forwards for a device token of
// account: a verified DeviceCheck token of class, running the app with
// rpIdHash appHash in appEnv. An empty appHash or appEnv leaves it out.
func deviceFor(t *testing.T, id, account, class, appHash, appEnv string) *entity.Entity {
	t.Helper()
	claims := deviceTokenClaims(time.Now().Add(time.Hour))
	claims[claimAccountID] = account
	npe, ok := claims["arkavo_npe"].(map[string]any)
	require.True(t, ok)
	npe["class"] = class
	for key, v := range map[string]string{"app_id_hash": appHash, "app_env": appEnv} {
		if v == "" {
			delete(npe, key)
		} else {
			npe[key] = v
		}
	}
	return deviceTokenEnv(t, id, signCWT(t, claims))
}

// The owner's rule, end to end through the real v2 PDP over a policy file
// that declares it: publishing needs an attested device running a production
// Arkavo app. Each row also asks for the creator's campaign content, which no
// rule gates, so a row that denies it shows the whole chain was denied (a
// device that is not bound) rather than one grant narrowed.
func TestDeviceRules_ThroughTheV2PDP(t *testing.T) {
	pdp := deviceRulesPDP(t, deviceRulesPolicy)
	content := []string{creatorCampaign, creatorSupporter}
	device := func(id, class, appHash, appEnv string) *entity.Entity {
		return deviceFor(t, id, creatorAccount, class, appHash, appEnv)
	}
	const (
		attested = chaindevice.ClassAttested
		prod     = chaindevice.EnvProduction
	)

	// A device a PEP vouches for in plain claims says what it likes, with a
	// listed app, and is still unverified and unbound.
	pepClaims := deviceClaims("phone", attested)
	pepClaims[claimAccountID] = creatorAccount
	pepNPE, ok := pepClaims["arkavo_npe"].(map[string]any)
	require.True(t, ok)
	pepNPE["app_id_hash"] = iosAppHash
	pepNPE["app_env"] = prod

	for _, tc := range []struct {
		name    string
		devices []*entity.Entity
		publish bool
		content bool
	}{
		{"person alone", nil, false, true},
		{"person + attested iOS production device", []*entity.Entity{device("e1", attested, iosAppHash, prod)}, true, true},
		{"the same with the Creator hash", []*entity.Entity{device("e1", attested, chaindevice.AppIDHash(creatorApp), prod)}, true, true},
		{"person + managed device", []*entity.Entity{device("e1", chaindevice.ClassManaged, iosAppHash, prod)}, false, true},
		{"attested, development", []*entity.Entity{device("e1", attested, iosAppHash, chaindevice.EnvDevelopment)}, false, true},
		{"attested, no app", []*entity.Entity{device("e1", attested, "", prod)}, false, true},
		{"attested, unlisted app", []*entity.Entity{device("e1", attested, chaindevice.AppIDHash(scriptedApp), prod)}, false, true},
		{"attested and managed: the cap still applies", []*entity.Entity{
			device("e1", attested, iosAppHash, prod), device("e2", chaindevice.ClassManaged, iosAppHash, prod),
		}, false, true},
		{"PEP-claims device saying attested with a listed app", []*entity.Entity{environmentEntity(t, "e1", pepClaims)}, false, false},
		{"device token for another account", []*entity.Entity{deviceFor(t, "e1", otherAccount, attested, iosAppHash, prod)}, false, false},
		{"one bound attested device and one unbound device", []*entity.Entity{
			device("e1", attested, iosAppHash, prod), deviceFor(t, "e2", otherAccount, attested, iosAppHash, prod),
		}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			chain := chainIdentifier(append([]*entity.Entity{claimsEntity(t, "e0", catalogCreatorClaims())}, tc.devices...)...)
			assert.Equal(t, tc.publish, permittedTo(t, pdp, testPEP, "publish", chain, publishValue), "publish")
			assert.Equal(t, tc.content, permitted(t, pdp, testPEP, chain, content...), "campaign content")
		})
	}

	// A device alone gets nothing: the chain has no subject to decide.
	t.Run("device token alone", func(t *testing.T) {
		ctx := callerContext(audit.ContextWithActorID(t.Context(), testPEP), testPEP)
		chain := chainIdentifier(device("e1", attested, iosAppHash, prod))

		decision, err := pdp.GetDecision(ctx, chain, &policy.Action{Name: "publish"}, resourceOf(publishValue), nil, nil)

		require.ErrorContains(t, err, "no subject entities")
		assert.Nil(t, decision)
	})
}

// arks main forwards a device as {sub, iss, aud, kid} (device_to_value): the
// audience makes it a device, and as plain PEP claims it is unverified and
// unbound, so the whole decision denies, with the rules or without. This is
// why arks must forward the device token before the platform is deployed.
func TestDeviceRules_ArksMainDeviceShapeDenies(t *testing.T) {
	arksDevice := deviceClaims("arks-ios-1", "")
	require.ElementsMatch(t, []string{"iss", "sub", "aud", "kid"}, slices.Collect(maps.Keys(arksDevice)))

	for name, policyFile := range map[string]string{"with device rules": deviceRulesPolicy, "without": patreonPolicy} {
		t.Run(name, func(t *testing.T) {
			pdp := deviceRulesPDP(t, policyFile)
			content := []string{creatorCampaign, creatorSupporter}
			alone := chainIdentifier(claimsEntity(t, "e0", catalogCreatorClaims()))
			withDevice := chainIdentifier(claimsEntity(t, "e0", catalogCreatorClaims()), environmentEntity(t, "e1", arksDevice))

			require.True(t, permitted(t, pdp, testPEP, alone, content...), "the person is entitled")
			assert.False(t, permitted(t, pdp, testPEP, withDevice, content...))
			if policyFile == deviceRulesPolicy {
				assert.False(t, permittedTo(t, pdp, testPEP, "publish", withDevice, publishValue))
			}
		})
	}
}

// A managed device caps the person to campaign and tier content: a definition
// FQN in the cap covers every value of it, the synthetic ones the sources
// grant included. Everything else the person holds is dropped, whether a
// source granted it (content-type) or a subject mapping did (status).
func TestDeviceRules_CapThroughTheV2PDP(t *testing.T) {
	pdp := deviceRulesPDP(t, deviceRulesPolicy)
	claims := func() map[string]any {
		c := catalogCreatorClaims()
		c["arkavo_entitlements"] = []any{creatorCampaign, creatorSupporter, contentVideo}
		return c
	}
	managed := deviceFor(t, "e1", creatorAccount, chaindevice.ClassManaged, iosAppHash, chaindevice.EnvProduction)

	for _, tc := range []struct {
		name string
		fqn  string
		kept bool
	}{
		{"campaign", creatorCampaign, true},
		{"campaign tier", creatorSupporter, true},
		{"content-type", contentVideo, false},
		{"status, from a subject mapping", statusFormer, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			alone := chainIdentifier(claimsEntity(t, "e0", claims()))
			capped := chainIdentifier(claimsEntity(t, "e0", claims()), managed)

			require.True(t, permitted(t, pdp, testPEP, alone, tc.fqn), "the person holds it")
			assert.Equal(t, tc.kept, permitted(t, pdp, testPEP, capped, tc.fqn), "with a managed device")
		})
	}
}

// A DeviceCheck token used as the subject (KAS rewrap from iOS) is a person
// and its device in one: the composite splits it, and the device's class, app
// and environment narrow the person as they would in a chain.
func TestDeviceRules_TokenRouteSplit(t *testing.T) {
	pdp := deviceRulesPDP(t, deviceRulesPolicy)
	exp := time.Now().Add(time.Hour)

	// decide mints the token with its arkavo_npe edited and reports whether
	// publish, then the campaign content, is permitted, as the KAS decides
	// them: from a client that is not on claims_chain_peps.
	decide := func(t *testing.T, edit func(npe map[string]any)) (bool, bool) {
		t.Helper()
		claims := splitTokenClaims(exp)
		npe, ok := claims["arkavo_npe"].(map[string]any)
		require.True(t, ok)
		edit(npe)
		id := tokenIdentifier(signCWT(t, claims))
		return permittedTo(t, pdp, "arks-media", "publish", id, publishValue),
			permitted(t, pdp, "arks-media", id, creatorCampaign, creatorSupporter)
	}

	for _, tc := range []struct {
		name    string
		edit    func(npe map[string]any)
		publish bool
	}{
		{"attested, iOS, production", func(map[string]any) {}, true},
		{"attested, the Creator app", func(npe map[string]any) { npe["app_id_hash"] = chaindevice.AppIDHash(creatorApp) }, true},
		{"managed", func(npe map[string]any) { npe["class"] = chaindevice.ClassManaged }, false},
		{"attested, development", func(npe map[string]any) { npe["app_env"] = chaindevice.EnvDevelopment }, false},
		{"attested, no app", func(npe map[string]any) { delete(npe, "app_id_hash") }, false},
		{"attested, unlisted app", func(npe map[string]any) { npe["app_id_hash"] = chaindevice.AppIDHash(scriptedApp) }, false},
		{"no class", func(npe map[string]any) { delete(npe, "class") }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			publish, content := decide(t, tc.edit)
			assert.Equal(t, tc.publish, publish, "publish")
			assert.True(t, content, "campaign content: the person's own grants, which no rule gates")
		})
	}
}

// heldFQNs is the value FQNs GetEntitlements finds id entitled to, which are
// the subject-mapped ones: it reads subject mappings alone, not the direct
// grants the sources make.
func heldFQNs(t *testing.T, pdp *access.JustInTimePDP, id *authzV2.EntityIdentifier) []string {
	t.Helper()
	entitlements, err := pdp.GetEntitlements(callerContext(t.Context(), testPEP), id, false)
	require.NoError(t, err)
	var fqns []string
	for _, e := range entitlements {
		fqns = slices.AppendSeq(fqns, maps.Keys(e.GetActionsPerAttributeValueFqn()))
	}
	slices.Sort(fqns)
	return fqns
}

// GetDecision and GetEntitlements agree on what a device leaves a person. The
// two routes narrow at different points, so each subject-mapped FQN the
// person holds is checked on both, with a device that caps it away and one
// that does not touch it.
func TestDeviceRules_RoutesAgree(t *testing.T) {
	// The Patreon source surfaces the membership's status; its benefits are
	// never filled from a token, so a benefits view is the only way a person
	// holds the entitlement values.
	benefitsView := sourceOf(SourceConfig{ID: "patreon", Issuer: testIssuer, PEPAssertable: true, PropertiesKey: "patreon"},
		fakeSource{res: source.Resolution{Outcome: source.OutcomeComplete, Properties: map[string]any{
			"status": "active", "benefits": []any{"exclusive-content", "discord"},
		}}})

	for _, tc := range []struct {
		name    string
		sources []configuredSource
		claims  map[string]any
		holds   []string // some of what the person holds, to show the case is the one named
	}{
		{
			"creator, status from the Patreon source",
			[]configuredSource{pepPatreonSource()},
			catalogCreatorClaims(),
			[]string{statusFormer},
		},
		{
			"active patron, status from the Patreon source",
			[]configuredSource{pepPatreonSource()},
			patronClaims("13167240", "active_patron"),
			[]string{patreonAttrNS + "status/value/active"},
		},
		{
			"status and entitlement values from a benefits view",
			[]configuredSource{benefitsView},
			catalogCreatorClaims(),
			[]string{patreonAttrNS + "status/value/active", patreonAttrNS + "entitlement/value/discord", patreonAttrNS + "entitlement/value/exclusive-content"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := newTestService(t, pepConfig(), verifiersFor(&fakeVerifier{}), tc.sources, nil)
			pdp := pdpFor(t, svc, deviceRulesPolicy)
			account, ok := tc.claims[claimAccountID].(string)
			require.True(t, ok)
			chain := func(devices ...*entity.Entity) *authzV2.EntityIdentifier {
				return chainIdentifier(append([]*entity.Entity{claimsEntity(t, "e0", tc.claims)}, devices...)...)
			}

			held := heldFQNs(t, pdp, chain())
			require.Subset(t, held, tc.holds, "the person holds subject-mapped values")
			for _, fqn := range held {
				require.True(t, permitted(t, pdp, testPEP, chain(), fqn), "%s: held without a device", fqn)
			}

			t.Run("managed device caps them away", func(t *testing.T) {
				managed := deviceFor(t, "e1", account, chaindevice.ClassManaged, iosAppHash, chaindevice.EnvProduction)
				entitled := heldFQNs(t, pdp, chain(managed))
				for _, fqn := range held {
					assert.NotContains(t, entitled, fqn, "GetEntitlements keeps %s", fqn)
					assert.False(t, permitted(t, pdp, testPEP, chain(managed), fqn), "GetDecision permits %s", fqn)
				}
			})
			t.Run("attested device leaves them", func(t *testing.T) {
				attested := deviceFor(t, "e1", account, chaindevice.ClassAttested, iosAppHash, chaindevice.EnvProduction)
				assert.Equal(t, held, heldFQNs(t, pdp, chain(attested)), "GetEntitlements")
				for _, fqn := range held {
					assert.True(t, permitted(t, pdp, testPEP, chain(attested), fqn), "GetDecision denies %s", fqn)
				}
			})
		})
	}
}

// With no device rules in the policy, a device that is bound narrows
// nothing: every chain decides as TestPatreonDecisions_ThroughTheV2PDP has
// it. A device that is not bound still denies, since binding does not depend
// on rules.
func TestDeviceRules_NoRulesDecidesAsBefore(t *testing.T) {
	svc := newTestService(t, pepConfig(), verifiersFor(&fakeVerifier{}),
		[]configuredSource{pepPatreonSource(), identityCoreSource()}, nil)
	pdp := pdpFor(t, svc, patreonPolicy)
	content := []string{creatorCampaign, creatorSupporter}
	own := []string{patreonAttrNS + "campaign/value/7237273", patreonAttrNS + "campaign-tier/value/7237273_supporter"}

	for _, tc := range []struct {
		name   string
		claims map[string]any
		fqns   []string
		want   bool
	}{
		{"creator", catalogCreatorClaims(), content, true},
		{"patron of 13167240", patronClaims("13167240", "active_patron"), content, true},
		{"patron of 7237273, creator's content", patronClaims("7237273", "active_patron"), content, false},
		{"patron of 7237273, own campaign", patronClaims("7237273", "active_patron"), own, true},
		{"declined patron", patronClaims("13167240", "declined_patron"), content, false},
		{"former patron", patronClaims("13167240", "former_patron"), content, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			account, ok := tc.claims[claimAccountID].(string)
			require.True(t, ok)
			person := func() *entity.Entity { return claimsEntity(t, "e0", tc.claims) }

			require.Equal(t, tc.want, permitted(t, pdp, testPEP, chainIdentifier(person()), tc.fqns...), "alone")
			for _, class := range []string{chaindevice.ClassAttested, chaindevice.ClassManaged} {
				device := deviceFor(t, "e1", account, class, iosAppHash, chaindevice.EnvProduction)
				assert.Equal(t, tc.want, permitted(t, pdp, testPEP, chainIdentifier(person(), device), tc.fqns...), "with a bound %s device token", class)
			}

			pepClaims := deviceClaims("phone", chaindevice.ClassAttested)
			pepClaims[claimAccountID] = account
			assert.False(t, permitted(t, pdp, testPEP, chainIdentifier(person(), environmentEntity(t, "e1", pepClaims)), tc.fqns...),
				"a device in PEP claims is unbound, so it denies without rules too")
		})
	}
}

// A device token sent in a subject entity would be a co-subject with no
// grants: GetDecision would deny while GetEntitlements reported the person's
// grants. The composite refuses it, so both routes fail alike.
func TestDeviceRules_DeviceTokenAsSubjectFailsBothRoutes(t *testing.T) {
	pdp := deviceRulesPDP(t, deviceRulesPolicy)
	token := signCWT(t, deviceTokenClaims(time.Now().Add(time.Hour)))
	chain := chainIdentifier(claimsEntity(t, "e0", catalogCreatorClaims()), claimsEntity(t, "e1", map[string]any{chaindevice.TokenClaim: token}))
	ctx := callerContext(audit.ContextWithActorID(t.Context(), testPEP), testPEP)

	decision, err := pdp.GetDecision(ctx, chain, &policy.Action{Name: "read"}, resourceOf(creatorCampaign), nil, nil)
	require.ErrorContains(t, err, "is not an environment entity", "GetDecision")
	assert.Nil(t, decision)

	entitlements, err := pdp.GetEntitlements(ctx, chain, false)
	require.ErrorContains(t, err, "is not an environment entity", "GetEntitlements")
	assert.Nil(t, entitlements)
}
