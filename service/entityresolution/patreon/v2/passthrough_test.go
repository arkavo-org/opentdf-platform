package patreon

import (
	"context"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/opentdf/platform/protocol/go/entity"
	ersV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
)

// buildJWT builds an UNSIGNED JWT with the given claims — entitiesFromToken
// parses without verification (the platform authn layer verifies upstream),
// so an unsigned token exercises the claim-handling logic directly.
func buildJWT(t *testing.T, claims map[string]interface{}) string {
	t.Helper()
	tok := jwt.New()
	for k, v := range claims {
		if err := tok.Set(k, v); err != nil {
			t.Fatalf("set claim %s: %v", k, err)
		}
	}
	b, err := jwt.NewSerializer().Serialize(tok)
	if err != nil {
		t.Fatalf("serialize jwt: %v", err)
	}
	return string(b)
}

// forbiddenClient fails the test if any Patreon lookup is attempted — the
// claims-passthrough path must never touch the API.
type forbiddenClient struct{ t *testing.T }

func (f *forbiddenClient) ResolveByUserID(context.Context, string) (*Membership, error) {
	f.t.Fatal("passthrough must not call ResolveByUserID")
	return nil, ErrMemberNotFound
}

func (f *forbiddenClient) ResolveByEmail(context.Context, string) (*Membership, error) {
	f.t.Fatal("passthrough must not call ResolveByEmail")
	return nil, ErrMemberNotFound
}

func (f *forbiddenClient) ResolveSelf(context.Context, string) (*Membership, error) {
	f.t.Fatal("passthrough must not call ResolveSelf")
	return nil, ErrMemberNotFound
}

func materializedClaims(t *testing.T) *anypb.Any {
	t.Helper()
	claims, err := structpb.NewStruct(map[string]interface{}{
		"sub": "arkavo:u1",
		"arkavo_patreon": map[string]interface{}{
			"role":            "consumer",
			"patreon_user_id": "p-77",
			"memberships": []interface{}{
				map[string]interface{}{
					"campaign_id":   "11111111",
					"patron_status": "active_patron",
					"tier_slugs":    []interface{}{"gold-tier", "early-access"},
				},
				map[string]interface{}{
					"campaign_id":   "22222222",
					"patron_status": "former_patron",
					"tier_slugs":    []interface{}{"vip"},
				},
				map[string]interface{}{
					"campaign_id":   "33333333",
					"patron_status": "active_patron",
					// legacy materialization: no tier_slugs yet
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("claims struct: %v", err)
	}
	wrapped, err := anypb.New(claims)
	if err != nil {
		t.Fatalf("any: %v", err)
	}
	return wrapped
}

func TestPassthrough_EmitsCampaignQualifiedEntitlements(t *testing.T) {
	svc := newSvc(t, Config{TrustMaterializedClaims: true}, &forbiddenClient{t: t})

	req := connect.NewRequest(&ersV2.ResolveEntitiesRequest{
		Entities: []*entity.Entity{{
			EphemeralId: "e0",
			EntityType:  &entity.Entity_Claims{Claims: materializedClaims(t)},
			Category:    entity.Entity_CATEGORY_SUBJECT,
		}},
	})
	resp, err := svc.ResolveEntities(context.Background(), req)
	if err != nil {
		t.Fatalf("ResolveEntities: %v", err)
	}
	reprs := resp.Msg.GetEntityRepresentations()
	if len(reprs) != 1 {
		t.Fatalf("want 1 representation, got %d", len(reprs))
	}

	got := map[string]bool{}
	for _, d := range reprs[0].GetDirectEntitlements() {
		got[d.GetAttributeValueFqn()] = true
		if len(d.GetActions()) != 1 || d.GetActions()[0] != "read" {
			t.Errorf("entitlement %s actions = %v, want [read]", d.GetAttributeValueFqn(), d.GetActions())
		}
	}

	want := []string{
		// active membership: campaign + campaign-qualified tiers in the
		// creator's own vocabulary
		"https://patreon.arkavo.com/attr/campaign/value/11111111",
		"https://patreon.arkavo.com/attr/campaign-tier/value/11111111_gold-tier",
		"https://patreon.arkavo.com/attr/campaign-tier/value/11111111_early-access",
		// active membership without materialized slugs: campaign only
		"https://patreon.arkavo.com/attr/campaign/value/33333333",
	}
	for _, fqn := range want {
		if !got[fqn] {
			t.Errorf("missing entitlement %s (got %v)", fqn, got)
		}
	}
	// Former patron at 22222222 must grant NOTHING — no cross-tenant or
	// lapsed-membership leakage.
	for fqn := range got {
		if len(got) > 0 && (fqn == "https://patreon.arkavo.com/attr/campaign/value/22222222" ||
			fqn == "https://patreon.arkavo.com/attr/campaign-tier/value/22222222_vip") {
			t.Errorf("former membership leaked entitlement: %s", fqn)
		}
	}
	if len(got) != len(want) {
		t.Errorf("entitlement count = %d, want %d: %v", len(got), len(want), got)
	}

	// The flattened .patreon.* view still surfaces active campaigns.
	props := reprs[0].GetAdditionalProps()[0].AsMap()
	patreon, ok := props["patreon"].(map[string]interface{})
	if !ok {
		t.Fatalf("patreon claims missing: %v", props)
	}
	if patreon["status"] != "active" {
		t.Errorf("status = %v, want active", patreon["status"])
	}
}

func TestPassthrough_AllFormerMembershipsGrantNothing(t *testing.T) {
	svc := newSvc(t, Config{TrustMaterializedClaims: true}, &forbiddenClient{t: t})
	claims, _ := structpb.NewStruct(map[string]interface{}{
		"arkavo_patreon": map[string]interface{}{
			"role":            "consumer",
			"patreon_user_id": "p-9",
			"memberships": []interface{}{
				map[string]interface{}{
					"campaign_id":   "44444444",
					"patron_status": "declined_patron",
					"tier_slugs":    []interface{}{"gold"},
				},
			},
		},
	})
	wrapped, _ := anypb.New(claims)
	req := connect.NewRequest(&ersV2.ResolveEntitiesRequest{
		Entities: []*entity.Entity{{
			EphemeralId: "e0",
			EntityType:  &entity.Entity_Claims{Claims: wrapped},
		}},
	})
	resp, err := svc.ResolveEntities(context.Background(), req)
	if err != nil {
		t.Fatalf("ResolveEntities: %v", err)
	}
	if n := len(resp.Msg.GetEntityRepresentations()[0].GetDirectEntitlements()); n != 0 {
		t.Errorf("declined patron got %d entitlements, want 0", n)
	}
}

func TestPassthrough_CustomNamespace(t *testing.T) {
	res := passthroughResolution(&arkavoPatreonClaim{
		memberships: []materializedMembership{{
			campaignID: "55",
			status:     "active_patron",
			tierSlugs:  []string{"basic"},
		}},
	}, "members.example.com")
	want := "https://members.example.com/attr/campaign-tier/value/55_basic"
	found := false
	for _, e := range res.entitlements {
		if e == want {
			found = true
		}
	}
	if !found {
		t.Errorf("custom namespace entitlement missing: %v", res.entitlements)
	}
}

func TestPassthrough_SlugifiesTierToEnforceSplitInvariant(t *testing.T) {
	res := passthroughResolution(&arkavoPatreonClaim{
		memberships: []materializedMembership{{
			campaignID: "77",
			status:     "active_patron",
			tierSlugs:  []string{"Gold Tier_Plus"},
		}},
	}, defaultEntitlementsNamespace)
	want := "https://patreon.arkavo.com/attr/campaign-tier/value/77_gold-tier-plus"
	found := false
	for _, e := range res.entitlements {
		if e == want {
			found = true
		}
	}
	if !found {
		t.Errorf("slug not normalized; got %v", res.entitlements)
	}
}

func TestPassthrough_DisabledByDefault(t *testing.T) {
	svc := newSvc(t, Config{InferUnknownAsFree: true}, freeFallbackClient{})
	req := connect.NewRequest(&ersV2.ResolveEntitiesRequest{
		Entities: []*entity.Entity{{
			EphemeralId: "e0",
			EntityType:  &entity.Entity_Claims{Claims: materializedClaims(t)},
		}},
	})
	resp, err := svc.ResolveEntities(context.Background(), req)
	if err != nil {
		t.Fatalf("ResolveEntities: %v", err)
	}
	if n := len(resp.Msg.GetEntityRepresentations()[0].GetDirectEntitlements()); n != 0 {
		t.Errorf("trust disabled but got %d entitlements — claim was honored ungated", n)
	}
}

func TestPassthrough_UntrustedIssuerLeaksNothingViaToken(t *testing.T) {
	// A signature-valid token from a NON-pinned issuer must not derive the
	// flattened patreon.* view OR direct entitlements from arkavo_patreon.
	// Build a JWT carrying iss=evil + a forged arkavo_patreon, run it
	// through CreateEntityChainsFromTokens (the token path), and assert the
	// subject entity reflects no active membership and no entitlements.
	svc := newSvc(t, Config{
		TrustMaterializedClaims: true,
		TrustedIssuer:           "https://identity.arkavo.net",
		InferUnknownAsFree:      true,
	}, freeFallbackClient{})

	forged := buildJWT(t, map[string]interface{}{
		"iss": "https://evil.example.com",
		"sub": "attacker",
		"arkavo_patreon": map[string]interface{}{
			"role":            "consumer",
			"patreon_user_id": "p-evil",
			"memberships": []interface{}{map[string]interface{}{
				"campaign_id":   "11111111",
				"patron_status": "active_patron",
				"tier_slugs":    []interface{}{"gold-tier"},
			}},
		},
	})
	resp, err := svc.CreateEntityChainsFromTokens(context.Background(),
		connect.NewRequest(&ersV2.CreateEntityChainsFromTokensRequest{
			Tokens: []*entity.Token{{EphemeralId: "t0", Jwt: forged}},
		}))
	if err != nil {
		t.Fatalf("CreateEntityChainsFromTokens: %v", err)
	}
	// Find the subject entity's claims; assert no active patreon status and
	// no preserved arkavo_patreon (so the second pass grants nothing).
	var subject *entity.Entity
	for _, e := range resp.Msg.GetEntityChains()[0].GetEntities() {
		if e.GetCategory() == entity.Entity_CATEGORY_SUBJECT {
			subject = e
		}
	}
	if subject == nil {
		t.Fatal("no subject entity")
	}
	var st structpb.Struct
	if err := subject.GetClaims().UnmarshalTo(&st); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	m := st.AsMap()
	if _, present := m["arkavo_patreon"]; present {
		t.Error("untrusted issuer: arkavo_patreon was preserved for second pass")
	}
	patreon, _ := m["patreon"].(map[string]interface{})
	if patreon["status"] == "active" {
		t.Errorf("untrusted issuer leaked active status: %v", patreon)
	}
}

func TestPassthrough_NonNumericCampaignIDSkipped(t *testing.T) {
	res := passthroughResolution(&arkavoPatreonClaim{
		memberships: []materializedMembership{
			{campaignID: "good_123", status: "active_patron", tierSlugs: []string{"gold"}},
			{campaignID: "12345678", status: "active_patron", tierSlugs: []string{"gold"}},
		},
	}, defaultEntitlementsNamespace)
	for _, e := range res.entitlements {
		if strings.Contains(e, "good_123") {
			t.Errorf("non-numeric campaign id produced an FQN: %s", e)
		}
	}
	// The valid numeric campaign still produced entitlements.
	if len(res.entitlements) == 0 {
		t.Error("valid campaign produced no entitlements")
	}
}

// freeFallbackClient always misses, exercising the InferUnknownAsFree path.
type freeFallbackClient struct{}

func (freeFallbackClient) ResolveByUserID(context.Context, string) (*Membership, error) {
	return nil, ErrMemberNotFound
}

func (freeFallbackClient) ResolveByEmail(context.Context, string) (*Membership, error) {
	return nil, ErrMemberNotFound
}

func (freeFallbackClient) ResolveSelf(context.Context, string) (*Membership, error) {
	return nil, ErrMemberNotFound
}
