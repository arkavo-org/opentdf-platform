package patreon

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/opentdf/platform/protocol/go/entity"
	ersV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
)

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
	svc := newSvc(t, Config{}, &forbiddenClient{t: t})

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
	svc := newSvc(t, Config{}, &forbiddenClient{t: t})
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
