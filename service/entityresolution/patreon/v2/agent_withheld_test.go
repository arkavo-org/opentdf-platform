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

const agentDID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"

// prodConfig mirrors the production patreon ERS: trust on, issuer pinned,
// unknown subjects inferred as free.
func prodConfig() Config {
	return Config{
		TrustMaterializedClaims: true,
		TrustedIssuer:           cwtTestIssuer,
		InferUnknownAsFree:      true,
	}
}

// activeMembership is a trusted arkavo_patreon claim that would grant a
// campaign entitlement to a person.
func activeMembership() map[any]any {
	return map[any]any{
		"role":            "consumer",
		"patreon_user_id": "p-77",
		"memberships": []any{map[any]any{
			"campaign_id":   "11111111",
			"patron_status": "active_patron",
			"tier_slugs":    []any{"gold-tier"},
		}},
	}
}

// agentCWT is an authnz-rs contract v2 agent token, plus an active Patreon
// membership and an azp, so nothing but the agent gate stands between it and
// entitlements.
func agentCWT(t *testing.T) string {
	t.Helper()
	return signCWT(t, cwtTestIssuer, agentDID, map[any]any{
		"azp":                  cwtTestAzp,
		"arkavo_account_id":    "owner-1",
		"arkavo_npe":           map[any]any{"type": "agent"},
		"arkavo_swarm":         "swarm-1",
		"arkavo_state_version": int64(3),
		"cnf":                  map[any]any{"jwk": map[any]any{"kty": "OKP", "crv": "Ed25519", "x": "AAAA"}},
		"arkavo_patreon":       activeMembership(),
	})
}

func resolveOne(t *testing.T, svc *EntityResolutionService, e *entity.Entity) *ersV2.EntityRepresentation {
	t.Helper()
	resp, err := svc.ResolveEntities(context.Background(),
		connect.NewRequest(&ersV2.ResolveEntitiesRequest{Entities: []*entity.Entity{e}}))
	if err != nil {
		t.Fatalf("ResolveEntities: %v", err)
	}
	return resp.Msg.GetEntityRepresentations()[0]
}

func claimsEntity(t *testing.T, claims map[string]any) *entity.Entity {
	t.Helper()
	s, err := structpb.NewStruct(claims)
	if err != nil {
		t.Fatalf("claims struct: %v", err)
	}
	a, err := anypb.New(s)
	if err != nil {
		t.Fatalf("any: %v", err)
	}
	return &entity.Entity{EphemeralId: "e0", EntityType: &entity.Entity_Claims{Claims: a}}
}

// assertWithheld: no patreon.* view for subject mappings to match and no
// direct entitlements.
func assertWithheld(t *testing.T, repr *ersV2.EntityRepresentation) {
	t.Helper()
	if n := len(repr.GetDirectEntitlements()); n != 0 {
		t.Errorf("withheld agent got %d direct entitlements", n)
	}
	for _, p := range repr.GetAdditionalProps() {
		if _, present := p.AsMap()["patreon"]; present {
			t.Errorf("withheld agent exposes a patreon view: %v", p.AsMap())
		}
	}
}

// An agent token resolves to one withheld subject: no environment entity,
// no patreon view, no preserved arkavo_patreon, even with a trusted active
// membership on it. The second pass withholds it too, and
// InferUnknownAsFree never turns it into a free/former follower.
func TestAgentToken_Withheld(t *testing.T) {
	svc := newSvc(t, prodConfig())
	ents := normalizedEntities(t, chainFor(t, svc, agentCWT(t)))
	if len(ents) != 1 {
		t.Fatalf("want a single subject entity, got %#v", ents)
	}
	if ents[0]["category"] != entity.Entity_CATEGORY_SUBJECT.String() {
		t.Errorf("category = %v", ents[0]["category"])
	}
	claims, _ := ents[0]["claims"].(map[string]any)
	if len(claims) != 1 || claims[claimAgentWithheld] != true {
		t.Fatalf("subject claims = %#v, want only %s", claims, claimAgentWithheld)
	}

	chain := chainFor(t, svc, agentCWT(t))
	assertWithheld(t, resolveOne(t, svc, chain[0]))
}

// Each agent marker gates on its own, including malformed ones; a device
// NPE and a person do not.
func TestAgentMarkers_ClaimsEntity(t *testing.T) {
	svc := newSvc(t, prodConfig())
	for _, tc := range []struct {
		name   string
		claims map[string]any
		gated  bool
	}{
		{"npe agent", map[string]any{"arkavo_npe": map[string]any{"type": "agent"}}, true},
		{"npe unknown type", map[string]any{"arkavo_npe": map[string]any{"type": "robot"}}, true},
		{"npe no type", map[string]any{"arkavo_npe": map[string]any{}}, true},
		{"npe not an object", map[string]any{"arkavo_npe": "agent"}, true},
		{"swarm", map[string]any{"arkavo_swarm": "s"}, true},
		{"state version", map[string]any{"arkavo_state_version": 0}, true},
		{"role string", map[string]any{"arkavo_roles": "agent"}, true},
		{"role list", map[string]any{"arkavo_roles": []any{"reader", "agent"}}, true},
		{"withheld flag", map[string]any{claimAgentWithheld: true}, true},
		{"device npe", map[string]any{"arkavo_npe": map[string]any{"type": "device"}}, false},
		{"person", map[string]any{"sub": "arkavo:u1", "arkavo_roles": []any{"reader"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repr := resolveOne(t, svc, claimsEntity(t, tc.claims))
			if tc.gated {
				assertWithheld(t, repr)
				return
			}
			patreon, _ := repr.GetAdditionalProps()[0].AsMap()["patreon"].(map[string]any)
			if patreon["tier_slug"] != tierFree {
				t.Errorf("ungated subject should still infer free, got %v", patreon)
			}
		})
	}
}

// A device NPE token keeps today's behaviour: its trusted membership is
// honoured.
func TestDeviceToken_NotWithheld(t *testing.T) {
	svc := newSvc(t, prodConfig())
	tok := signCWT(t, cwtTestIssuer, "did:key:z6Mkdevice", map[any]any{
		"azp":            cwtTestAzp,
		"arkavo_npe":     map[any]any{"type": "device"},
		"arkavo_patreon": activeMembership(),
	})
	ents := normalizedEntities(t, chainFor(t, svc, tok))
	if len(ents) != 2 {
		t.Fatalf("device token: want environment + subject, got %#v", ents)
	}
	claims, _ := ents[1]["claims"].(map[string]any)
	patreon, _ := claims["patreon"].(map[string]any)
	if patreon["status"] != statusActive {
		t.Errorf("device token lost its membership: %v", patreon)
	}
}
