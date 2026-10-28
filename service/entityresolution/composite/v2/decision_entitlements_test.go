package composite

import (
	"maps"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestArkavoEntitlementsDecide_ThroughTheV2PDP pins opentdf-platform#69:
// identity.arkavo.net derives the Patreon grants once, into
// arkavo_entitlements, and every route decides from that list alone. The
// tokens are shaped as identity mints them, both tier forms included, and
// their arkavo_patreon claim disagrees with arkavo_entitlements on purpose:
// it never grants and never takes away.
func TestArkavoEntitlementsDecide_ThroughTheV2PDP(t *testing.T) {
	svc := newTestService(t, pepConfig(), verifiersFor(&fakeVerifier{}),
		[]configuredSource{pepPatreonSource(), identityCoreSource()}, nil)
	pdp := pdpFor(t, svc, patreonPolicy)
	exp := time.Now().Add(time.Hour)

	const (
		otherCampaign = patreonAttrNS + "campaign/value/7237273"
		otherTier777  = patreonAttrNS + "campaign-tier/value/7237273_tier-777"
		otherPatron   = patreonAttrNS + "campaign-tier/value/7237273_patron"
		ghostCampaign = patreonAttrNS + "campaign/value/999"
		ghostTier     = patreonAttrNS + "campaign-tier/value/999_supporter"
	)
	// A consumer with two active memberships: 13167240 through the slug form
	// and 7237273 through the id form. arkavo_patreon also claims an active
	// membership of 999, which arkavo_entitlements does not carry.
	consumer := map[string]any{
		"iss":               testIssuer,
		"sub":               "did:key:z6Mkconsumer",
		"arkavo_account_id": "00000000-0000-0000-0000-0000000c0de5",
		"arkavo_patreon": map[string]any{"role": "consumer", "memberships": []any{
			map[string]any{"campaign_id": "13167240", "patron_status": "active_patron", "tier_slugs": []any{"supporter"}},
			map[string]any{"campaign_id": "7237273", "patron_status": "active_patron", "tier_slugs": []any{"patron"}},
			map[string]any{"campaign_id": "999", "patron_status": "active_patron", "tier_slugs": []any{"supporter"}},
		}},
		"arkavo_entitlements": []any{
			creatorCampaign, creatorSupporter, patreonAttrNS + "campaign-tier/value/13167240_tier-100",
			otherCampaign, otherTier777,
		},
	}
	// The campaign owner: their own campaign and every tier of it, in both
	// forms, plus the publish entitlement. arkavo_patreon has no memberships.
	creator := creatorClaims(exp)

	viaToken := func(t *testing.T, action string, claims map[string]any, fqns ...string) bool {
		t.Helper()
		claims = maps.Clone(claims)
		claims["exp"] = exp
		return permittedTo(t, pdp, "arks-media", action, tokenIdentifier(signCWT(t, claims)), fqns...)
	}
	viaCatalog := func(t *testing.T, claims map[string]any, fqns ...string) bool {
		t.Helper()
		claims = maps.Clone(claims)
		delete(claims, "exp")
		return permitted(t, pdp, testPEP, chainIdentifier(claimsEntity(t, "catalog-subject", claims)), fqns...)
	}
	// agree asserts one answer on the KAS route and the catalog route.
	agree := func(t *testing.T, want bool, claims map[string]any, fqns ...string) {
		t.Helper()
		require.Equal(t, want, viaToken(t, "read", claims, fqns...), "KAS route")
		require.Equal(t, want, viaCatalog(t, claims, fqns...), "catalog route")
	}

	t.Run("creator opens their own slug-form content", func(t *testing.T) {
		agree(t, true, creator, creatorCampaign, creatorSupporter)
	})
	t.Run("creator opens their own id-form content", func(t *testing.T) {
		agree(t, true, creator, creatorCampaign, creatorTier555)
	})
	t.Run("creator publishes on the token route", func(t *testing.T) {
		require.True(t, viaToken(t, "publish", creator, publishValue))
		require.False(t, viaToken(t, "read", creator, publishValue), "publish is not read")
	})
	t.Run("consumer opens slug-form content of the first membership", func(t *testing.T) {
		agree(t, true, consumer, creatorCampaign, creatorSupporter)
	})
	t.Run("consumer opens id-form content of the second membership", func(t *testing.T) {
		agree(t, true, consumer, otherCampaign, otherTier777)
	})
	t.Run("a tier arkavo_patreon names but arkavo_entitlements lacks is denied", func(t *testing.T) {
		agree(t, false, consumer, otherCampaign, otherPatron)
	})
	t.Run("a membership only arkavo_patreon claims is denied", func(t *testing.T) {
		agree(t, false, consumer, ghostCampaign, ghostTier)
	})
	t.Run("a tier the consumer does not hold is denied", func(t *testing.T) {
		agree(t, false, consumer, creatorCampaign, creatorTier555)
	})
}
