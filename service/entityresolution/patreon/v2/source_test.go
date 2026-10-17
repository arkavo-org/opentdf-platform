package patreon

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/opentdf/platform/service/entityresolution/source"
)

const sourceNS = "https://patreon.arkavo.com/attr/"

func resolveSource(t *testing.T, cfg SourceConfig, claims map[string]any) source.Resolution {
	t.Helper()
	res, err := NewTokenSource(cfg).Resolve(context.Background(), source.Subject{Claims: claims, Kind: source.KindPerson, Trust: source.TrustVerified}, source.Query{Action: "read"})
	require.NoError(t, err)
	return res
}

func grantFQNs(res source.Resolution) []string {
	out := make([]string, 0, len(res.Grants))
	for _, g := range res.Grants {
		out = append(out, g.FQN)
	}
	return out
}

func TestTokenSource_CreatorTiersFromEntitlements(t *testing.T) {
	res := resolveSource(t, SourceConfig{}, map[string]any{
		"arkavo_patreon": map[string]any{
			"role":        "creator",
			"campaign_id": "13167240",
			"memberships": []any{},
		},
		"arkavo_entitlements": []any{
			sourceNS + "campaign/value/13167240",
			sourceNS + "campaign-tier/value/13167240_supporter",
			sourceNS + "campaign-tier/value/13167240_free",
			sourceNS + "campaign-tier/value/13167240_tier-555",
			"https://arkavo.ai/attr/tdf/value/decrypt",
			"https://patreon.arkavo.com/attr/arkavo-creator/value/publish",
		},
	})

	assert.Equal(t, source.OutcomeComplete, res.Outcome)
	assert.ElementsMatch(t, []string{
		sourceNS + "campaign/value/13167240",
		sourceNS + "campaign-tier/value/13167240_supporter",
		sourceNS + "campaign-tier/value/13167240_free",
		sourceNS + "campaign-tier/value/13167240_tier-555",
	}, grantFQNs(res))
	for _, g := range res.Grants {
		assert.Equal(t, []string{"read"}, g.Actions)
	}
}

func TestTokenSource_PatronGrantsComeOnlyFromEntitlements(t *testing.T) {
	arkavoPatreon := map[string]any{
		"role": "consumer",
		"memberships": []any{map[string]any{
			"campaign_id":   "7237273",
			"patron_status": "active_patron",
			"tier_slugs":    []any{"Supporter"},
		}},
	}

	res := resolveSource(t, SourceConfig{}, map[string]any{
		"arkavo_patreon": arkavoPatreon,
		"arkavo_entitlements": []any{
			sourceNS + "campaign/value/7237273",
			sourceNS + "campaign-tier/value/7237273_supporter",
			sourceNS + "campaign-tier/value/7237273_tier-42",
		},
	})
	assert.ElementsMatch(t, []string{
		sourceNS + "campaign/value/7237273",
		sourceNS + "campaign-tier/value/7237273_supporter",
		sourceNS + "campaign-tier/value/7237273_tier-42",
	}, grantFQNs(res))

	res = resolveSource(t, SourceConfig{}, map[string]any{"arkavo_patreon": arkavoPatreon})
	assert.Empty(t, res.Grants)
	assert.Equal(t, source.OutcomeComplete, res.Outcome)
	assert.Equal(t, "active", res.Properties["status"])
	assert.Equal(t, "supporter", res.Properties["tier_slug"])
}

func TestTokenSource_MalformedEntitlementsIgnored(t *testing.T) {
	res := resolveSource(t, SourceConfig{}, map[string]any{
		"arkavo_entitlements": []any{
			42,
			"HTTPS://PATREON.ARKAVO.COM/attr/campaign/value/7237273",
			sourceNS + "campaign/value/abc",
			sourceNS + "campaign-tier/value/7237273",
			sourceNS + "campaign-tier/value/7237273_Bad_Slug",
			"https://other.example/attr/campaign/value/7237273",
			"https://patreon.arkavo.com.evil/attr/campaign/value/7237273",
		},
	})
	assert.Equal(t, []string{sourceNS + "campaign/value/7237273"}, grantFQNs(res))
}

func TestTokenSource_ConfiguredNamespaceIsExact(t *testing.T) {
	res := resolveSource(t, SourceConfig{EntitlementsNamespace: "creators.example"}, map[string]any{
		"arkavo_entitlements": []any{
			sourceNS + "campaign/value/7237273",
			"https://creators.example/attr/campaign/value/7237273",
		},
	})
	assert.Equal(t, []string{"https://creators.example/attr/campaign/value/7237273"}, grantFQNs(res))
}

func TestTokenSource_NoClaimInfersFree(t *testing.T) {
	res := resolveSource(t, SourceConfig{InferUnknownAsFree: true}, map[string]any{})
	assert.Empty(t, res.Grants)
	assert.Equal(t, source.OutcomeComplete, res.Outcome)
	assert.Equal(t, "former", res.Properties["status"])
	assert.Equal(t, "free", res.Properties["tier_slug"])
}

func TestTokenSource_NoClaimNotApplicable(t *testing.T) {
	res := resolveSource(t, SourceConfig{}, map[string]any{})
	assert.Empty(t, res.Grants)
	assert.Nil(t, res.Properties)
	assert.Equal(t, source.OutcomeNotApplicable, res.Outcome)
}

func TestTokenSource_DeclinedMembershipView(t *testing.T) {
	res := resolveSource(t, SourceConfig{}, map[string]any{
		"arkavo_patreon": map[string]any{
			"memberships": []any{map[string]any{
				"campaign_id":   "7237273",
				"patron_status": "declined_patron",
				"tier_slugs":    []any{"supporter"},
			}},
		},
	})
	assert.Empty(t, res.Grants)
	assert.Equal(t, "declined", res.Properties["status"])
}

func TestTokenSource_RoleNeverGrants(t *testing.T) {
	res := resolveSource(t, SourceConfig{}, map[string]any{
		"role": "creator",
		"arkavo_patreon": map[string]any{
			"role":        "creator",
			"campaign_id": "13167240",
		},
	})
	assert.Empty(t, res.Grants)
}
