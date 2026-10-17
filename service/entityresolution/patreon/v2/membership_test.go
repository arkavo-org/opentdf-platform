package patreon

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMembershipView_ActiveCampaignsOnly(t *testing.T) {
	claim := parseArkavoPatreon(map[string]any{
		"sub": "arkavo:u1",
		"arkavo_patreon": map[string]any{
			"role":            "consumer",
			"patreon_user_id": "p-77",
			"memberships": []any{
				map[string]any{
					"campaign_id":   "11111111",
					"patron_status": "active_patron",
					"tier_slugs":    []any{"Gold Tier", "early-access"},
				},
				map[string]any{
					"campaign_id":   "22222222",
					"patron_status": "former_patron",
					"tier_slugs":    []any{"vip"},
				},
				map[string]any{
					"campaign_id":   "33333333",
					"patron_status": "active_patron",
					// legacy materialization: no tier_slugs
				},
			},
		},
	})
	require.NotNil(t, claim)

	mem := membershipView(claim)
	assert.Equal(t, "p-77", mem.UserID)
	assert.Equal(t, statusActive, mem.Status)
	assert.Equal(t, []string{"11111111", "33333333"}, mem.CampaignIDs, "a former membership surfaces no campaign")
	assert.Equal(t, "gold-tier", mem.TierSlug, "the first active slug, slugified")
}

func TestMembershipView_CreatorSurfacesOwnedCampaign(t *testing.T) {
	mem := membershipView(parseArkavoPatreon(map[string]any{
		"arkavo_patreon": map[string]any{"role": "creator", "campaign_id": "13167240"},
	}))
	assert.Equal(t, []string{"13167240"}, mem.CampaignIDs)
	assert.Equal(t, tierFree, mem.TierSlug)
}

// An ACTIVE membership whose only campaign is malformed must not leave the
// flattened view reporting status=active with no campaign behind it.
func TestMembershipView_MalformedActiveCampaignDoesNotFlipStatus(t *testing.T) {
	mem := membershipView(&arkavoPatreonClaim{
		memberships: []materializedMembership{
			{campaignID: "bad_id", status: "active_patron", tierSlugs: []string{"gold"}},
		},
	})
	assert.NotEqual(t, statusActive, mem.Status)
	assert.Empty(t, mem.CampaignIDs)
	assert.Equal(t, tierFree, mem.TierSlug)

	// A valid active campaign alongside a malformed one: status active, only
	// the valid campaign surfaces.
	mem = membershipView(&arkavoPatreonClaim{
		memberships: []materializedMembership{
			{campaignID: "bad_id", status: "active_patron", tierSlugs: []string{"gold"}},
			{campaignID: "99", status: "active_patron", tierSlugs: []string{"silver"}},
		},
	})
	assert.Equal(t, statusActive, mem.Status)
	assert.Equal(t, []string{"99"}, mem.CampaignIDs)
	assert.Equal(t, "silver", mem.TierSlug)
}

func TestSlugify(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"VIP", "vip"},
		{"Early Access", "early-access"},
		{"  Behind The Scenes  ", "behind-the-scenes"},
		{"!!!", ""},
		{"foo--bar", "foo-bar"},
		{"Tier_With_Underscores", "tier-with-underscores"},
	} {
		if got := slugify(tc.in); got != tc.want {
			t.Errorf("slugify(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
