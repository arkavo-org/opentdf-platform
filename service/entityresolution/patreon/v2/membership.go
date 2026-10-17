package patreon

import (
	"regexp"

	"google.golang.org/protobuf/types/known/structpb"
)

// The Patreon membership view.
//
// identity.arkavo.net materializes every consumer's Patreon memberships into
// the `arkavo_patreon` CWT claim at token mint, using the consumer's own
// OAuth token, which sees every campaign they back. That claim feeds only the
// flattened .patreon.* view below; it grants nothing. Grants come from
// arkavo_entitlements (see source.go), in the campaign-qualified form:
//
//	https://<ns>/attr/campaign/value/<campaign_id>
//	https://<ns>/attr/campaign-tier/value/<campaign_id>_<tier_slug>
//
// Tiers are campaign-qualified in the creator's OWN tier vocabulary: no
// cross-creator tier normalization, so a vip at creator A grants nothing at
// creator B. Content is tagged at protect time with the explicit value list
// for "this tier and up" (the Creator app knows its own ladder), so no server
// ever needs per-campaign hierarchy knowledge.
const (
	defaultEntitlementsNamespace = "patreon.arkavo.com"
	campaignAttributeName        = "campaign"
	campaignTierAttributeName    = "campaign-tier"
)

// numericCampaignID guards the FQN split invariant on the campaign side:
// campaign ids must be numeric (Patreon's are), so they never contain the
// '_' separator, and tier slugs never contain one either (slugify maps
// separators to '-'), so the first '_' of a campaign-tier value splits it
// unambiguously. A non-conforming id is skipped rather than producing an
// ambiguous FQN.
var numericCampaignID = regexp.MustCompile(`^[0-9]+$`)

// materializedMembership is one campaign membership as materialized into
// the arkavo_patreon claim by identity.arkavo.net.
type materializedMembership struct {
	campaignID string
	status     string
	tierSlugs  []string
}

// arkavoPatreonClaim is the parsed arkavo_patreon claim.
type arkavoPatreonClaim struct {
	role        string
	userID      string
	campaignID  string
	memberships []materializedMembership
}

// parseArkavoPatreon extracts the materialized claim, tolerantly: absent or
// malformed returns nil.
func parseArkavoPatreon(claims map[string]interface{}) *arkavoPatreonClaim {
	raw, isMap := claims["arkavo_patreon"].(map[string]interface{})
	if !isMap {
		return nil
	}
	out := &arkavoPatreonClaim{}
	out.role, _ = raw["role"].(string)
	out.userID, _ = raw["patreon_user_id"].(string)
	out.campaignID, _ = raw["campaign_id"].(string)

	rawMemberships, _ := raw["memberships"].([]interface{})
	for _, rm := range rawMemberships {
		m, memIsMap := rm.(map[string]interface{})
		if !memIsMap {
			continue
		}
		mem := materializedMembership{}
		mem.campaignID, _ = m["campaign_id"].(string)
		mem.status, _ = m["patron_status"].(string)
		if slugs, hasSlugs := m["tier_slugs"].([]interface{}); hasSlugs {
			for _, s := range slugs {
				if slug, isString := s.(string); isString && slug != "" {
					mem.tierSlugs = append(mem.tierSlugs, slug)
				}
			}
		}
		if mem.campaignID != "" {
			out.memberships = append(out.memberships, mem)
		}
	}
	return out
}

// membershipView flattens a materialized claim into the Membership view
// backing the .patreon.* selectors: status, tier_slug and campaign_ids. It
// grants nothing. Only ACTIVE memberships with a valid campaign id count;
// declined/former patrons surface their status and nothing else.
func membershipView(claim *arkavoPatreonClaim) *Membership {
	mem := &Membership{
		UserID:   claim.userID,
		TierSlug: tierFree,
		Status:   normalizeStatus(""),
	}

	for _, m := range claim.memberships {
		status := normalizeStatus(m.status)
		if status != statusActive {
			// Surface a non-active status in the flattened view only while
			// no active+valid campaign has been seen.
			if mem.Status != statusActive {
				mem.Status = status
			}
			continue
		}
		if !numericCampaignID.MatchString(m.campaignID) {
			// Active but malformed campaign id would break the
			// <campaign_id>_<tier_slug> split. Skip it AND don't let it
			// alone promote the flattened view to active.
			continue
		}
		mem.Status = statusActive
		mem.CampaignIDs = append(mem.CampaignIDs, m.campaignID)
		for _, rawSlug := range m.tierSlugs {
			// Flattened tier_slug is informational only; gating uses the
			// campaign-qualified entitlements.
			if slug := slugify(rawSlug); slug != "" && mem.TierSlug == tierFree {
				mem.TierSlug = slug
			}
		}
	}

	// Creator role: surface the owned campaign.
	if claim.role == "creator" && claim.campaignID != "" {
		mem.CampaignIDs = append(mem.CampaignIDs, claim.campaignID)
	}
	return mem
}

// membershipStruct is the .patreon.* view as a structpb.Struct.
func membershipStruct(mem *Membership) (*structpb.Struct, error) {
	m := map[string]interface{}{
		"user_id":           mem.UserID,
		"email":             mem.Email,
		"full_name":         mem.FullName,
		"status":            mem.Status,
		"tier_slug":         mem.TierSlug,
		"tier_amount_cents": mem.TierAmount,
		"campaign_ids":      toIfaceSlice(mem.CampaignIDs),
		"benefits":          toIfaceSlice(mem.Benefits),
	}
	if mem.PledgeStart != "" {
		m["pledge_start"] = mem.PledgeStart
	}
	if mem.LastChargeAt != "" {
		m["last_charge_at"] = mem.LastChargeAt
	}
	return structpb.NewStruct(m)
}

func toIfaceSlice(in []string) []interface{} {
	out := make([]interface{}, len(in))
	for i, v := range in {
		out[i] = v
	}
	return out
}
