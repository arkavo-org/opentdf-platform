package patreon

import (
	"fmt"
)

// Claims-passthrough resolution: the SaaS multi-creator path.
//
// identity.arkavo.net materializes every consumer's Patreon memberships into
// the `arkavo_patreon` CWT claim at token mint, using the consumer's own
// OAuth token — which sees every campaign they back. When those materialized
// memberships arrive in an entity's claims (forwarded by an authenticated
// PEP from a signature-verified token, or re-encoded by the platform's own
// CWT verifier), this provider needs NO Patreon API access, NO per-creator
// credentials, and NO per-creator policy:
//
//   - each ACTIVE membership emits direct entitlements (experimental
//     synthetic-value support; only the attribute *definitions* below need
//     to exist in policy):
//     https://<ns>/attr/campaign/value/<campaign_id>
//     https://<ns>/attr/campaign-tier/value/<campaign_id>_<tier_slug>
//   - tier entitlements are campaign-qualified in the creator's OWN tier
//     vocabulary — no cross-creator tier normalization, and no cross-tenant
//     privilege leakage (a vip at creator A grants nothing at creator B).
//
// Content is tagged at protect time with the explicit value list for "this
// tier and up" (the Creator app knows its own ladder), so no server ever
// needs per-campaign hierarchy knowledge.
const (
	defaultEntitlementsNamespace = "patreon.arkavo.com"
	campaignAttributeName        = "campaign"
	campaignTierAttributeName    = "campaign-tier"
	// Tier slugs never contain '_' (slugify maps separators to '-'), and
	// campaign ids are numeric, so the first '_' splits unambiguously.
	campaignTierSeparator = "_"
)

// resolution is a resolved entity: the flattened membership view (backing
// the legacy .patreon.* selectors) plus any directly granted attribute
// value FQNs derived from trusted, pre-materialized claims.
type resolution struct {
	mem          *Membership
	entitlements []string
}

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
// malformed returns nil (callers fall back to live resolution paths).
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

// passthroughResolution converts a materialized claim into the flattened
// membership view plus campaign-qualified direct entitlements. Only ACTIVE
// memberships grant anything — declined/former patrons emit no entitlements
// for that campaign.
func passthroughResolution(claim *arkavoPatreonClaim, namespace string) *resolution {
	mem := &Membership{
		UserID:   claim.userID,
		TierSlug: tierFree,
		Status:   normalizeStatus(""),
	}

	var entitlements []string
	for _, m := range claim.memberships {
		status := normalizeStatus(m.status)
		if mem.Status != statusActive {
			mem.Status = status
		}
		if status != statusActive {
			continue
		}
		mem.Status = statusActive
		mem.CampaignIDs = append(mem.CampaignIDs, m.campaignID)
		entitlements = append(entitlements, fmt.Sprintf(
			"https://%s/attr/%s/value/%s", namespace, campaignAttributeName, m.campaignID,
		))
		for _, rawSlug := range m.tierSlugs {
			// Enforce the FQN split invariant rather than trusting the
			// materializer: slugify guarantees lowercase, no '_' and no
			// spaces, so <campaign_id>_<tier_slug> splits unambiguously and
			// matches the policy value form.
			slug := slugify(rawSlug)
			if slug == "" {
				continue
			}
			// Flattened tier_slug is informational only in multi-creator
			// mode; gating uses the campaign-qualified entitlements below.
			if mem.TierSlug == tierFree {
				mem.TierSlug = slug
			}
			entitlements = append(entitlements, fmt.Sprintf(
				"https://%s/attr/%s/value/%s%s%s",
				namespace, campaignTierAttributeName, m.campaignID, campaignTierSeparator, slug,
			))
		}
	}

	// Creator role: surface the owned campaign like the live path does.
	if claim.role == "creator" && claim.campaignID != "" {
		mem.CampaignIDs = append(mem.CampaignIDs, claim.campaignID)
	}

	return &resolution{mem: mem, entitlements: entitlements}
}

// entitlementsNamespace returns the configured namespace for emitted
// entitlement FQNs.
func (c *Config) entitlementsNamespace() string {
	if c.EntitlementsNamespace != "" {
		return c.EntitlementsNamespace
	}
	return defaultEntitlementsNamespace
}

// issuerTrusted reports whether the verified token's issuer is acceptable
// for materialized-claim passthrough. Empty TrustedIssuer = no check.
func (s *EntityResolutionService) issuerTrusted(claims map[string]interface{}) bool {
	if s.cfg.TrustedIssuer == "" {
		return true
	}
	iss, _ := claims["iss"].(string)
	return iss == s.cfg.TrustedIssuer
}
