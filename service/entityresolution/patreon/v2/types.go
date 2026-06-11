package patreon

import (
	"errors"
	"strings"
)

// Normalized claim values surfaced to the policy engine.
const (
	tierFree       = "free"
	statusActive   = "active"
	statusDeclined = "declined"
	statusFormer   = "former"
	// Raw Patreon patron_status for an active pledge.
	patronStatusActive = "active_patron"
)

// ErrMemberNotFound is returned when a subject carries no usable Patreon
// claim (and, with InferUnknownAsFree, is then treated as a free follower).
var ErrMemberNotFound = errors.New("patreon member not found")

// Membership is the flattened subject-claim view of Patreon state surfaced
// to the policy engine under the .patreon.* selectors. In claims-passthrough
// mode it is derived from the materialized arkavo_patreon claim; the
// campaign-qualified entitlements (see passthrough.go) are the authoritative
// gating signal, this view is for legacy/coarse selectors.
type Membership struct {
	UserID       string   `json:"user_id"`
	Email        string   `json:"email"`
	FullName     string   `json:"full_name"`
	Status       string   `json:"status"`
	TierSlug     string   `json:"tier_slug"`
	TierAmount   int      `json:"tier_amount_cents"`
	CampaignIDs  []string `json:"campaign_ids"`
	Benefits     []string `json:"benefits"`
	PledgeStart  string   `json:"pledge_start,omitempty"`
	LastChargeAt string   `json:"last_charge_at,omitempty"`
}

// normalizeStatus maps Patreon's patron_status to the policy vocabulary.
func normalizeStatus(in string) string {
	switch strings.ToLower(in) {
	case patronStatusActive:
		return statusActive
	case "declined_patron":
		return statusDeclined
	case "former_patron":
		return statusFormer
	case "":
		return statusFormer
	default:
		return strings.ToLower(in)
	}
}

// slugify lowercases a tier title and collapses non-alphanumeric runs to a
// single '-', producing the campaign-qualified entitlement value form
// (lowercase, no '_' separator, no spaces). Mirrors authnz's slugify_tier.
func slugify(in string) string {
	in = strings.ToLower(strings.TrimSpace(in))
	if in == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(in))
	prevDash := false
	for _, r := range in {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			prevDash = false
		case r == '-' || r == '_' || r == ' ':
			if !prevDash {
				b.WriteRune('-')
				prevDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}
