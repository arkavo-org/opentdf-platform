package patreon

import (
	"context"
	"regexp"
	"strings"

	"github.com/opentdf/platform/service/entityresolution/source"
)

// entitlementsClaim is the CWT claim identity.arkavo.net fills with the
// subject's attribute value FQNs. It is the only place Patreon grants come
// from; arkavo_patreon feeds the .patreon properties and nothing else.
const entitlementsClaim = "arkavo_entitlements"

// campaignTierValue is the campaign-tier value shape: <campaign digits>_<slug>.
var campaignTierValue = regexp.MustCompile(`^[0-9]+_[a-z0-9-]+$`)

// SourceConfig configures the Patreon token source.
type SourceConfig struct {
	// EntitlementsNamespace is the namespace of the campaign and
	// campaign-tier definitions. Default patreon.arkavo.com.
	EntitlementsNamespace string `mapstructure:"entitlements_namespace"`
	// InferUnknownAsFree gives a subject with no arkavo_patreon claim the
	// free membership view instead of nothing.
	InferUnknownAsFree bool `mapstructure:"infer_unknown_as_free"`
}

// Definitions returns the attribute definition FQNs the source grants values
// of: campaign and campaign-tier, in its namespace.
func (c SourceConfig) Definitions() []string {
	prefix := "https://" + c.namespace() + "/attr/"
	return []string{prefix + campaignAttributeName, prefix + campaignTierAttributeName}
}

// namespace is the configured namespace, defaulted and lowercased.
func (c SourceConfig) namespace() string {
	ns := c.EntitlementsNamespace
	if ns == "" {
		ns = defaultEntitlementsNamespace
	}
	return strings.ToLower(ns)
}

type tokenSource struct {
	namespace          string
	inferUnknownAsFree bool
}

// NewTokenSource returns the source that reads Patreon grants from the
// verified token's arkavo_entitlements claim and Patreon properties from its
// arkavo_patreon claim.
func NewTokenSource(cfg SourceConfig) source.Source {
	return &tokenSource{namespace: cfg.namespace(), inferUnknownAsFree: cfg.InferUnknownAsFree}
}

// Resolve never fails: there is no I/O, and malformed claim data is dropped.
func (s *tokenSource) Resolve(_ context.Context, subject source.Subject, _ source.Query) (source.Resolution, error) {
	res := source.Resolution{
		Grants:     s.grants(subject.Claims),
		Properties: s.properties(subject.Claims),
	}
	if len(res.Grants) > 0 || res.Properties != nil {
		res.Outcome = source.OutcomeComplete
	} else {
		res.Outcome = source.OutcomeNotApplicable
	}
	return res, nil
}

// grants returns every arkavo_entitlements string that is a well-formed
// campaign or campaign-tier value in the configured namespace. ParseFQN is
// only structural, so the namespace and the value shape are checked here.
func (s *tokenSource) grants(claims map[string]any) []source.Grant {
	var out []source.Grant
	seen := map[string]bool{}
	for _, raw := range stringList(claims[entitlementsClaim]) {
		fqn, ok := source.ParseFQN(raw)
		if !ok || fqn.Namespace != s.namespace || !validValue(fqn) {
			continue
		}
		key := fqn.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, source.Grant{FQN: key, Actions: []string{"read"}})
	}
	return out
}

func validValue(fqn source.FQN) bool {
	switch fqn.Definition {
	case campaignAttributeName:
		return numericCampaignID.MatchString(fqn.Value)
	case campaignTierAttributeName:
		return campaignTierValue.MatchString(fqn.Value)
	default:
		return false
	}
}

// properties returns the Patreon membership view, or the free view when
// there is no claim and InferUnknownAsFree is set, or nil.
func (s *tokenSource) properties(claims map[string]any) map[string]any {
	var mem *Membership
	if claim := parseArkavoPatreon(claims); claim != nil {
		mem = membershipView(claim)
	} else if s.inferUnknownAsFree {
		mem = &Membership{TierSlug: tierFree, Status: statusFormer}
	} else {
		return nil
	}
	st, err := membershipStruct(mem)
	if err != nil {
		return nil
	}
	return st.AsMap()
}

// stringList returns the string elements of a claim list; anything else in
// it, or a non-list claim, is ignored.
func stringList(v any) []string {
	switch list := v.(type) {
	case []string:
		return list
	case []any:
		out := make([]string, 0, len(list))
		for _, e := range list {
			if str, ok := e.(string); ok {
				out = append(out, str)
			}
		}
		return out
	default:
		return nil
	}
}
