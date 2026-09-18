package authzen

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/opentdf/platform/service/pkg/authz"
)

// The bootstrap root of trust exists to solve one problem: the policy that
// decides who may change policy cannot be the only thing standing between a
// caller and that change. A request to write a subject mapping is governed
// by the same policy graph the request is about to modify, so a platform
// with an empty or broken policy graph would have no way back in.
//
// The answer is a small, fixed set of capabilities asserted directly by a
// token from a configured root authority:
//
//	root authority
//	     │  signs a CWT carrying `capabilities`
//	     ├── policy.bootstrap   seed the policy graph
//	     ├── policy.admin       administer policy
//	     └── authority.rotate   rotate platform keys
//
// Everything else — including ordinary administrative API access — flows
// through the normal decision path. Bootstrap capabilities only ever
// permit; they never deny, and they are never granted by policy.

// Capabilities recognized by the bootstrap root of trust.
const (
	CapabilityPolicyBootstrap = "policy.bootstrap"
	CapabilityPolicyAdmin     = "policy.admin"
	CapabilityAuthorityRotate = "authority.rotate"
)

// DefaultCapabilitiesClaim is the token claim inspected for capabilities.
const DefaultCapabilitiesClaim = "capabilities"

var (
	// ErrBootstrapIssuerRequired is returned when the bootstrap root of
	// trust is enabled without naming the authority that signs its tokens.
	// Honoring a capability claim from any issuer would let any token
	// source mint platform administrators.
	ErrBootstrapIssuerRequired = errors.New("authzen: bootstrap requires at least one trusted issuer")
	// ErrUnknownCapability is returned for a capability the platform does
	// not define.
	ErrUnknownCapability = errors.New("authzen: unknown bootstrap capability")
)

// BootstrapConfig configures the root of trust. It is disabled by default:
// a platform that does not need a break-glass path should not have one.
type BootstrapConfig struct {
	Enabled bool `mapstructure:"enabled" json:"enabled" default:"false"`
	// Issuers that may assert capabilities. Required when enabled.
	Issuers []string `mapstructure:"issuers" json:"issuers"`
	// CapabilitiesClaim is the token claim holding the capability list.
	CapabilitiesClaim string `mapstructure:"capabilities_claim" json:"capabilities_claim" default:"capabilities"`
	// RequireConfirmation requires the token to carry a `cnf` confirmation
	// claim, so a root capability is bound to a key the holder must prove
	// possession of rather than to a bearer secret alone.
	RequireConfirmation bool `mapstructure:"require_confirmation" json:"require_confirmation" default:"true"`
	// Capabilities overrides what each capability grants. Unset
	// capabilities keep their built-in scope.
	Capabilities map[string]CapabilityScope `mapstructure:"capabilities" json:"capabilities"`
}

// CapabilityScope is what a capability authorizes: glob patterns over
// resources and actions, in the same form as platform grants.
type CapabilityScope struct {
	Resources []string `mapstructure:"resources" json:"resources" yaml:"resources"`
	Actions   []string `mapstructure:"actions" json:"actions" yaml:"actions"`
}

// defaultCapabilityScopes are deliberately narrow. policy.admin covers
// administration of the policy graph and the KAS registry; policy.bootstrap
// covers only what seeding a graph requires; authority.rotate covers key
// rotation. None of them is a platform-wide wildcard.
func defaultCapabilityScopes() map[string]CapabilityScope {
	return map[string]CapabilityScope{
		CapabilityPolicyAdmin: {
			Resources: []string{"policy.*", "kasregistry.*", "/policy/*"},
			Actions:   []string{"*"},
		},
		CapabilityPolicyBootstrap: {
			Resources: []string{
				"policy.namespaces.*",
				"policy.attributes.*",
				"policy.subjectmapping.*",
				"policy.resourcemapping.*",
				"policy.registeredresources.*",
				"policy.actions.*",
			},
			Actions: []string{"*"},
		},
		CapabilityAuthorityRotate: {
			Resources: []string{"kasregistry.*", "policy.kasregistry.*"},
			Actions:   []string{"*"},
		},
	}
}

// Bootstrap evaluates root-of-trust capabilities.
type Bootstrap struct {
	enabled             bool
	issuers             []string
	claim               string
	requireConfirmation bool
	scopes              map[string]CapabilityScope
}

// NewBootstrap builds a bootstrap evaluator from configuration.
func NewBootstrap(cfg BootstrapConfig) (*Bootstrap, error) {
	b := &Bootstrap{
		enabled:             cfg.Enabled,
		issuers:             cfg.Issuers,
		claim:               cfg.CapabilitiesClaim,
		requireConfirmation: cfg.RequireConfirmation,
		scopes:              defaultCapabilityScopes(),
	}
	if b.claim == "" {
		b.claim = DefaultCapabilitiesClaim
	}
	for name, scope := range cfg.Capabilities {
		if _, ok := b.scopes[name]; !ok {
			return nil, fmt.Errorf("%w: %s", ErrUnknownCapability, name)
		}
		if len(scope.Resources) == 0 || len(scope.Actions) == 0 {
			return nil, fmt.Errorf("authzen: capability %s must set both resources and actions", name)
		}
		b.scopes[name] = scope
	}
	if b.enabled && len(b.issuers) == 0 {
		return nil, ErrBootstrapIssuerRequired
	}
	return b, nil
}

// Enabled reports whether the root of trust is active.
func (b *Bootstrap) Enabled() bool { return b != nil && b.enabled }

// CapabilitiesClaim is the token claim capabilities are read from.
func (b *Bootstrap) CapabilitiesClaim() string {
	if b == nil || b.claim == "" {
		return DefaultCapabilitiesClaim
	}
	return b.claim
}

// TrustsIssuer reports whether tokens from an issuer may assert
// capabilities.
func (b *Bootstrap) TrustsIssuer(issuer string) bool {
	if !b.Enabled() || issuer == "" {
		return false
	}
	return slices.Contains(b.issuers, issuer)
}

// Evaluate permits a request when the subject holds a capability whose
// scope covers it. It never denies: a caller without a capability is simply
// authorized the ordinary way.
func (b *Bootstrap) Evaluate(req authz.DecisionRequest) authz.Decision {
	abstain := authz.Decision{Effect: authz.EffectAbstain, Source: SourceBootstrap}
	if !b.Enabled() || len(req.Subject.Capabilities) == 0 {
		return abstain
	}
	if !b.TrustsIssuer(req.Context.Issuer) {
		abstain.Reason = "issuer is not a bootstrap authority"
		return abstain
	}
	if b.requireConfirmation && !subjectHasConfirmation(req.Subject) {
		abstain.Reason = "capability token is not key-bound"
		return abstain
	}

	for _, capability := range req.Subject.Capabilities {
		scope, ok := b.scopes[strings.TrimSpace(capability)]
		if !ok {
			continue
		}
		if matchesOne(req.Resource.ID, scope.Resources) && matchesOne(req.Action.Name, scope.Actions) {
			return authz.Decision{
				Effect: authz.EffectPermit,
				Source: SourceBootstrap,
				Reason: "root capability " + capability,
			}
		}
	}
	abstain.Reason = "no capability covers this request"
	return abstain
}

// subjectHasConfirmation reports whether the subject's token carries a
// `cnf` confirmation claim (RFC 8747 for CWT, RFC 7800 for JWT).
func subjectHasConfirmation(s authz.Subject) bool {
	if s.Token == nil {
		return false
	}
	cnf, ok := s.Token.Get("cnf")
	return ok && cnf != nil
}

// CapabilitiesFromClaim reads a capability list out of a token claim value.
// Both a single string and a list of strings are accepted.
func CapabilitiesFromClaim(claim any) []string {
	switch v := claim.(type) {
	case nil:
		return nil
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}
