package authzen

import (
	"fmt"
	"sort"
	"strings"

	"github.com/opentdf/platform/service/pkg/authz"
	"gopkg.in/yaml.v3"

	_ "embed"
)

// rolePrefix marks a subject identifier as a role rather than a raw
// group/user identifier.
const rolePrefix = "role:"

// RoleUnknown is bound to every authenticated caller so policy can grant
// the small set of operations that require authentication but no role.
const RoleUnknown = "unknown"

//go:embed default_grants.yaml
var defaultGrantsYAML string

// Grant is one platform grant: which subjects may take which actions on
// which resources. Subjects, resources and actions are glob patterns; "*"
// matches anything.
type Grant struct {
	Subjects  []string `yaml:"subjects" json:"subjects"`
	Resources []string `yaml:"resources" json:"resources"`
	Actions   []string `yaml:"actions" json:"actions"`
	// Effect is "permit" (default) or "deny". A matching deny always wins.
	Effect string `yaml:"effect" json:"effect"`
}

// Binding maps an identifier carried by a subject — an idP group, a client
// ID, a username — onto a platform role.
type Binding struct {
	Subject string `yaml:"subject" json:"subject"`
	Role    string `yaml:"role" json:"role"`
}

// GrantSet is the platform's baseline authorization table: the operations
// the control plane permits before any policy-defined entitlement is
// consulted. It is data, not code, and is fully replaceable by operators.
type GrantSet struct {
	Grants   []Grant   `yaml:"grants" json:"grants"`
	Bindings []Binding `yaml:"bindings" json:"bindings"`

	// SkippedLines records legacy policy lines that could not be
	// translated, so startup can report them rather than silently drop
	// authorization the operator believes is in force.
	SkippedLines []string `yaml:"-" json:"-"`
}

// DefaultGrants returns the built-in grant set.
func DefaultGrants() (*GrantSet, error) {
	return ParseGrantSet(defaultGrantsYAML)
}

// Merge appends another grant set's grants and bindings to this one.
func (g *GrantSet) Merge(other *GrantSet) {
	if g == nil || other == nil {
		return
	}
	g.Grants = append(g.Grants, other.Grants...)
	g.Bindings = append(g.Bindings, other.Bindings...)
	g.SkippedLines = append(g.SkippedLines, other.SkippedLines...)
}

// Bind adds a binding of an identifier to a role.
func (g *GrantSet) Bind(subject, role string) {
	if g == nil || subject == "" || role == "" {
		return
	}
	g.Bindings = append(g.Bindings, Binding{Subject: subject, Role: role})
}

// Evaluate answers whether the grant set permits the request. It returns
// EffectAbstain when no grant matches, leaving the final answer to the
// engine.
func (g *GrantSet) Evaluate(req authz.DecisionRequest) authz.Decision {
	if g == nil || len(g.Grants) == 0 {
		return authz.Decision{Effect: authz.EffectAbstain, Source: SourceGrants, Reason: "no grants configured"}
	}

	subjects := g.subjectIdentifiers(req.Subject)
	var permitted *Grant

	for i := range g.Grants {
		grant := &g.Grants[i]
		if !grant.matches(subjects, req.Resource.ID, req.Action.Name) {
			continue
		}
		if strings.EqualFold(grant.Effect, string(authz.EffectDeny)) {
			// A matching deny is final, exactly as it was under the
			// previous enforcer's policy effect.
			return authz.Decision{
				Effect: authz.EffectDeny,
				Source: SourceGrants,
				Reason: "denied by platform grant",
			}
		}
		if permitted == nil {
			permitted = grant
		}
	}

	if permitted != nil {
		return authz.Decision{
			Effect: authz.EffectPermit,
			Source: SourceGrants,
			Reason: "permitted by platform grant",
		}
	}
	return authz.Decision{Effect: authz.EffectAbstain, Source: SourceGrants, Reason: "no matching grant"}
}

func (g *Grant) matches(subjects []string, resource, action string) bool {
	return matchesAny(subjects, g.Subjects) &&
		matchesOne(resource, g.Resources) &&
		matchesOne(action, g.Actions)
}

// matchesAny reports whether any of the subject's identifiers matches any
// of the grant's subject patterns.
func matchesAny(values, patterns []string) bool {
	for _, v := range values {
		if matchesOne(v, patterns) {
			return true
		}
	}
	return false
}

func matchesOne(value string, patterns []string) bool {
	for _, p := range patterns {
		if PatternMatch(value, p) {
			return true
		}
	}
	return false
}

// PatternMatch reports whether value matches a glob pattern in which "*"
// matches any run of characters. An empty pattern matches nothing; the
// pattern "*" matches everything.
func PatternMatch(value, pattern string) bool {
	if pattern == "" {
		return false
	}
	if pattern == "*" {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return value == pattern
	}

	segments := strings.Split(pattern, "*")
	// Leading segment must prefix the value.
	if first := segments[0]; first != "" {
		if !strings.HasPrefix(value, first) {
			return false
		}
		value = value[len(first):]
	}
	// Trailing segment must suffix the remainder.
	if last := segments[len(segments)-1]; last != "" {
		if !strings.HasSuffix(value, last) {
			return false
		}
		value = value[:len(value)-len(last)]
	}
	// Interior segments must appear in order.
	for _, seg := range segments[1 : len(segments)-1] {
		if seg == "" {
			continue
		}
		idx := strings.Index(value, seg)
		if idx < 0 {
			return false
		}
		value = value[idx+len(seg):]
	}
	return true
}

// ParseGrantSet parses a grant set from YAML, or from the legacy
// comma-separated policy lines the platform accepted previously. An empty
// document yields an empty set.
func ParseGrantSet(doc string) (*GrantSet, error) {
	if strings.TrimSpace(doc) == "" {
		return &GrantSet{}, nil
	}
	if isLegacyPolicy(doc) {
		return parseLegacyPolicy(doc)
	}

	set := &GrantSet{}
	if err := yaml.Unmarshal([]byte(doc), set); err != nil {
		return nil, fmt.Errorf("authzen: failed to parse grants: %w", err)
	}
	if err := set.Validate(); err != nil {
		return nil, err
	}
	return set, nil
}

// Validate rejects grants that cannot express a decision.
func (g *GrantSet) Validate() error {
	for i, grant := range g.Grants {
		switch {
		case len(grant.Subjects) == 0:
			return fmt.Errorf("authzen: grant %d has no subjects", i)
		case len(grant.Resources) == 0:
			return fmt.Errorf("authzen: grant %d has no resources", i)
		case len(grant.Actions) == 0:
			return fmt.Errorf("authzen: grant %d has no actions", i)
		}
		if grant.Effect != "" &&
			!strings.EqualFold(grant.Effect, string(authz.EffectPermit)) &&
			!strings.EqualFold(grant.Effect, string(authz.EffectDeny)) {
			return fmt.Errorf("authzen: grant %d has unknown effect %q", i, grant.Effect)
		}
	}
	for i, b := range g.Bindings {
		if b.Subject == "" || b.Role == "" {
			return fmt.Errorf("authzen: binding %d must set both subject and role", i)
		}
	}
	return nil
}

// GrantSources are the places a platform grant table can come from, in the
// precedence order the platform applies them.
type GrantSources struct {
	// Builtin replaces the embedded default table (set programmatically by
	// an embedding application).
	Builtin string
	// Grants replaces the table entirely (operator configuration).
	Grants string
	// Extension is merged on top of the table in force.
	Extension string
	// RoleMap binds platform roles to idP group identifiers, keyed by role.
	RoleMap map[string]string
}

// BuildGrantSet assembles the platform grant table from its sources.
//
// The embedded defaults ship with bindings for the conventional
// `opentdf-admin` and `opentdf-standard` groups. Those bindings are the
// platform's opinion about an unconfigured deployment, so as soon as an
// operator states their own — through a role map or an extension — the
// defaults step aside rather than silently granting administration to a
// group the operator did not name.
func BuildGrantSet(src GrantSources) (*GrantSet, error) {
	var (
		set          *GrantSet
		err          error
		usingDefault bool
	)

	switch {
	case strings.TrimSpace(src.Grants) != "":
		set, err = ParseGrantSet(src.Grants)
	case strings.TrimSpace(src.Builtin) != "":
		set, err = ParseGrantSet(src.Builtin)
	default:
		set, err = DefaultGrants()
		usingDefault = true
	}
	if err != nil {
		return nil, err
	}

	operatorBindings := len(src.RoleMap) > 0 || strings.TrimSpace(src.Extension) != ""
	if usingDefault && operatorBindings {
		set.Bindings = nil
	}

	roles := make([]string, 0, len(src.RoleMap))
	for role := range src.RoleMap {
		roles = append(roles, role)
	}
	sort.Strings(roles)
	for _, role := range roles {
		set.Bind(src.RoleMap[role], role)
	}

	if strings.TrimSpace(src.Extension) != "" {
		ext, err := ParseGrantSet(src.Extension)
		if err != nil {
			return nil, err
		}
		set.Merge(ext)
	}

	if err := set.Validate(); err != nil {
		return nil, err
	}
	return set, nil
}

// subjectIdentifiers expands a subject into every identifier a grant may
// match: its roles as presented, its username and client ID, whatever those
// identifiers are bound to, and the catch-all authenticated role.
func (g *GrantSet) subjectIdentifiers(s authz.Subject) []string {
	seen := make(map[string]struct{})
	queue := make([]string, 0, len(s.Roles)+3) //nolint:mnd // roles + id + client + unknown

	add := func(id string) {
		if id == "" {
			return
		}
		if _, ok := seen[id]; ok {
			return
		}
		seen[id] = struct{}{}
		queue = append(queue, id)
	}

	for _, r := range s.Roles {
		add(r)
	}
	add(s.ID)
	add(s.ClientID)
	add(rolePrefix + RoleUnknown)

	// Resolve bindings transitively so an idP group bound to a role that is
	// itself bound to another role resolves fully. The queue is bounded by
	// the number of distinct identifiers, so this terminates.
	for i := 0; i < len(queue); i++ {
		current := queue[i]
		for _, b := range g.Bindings {
			if b.Subject == current {
				role := b.Role
				if !strings.HasPrefix(role, rolePrefix) {
					role = rolePrefix + role
				}
				add(role)
			}
		}
	}

	return queue
}
