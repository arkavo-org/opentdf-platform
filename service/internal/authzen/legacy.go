package authzen

import (
	"fmt"
	"strings"

	"github.com/opentdf/platform/service/pkg/authz"
)

// The platform previously expressed endpoint authorization as
// comma-separated policy lines:
//
//	p, role:standard, policy.*, read, allow
//	g, opentdf-admin, role:admin
//
// That table is now a GrantSet, but operator configuration written in the
// old form still loads: the lines are translated into grants and bindings
// at startup so upgrading does not require rewriting policy. New
// configuration should use the YAML form.

const (
	legacyPolicyPrefix  = "p,"
	legacyGroupPrefix   = "g,"
	legacyMinPolicyLen  = 4 // p, subject, resource, action
	legacyFullPolicyLen = 5 // p, subject, resource, action, effect
	legacyGroupLen      = 3 // g, subject, role
	legacyAllowEffect   = "allow"
	legacyDenyEffect    = "deny"
)

// isLegacyPolicy reports whether a document is written in the legacy
// comma-separated form rather than YAML.
func isLegacyPolicy(doc string) bool {
	for _, line := range strings.Split(doc, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		normalized := strings.ReplaceAll(line, " ", "")
		normalized = strings.ReplaceAll(normalized, "\t", "")
		if strings.HasPrefix(normalized, legacyPolicyPrefix) || strings.HasPrefix(normalized, legacyGroupPrefix) {
			return true
		}
		// The first meaningful line decides: anything else is YAML.
		return false
	}
	return false
}

// parseLegacyPolicy translates legacy policy lines into a GrantSet.
// Unrecognized lines are skipped rather than rejected, matching how the
// previous enforcer treated them, and are reported so the caller can log
// them.
func parseLegacyPolicy(doc string) (*GrantSet, error) {
	set := &GrantSet{}
	var skipped []string

	for _, raw := range strings.Split(doc, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := splitLegacyFields(line)
		switch fields[0] {
		case "p":
			grant, err := legacyGrant(fields)
			if err != nil {
				skipped = append(skipped, line)
				continue
			}
			set.Grants = append(set.Grants, *grant)
		case "g":
			if len(fields) != legacyGroupLen {
				skipped = append(skipped, line)
				continue
			}
			set.Bindings = append(set.Bindings, Binding{
				Subject: fields[1],
				Role:    strings.TrimPrefix(fields[2], rolePrefix),
			})
		default:
			skipped = append(skipped, line)
		}
	}

	if len(set.Grants) == 0 && len(set.Bindings) == 0 && len(skipped) > 0 {
		return nil, fmt.Errorf("authzen: no usable policy lines found; first unparsed line: %q", skipped[0])
	}
	set.SkippedLines = skipped
	return set, nil
}

func splitLegacyFields(line string) []string {
	parts := strings.Split(line, ",")
	fields := make([]string, 0, len(parts))
	for _, p := range parts {
		fields = append(fields, strings.TrimSpace(p))
	}
	return fields
}

func legacyGrant(fields []string) (*Grant, error) {
	if len(fields) < legacyMinPolicyLen || len(fields) > legacyFullPolicyLen {
		return nil, fmt.Errorf("authzen: legacy policy line must have %d or %d fields, got %d",
			legacyMinPolicyLen, legacyFullPolicyLen, len(fields))
	}
	effect := string(authz.EffectPermit)
	if len(fields) == legacyFullPolicyLen {
		switch strings.ToLower(fields[4]) {
		case legacyAllowEffect, string(authz.EffectPermit):
			effect = string(authz.EffectPermit)
		case legacyDenyEffect:
			effect = string(authz.EffectDeny)
		default:
			return nil, fmt.Errorf("authzen: unknown legacy policy effect %q", fields[4])
		}
	}
	for _, f := range fields[1:legacyMinPolicyLen] {
		if f == "" {
			return nil, fmt.Errorf("authzen: legacy policy line has an empty field: %v", fields)
		}
	}
	return &Grant{
		Subjects:  []string{fields[1]},
		Resources: []string{fields[2]},
		Actions:   []string{fields[3]},
		Effect:    effect,
	}, nil
}
