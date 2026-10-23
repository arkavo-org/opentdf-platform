// Package entityconstraint is the contract between an entity resolver and the
// PDP for an entity that narrows its chain's subjects instead of being one. A
// device that comes with a person is such an entity: it never holds the
// person's entitlements, so it cannot be decided as a subject, but its class
// may cap what the person holds.
//
// The resolver puts the constraint in the entity's representation, under
// PropKey in an AdditionalProps struct. The PDP reads it only from the
// representation, never from the entity the caller sent.
package entityconstraint

import (
	"strings"

	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
)

const (
	// PropKey is the AdditionalProps key a constraint travels under.
	PropKey = "arkavo_constraint"
	// KindDevice is the kind of a device constraint.
	KindDevice = "device"
)

// Constraint is what one non-person entity allows its chain's subjects to
// keep. One that is not capped removes nothing.
type Constraint struct {
	Kind   string
	Class  string
	Capped bool
	// Allow holds the lowercased value FQNs a capped constraint keeps.
	Allow map[string]bool
}

// Props renders a constraint for an AdditionalProps struct. allow is ignored
// when capped is false.
func Props(kind, class string, capped bool, allow []string) map[string]any {
	list := make([]any, 0, len(allow))
	if capped {
		for _, fqn := range allow {
			list = append(list, strings.ToLower(fqn))
		}
	}
	return map[string]any{
		"kind":   kind,
		"class":  class,
		"capped": capped,
		"allow":  list,
	}
}

// FromRepresentation returns the constraint rep carries, if any. One with a
// kind but a malformed cap is read as capped to nothing, so a broken resolver
// narrows rather than widens.
func FromRepresentation(rep *entityresolutionV2.EntityRepresentation) (Constraint, bool) {
	for _, props := range rep.GetAdditionalProps() {
		field, ok := props.GetFields()[PropKey]
		if !ok {
			continue
		}
		m := field.GetStructValue().AsMap()
		kind, _ := m["kind"].(string)
		if kind == "" {
			continue
		}
		class, _ := m["class"].(string)
		c := Constraint{Kind: kind, Class: class, Allow: map[string]bool{}}
		capped, isBool := m["capped"].(bool)
		c.Capped = capped || !isBool
		if !c.Capped {
			return c, true
		}
		allow, _ := m["allow"].([]any)
		for _, v := range allow {
			if fqn, isString := v.(string); isString {
				c.Allow[strings.ToLower(fqn)] = true
			}
		}
		return c, true
	}
	return Constraint{}, false
}

// Keeps reports whether every constraint in cs lets a subject keep fqn.
// FQNs match exactly, ignoring case: a cap on a hierarchy value does not
// cover the values below it.
func Keeps(cs []Constraint, fqn string) bool {
	key := strings.ToLower(fqn)
	for _, c := range cs {
		if c.Capped && !c.Allow[key] {
			return false
		}
	}
	return true
}
