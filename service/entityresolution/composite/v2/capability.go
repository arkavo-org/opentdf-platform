package composite

import (
	"slices"

	"github.com/opentdf/platform/service/entityresolution/source"
)

const defaultAction = "read"

// capability is what a source is allowed to do: serve some kinds of subject,
// under one issuer, and grant some actions on the attribute definitions it
// owns. The resolver enforces it on every grant a source returns.
type capability struct {
	issuer        string
	definitions   map[string]bool
	actions       []string
	subjects      map[source.Kind]bool
	pepAssertable bool
}

func newCapability(sc SourceConfig) capability {
	c := capability{
		issuer:        sc.Issuer,
		definitions:   map[string]bool{},
		actions:       sc.Actions,
		subjects:      map[source.Kind]bool{},
		pepAssertable: sc.PEPAssertable,
	}
	for _, g := range sc.Grants {
		if def, ok := definitionKey(g); ok {
			c.definitions[def] = true
		}
	}
	if len(c.actions) == 0 {
		c.actions = []string{defaultAction}
	}
	kinds := sc.Subjects
	if len(kinds) == 0 {
		kinds = []source.Kind{source.KindPerson, source.KindAgent, source.KindDevice}
	}
	for _, k := range kinds {
		c.subjects[k] = true
	}
	return c
}

// admits reports whether the source may be asked about s. A verified token
// must come from the source's issuer; a PEP's claims only when the source is
// pep_assertable and they carry that issuer; a subject with no trust has no
// claims to judge.
func (c capability) admits(s source.Subject) bool {
	if !c.subjects[s.Kind] {
		return false
	}
	iss, _ := s.Claims["iss"].(string)
	switch s.Trust {
	case source.TrustVerified:
		return iss != "" && iss == c.issuer
	case source.TrustPEP:
		return c.pepAssertable && iss != "" && iss == c.issuer
	case source.TrustNone:
		return true
	}
	return false
}

// allows reports whether g is a value of a definition the source owns, with
// only actions the source may grant.
func (c capability) allows(g source.Grant) bool {
	fqn, ok := source.ParseFQN(g.FQN)
	if !ok || !c.definitions[fqn.DefinitionFQN()] {
		return false
	}
	for _, a := range g.Actions {
		if !slices.Contains(c.actions, a) {
			return false
		}
	}
	return true
}
